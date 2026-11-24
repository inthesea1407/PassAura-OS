# PassAura OS — Backend (Supabase) notes

This document records the Module 3 review of the SQL drafts (0001–0003), the hardening
migrations (0004–0006), the SQL and Deno tests, the Edge Function fixes, and the admin
panel hardening. It is the companion to `docs/CONTRACTS.md` (frozen contracts).

Nothing in 0001–0003 was edited. All fixes are additive migrations.

---

## 1. Findings (severity, file, what changed)

### F1 — CRITICAL — `0002_admin.sql` + `admin/app.js`
`admin_set_device_revoked(uuid, boolean)` is a toggle: passing `false` silently
un-revokes a device, and the panel exposed a "Restore" button wired to it. A revoked
(stolen) device could be brought back by the owner in one click, or by any leaked
owner session.

**Fix:** `0005_admin_deny_and_helpers.sql` redefines `admin_set_device_revoked` to
accept only `p_revoked = true` (raises `USE_ADMIN_RESTORE_DEVICE` otherwise) and adds a
separate `admin_restore_device(uuid)`. `admin/app.js` calls the two distinct RPCs and
shows "Revoke" / "Restore" as separate actions with a confirmation each.

### F2 — CRITICAL — `0001_init.sql`
The seed window (`if v_count < v_cfg.seed_limit`) ran **before** the `mode`/`invites_paused`
checks, so a `closed` project still registered the first N devices for free, and
`seed_limit` could be raised later to re-open the window.

**Fix:** `0004_fixes.sql` `register_device` now checks `closed`/`paused` first, then
counts **seed** devices only (`is_seed = true`) against `seed_limit`, and a trigger
`tg_admin_config_seed_limit_guard` forbids ever increasing `seed_limit`.

### F3 — CRITICAL — `0001_init.sql` vs `0003_ratelimit_redeem.sql`
`0001` did `grant execute on register_device to anon, service_role`, then `0003` revoked
from `anon`. This is order-dependent: if migrations are ever re-run out of order, or
0003 is rolled back, `anon` can call `register_device` **directly via PostgREST** and
bypass the Edge Function's IP rate limit and input validation.

**Fix:** `0004_fixes.sql` explicitly `revoke all ... from public, anon, authenticated`
and `grant execute ... to service_role` on `register_device`. `40_rate_limit.sql` /
`20_register_device.sql` assert anon cannot call it.

### F4 — HIGH — `0003_ratelimit_redeem.sql`
`rate_limit_hit` is `security definer` and trusted caller-supplied `p_bucket`, `p_max`,
`p_window_seconds` with no bounds. The prune `delete from rate_limits where window_start <
now() - interval '1 day'` ran on **every call**, unbounded (table scan, and could delete
rows other buckets still need).

**Fix:** `0006_ratelimit_hardening.sql` validates bucket length (≤ 200), `p_max` in
1..100000, window in 1..86400 seconds, and bounds the prune to 500 rows per call. Also
pins `search_path = ''`.

### F5 — HIGH — `0003_ratelimit_redeem.sql`
`admin_issue_premium_key(p_plan, p_days, ...)` accepted `p_days <= 0`, producing a key
that is already expired at issue time, and accepted unvalidated `p_plan`/`p_project`.

**Fix:** `0004_fixes.sql` bounds `p_days` to 1..3650, caps `p_plan` length at 40, and
requires `p_project` to exist in `projects`. The panel validates 1..3650 client-side too.

### F6 — HIGH — `0002_admin.sql`
`owners` has RLS enabled with **no policies**. That is fail-closed for reads, but the
intent is undocumented and any future `grant` would silently expose the owner list.

**Fix:** `0005_admin_deny_and_helpers.sql` explicitly `revoke all on owners from anon,
authenticated`. `is_owner()` is redefined with `search_path = ''` and reads `auth.uid()`
via `(select auth.uid())` to avoid per-row re-evaluation.

### F7 — HIGH — `admin/index.html`
`<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2">` with no SRI and a
floating `@2` tag. A compromised CDN or MITM of the CDN response can run arbitrary JS
with the owner's session. There was also no `integrity`/`crossorigin`.

**Fix:** the script tag is pinned to `@2.49.8`, has `integrity="sha384-..."` (placeholder
to be filled from `openssl dgst -sha384 -binary | openssl base64 -A`), and
`crossorigin="anonymous"`. The CSP is expanded: `object-src 'none'; base-uri 'none';
form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self'`, and
`style-src` uses a hash for the inline `<style>` instead of `'unsafe-inline'`.

### F8 — HIGH — `admin/app.js`
`esc()` escaped `& < > "` but not `'` or `` ` ``. All interpolations happened to use
double quotes, but the function is unsafe-by-default for future edits.

**Fix:** the escaper now covers `& < > " ' `` ` ``. Every `innerHTML` built from DB
values goes through it. Secrets are still rendered with `textContent`.

### F9 — HIGH — `supabase/functions/register/index.ts` and `redeem-key/index.ts`
The client IP was taken from the **first** `x-forwarded-for` hop, which is
client-spoofable. An attacker can send `X-Forwarded-For: 1.2.3.4` and defeat the per-IP
rate limit.

**Fix:** `clientIp()` prefers the platform header `cf-connecting-ip` and otherwise takes
the **last** `x-forwarded-for` hop (the one added by the trusted proxy).

### F10 — HIGH — both Edge Functions
`return j({ error: error.message }, 403)` leaked internal DB error strings and mapped
any DB failure to 403 with a non-contract error code. A unique-constraint violation on a
concurrent registration would surface as a raw Postgres message.

**Fix:** a whitelist of contract-visible codes (`REGISTRATION_CLOSED`,
`INVITE_INVALID_OR_USED`, `DEVICE_REVOKED`, `DEVICE_ALREADY_REGISTERED` for register;
`KEY_INVALID`, `DEVICE_INVALID` for redeem). Anything else is logged server-side with
`console.error` and returned as a generic contract code.

### F11 — MEDIUM — `0001_init.sql`
The revoked/already-registered checks ran before `lock table devices`, so two concurrent
requests with the same hash could both pass and one would raise a raw
`unique_violation` instead of `DEVICE_ALREADY_REGISTERED`.

**Fix:** `register_device` in 0004 keeps the fast-path checks but wraps the `insert` in
`begin ... exception when unique_violation then raise exception
'DEVICE_ALREADY_REGISTERED'`. The invite is consumed atomically with a single
`update ... where used_by_device is null returning id`.

### F12 — MEDIUM — `0001_init.sql`
The `anon` grant on `register_device` (see F3) is also a default-grant hazard.

**Fix:** covered by F3; 0004 revokes from `public, anon, authenticated` explicitly.

### F13 — MEDIUM — `0002_admin.sql`
`admin_issue_invites(p_count, p_owner_device)` accepted any uuid for `p_owner_device`,
including a revoked or non-existent device.

**Fix:** `0004_fixes.sql` requires `p_owner_device` to be null or an existing, non-revoked
device (`raise exception 'OWNER_DEVICE_INVALID'`).

### F14 — MEDIUM — `0003_ratelimit_redeem.sql`
`redeem_premium_key` locks with `select ... for update`; on a missing row no lock is
taken, so two concurrent wrong-code attempts both proceed. Benign but worth documenting.
`premium_active` is `security definer` and will bypass future RLS on `premium_keys` /
`devices` — intended, but must stay documented.

**Fix:** documented here; `premium_active` is unchanged (correct as-is).

### F15 — MEDIUM — `admin/app.js`
The panel sent `updated_at: new Date().toISOString()` on `admin_config` and
`feature_flags` updates — client clock, and unnecessary.

**Fix:** removed from the payload. `0004_fixes.sql` adds a `tg_stamp_updated_at` trigger
on `admin_config` and `feature_flags` so the DB always stamps it.

### F16 — MEDIUM — `admin/app.js`
`+$('n').value` and `+$('days').value` could be `0` / `NaN` and reach the RPC.

**Fix:** the panel now parses and bounds `n` (1..50) and `days` (1..3650) before calling.

### F17 — LOW — `0003_ratelimit_redeem.sql`
`redeem_premium_key` is defined **twice** in the same file (first without
`redeemed_by_device`, then with). The second wins, but it is confusing.

**Fix:** the canonical body is in `0003` (the second definition); 0006 does not touch it.
No behavior change.

### F18 — LOW — `admin/index.html`
CSP lacked `frame-ancestors`, `base-uri`, `form-action`, `object-src`.

**Fix:** added to the CSP in `admin/index.html` (see F7).

### F19 — LOW — `0001_init.sql`
`hardware_id_hash text` had no format check; service_role could store any string.

**Fix:** `0004_fixes.sql` adds `check (hardware_id_hash ~ '^[0-9a-f]{64}$')` and
`register_device` re-validates and raises `BAD_HARDWARE_ID_HASH`.

### F20 — LOW — `0002_admin.sql`
Free-text columns (`plan`, `note`) had no length caps.

**Fix:** `admin_issue_premium_key` caps `p_plan` at 40 chars and `p_note` at 200.

---

## 2. What changed, in one table

| Area | File | Change |
|---|---|---|
| Seed window | `0004_fixes.sql` | closed/paused checked first; seed count only counts `is_seed`; `seed_limit` can never increase |
| Registration | `0004_fixes.sql` | race-safe unique violation, atomic invite consume, hash format check, anon denied |
| Admin RPCs | `0004_fixes.sql`, `0005_admin_deny_and_helpers.sql` | restore separated from revoke, `search_path=''`, owner/MFA re-checked, `owners` deny-listed |
| Rate limit | `0006_ratelimit_hardening.sql` | input bounds, bounded prune, `search_path=''` |
| Edge Functions | `supabase/functions/*/index.ts` | spoof-proof IP, contract-only error mapping |
| Tests | `supabase/tests/*.sql`, `supabase/functions/**/index.test.ts` | pgTAP + Deno coverage of the contract |
| Panel | `admin/index.html`, `admin/app.js`, `admin/config.js`, `admin/i18n.js` | SRI-pinned supabase-js, strict CSP, EN/AR toggle, complete escaper, server-stamped timestamps, bounded inputs |

---

## 3. How to run

### SQL (pgTAP)
Requires a Postgres with the migrations applied and `pgTAP` available (Supabase has it
in the `extensions` schema).

```sh
# 1. Apply migrations in order (0001 .. 0006).
for f in supabase/migrations/*.sql; do
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
done

# 2. Run the tests.
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/run.sql

run.sql runs, in order: 00_setup.sql (installs pgTAP), 10_rls_and_anon.sql
(anon read/write denial, non-owner admin_* denial, aal1 denial), 20_register_device.sql
(closed mode, paused invites, seed window, invite single use, revoked device, bad hash,
anon direct-call denial), 30_redeem_premium_key.sql (issue/redeem twice, revoked,
expired, revoked device, aal1 denial), 40_rate_limit.sql (allowed 1..N, blocked N+1,
anon denial).

Each test file is begin; ... rollback; so it leaves the DB untouched.

Deno (Edge Functions)

Requires Deno ≥ 1.40. The tests mock the Supabase client — no network, no secrets.

sh
Copy
Download
deno test --allow-env supabase/functions/register/index.test.ts
deno test --allow-env supabase/functions/redeem-key/index.test.ts

The tests cover:

register: 200 with device_id, 403 for each of the four contract codes, 429 when
the rate-limit bucket is exhausted or rate_limit_hit errors, 400 on bad hash and on
malformed JSON, and the clientIp anti-spoof behavior.

redeem-key: 200 with premium_until, 200 with premium_until: null (perpetual key),
403 KEY_INVALID, 403 DEVICE_INVALID, 429 on bucket exhausted or RPC error, and
truncation of code to 64 chars before the RPC.

Admin panel

Put SUPABASE_URL and SUPABASE_ANON_KEY in admin/config.js (public values only).

Replace the two placeholders in admin/index.html:

integrity="sha384-REPLACE_WITH_REAL_SHA384_BASE64" on the supabase-js <script>

'sha256-REPLACE_WITH_STYLE_HASH' in the style-src directive
(echo -n "<style contents>" | openssl dgst -sha256 -binary | openssl base64 -A).

Serve admin/ over HTTPS. CSP is default-src 'self', so no file:// or http://.

The EN/AR toggle in admin/i18n.js is client-only; it does not call Supabase.

4. What I could not run

I could not run any of the following in this environment, so they remain unverified
by execution and should be run in CI against a throwaway Supabase project:

Postgres / Supabase migrations 0004–0006 (no live DB, no psql, no DATABASE_URL).

supabase/tests/run.sql and each 10_*/20_*/30_*/40_* test file (no pgTAP).

Deno tests supabase/functions/**/index.test.ts (no Deno runtime here).

The hardened admin/index.html under a browser CSP validator (no headless browser);
the style-src sha256 and the supabase-js integrity hash are placeholders that
must be regenerated against the exact files you deploy.

End-to-end redeploy of the two Edge Functions (supabase functions deploy register,
supabase functions deploy redeem-key) — deploy only after owner approval, per the
comment in register/index.ts.

Everything above is a code change and a test specification; it is not a claim that the
tests pass. Please run the three command groups in §3 in CI and record the results before
treating the backend as hardened.
## Round 2 — Concurrency, indexes, rate-limit cleanup

This section is appended to the Module 3 BACKEND.md. Migrations 0001–0006 are
unchanged; 0007 and 0008 are new.

### 1. Race-condition tests (`supabase/tests/50_concurrency.sql`)

Three races are covered, each using `dblink` to open a competing session that
holds a transaction open while the test session runs:

- **One invite, two devices.** Session 2 consumes the invite and commits;
  session 1 then attempts the same code and must raise `INVITE_INVALID_OR_USED`.
  Assertion also checks that the winning device exists exactly once.
- **Seed-limit boundary.** Two sessions both see `count(is_seed) < seed_limit`
  and both attempt to insert a seed device. The test asserts that the total
  seed count never exceeds `seed_limit`.
- **One key, two devices.** Session 2 redeems the key (taking the `FOR UPDATE`
  lock) and commits; session 1 then attempts the same key and must raise
  `KEY_INVALID`. Assertion checks the key is bound to exactly one device.

**Caveat on `dblink` and Supabase runtimes:** pgTAP suites that use `dblink`
for concurrency **work under the Docker runtime** (`supabase start`, then
`supabase test db`) but **fail under the native runtime**, because native
Postgres refuses non-superuser `dblink` connections when the server only
accepts trust auth (supabase/cli#6832). If you run on native, replace the
`dblink` calls with an external harness that opens two `psql` connections and
interleaves the transactions manually.

**Likely finding exposed by the seed-boundary test:** `register_device` in
`0004_fixes.sql` counts seed devices and inserts without an advisory lock or
a `SELECT ... FOR UPDATE` on a serialization row. Two concurrent calls can both
pass the count check and both insert as seed, exceeding `seed_limit`. The test
above is written to **fail loudly** if this happens. If it fails in your
environment, the fix is a migration `0009` that either:
  (a) takes `pg_advisory_xact_lock(hashtext('seed_window'))` before the count,
      or
  (b) adds a `seed_window` row in `admin_config` and `SELECT ... FOR UPDATE`s it.
Option (a) is simpler; option (b) is more explicit. I did not add either in this
round because the brief asked for tests, not a fix, and I wanted the test to
demonstrate the gap rather than hide it behind a lock that was never tested.

### 2. Indexes (`0007_indexes.sql`)

Only two indexes were added; everything else was deliberately omitted:

- **`invites_open_code_hash_idx`** — partial index on `(code_hash) WHERE
  used_by_device IS NULL`. The plain btree on `code_hash` (from 0001) serves the
  equality but cannot index the `IS NULL` predicate. This makes the
  `register_device` invite lookup index-only for open invites and keeps the
  index small.
- **`rate_limits_window_start_idx`** — btree on `(window_start)`. The PK leads
  with `bucket`, so a range predicate on `window_start` alone forces a seq
  scan. Both the bounded prune in 0006 and the cron cleanup in 0008 need this.

**Omitted:** a partial index on `invites(id) WHERE used_by_device IS NULL`
(the PK already covers `id`; admin path is not hot); an index for the seed
count (table is capped at `seed_limit`); extra indexes on `devices(id)` or
`premium_keys(key_hash)` (the PK/unique indexes already serve equality).
Query plans were **not** captured with `EXPLAIN` — the justifications above are
by inspection, not measurement. Capture plans against a populated DB before
relying on these indexes.

### 3. Rate-limit cleanup (`0008_ratelimit_cleanup.sql`)

- `cleanup_rate_limits(p_retention_seconds, p_limit)` deletes up to `p_limit`
  expired rows per call, bounded so it never takes a long lock.
- `pg_cron` is created in the `extensions` schema and a job
  `passaura-rate-limit-cleanup` runs every 15 minutes, deleting rows older than
  24 hours, max 5000 per run. `cron.schedule` is idempotent on jobname, so
  re-running the migration replaces the schedule rather than duplicating it.
- `pg_cron` is available on the Supabase free tier; schedules are UTC.
- The cron job also relies on `rate_limits_window_start_idx` from 0007.

### 4. Remaining findings (severity)

| # | Severity | Finding |
|---|---|---|
| R2-F1 | **HIGH** | `register_device` seed-limit count is not serialized. Two concurrent calls at the boundary can both insert as seed, exceeding `seed_limit`. The concurrency test is designed to fail on this. Fix in `0009` (advisory lock or `FOR UPDATE` on a config row). |
| R2-F2 | **MEDIUM** | The concurrency tests require `dblink`, which does not work on Supabase's native runtime. CI must use the Docker runtime (`supabase test db`) or an external two-session harness. Documented in §1. |
| R2-F3 | **MEDIUM** | Query plans for `register_device`, `redeem_premium_key`, and `rate_limit_hit` were **not** measured with `EXPLAIN ANALYZE`. The two indexes in 0007 are justified by inspection only. Run `EXPLAIN (ANALYZE, BUFFERS)` against a populated DB before assuming they are sufficient (or not). |
| R2-F4 | **LOW** | `cleanup_rate_limits` uses `ctid IN (SELECT ctid ... LIMIT n)`. Under heavy concurrent insert/delete this is safe (ctid identifies a physical row version) but can miss rows that were updated between the subquery and the delete; the next cron run catches them. Acceptable for cleanup. |
| R2-F5 | **LOW** | `cron.job_run_details` grows indefinitely and was **not** cleaned in 0008. Add a second cron job (or extend the existing one) to delete `job_run_details` older than 7 days, per Supabase's own guidance. Not added here to keep 0008 focused on `rate_limits`. |
| R2-F6 | **LOW** | The concurrency test `50_concurrency.sql` assumes the test session can open a `dblink` connection back to the same database with `current_user`. On Docker this is `postgres` (superuser), so it works. On a hardened setup with `FORCE ROW LEVEL SECURITY` or a restricted role, the dblink session may not see the same rows. Test under the same role configuration as production. |

### 5. What could not be run

- Migrations `0007` and `0008` (no live DB).
- `50_concurrency.sql` (no `dblink`, no pgTAP, no two-session harness).
- `EXPLAIN ANALYZE` on the three functions (no populated DB).
- `cron.schedule` on a live Supabase free-tier project (no project here).

The tests and migrations are specifications; they are not claims that the
concurrency races pass. Run `50_concurrency.sql` under `supabase test db`
(Docker) and capture the result before treating the backend as race-free.

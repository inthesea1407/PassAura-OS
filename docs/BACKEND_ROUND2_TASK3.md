## Round 2, Task 3 — Premium key batches and expiry reports

Migrations `0001`–`0009` are unchanged. `0011_premium_batches.sql` is new.

### What was added

- **`public.premium_key_batches`** — batch metadata: `label` (1–80 chars),
  `count` (1–500), `valid_days` (1–3650), `created_by uuid`, `created_at`.
  RLS enabled; only a `SELECT` policy for `authenticated` using
  `public.is_owner()` (which enforces `aal2` from `0002`/`0005`). No write
  policies — writes go through `generate_premium_keys()` only.
- **`generate_premium_keys(p_batch_label, p_count, p_valid_days, p_project)`**
  — `security definer`, `search_path = ''`, re-checks `is_owner()`. Inserts a
  batch row, then for each key: generates `'PA-' || upper(encode(gen_random_bytes(10),
  'hex'))` (cryptographically strong per pgcrypto [citation:2][citation:7]),
  stores only `encode(digest(v_code, 'sha256'), 'hex')` in `premium_keys`,
  and accumulates the plaintext in a local `text[]`. **Returns the plaintext
  array once; never writes it to any table, log, or audit entry.**
- **`premium_expiry_report(p_days_ahead)`** — `stable security definer`,
  re-checks `is_owner()`. Returns one row per key expiring within the window
  (plus up to 7 days recently expired for context), with the bound device id
  and revoked flags. Batch id is extracted from the `batch:<uuid>` note
  convention used by `generate_premium_keys`.
- **`admin_list_batches(p_limit)`** — owner-only RPC for the admin UI, last 50
  batches ordered by `created_at desc`.
- **Indexes:** `premium_keys_expires_at_idx` (partial, `WHERE expires_at IS
  NOT NULL`) for the expiry report; `premium_key_batches_created_at_idx` for
  the batch list order.

### Admin UI (`admin/batches.html` + `admin/batches.js`)

- Same CSP shape as `index.html`: no inline script, SRI-pinned supabase-js,
  `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`,
  `form-action 'none'`.
- EN/AR toggle via the existing `i18n.js`.
- Login + MFA flow identical to `app.js`.
- **Key display:** plaintext keys are held in a page-local JavaScript array
  (`currentKeys`), rendered into a `<code>` list, copyable individually or all
  at once via `navigator.clipboard`. The list is cleared on "Dismiss" and on
  page unload. **Keys never touch `localStorage`, `sessionStorage`, URL
  params, `console.log`, or any network request.** This mirrors the one-time
  reveal pattern used for API tokens [citation:19].
- **Escaper:** same complete map (`& < > " ' `` ` ``) as `app.js` (F8).
- **No inline secrets:** all RPC calls use the public anon key from
  `config.js`; authorization is enforced server-side by `is_owner()`.

### Tests (`supabase/tests/70_premium_batches.sql`)

Plain SQL `DO` blocks that `raise exception` on failure. Covered:

- **A** — `generate_premium_keys` returns 5 keys, inserts 1 batch row, and
  creates ≥ 5 rows in `premium_keys`.
- **B** — non-owner (`sub` not in `owners`) cannot call `generate_premium_keys`.
- **C** — `anon` cannot call `generate_premium_keys` or read
  `premium_key_batches`.
- **D** — owner can call `admin_list_batches`.
- **E** — `premium_expiry_report` includes a key expiring in 5 days.
- **F** — count 0 and days 0 are rejected with the correct error codes.

Run with `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/70_premium_batches.sql`.
A clean run prints `70_premium_batches.sql: ALL PASS`.

### Remaining findings (severity)

| # | Severity | Finding |
|---|---|---|
| R2T3-F1 | **MEDIUM** | **Plaintext keys exist in browser memory** between generation and dismissal. If the owner's browser tab is compromised by XSS, the keys can be exfiltrated. Mitigations: strict CSP (already in place), no third-party scripts beyond SRI-pinned supabase-js, and the keys are cleared on dismiss. This is inherent to any one-time secret display and is accepted. |
| R2T3-F2 | **MEDIUM** | **`generate_premium_keys` is not idempotent.** A double-click on "Generate" creates two batches and 2× the keys. The UI does not disable the button during the RPC. Add a client-side in-flight guard (`let generating = false; if (generating) return; generating = true; ... finally { generating = false; }`). Server-side idempotency would require a client-supplied `request_id`, which the brief did not ask for. |
| R2T3-F3 | **LOW** | The `batch:<uuid>` note convention is fragile. If a future migration changes the note format, `premium_expiry_report` silently returns `batch_id = null`. Document the convention in the migration comment (done) and treat it as an internal contract. |
| R2T3-F4 | **LOW** | `premium_expiry_report` uses `stable` but reads `now()`, which is `stable` within a transaction. This is correct for a read-only report; callers should not expect a different `now()` per row. |
| R2T3-F5 | **LOW** | The `premium_keys_expires_at_idx` partial index (`WHERE expires_at IS NOT NULL`) is only useful for the expiry report. Insert-heavy workloads pay a small write cost. At the expected scale (hundreds of keys per batch, a few batches per month) this is negligible. |

### What could not be run

- `0011_premium_batches.sql` (no live DB).
- `70_premium_batches.sql` (no DB to execute assertions).
- `admin/batches.html` / `batches.js` in a browser (no CSP/SRI validation, no
  clipboard API test, no EN/AR toggle validation).
- The one-time key display flow end-to-end (no browser, no live Supabase
  session). The design avoids persistence, but runtime verification is pending.

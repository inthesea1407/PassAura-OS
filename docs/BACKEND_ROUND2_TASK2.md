## Round 2, Task 2 — Audit log retention and admin action history

Migrations `0001`–`0008` are unchanged. `0010_audit_retention.sql` is new.

### What was added

- **`public.audit_log`** — `actor uuid`, `action text` (1–80 chars), `target text`
  (≤ 200), `details jsonb` (≤ 4 KB), `created_at timestamptz`. RLS enabled;
  **only** a `SELECT` policy for `authenticated` using `public.is_owner()`
  (which already enforces `aal2` from `0002`/`0005`). No INSERT/UPDATE/DELETE
  policies — writes go through `log_admin_action()` only.
- **`log_admin_action(p_action, p_target, p_details)`** — `security definer`,
  `search_path = ''`, re-checks `is_owner()`, validates lengths and JSON size,
  inserts the row, returns the new id. `EXECUTE` revoked from `public`/`anon`,
  granted to `authenticated`.
- **`admin_list_audit_log(p_limit)`** — `stable security definer`, `search_path = ''`,
  re-checks `is_owner()`, clamps `p_limit` to 1..500 (default 100), returns
  `(id, actor, action, target, details, created_at)` ordered newest-first.
- **`cleanup_audit_log(p_retention_days, p_limit)`** — deletes rows older than
  `p_retention_days` in bounded batches (`ctid in (select ctid ... limit p_limit)`),
  returns the deleted count. `EXECUTE` granted to `service_role` only.
- **Index `audit_log_created_at_idx`** on `created_at` — serves both the cleanup
  range predicate and the admin list order-by.
- **pg_cron job** `passaura-audit-retention` — **commented out** in the
  migration per the brief ("commented out until owner approval"). When enabled,
  it runs `cleanup_audit_log(90, 5000)` every 15 minutes. pg_cron runs jobs as
  the `postgres` role and bypasses RLS, which is why `cleanup_audit_log` is
  revoked from `anon`/`authenticated` and granted only to `service_role`.

### Admin UI

- **`admin/history.html`** — same CSP shape as `index.html` (strict, no inline
  script, SRI-pinned supabase-js, `frame-ancestors 'none'`, `object-src 'none'`,
  `base-uri 'none'`, `form-action 'none'`). EN/AR toggle via the existing
  `i18n.js`. Login + MFA flow identical to `app.js`.
- **`admin/history.js`** — same complete escaper (`& < > " ' `` ` ``) as
  `app.js`. Reads only through `sb.rpc("admin_list_audit_log", { p_limit: 100 })`.
  No direct table reads, no inline secrets. Details rendered inside `<pre>`
  with `esc(JSON.stringify(...))`.

### Tests (`supabase/tests/60_audit.sql`)

Plain SQL assertions in `DO` blocks that `raise exception` on failure. Covered:

- **A** — `log_admin_action` inserts a row and returns its id.
- **B** — non-owner (different `sub`) cannot call `log_admin_action`.
- **C** — `anon` cannot read `audit_log` directly.
- **D** — `anon` cannot call `admin_list_audit_log`.
- **E** — owner can list rows; `p_limit = 0` is clamped to 1.
- **F** — `cleanup_audit_log(90, 100)` deletes an old row and returns ≥ 1.
- **G** — oversized `details` (> 4 KB) is rejected with `DETAILS_TOO_LARGE`.

Run with `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/60_audit.sql`.
A clean run prints `60_audit.sql: ALL PASS`.

### Remaining findings (severity)

| # | Severity | Finding |
|---|---|---|
| R2T2-F1 | **MEDIUM** | The pg_cron job is commented out, so **no automatic retention runs** until the owner uncomments it. The table will grow unbounded until then. The manual `cleanup_audit_log` is available; consider a manual call in the admin panel or a reminder in the runbook. |
| R2T2-F2 | **MEDIUM** | `log_admin_action` is `security definer` and callable by any `authenticated` user; it re-checks `is_owner()` internally, but a future refactor that removes that check would silently open writes. Keep the check; add a test (B above) that pins it. |
| R2T2-F3 | **LOW** | The admin UI shows `actor` as a raw uuid. A future improvement is to join `auth.users.email` in `admin_list_audit_log`, but that would expose emails to the owner UI; acceptable as-is for a single-owner project. |
| R2T2-F4 | **LOW** | `audit_log` has no FK on `target` (it is free text: uuid, slug, or code hash). This is intentional (targets span multiple tables), but means the audit log can reference deleted entities. That is the point of an audit log; document it. |
| R2T2-F5 | **LOW** | `cleanup_audit_log` uses `ctid IN (SELECT ctid ... LIMIT n)`, which can miss rows updated between the subquery and the delete under concurrent writes. The next run catches them. Acceptable for a 90-day retention job. |

### What could not be run

- `0010_audit_retention.sql` (no live DB).
- `60_audit.sql` (no DB to execute assertions).
- The commented pg_cron job (intentionally disabled; not scheduled anywhere).
- `admin/history.html` / `history.js` in a browser (no CSP/SRI/MFA validation).
- The RLS policy against a real `aal2` JWT (no Supabase Auth instance). The policy
  delegates to `is_owner()`, which was already audited in Round 1; the only new
  RLS surface is `audit_log_owner_select`, which is a `SELECT`-only policy.

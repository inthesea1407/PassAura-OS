# Owner control panel (plan + MVP)

Status: MVP in `admin/` (static HTML + JS, no build) and `supabase/migrations/0002_admin.sql`. Written, not deployed, not tested against a live Supabase project. Deploy waits for owner approval.

## Design
- Owner-only: Supabase Auth email login plus TOTP MFA (free). `is_owner()` requires a row in `owners` and an `aal2` session. Everything else is denied by RLS.
- No secrets in the front-end. `admin/config.js` holds only the project URL and the anon key (public by design). The service_role key is never used.
- Secrets are shown once: invite codes and premium keys are generated in SQL functions and stored as sha256 hashes.
- Only the owner can revoke a member (`admin_set_device_revoked`). Export is not blocked.
- Project registry: `projects` table. Flags, announcements and premium keys are per project. Add a site by adding a project row (or the Add project button).

## Controls
POS: mode (free-invite/paid/closed), paid scope (new only/everyone), stop invites, issue/revoke invites, list registrations, revoke/restore member.
PassAura: premium trial keys issue/revoke, feature flags and pricing (public flags readable by the site through anon), announcements (publish/unpublish).

## Owner steps (Supabase)
1. Run 0001_init.sql then 0002_admin.sql in the SQL editor.
2. Create the owner user in Supabase Auth, enrol TOTP, then insert that user id into `owners`.
3. Put URL + anon key in `admin/config.js`.
4. Host later (GitHub Pages is free; Vercel deploy stays on hold).

## Known gaps
- Not run against Postgres. register_device() rejects revoked and duplicate hardware; rate limiting is in 0003 + Edge Functions (draft). Premium key redemption is drafted (0003 + redeem-key function); key-to-device binding and site entitlement checks are not. Static host + CDN supabase-js (pin a version and add SRI before deploy). Membership tables are POS-specific.

# Admin panel design (owner only)

Logic lives in `pos-core::admin`. The panel is a thin UI over it.

## Controls
1. Access mode: Free-invite (current) / Paid / Closed.
   - Paid: invites stop working; joining needs verified payment. Existing members keep access.
   - Closed: nobody new joins. Existing members keep access.
2. Pause invite issuance (members cannot create new codes).
3. Pause invite redemption (codes cannot be used).
4. Revoke a member (voids their unredeemed invites, keeps their export right, does not revoke people they invited).
5. View: member count, seeds used (x/1000), invites issued/redeemed, admin event log.

## Security of the panel
- Owner only. Sign-in with a passkey or hardware key, never a shared password. Admin actions need a fresh re-auth.
- Admin token cannot be created by apps (`AdminToken::verified_owner` is called only by the owner-credential check).
- Every admin action is logged (`AdminEvent`). Log is append-only.
- Confirm step with a summary before mode changes ("Switching to Paid: 1,234 members keep access").
- Not built: the web/mobile UI, the owner credential check, persistence of the event log, payment provider for Paid mode (payment costs money and needs the owner's own decision).

## Wireframe
Top: current mode badge + dropdown. Row of two toggles: Pause issuing, Pause redeeming. Table of members (device short id, join date, inviter, status, Revoke button). Side card: stats. Bottom: event log.

## Review hardening (from ChatGPT review)
- Roles: Owner (all actions) and Support (revoke only). Role checked in `pos-core::admin`.
- Re-authentication: every action needs a session authenticated within 5 minutes; stale sessions are refused (tested).
- Web panel must add: strong auth (passkey/hardware key), CSRF tokens, SameSite cookies, short sessions, confirmation dialogs. These live in the UI/backend, not yet built.
- Vault keys and export never depend on membership, payment or access mode (`can_export_vault`).

## Paid mode scope (owner decides later)
Both options stay open (`PaidScope`):
- New only (default): people who join after the switch pay; existing members stay free.
- Everyone: existing members must pay too; unpaid members lose OS/Premium access but keep vault export.
The owner can change the scope or return to free-invite later. Before choosing Everyone the panel should show how many members would lose access. Charging existing members who joined for free is a trust and reputation decision, and may have consumer-protection implications depending on country; the vault export right is what keeps it safe.

# Payments (draft, nothing enabled)

Status: design plus a provider-agnostic backend. No provider is signed up or integrated. No money moves.

## What exists
- `supabase/migrations/0012_payments.sql`: `payments` table, `record_payment()`, `refund_payment()`, and a gate in `register_device` that applies only when `mode = 'paid'` and `admin_config.paid_enforcement = true`. The flag defaults to false. Not applied to any live database.
- `crates/pos-core/src/fawry.rs`: pure check of Fawry's server-to-server notification signature (SHA-256 over the documented field order plus the merchant secure key). Unit tests use vectors computed independently. Never run against a real Fawry account.

## Planned flow (Fawry, not built)
1. App asks the backend for a reference (merchantRefNumber tied to the device hash). Not built.
2. Customer pays at Fawry. Fawry POSTs the notification to a callback URL that is set once at merchant setup.
3. An Edge Function (not built) recomputes the signature with the secure key kept as a Supabase secret, requires orderStatus PAID and the exact amount (`is_payable`), then calls `record_payment()` with the service role.
4. The device calls `register_device`. With the gate on, one unused paid payment is consumed.
Fawry retries until HTTP 200, and `record_payment` is idempotent on (provider, provider_ref).

## Known limits
- Fawry's published onboarding asks for a commercial register, tax card, owner ID and a bank account (third-party sources list a setup fee and monthly fee). This conflicts with the owner's rules (no ID, no upfront fees). Unconfirmed with Fawry itself.
- Recurring subscriptions are not documented for Fawry reference payments. Membership never expires, so a one-time payment fits.
- Scope "everyone" (existing members must pay) is not enforced in SQL yet.

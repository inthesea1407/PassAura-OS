# Module 1 (ChatGPT): Rust registry client
Project: PassAura OS (POS), open source (MIT), Rust workspace. Zero budget, free tools only, no secrets in files.
Build a NEW crate `crates/pos-client/` (library + tiny CLI example) that talks to the two Edge Functions in the contract below.
Must include: salted hardware-id hashing (sha256, input is an opaque byte string, salt passed in), request/response types matching the contract exactly, error enum mapping every error code, an HTTP trait so the HTTP layer is injectable (no network in tests; use a fake), HTTPS-only URL validation, retry with backoff only on 429/5xx, local cache of device_id and premium_until in a JSON file with an expiry check, and at least 15 unit tests.
Dependencies: serde, serde_json, sha2, thiserror only (plus ureq with rustls as an optional feature). Must pass `cargo test`, `cargo clippy`, and be MIT-compatible.
Touch ONLY: crates/pos-client/** and docs/CLIENT.md. Do not edit the root Cargo.toml (the integrator adds the workspace member).
Contract: Register POST {invite_code, hardware_id_hash(64 hex)} -> 200 {device_id}; 403 {error: REGISTRATION_CLOSED|INVITE_INVALID_OR_USED|DEVICE_REVOKED|DEVICE_ALREADY_REGISTERED}; 429 RATE_LIMITED; 400. Redeem POST {code, device_id} -> 200 {premium_until|null}; 403 {error: KEY_INVALID|DEVICE_INVALID}; 429.
Return: a zip or a unified diff (git format-patch) of your folder, or code blocks per file with full paths. Say honestly what you did not test.

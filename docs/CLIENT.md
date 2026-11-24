# PassAura OS pos-client

Rust client for the PassAura OS registry and premium redemption Edge Functions.

This crate is separate from pos-core. It does not modify policy, membership
rules, invitation quotas, package verification, or admin controls.

## Endpoints

The endpoint contract is defined in docs/CONTRACTS.md.

### Register

POST `register`

Request:

    {
      "invite_code": "",
      "hardware_id_hash": "<64 lowercase hexadecimal characters>"
    }

`invite_code` can be empty during the seed registration window.

Success (200):

    {
      "device_id": "<uuid>"
    }

Errors:

- 403 REGISTRATION_CLOSED
- 403 INVITE_INVALID_OR_USED
- 403 DEVICE_REVOKED
- 403 DEVICE_ALREADY_REGISTERED
- 429 RATE_LIMITED
- 400 bad input

### Redeem Premium

POST `redeem-key`

Request:

    {
      "code": "<premium key>",
      "device_id": "<uuid>"
    }

Success (200):

    {
      "premium_until": "RFC3339 timestamp or null"
    }

Errors:

- 403 KEY_INVALID
- 403 DEVICE_INVALID
- 429 RATE_LIMITED

## Hardware identifier hashing

`salted_hardware_id_hash(salt, opaque_hardware_id)` computes SHA-256 of:

    salt || opaque_hardware_id

The result is a lowercase hexadecimal string of 64 characters.

The raw hardware identifier is not sent in the request.

This function does not perform hardware attestation, prove that an identifier
came from secure hardware, or guarantee device uniqueness. The server must
independently verify any attestation requirements.

## Request validation

The registration client checks that the hardware hash has exactly 64 lowercase
hexadecimal characters.

The redeem client checks that the key is non-empty and the device ID follows
the UUID layout.

Successful response fields are also validated for basic shape.

## HTTP transport

`HttpTransport` is injectable.

Tests use a fake transport. Tests do not need a network connection.

The transport returns HTTP status and body, including non-success responses.
The client handles status mapping and retry policy.

The optional `ureq` feature enables the `UreqTransport` implementation.

Endpoints are required to use HTTPS.

The URL validator is intentionally dependency-free and conservative. It is not
a standards-compliant URL parser. The production transport must additionally
validate TLS certificates normally.

## Retry behavior

The client retries only:

- HTTP 429
- HTTP 500 through 599

Retries are bounded by `RetryPolicy`.

The default policy is:

- 3 total attempts
- 250 ms initial delay
- 3 seconds maximum delay

Backoff doubles for each retry, subject to the maximum delay.

The client does not retry:

- 400
- 403
- Other non-retryable HTTP statuses
- Transport errors

## Local cache

`DeviceCache` stores:

- `device_id`
- `premium_until`
- `expires_at`

The cache is JSON and is not encrypted by this crate.

The caller must store it in app-private storage with suitable filesystem
permissions.

Cache expiry is a freshness check. It is not authoritative membership or
premium status. A revoked device must not continue to receive server-
authorized features merely because its local cache has not expired.

The cache does not affect vault decryption or export.

## Example

The example requires the optional `ureq` feature:

    cargo run -p pos-client --features ureq --example register_cli -- \
      https://example.org/register \
      https://example.org/redeem-key \
      INVITE_CODE \
      OPAQUE_DEVICE_ID \
      LOCAL_SALT

Do not use actual device identifiers, invite codes, keys, or sensitive values
in terminal history or public logs.

## Tests

The unit tests use a fake HTTP transport.

They cover:

- Hash output format
- Salt-dependent hashing
- Input-dependent hashing
- Hash validation
- HTTPS validation
- Registration success
- Empty invite code
- Invalid hash rejection
- Device ID response validation
- Redeem success
- Redeem validation
- Error-code mapping
- Retry behavior
- Non-retry behavior
- Cache serialization
- Cache expiry
- Invalid JSON

## Build verification

Run from the repository root after the workspace integrator adds `pos-client`
to the workspace members:

    cargo test -p pos-client

    cargo clippy -p pos-client --all-targets --all-features -- -D warnings

The example requires the `ureq` feature:

    cargo check -p pos-client --features ureq --examples

No actual Edge Function request is performed by the unit tests.

## Limitations

- No hardware attestation
- No secure hardware identifier generation
- No secure cache encryption
- No server-side authorization implementation
- No real network integration test
- No Android binding
- No root workspace edits

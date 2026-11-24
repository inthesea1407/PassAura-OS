# Shared contracts (frozen for the parallel module work; do not change, ask the integrator)

## Register device (Edge Function `register`, POST JSON)
Request: {"invite_code": string (may be empty during the first-1000 seed window), "hardware_id_hash": 64 lowercase hex chars (sha256 of salted hardware id; the client hashes, the raw id never leaves the device)}
200: {"device_id": uuid}   403: {"error": "REGISTRATION_CLOSED"|"INVITE_INVALID_OR_USED"|"DEVICE_REVOKED"|"DEVICE_ALREADY_REGISTERED"}   429: {"error":"RATE_LIMITED"}   400: bad input

## Redeem premium key (Edge Function `redeem-key`, POST JSON)
Request: {"code": string, "device_id": uuid}
200: {"premium_until": RFC3339|null}   403: {"error":"KEY_INVALID"|"DEVICE_INVALID"}   429 RATE_LIMITED

## Policy file (existing, crates/pos-core): JSON policy documents as in policies/**. Do not change the schema.
## Signed package manifest (existing, crates/pos-pkg): Ed25519, do not change.
## Rules for every module: free tools only, no secrets/keys/tokens in files, only HTTPS, MIT licence, touch only your own paths.

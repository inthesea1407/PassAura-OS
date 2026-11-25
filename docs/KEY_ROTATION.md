
# PassAura OS Allowlist Signing & Key Rotation

## 1. Document format

The runtime format is allowlist v2 only. See `docs/ALLOWLIST_FORMAT.md` for the
fields, the signed bytes, and the verification order. The earlier JSON signing
format that used the domain separator `PassAuraOS-Allowlist-Signature-v1` and a
binary canonical layout was removed (`allowlist_signing.rs`); it is not accepted
at runtime and cannot be migrated.

## 2. Canonical signing format

v2 signs the sorted-key canonical JSON of the document without `signature_hex`
(`allowlist_v2::canonical_payload_bytes`). JSON key order and whitespace do not
change the signed bytes. Signatures are checked with Ed25519 `verify_strict`.

## 3. Key roles

Maintain these roles:

- **Active key:** used to sign newly issued documents.
- **Previous key:** still accepted during the planned overlap.
- **Retired key:** no longer trusted for newly verified documents.
- **Revoked key:** rejected immediately after the revocation update.

Devices should receive a trusted keyring containing the active key and
previous keys with explicit retirement deadlines.

The active key should have no scheduled retirement in the current
keyring. Previous keys must have a retirement timestamp.

## 4. Planned rotation procedure

### Before rotation

1. Generate the new Ed25519 key in a secure environment.
2. Keep the private key offline and backed up securely.
3. Assign the new public key a unique `key_id`.
4. Update the trusted keyring to include:
   - the new active key
   - the previous key with a `retire_at` deadline
5. Distribute the keyring update through the authenticated update channel.
6. Verify devices receive and validate the new keyring.

### Rotation

1. Begin signing documents with the new key ID.
2. Issue allowlists with reasonable expiration periods.
3. Continue accepting documents signed by the previous key only while
   its retirement deadline has not passed.
4. Monitor deployment and verification errors without collecting
   unnecessary personal information.

### After overlap

1. Remove the old public key from the trusted keyring.
2. Reject old-key documents.
3. Confirm the deployed device population has received the new keyring.
4. Retain old key material only as required by a documented backup policy.

## 5. Emergency revocation

If a signing key is suspected compromised:

1. Stop signing with that key immediately.
2. Remove the compromised key from the trusted keyring.
3. Generate a replacement key.
4. Publish a replacement keyring through an authenticated channel.
5. Sign a fresh allowlist with the replacement key.
6. Ensure devices reject all documents signed by the compromised key.
7. Investigate how the private key was exposed.

A retirement deadline alone is not sufficient for compromise response:
a compromised key should be removed from trust, not merely given a
future expiration.

## 6. Clock behavior

Verification uses the device's Unix clock.

The document is rejected if:

- `issued_at` is later than the device's current time
- `now` is at or after `expires_at`
- the signing key has reached its retirement deadline

If the clock is wrong:

- A clock far in the future can cause valid allowlists to appear expired.
- A clock far in the past can cause future-issued documents to be rejected.
- A clock set backward can affect retirement and expiration decisions.

Devices should fail closed when the time cannot be trusted. Do not
silently bypass signature or expiry checks.

A future improvement is a trusted-time mechanism or a monotonic time
anchor. A monotonic clock alone cannot validate absolute expiry after a
reboot without a trusted persisted time source.

## 7. Security limitations

- Signature verification does not establish that a package is safe.
- A valid signature does not replace package hash verification.
- A valid allowlist does not prove OS enforcement is active.
- Ed25519 private keys must never be embedded in the client.
- Public-key distribution and keyring updates require authentication.
- The current verifier uses a caller-supplied timestamp.
- Key rotation does not protect devices that never receive the new
  trusted keyring.
- The current format is versioned. Do not silently change canonical
  serialization for version 1.

Dependency/API assumptions

Because I could not inspect the existing pos-gate/Cargo.toml, this module assumes:

Crate

	

Assumption




ed25519-dalek

	

v2, SigningKey, VerifyingKey, verify_strict




base64

	

v0.22+ engine API




serde

	

derive enabled




serde_json

	

existing dependency




rand_core

	

v0.6-compatible OsRng, with getrandom enabled for tests

A likely dependency addition for tests is rand_core with getrandom, but I have not edited the existing manifest because its current contents could not be retrieved.

Remaining gap

The code supports overlapping trusted keys and retirement deadlines, but the active-key role is currently a documented convention rather than an enforced Keyring type. I would add that explicitly before calling Task 4 complete.

Verification status: no repository changes were made; no cargo test, cargo clippy, compilation, or runtime verification was performed. The code is a proposed implementation, not tested code.


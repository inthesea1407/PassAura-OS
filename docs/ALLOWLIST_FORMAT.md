# Allowlist format (v2 only at runtime)

Status: draft, tested in CI/emulation only. Nothing here is a security audit or a guarantee.

## What is accepted where

| Format | Runtime (`verify`, `install`, Linux backend) | Offline migration |
|---|---|---|
| v2 (`"version": 2`) | accepted | not applicable |
| text-v1 (`signed_by`, `packages[name,version]`, no `version` key) | rejected | supported (`allowlist-migrate`) |
| JSON signing-module shape (binary canonical bytes, `publisher`) | rejected, module removed | rejected |
| JSON "version 1" shape (`key_id`, `entries`, `signature`) | rejected | rejected |
| any other `version` | rejected (`UnsupportedVersion`) | rejected |

The two JSON shapes have no supported legacy signature path: one lost its module
and its `publisher` field has no v2 equivalent, the other has no documented signed
bytes. Authenticity is never inferred from a document's structure. Runtime
rejection uses the existing failure exit code (2); no new exit codes were added.

## v2 document

Fields: `format` ("passaura-allowlist"), `version` (2), `sequence`, `issued_at`,
`expires_at`, `signed_by`, `keyring` (keys with `key_id`, `public_key_hex`,
`valid_from`, `valid_until`, `retired`), `entries` (`name`, optional `version`,
`sha256`), `signature_hex`. Signed bytes: sorted-key canonical JSON without
`signature_hex` (unchanged; the committed v2 vectors still pass).

Verification order (`verify_v2`, via `verify_v2_trusted` at runtime), all fail closed:
1. the signer must also be in the caller's TRUSTED keyring (same key_id and public key);
2. format, validity window, keyring sanity, signer key valid and not retired;
3. Ed25519 `verify_strict` over the canonical bytes of the original document;
4. only after the signature is valid: sequence against stored state
   (lower is rejected; equal with a different digest is rejected).

## Migrating a text-v1 file (offline, one way)

    pos-cli allowlist-migrate --from-v1 old.json --trusted-key keyring.json \
        --sha256-map hashes.json --out new-unsigned-v2.json

- The v1 signature is checked with the original v1 rules (signed bytes unchanged),
  using `verify_strict`, against a key from `--trusted-key` only. A key inside the
  document is never used. Expired or not-yet-valid v1 files fail.
  Note: v1 verification used non-strict `verify` before this change; strict can
  reject unusual signatures that were previously accepted.
- v1 entries have no sha256 but v2 entries need one. The OPERATOR supplies them in
  `--sha256-map`: a JSON object `{"name@version": "<64 lowercase hex>"}`. The tool
  checks the hash FORMAT only. It cannot know whether a hash matches the real
  application file; the operator is responsible for where the hashes come from.
- If any entry has no hash the migration fails and lists every missing `name@version`.
  Nothing is written. No hash is invented and none is left empty.
- Output is an UNSIGNED v2: `sequence` 0, empty `signature_hex`, one key (the trusted
  key) valid from 0 to the old `expires_at`. It fails `verify` until newly signed.
  The v1 signature is not carried over because v2 signs different bytes. Review the
  times and key window, then run `pos-cli sign`.
- The command never overwrites an existing file. Pick a new output path; do not
  point it at an installed allowlist.

## Rollback state limits

`--state FILE` (see `rollback.rs`) records the last accepted sequence and digest.
It is NOT real rollback protection: deleting the file resets the counter, there is
no inter-process lock, and no installer is connected to it, so it only records intent.

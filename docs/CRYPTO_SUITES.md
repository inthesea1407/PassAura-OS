# pos-crypto-suites

A pure-function crate (`crates/pos-crypto-suites`): no file I/O, no network, no key storage, `#![forbid(unsafe_code)]`.
It owns no file format. The vault store decides how to use it.

## Status, stated plainly
- Not audited. Not run on real hardware. CI and unit tests only.
- `ml-kem` (RustCrypto, FIPS 203) says in its own README that it has never been independently audited.
- Nothing here is claimed to be unbreakable or quantum-safe. Layering and hybrid wrapping are defense in depth against a flaw in one primitive. They do not fix a weak passphrase, a compromised device, or a bug in this crate.
- No home-made primitives. Libraries: aes-gcm, chacha20poly1305, argon2, hkdf, sha2 (RustCrypto), ml-kem 0.3.4, x25519-dalek 3.

## AEAD suites (`aead`)
Blob: `suite(1) || nonces || ciphertext+tag`. 32-byte data key (DEK) in.
| id | name | construction |
|----|------|--------------|
| 1 | V1 | XChaCha20-Poly1305, 24-byte random nonce |
| 2 | L1 | AES-256-GCM (inner, 12-byte nonce) inside XChaCha20-Poly1305 (outer, 24-byte nonce). Two layer keys come from the DEK by HKDF-SHA256 with different labels. |

- AAD = fixed prefix, suite id, caller AAD length, caller AAD. The caller passes the suite it EXPECTS to `open`, so a blob cannot be silently downgraded or upgraded. Relabeling the suite byte fails.
- L1 costs two passes and about 28 extra bytes per blob. On a 2 GB phone the cost is CPU time, not memory.
- Both layers authenticate the same AAD.

## Argon2id (`argon`)
Parameters `m` (KiB), `t`, `p`, stored as a 12-byte big-endian block in the vault header and re-validated on every read, before any derivation.

Policy (a resource policy chosen for this project, not a standard):
- Floor, any device: m >= 19456 KiB, t >= 2, p >= 1 (OWASP Password Storage Cheat Sheet).
- Default writer profile: 64 MiB, t=3, p=4 (RFC 9106 second recommended option).
- Ceiling for the READING device: m <= RAM/8 of its tier, t <= 10, p <= 8. This stops a hostile header from exhausting memory.
- "high" profile: half the tier ceiling, t=3, p=4.

| tier | ceiling | high m |
|------|---------|--------|
| 2 GB | 256 MiB | 128 MiB |
| 4 GB | 512 MiB | 256 MiB |
| 8 GB | 1 GiB | 512 MiB |
| 16 GB | 2 GiB | 1 GiB |
| 32 GB | 4 GiB | 2 GiB |
| 64 GB | 8 GiB | 4 GiB |

A file written with "high" on a 64 GB machine is refused by a 2 GB phone (by design: it would not fit). Export a lower-profile copy first.
Measured once on the CI-class sandbox (1 core, release build): high 2 GB tier 0.28 s, 4 GB 0.57 s, 8 GB 1.27 s. Not measured on a phone; ARM phones will be slower. The tier values are my engineering choice and can be changed.

## Hybrid DEK wrap (`hybrid`)
X25519 plus ML-KEM-768. Blob: `version(1) || x25519 ephemeral pub (32) || ML-KEM ct (1088) || V1 blob of the DEK`.
The wrap key is HKDF-SHA256 over both shared secrets, with the ephemeral key, the ciphertext and both recipient public keys as context. Public key sizes: X25519 32 B, ML-KEM-768 1184 B. Secret half is stored as 96 bytes (X25519 scalar plus ML-KEM seed), zeroized on drop.
ML-KEM uses implicit rejection: a tampered ciphertext gives an unrelated secret and the AEAD then fails (tests cover this).
All-zero X25519 shared secrets (low-order points) are rejected.

## Limits
- Keys live in process memory while in use. Zeroization is best effort (no mlock, swap or core dumps not controlled).
- No constant-time claims beyond what the libraries provide.
- Argon2 RFC 9106 test vectors are not included: the crate's API has no secret or associated data input. Known-answer tests cover X25519 (RFC 7748) and HKDF (RFC 5869) only.
- Key rotation, header format and storage belong to pos-vault-store.

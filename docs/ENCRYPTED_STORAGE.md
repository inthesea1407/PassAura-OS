# Encrypted storage (pos-vault-store, format v2)

Crate `crates/pos-vault-store`: one encrypted file, `#![forbid(unsafe_code)]`, no network, no key storage. It depends at runtime on `pos-crypto-suites` for `ArgonParams`, `Tier`, the Argon2id key derivation and the L1 payload suite, and on `chacha20poly1305` for the V1 payload and the data-key wrap. Nothing here is audited or certified. The code gives integrity and confidentiality from the cited libraries, and no more.

## Layout
```
file     = header | envelope | payload
header   = "PAVS" | version u16 BE (=2) | aead id u8 | file id [16]                    23 bytes, immutable
envelope = kdf id u8 (=1) | m_kib u32 | t u32 | p u32 | salt [16] | wrap nonce [24] | version u64 BE | wrapped DEK [32+16]   109 bytes, mutable
payload  = aead id 1: nonce [24] | ciphertext | tag [16]            AAD = the 23 header bytes
           aead id 2: pos-crypto-suites L1 blob                     caller AAD = the 23 header bytes
```
- Data key (DEK): random 32 bytes. It encrypts the payload.
- Envelope: the DEK is wrapped with XChaCha20-Poly1305 under a key (KEK) from Argon2id (v0x13, 32-byte output) over the passphrase and the stored salt. Wrap AAD = label `pos-vault-store/v2/dek-wrap`, the header, and the envelope bytes before the wrapped DEK (kdf id, params, salt, nonce, version). The envelope tag is therefore bound to the header (including the AEAD id) and to its own parameters. The wrap is XChaCha20-Poly1305 for both AEAD ids.
- AEAD id 1 = XChaCha20-Poly1305 (suite V1). Payload bytes are unchanged from the first version of this crate.
- AEAD id 2 = suite L1 from `pos-crypto-suites` (AES-256-GCM inside XChaCha20-Poly1305, two layer keys from the DEK by HKDF). The payload is the suites blob (`suite id || nonces || ciphertext+tag`), so it starts with the byte 2. Its layout differs from id 1 and is not byte-compatible with it. No other suite (hybrid wrap, K1) is used.
- The reader passes the suite it EXPECTS. A header that names another known suite gives `SuiteMismatch` before any key derivation. An unknown id gives `UnsupportedAead`. Relabeling the id in a header changes the bytes the wrap tag covers, so it fails as `EnvelopeAuth` (tested both ways).
- Payload size cap: 64 MiB plaintext (accepted after an engineering review, not an audit). Approximate peak memory while sealing or opening a maximum-size payload is 2-3x the plaintext, roughly 130-200 MB. That is an estimate from the design, not a measured device result.
- Randomness: the injectable `Random` trait supplies the file id, DEK, salt, wrap nonce and V1 payload nonce. Production uses `OsRandom` (`getrandom`). The L1 payload nonces come from `pos-crypto-suites`' own OS randomness and do NOT use the injected source, so L1 output is not deterministic under a fake RNG. The roundtrip and tamper tests do not depend on L1 determinism.

## API (breaking change from the first version; no wrappers)
```
seal(pass, plaintext, suite, &ArgonParams, &WriteLimits, &mut dyn Random)
open(pass, file, expected_suite, reader_tier)
open_min_version(pass, file, expected_suite, reader_tier, min_version) -> (plaintext, version)
rewrap(old_pass, new_pass, file, expected_suite, &new_params, &WriteLimits, &mut dyn Random)
WriteLimits { writer: Tier, target_reader: Tier }    WriteLimits::new(writer) sets target = writer
```
`Tier` (Gb2 ... Gb64) is the RAM class of the device doing the work. The caller asserts it and it is trusted as given. This crate does no RAM or hardware detection. A caller that overstates its tier can exhaust its own memory.

## Argon2id bounds (checked on read and on write, before any KDF run)
| | m (KiB) | t | p |
|---|---|---|---|
| floor, all tiers | >= 19456 | >= 2 | >= 1 |
| writer default `ArgonParams::DEFAULT` | 65536 (64 MiB) | 3 | 4 |
| ceiling | <= tier RAM / 8 | <= 10 | <= 8 |

Memory ceilings: 2 GB tier 262144 KiB (256 MiB), 4 GB 512 MiB, 8 GB 1 GiB, 16 GB 2 GiB, 32 GB 4 GiB, 64 GB 8 GiB (`Tier::ceiling_m_kib` in `pos-crypto-suites`).
- Reader: parameters read from the file are checked against the reader's tier before the KDF. A file written for a bigger tier is refused by a smaller tier with `ParamAboveCap(Memory)`.
- Writer: the parameters must fit BOTH the writer tier and the target reader tier in `WriteLimits`. The effective ceiling is the smaller of the two. A target tier above the writer tier is allowed. Nothing is adjusted or downshifted silently; parameters that do not fit return an error.
- Default `ArgonParams::DEFAULT` fits every tier. `ArgonParams::high(tier)` from `pos-crypto-suites` can be refused by a lower-tier reader.
- Errors are distinct: `ParamBelowFloor(Memory|Time|Parallelism)` and `ParamAboveCap(...)`.
- `pos-crypto-suites` documents the same ceilings and floor. Its `high` profiles are not selected here; the caller picks the parameters.
Sources, re-read on 2026-11-25:
- Floor: OWASP Password Storage Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html : "minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism". OWASP also lists other equal-strength points (m=47104/t=1, m=12288/t=3, m=9216/t=4, m=7168/t=5, all p=1). The per-axis floor here (m >= 19456 and t >= 2) is this project's own policy, stricter than OWASP: it rejects m=47104,t=1 and m=12288,t=3. It is not a universal OWASP minimum.
- Default: RFC 9106 section 4 "SECOND RECOMMENDED option": t=3, p=4, m=2^16 KiB (64 MiB), 128-bit salt. The FIRST option (t=1, p=4, 2 GiB) does not fit the smaller tiers. RFC 9106 recommends 16-byte salts; that is the salt size used.
- Ceilings and the t and p caps: an operational resource decision of this project, not from a standard. RFC 9106 allows p up to 2^24-1 and gives no caps.
Not tested: Argon2 runs with large memory costs (no KDF was run above the floor parameters in tests; the bounds checks are tested without running the KDF) and Argon2 time on real devices.

## Rewrap
`rewrap` unwraps the DEK with the old passphrase (old envelope read on the writer tier), then authenticates the payload (decrypts it with the DEK; failure is `PayloadAuth` and nothing is written; the plaintext is a `Zeroizing` buffer dropped at once). Only then does it build a new envelope (new salt, new nonce, chosen params, new passphrase). Header and payload bytes are copied byte for byte.
v1 is rewrap only. The DEK does not change. Data-key rotation and re-encryption are future work and nothing is claimed about them.

## Limits (accepted)
- Randomness comes from the operating system (`getrandom`). A broken OS RNG breaks everything here.
- Random 192-bit nonces make reuse very unlikely. Tests that two files differ are not proof of nonce uniqueness.
- The RustCrypto AEAD audit history (the 2020 NCC Group review of AES-GCM and ChaCha20Poly1305) covered older code. It is not a certification of the versions used here (chacha20poly1305 0.10.1, argon2 0.5.3 via suites, aes-gcm 0.10 via suites). `ml-kem` is not used by this crate.
- "No audit of the Argon2 crate was found" does not mean none exists.
- Atomic replace: random-suffix temp file in the same directory (`create_new`, exclusive, mode 0600 on unix), `write_all`, `sync_all`, `rename`, parent-directory fsync on unix, temp removed on error (up to 4 tries if the random name collides). It depends on a cooperating local filesystem. A symlink or file already at the temp name makes that try fail (tested for a pre-existing symlink) and is left alone. `rename` replaces the destination: a destination symlink is replaced, not followed (tested on Linux). There is no file lock, so concurrent writers can lose updates (last rename wins). Path components can be swapped by another local user between calls (no `openat`-style directory handle is used), so this is not safe against a hostile local user with write access to the directory. Windows rename semantics are untested; non-unix skips the mode and directory fsync. Only Linux was tested. Power-loss crash points were not tested.
- Rewrap does not invalidate a leaked old copy. Anyone holding an old file and its old passphrase can still open that old file.
- Rollback and splice: an older payload of the SAME file (same header and same data key) can be put back under a newer envelope and it still opens, because rewrap keeps the data key and the payload bytes. A payload from a different file is rejected (the header is bound). An attacker who holds an old complete copy can also restore it. Rollback of the envelope is detectable only through the envelope `version` (u64, 1 at `seal`, +1 at every `rewrap`, authenticated by the wrap tag): `open_min_version` returns `RollbackDetected` for a file below the minimum the CALLER holds. This crate stores no minimum, so an attacker who can restore an old file is detected only if the caller keeps its minimum where the attacker cannot roll it back. `open` has no minimum and still opens old copies. The payload never changes after `seal` (rewrap only), so the version tracks envelope state (passphrase, parameters), not data revisions. Old copies stay valid under their own passphrase.
- A wrong passphrase and a tampered header or envelope give the same `EnvelopeAuth` error. They cannot be told apart.
- The DEK is generated directly into a `Zeroizing` buffer. The RNG, the AEAD libraries and the allocator may still keep copies. Zeroization is best effort (`Zeroizing` DEK, KEK, plaintext returned by `open`); swap and core dumps are not controlled. Input slices from the caller are the caller's to clear.
- `cargo-deny` 0.22.1 (release binary, sha256 13f7e825e9cb811c2f8de63f29b0f45851dfb53004029f0f2501af524728364d) ran `check` (advisories, bans, licenses, sources) on this tree. See the patch report for the result and warnings.
- Bounds-before-KDF and suite-before-KDF are shown by a unit test with a counting fake KDF (zero calls out of bounds or on a wrong expected suite, exactly one call at every tier's ceiling edge), plus error types in the integration tests.
- Tamper tests: a unit test flips bit 0 and bit 7 at EVERY byte offset of a tiny container (empty plaintext, floor params, deterministic RNG; 172 bytes for V1) for V1 and for L1, and asserts an error of the expected class for the region. To keep it fast it goes through a private `open_with` and a memoized real-Argon2 KDF (the KEK is cached per passphrase, salt and params; a changed salt or params gets a freshly computed KEK). `open` is the single line `open_with(.., &derive_kek(reader))` and the memoized KDF only wraps that same function. A bridge test runs the public `open` and the memoized path side by side at 17 offsets across all regions and requires equal errors. The same flips at every offset through the public `open` with the real KDF are in an `#[ignore]` test (`cargo test -p pos-vault-store -- --ignored`); it is not part of the default run. The integration tests also flip sampled bytes through the public `open` and `rewrap`. This is not a proof of tamper resistance beyond those cases.
- No networking, policy application, real keys or system changes are involved.

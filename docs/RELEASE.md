
# PassAura OS — Reproducible Builds & Release Signing

This document describes how to produce, hash, sign, publish, and
verify official PassAura OS `pos-gate` and `pos-cli` releases.

## Release model

- Releases are triggered by version tags.
- CI builds Linux and Windows binaries.
- CI creates `SHA256SUMS`.
- CI uploads release artifacts.
- Release signing is a manual, offline operation.
- CI never stores or receives the release private key.
- Users can verify checksums and signatures without internet access.

A GitHub release is a distribution channel, not a trust anchor.

## 1. Prepare a release

Before releasing:

1. Ensure the workspace is in a reviewed state.
2. Ensure `Cargo.lock` is committed.
3. Run all CI checks successfully.
4. Review dependency changes and advisories.
5. Verify the intended binaries exist:
   - `pos-gate`
   - `pos-cli`
6. Decide the release version.

Use a version tag such as:

```text
v0.1.0
```

Tags should not be reused for different source revisions.

## 2. Create and push the release tag

Example:

```bash
git tag -a v0.1.0 -m "PassAura OS v0.1.0"
git push origin v0.1.0
```

A tag push starts `.github/workflows/release.yml`.

## 3. Reproducible build inputs

The build must use:

- A committed `Cargo.lock`.
- Stable Rust, with the repository toolchain file.
- Locked dependencies.
- `cargo build --locked`.
- A fixed `SOURCE_DATE_EPOCH`.
- No embedded credentials or secrets.
- No network access during the compilation step where feasible.

CI obtains `SOURCE_DATE_EPOCH` from the tagged commit timestamp:

```bash
git log -1 --format=%ct "$GITHUB_SHA"
```

Set it in the build environment before compiling:

```bash
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$GITHUB_SHA")"
```

Build:

```bash
cargo build --locked --release --bin pos-gate --bin pos-cli
```

Linux output:

```text
target/release/pos-gate
target/release/pos-cli
```

Windows output:

```text
target/release/pos-gate.exe
target/release/pos-cli.exe
```

`--locked` refuses to silently update dependency resolution.

## 4. Reproducibility limitations

Using a lockfile and `SOURCE_DATE_EPOCH` improves repeatability but does
not guarantee bit-for-bit reproducibility.

Build outputs may vary because of:

- Compiler or linker versions.
- Operating-system image updates.
- Native toolchains.
- Environment differences.
- Build scripts.
- Embedded timestamps not controlled by `SOURCE_DATE_EPOCH`.

For stronger reproducibility, pin the compiler version, build container,
native toolchain, and environment. Rebuild independently and compare
the output hashes.

Linux and Windows binaries are separate build outputs and are not
expected to have identical hashes.

## 5. Create SHA256SUMS

The release workflow collects the Linux and Windows binaries into a
release directory and generates:

```text
SHA256SUMS
```

The file contains hashes and filenames, for example:

```text
<sha256>  pos-gate-linux-x86_64
<sha256>  pos-cli-linux-x86_64
<sha256>  pos-gate-windows-x86_64.exe
<sha256>  pos-cli-windows-x86_64.exe
```

The checksum file must not include itself or its signature.

Generate checksums manually if needed:

```bash
sha256sum pos-gate-linux-x86_64 \
  pos-cli-linux-x86_64 \
  pos-gate-windows-x86_64.exe \
  pos-cli-windows-x86_64.exe > SHA256SUMS
```

## 6. Offline Ed25519 signing

The release signing key must never be placed in GitHub Actions,
repository secrets, source files, build artifacts, or online development
environments.

Signing takes place on an offline system using a protected release
private key.

### Signature format

- Signature algorithm: Ed25519.
- Signed input: exact bytes of `SHA256SUMS`.
- Signature filename: `SHA256SUMS.sig`.
- Public key: raw 32-byte Ed25519 public key, base64 encoded.
- Private key: raw 32-byte Ed25519 seed, base64 encoded.
- Key ID: a stable identifier associated with the public key.
- Signature: Ed25519 detached signature.

The key format is compatible with the raw Ed25519 public-key material
used by the PassAura OS allowlist keyring (`TrustedPublicKey`).

The release key should be separate from allowlist signing keys in
production unless a deliberate shared-key design has been reviewed.
Sharing keys increases the impact of compromise.

### Convert the raw key material for OpenSSL

OpenSSL commonly expects PEM/DER key structures rather than a raw
base64 seed/public-key string.

For a 32-byte Ed25519 private seed, the PKCS#8 DER prefix is:

```text
302e020100300506032b657004220420
```

For a 32-byte Ed25519 public key, the SPKI DER prefix is:

```text
302a300506032b6570032100
```

These prefixes are format wrappers, not key material.

On an offline signing computer, decode the raw base64 key into bytes,
prepend the relevant DER prefix, and write a DER key file. Protect the
resulting private-key file with restrictive permissions.

For example, using Python:

```python
import base64
from pathlib import Path

private_seed_b64 = input("Private seed (base64): ").strip()
seed = base64.b64decode(private_seed_b64, validate=True)

if len(seed) != 32:
    raise SystemExit("Expected a 32-byte Ed25519 seed")

pkcs8_prefix = bytes.fromhex(
    "302e020100300506032b657004220420"
)

Path("release-private.der").write_bytes(pkcs8_prefix + seed)
```

Do not save the seed in the script or shell history.

Convert the DER private key to PEM:

```bash
openssl pkey -inform DER \
  -in release-private.der \
  -out release-private.pem
```

Restrict file access:

```bash
chmod 600 release-private.pem
```

### Sign SHA256SUMS

Copy the release files and `SHA256SUMS` to the offline signing
computer using a controlled transfer process.

Review the checksum file and verify that it contains only the expected
release files.

Sign:

```bash
openssl pkeyutl -sign -rawin \
  -inkey release-private.pem \
  -in SHA256SUMS \
  -out SHA256SUMS.sig
```

The signature covers the exact bytes of `SHA256SUMS`. Do not edit,
reformat, or regenerate that file after signing.

Return `SHA256SUMS.sig` to the release operator for upload.

## 7. Offline signature verification

Users need:

- `SHA256SUMS`
- `SHA256SUMS.sig`
- The official PassAura OS release public key obtained independently
  through a trusted channel
- OpenSSL
- The release binaries

Do not trust a public key downloaded only from the same release page
as the files being verified unless its identity was already verified.

### Convert the public key

The raw 32-byte base64 public key used in the allowlist keyring can
be converted to DER using this SPKI prefix:

```text
302a300506032b6570032100
```

Example Python conversion:

```python
import base64
from pathlib import Path

public_key_b64 = input("Trusted public key (base64): ").strip()
public_key = base64.b64decode(public_key_b64, validate=True)

if len(public_key) != 32:
    raise SystemExit("Expected a 32-byte Ed25519 public key")

spki_prefix = bytes.fromhex("302a300506032b6570032100")
Path("release-public.der").write_bytes(spki_prefix + public_key)
```

Convert to PEM:

```bash
openssl pkey -pubin -inform DER \
  -in release-public.der \
  -out release-public.pem
```

### Verify the detached signature

```bash
openssl pkeyutl -verify -pubin -inkey release-public.pem \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

Verification must succeed before trusting the checksum list.

Then verify the binaries:

Linux:

```bash
sha256sum -c SHA256SUMS
```

Windows PowerShell:

```powershell
.\scripts\verify-release.ps1
```

## 8. Key custody

Release signing keys must:

- Be generated on a controlled offline system.
- Never be committed to the repository.
- Never be uploaded to GitHub.
- Never be stored in CI secrets.
- Never be included in APKs, binaries, archives, or logs.
- Have at least one securely stored backup.
- Have documented key IDs and ownership.
- Be access-controlled.
- Be rotated periodically.
- Be protected from casual copying.
- Be used only after reviewing the release checksums.

Prefer offline hardware-backed key custody when available.

Keep the public key available through independently verifiable channels.

## 9. Release key compromise

If a release signing key is suspected or confirmed compromised:

1. Stop signing and publishing new releases with it.
2. Preserve evidence and identify the last known trustworthy release.
3. Publish a compromise notice through established project channels.
4. Mark the compromised key ID as revoked in the project's trust records.
5. Distribute a replacement public key through independently verified channels.
6. Re-sign trustworthy releases with the new key if appropriate.
7. Rebuild releases if source integrity or build integrity is in doubt.
8. Tell users not to trust signatures from the compromised key after
   the effective compromise point.
9. Review access to backups, signing machines, and release accounts.
10. Record the incident and its remediation.

## 10. Revocation path

Revocation is not automatic.

A revocation notice should contain:

- Compromised key ID.
- Public-key fingerprint.
- Date discovered.
- Effective revocation date.
- Affected release range, if known.
- Replacement key ID and fingerprint.
- Where users can obtain the replacement key.
- Whether affected binaries need replacement.

Users who previously trusted the compromised public key must update
their local trust store. A valid Ed25519 signature proves that the
signing key signed the checksum file; it does not prove that the
release is safe or that the key was uncompromised.

## 11. Release assets

Expected release assets:

```text
pos-gate-linux-x86_64
pos-cli-linux-x86_64
pos-gate-windows-x86_64.exe
pos-cli-windows-x86_64.exe
SHA256SUMS
SHA256SUMS.sig
```

The automated release initially publishes the binaries and `SHA256SUMS`.

`SHA256SUMS.sig` is added after manual offline signing.

## 12. Final release checklist

- [ ] CI passed for the tagged source.
- [ ] Tag points to the intended commit.
- [ ] Cargo.lock is committed.
- [ ] Dependencies reviewed.
- [ ] Linux binaries built.
- [ ] Windows binaries built.
- [ ] SHA256SUMS generated.
- [ ] Release files independently reviewed.
- [ ] SHA256SUMS signed offline.
- [ ] Signature verified using the expected public key.
- [ ] Offline checksum verification passed.
- [ ] Private key remained offline.
- [ ] Release notes reviewed.

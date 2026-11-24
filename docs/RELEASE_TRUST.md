# PassAura OS Release Trust

## Purpose

PassAura OS must not trust a locally generated checksum manifest as its
release trust anchor.

A checksum proves that an artifact matches a listed digest. It does not
prove who created the manifest. If an attacker can replace both the artifact
and its checksum manifest, checksum verification alone cannot detect that.

PassAura OS uses a detached Ed25519 signature to authenticate the release
manifest. SHA-256 hashes are then used to verify individual release
artifacts against that authenticated manifest.

## Trust chain

The trust chain is:

1. The official POS image ships a pinned minisign public key.
2. The release publisher signs `SHA256SUMS` with the corresponding
   private key.
3. The release includes `SHA256SUMS` and `SHA256SUMS.minisig`.
4. The verifier authenticates the manifest with the pinned public key.
5. Only after successful signature verification does the verifier parse
   the manifest and verify artifact hashes.
6. Any verification failure aborts the release verification.

The signature authenticates the manifest. The manifest authenticates the
listed artifacts through their SHA-256 digests.

## Trust anchor

The default pinned public key path is:

`/usr/share/pos/release.pub`

This public key must be installed as part of the trusted image build.
It must not be downloaded from the same release location being verified.

The verifier accepts an optional environment override for test environments:

`POS_RELEASE_PUBLIC_KEY`

Production verification must use the public key pinned in the image.
Do not override the trust anchor with a key obtained from the release
download location.

The public key is not secret. The signing private key is secret and must
never be committed to the repository, included in images, or written to
release artifacts.

## Release files

Expected files:

- `SHA256SUMS` — SHA-256 manifest.
- `SHA256SUMS.minisig` — detached minisign signature.
- `release.pub` — public key used by the maintainer to sign releases
  (the installed verifier uses the pinned key in the image).
- Release artifacts listed in `SHA256SUMS`.

The manifest uses sha256sum-compatible lines:

`<64-character SHA-256 hash>  <filename>`

Only simple filenames are supported. Paths, absolute paths, and
traversal sequences are rejected. The manifest must contain at least
one artifact.

## Verification

Install minisign on the target system, then run:

```bash
scripts/verify-release.sh

The verifier uses the current directory as the release directory by
default.

Environment overrides are available for isolated testing:

Bash
POS_RELEASE_DIR=/path/to/release \
POS_RELEASE_PUBLIC_KEY=/path/to/test-public-key \
scripts/verify-release.sh

These overrides are not a production trust configuration.

Signing a release manifest

A maintainer creates the manifest after the release artifacts are finalized:

Bash
sha256sum artifact-1 artifact-2 > SHA256SUMS

Sign the manifest:

Bash
minisign -Sm SHA256SUMS

This creates SHA256SUMS.minisig.

Publish the manifest, detached signature, and artifacts together.

Verification behavior

The verifier fails closed if:

Minisign is unavailable.

The manifest is missing.

The detached signature is missing.

The pinned public key is missing.

Signature verification fails.

The manifest is malformed.

An artifact is missing.

An artifact hash does not match.

The manifest contains no artifacts.

The manifest signature is checked before its contents are parsed or used.

Key rotation

Key rotation must be planned and reviewed before replacing the pinned key.

A release image may support multiple trusted public keys during a transition.
The verifier must accept signatures only from explicitly pinned keys.
A key must not become trusted merely because it appears in a release,
manifest, network response, or download directory.

A safe rotation process should:

Generate a new signing key pair in a trusted environment.

Review and independently confirm the new public-key fingerprint.

Ship an image that pins both the old and new public keys.

Use the new key to sign releases.

Confirm that verification with the new key works.

Remove the old key in a later image after the transition period.

This implementation currently pins one key. Multi-key rotation is a
future enhancement, not an implemented feature.

Security limitations

A valid signature proves that the manifest was signed by a key accepted
by the verifier. It does not prove that:

The software is free of vulnerabilities.

The signing key was not compromised.

The release build process was trustworthy.

The source code corresponds to the binary.

The binary is safe to install.

The installed system cannot be modified by an administrator or attacker.

SHA-256 checks provide artifact integrity relative to the signed manifest.
They do not provide independent provenance or reproducible-build evidence.

Testing

The Bats tests use a mock minisign executable to test verifier behavior.
They do not perform real cryptographic verification.

A real release verification test must additionally use:

A real minisign key pair.

A manifest signed with its private key.

The matching public key.

Known release artifacts.

Negative cases using invalid signatures and modified artifacts.

Until those tests are completed and reviewed, this verifier must not be
described as production-ready release security.

# pos-cli: PassAura OS command-line tool

`pos-cli` verifies signed allowlists and gates package installs against them. It is part of the
PassAura OS Rust workspace next to `pos-gate` (allowlist verification) and `pos-core` (policy).
Status: draft, tested in CI/emulation only; no hardware run and no external audit.

## Allowlist format

Only **allowlist v2** is accepted at runtime (`verify`, `install`, `sign`). text-v1, the two JSON
"version 1" shapes and any other version are rejected with exit code 2. The one supported way
out of text-v1 is the offline `allowlist-migrate` command below. Format details, signed bytes
and limits: `docs/ALLOWLIST_FORMAT.md`.

## Install

```sh
cargo build -p pos-cli --release
# binary at target/release/pos-cli
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Verification or data failure (bad signature, expired, untrusted signer, unsupported or legacy version, malformed JSON, missing file, refused output path) |
| 3 | Package not allowed by the allowlist (`install`), or audit file unreadable (`audit`) |
| 4 | Usage error (unknown subcommand, missing required flag, `install` without `--state` when not a dry run) |

Malformed input is a verification failure (2), not a usage error (4), so scripts can tell
"you called me wrong" from "the data is bad".

## verify

```sh
pos-cli verify allowlist.json --keyring keyring.json [--state state.json]
```

Parses the file as v2, then verifies it against the **trusted** keyring: the signer must be in
`--keyring` with the same `key_id` and the same public key. A v2 document carries its own keyring,
which is never trusted by itself. After that: validity window, signing-key validity, Ed25519
`verify_strict` over the canonical bytes, and only then the sequence check. With `--state`, a lower
sequence, or an equal sequence with different content, is rejected. `now` is the current Unix time;
a clock before 1970 is treated as 0 (fail closed).

Success prints `ok: v2 allowlist verified (sequence N)` and exits 0. Any failure prints the error to
stderr and exits 2.

## install

```sh
pos-cli install ripgrep --allowlist allowlist.json --keyring keyring.json --dry-run
```

Verifies the allowlist exactly like `verify`, then checks that the package name is an entry.
Allowed: prints a dry-run line, exit 0. Not listed: `not allowed: <pkg> ...`, exit 3.
Verification failure: exit 2. Invalid package identifier or a non-dry-run without `--state`: exit 4.

A real (non-dry-run) run records the accepted sequence in `--state` and prints
`installer not wired in this build`. It installs nothing. The state file only records intent:
deleting it resets the counter, there is no inter-process lock, and no installer is connected to
it, so it is **not** real rollback protection.

## sign

```sh
pos-cli sign unsigned-v2.json --private-key private-key.json --out signed-v2.json
```

Takes an unsigned v2 document, signs the canonical bytes and writes the result. The private key
must match the `signed_by` key in the document, otherwise it fails (exit 2). `--out` must be a new
file; an existing path is never overwritten.

## allowlist-migrate

```sh
pos-cli allowlist-migrate --from-v1 old.json --trusted-key keyring.json \
    --sha256-map hashes.json --out new-unsigned-v2.json
```

Offline, one way, text-v1 only. The v1 signature is verified with the original v1 rules (signed
bytes unchanged, `verify_strict`) against a key from `--trusted-key`; a key inside the document is
never used. The operator supplies the sha256 of every entry in `--sha256-map`, a JSON object
`{"name@version": "<64 lowercase hex>"}`. Only the format of each hash is checked, not whether it
matches the real application file. A missing hash fails the migration (exit 2) and lists every
missing `name@version`; no hash is invented. The output is an unsigned v2 (sequence 0) that fails
`verify` until it is signed with `sign`. Review its times and key window first.

`--out` must be a new file. It is refused (exit 2, nothing written) when it already exists, when it
is one of the input files, or when it is under a PassAura system directory (`/etc/passaura`,
`/var/lib/passaura`, `/usr/share/passaura`, `/usr/lib/passaura`, `/usr/local/share/passaura`,
`/usr/local/lib/passaura`), even if the file or directory does not exist yet. A missing required
flag exits 4.

## keygen

```sh
pos-cli keygen --out ./keys
```

Writes `keyring.json` (public, safe to distribute: `{"keys":[{"key_id":"ed25519:<hex16>","public_key_hex":"<hex64>"}]}`)
and `private-key.json` (secret; mode 0600 on Unix). It creates the directory if missing and refuses
to overwrite existing key files. Do not commit `private-key.json`.

## audit

`pos-cli audit verify FILE` checks the hash chain (exit 0 ok, 2 tampered or corrupt, 3 unreadable).
`pos-cli audit tail FILE -n N` prints the last N records. Removal of the newest records is not
detectable.

## Tests

```sh
cargo test -p pos-cli
```

`crates/pos-cli/tests/cli.rs` (assert_cmd + tempfile) covers usage errors, verify and install
(valid, tampered, expired, wrong keyring, v2 rollback state, legacy and unknown versions rejected),
trust (a document's own keyring cannot vouch for itself, including a same-`key_id` different-key
keyring), `sign` (key mismatch, no overwrite), `allowlist-migrate` (success, unsigned result fails
`verify`, missing hashes, wrong key, protected and existing output paths), keygen, audit, and
no-panic on garbage input. Vectors: `docs/CONFORMANCE.md`.

## Exact-file install and recovery

`install` also takes `--package-file <deb>`, `--audit-log <file>` and `--recover retry|abandon` (no
default). They are described in `docs/INSTALL_PIPELINE.md`, including exit codes, the retry warning and
the torn-journal limit. Without those flags `install` behaves as before.

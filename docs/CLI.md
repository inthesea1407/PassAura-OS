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

## update

```
pos-cli update --channel stable
  (--transport-dir DIR | --transport-url https://HOST[/PATH])
  --update-keys update-keys.json --threshold 2
  --keyring keyring.json
  --state state.json --audit-log audit.jsonl
  --update-state-dir update-state/ [--dry-run]
```

Checks a channel for a signed update and, when the channel advanced, verifies the manifest
(threshold Ed25519, expiry, per-channel rollback state), stages the payloads from the transport
with their hashes re-checked, and installs every `X.deb` artifact whose paired signed
`X.allowlist.json` authorizes it, through the install pipeline. See
docs/UPDATE_CLIENT_DESIGN.md and docs/UPDATE_INSTALL_HANDOFF.md.

Exactly one transport is passed. `--transport-dir DIR` reads the signed envelope from
`DIR/<channel>.json` and each artifact from `DIR/<name>`. `--transport-url URL` fetches
`URL/<channel>.json` and `URL/<name>` over https only (rustls with bundled webpki roots; no
redirects, proxies, caching or retries; responses size-capped before reading; no credentials in
the URL). TLS is transport, not trust: the signed manifest remains the only root of trust. See
docs/UPDATE_TRANSPORT_HTTPS.md.

`--update-keys` is `{"keys":[{key_id,public_key_hex,valid_from,valid_until,retired}]}` and
authorizes fetching and staging only; `--keyring` is the install keyring and alone authorizes
installs. `--dry-run` verifies and stages, prints what a real run would install, and stops:
nothing is installed and no state is persisted. An already-current channel prints its sequence
and does nothing. Exit 0 ok or already-current, 2 verification/staging/install failure, 4 usage.
The real run executes `dpkg`; that path has never run on hardware.

## review-check

```
pos-cli review-check --deb package.deb --sha256 HASH --name NAME [--version VERSION]
```

Store pre-review checks on a submitted `.deb` (docs/STORE_REVIEW_MODEL.md): the file's SHA-256
must equal the submission's hash, the name must pass the gate's safe-name rules, the package's
own `control` identity must match the declared name and version, and every maintainer script
(preinst, postinst, prerm, postrm, config) is scanned with documented heuristics. FAIL findings
(download piped to a shell, recursive delete or world-writable chmod rooted at /, raw writes to
block devices, mkfs, fork bombs, non-UTF-8 scripts) fail the review; WARN findings (network
fetches, remote URLs, sudo) are printed for a human. Heuristics are not detection: a pass says
nothing about what the installed binary does at runtime. Findings name the pattern and line
number, never the script content. Exit 0 pass, 2 check failure, 4 usage.

## store-publish

```
pos-cli store-publish --deb package.deb --submission-sha256 HASH \
  --keyring keyring.json --key-id KEY_ID --sequence N [--lifetime-days 30] --out DIR
```

Publishes an approved store submission (docs/STORE_REVIEW_MODEL.md section 8): the artifact's
SHA-256 must equal the approved submission's hash (any swap refuses the publish), the package's
control identity and the gate's safe-name rules are re-checked, and the release pair is written:
`DIR/<name>-<version>.deb` and an UNSIGNED `DIR/<name>-<version>.allowlist.json` (v2, one entry,
the release key's public half embedded). Existing files are never overwritten. The owner signs
the allowlist offline with `pos-cli sign`; this tool never sees the release key. Exit 0 ok,
2 failure.

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

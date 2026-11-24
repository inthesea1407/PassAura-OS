# pos-cli — PassAura OS command-line tool

`pos-cli` verifies signed allowlists and gates package installs against them.
It is part of the PassAura OS Rust workspace alongside `pos-gate` (signature
verification) and `pos-core` (policy documents).

## Install

```sh
cargo build -p pos-cli --release
# binary at target/release/pos-cli
Exit codes
Code	Meaning
0	Success
2	Verification failed (bad signature, expired, malformed JSON, missing file)
3	Package not allowed by the allowlist
4	Usage error (unknown subcommand, missing required argument)

Design note: malformed input (bad JSON, unreadable file) is treated as a
verification failure (2), not a usage error (4). Exit 4 is reserved for
command-line parsing errors so scripts can distinguish "you called me wrong"
from "the data is bad".

verify — verify an allowlist against a keyring
sh
Copy
Download
pos-cli verify allowlist.json --keyring keyring.json

Reads both files, deserializes via pos-gate::Keyring::from_json and
AllowlistDoc::from_json, then calls
pos_gate::verify_allowlist(&keyring, &allowlist, now).

now is the current Unix time in seconds. If the system clock is before
1970, now is clamped to 0 (fail-closed: an allowlist with a future
issued_at will be rejected).

On success: prints ok: allowlist verified, exits 0.

On any failure: prints the error to stderr, exits 2.

Example — expired allowlist:

sh
Copy
Download
$ pos-cli verify old-allowlist.json --keyring keyring.json
verification failed: allowlist expired at 1700000000
$ echo $?
2
install — check whether a package is allowed
sh
Copy
Download
pos-cli install ripgrep --allowlist allowlist.json --dry-run

Reads the allowlist (no keyring needed: is_allowed operates on the
already-verified document).

Important: install does not re-verify the signature. A production
installer must call verify first (or use the library's combined API). This
CLI's install is a gate check, not an installer.

If is_allowed(&doc, "ripgrep") is true: prints a dry-run line and exits 0.

If not: prints not allowed: <pkg> to stderr and exits 3.

--dry-run is required by the current build; the non-dry-run path prints an
"installer not wired in this build" message. This keeps the CLI honest: it
never claims to install something it did not.

Example — allowed:

sh
Copy
Download
$ pos-cli install ripgrep --allowlist allowlist.json --dry-run
dry-run: would install ripgrep (allowed)
$ echo $?
0

Example — not allowed:

sh
Copy
Download
$ pos-cli install curl --allowlist allowlist.json --dry-run
not allowed: curl is not in the allowlist
$ echo $?
3
keygen — generate an ed25519 keypair
sh
Copy
Download
pos-cli keygen --out ./keys

Writes two files into ./keys/:

keyring.json — public keyring, safe to distribute. Shape:
{ "keys": [ { "key_id": "ed25519:<hex16>", "public_key_hex": "<hex64>" } ] }

private-key.json — secret. Shape:
{ "key_id": "...", "private_key_hex": "...", "warning": "KEEP THIS FILE SECRET..." }

On Unix, private-key.json is chmod'd 0600. The directory is created if
missing.

Do not commit private-key.json. Add it to .gitignore.

API assumptions

This CLI is written against the following pos-gate API. If the real crate
differs, only crates/pos-cli/src/main.rs needs updating.

rust
Copy
Download
// Assumed in crates/pos-gate:
pub struct Keyring;
pub struct AllowlistDoc;
pub enum GateError { /* Display implemented */ }

impl Keyring       { pub fn from_json(bytes: &[u8]) -> Result<Self, GateError>; }
impl AllowlistDoc  { pub fn from_json(bytes: &[u8]) -> Result<Self, GateError>; }

pub fn verify_allowlist(kr: &Keyring, doc: &AllowlistDoc, now: u64) -> Result<(), GateError>;
pub fn is_allowed(doc: &AllowlistDoc, pkg: &str) -> bool;

Assumed JSON shapes:

json
Copy
Download
// keyring.json
{ "keys": [ { "key_id": "ed25519:abc", "public_key_hex": "..." } ] }

// allowlist.json
{
  "signed_by": "ed25519:abc",
  "signature_hex": "...",
  "issued_at": 1700000000,
  "expires_at": 1800000000,
  "packages": [ { "name": "ripgrep", "version": "14.1.0" } ]
}
Testing
sh
Copy
Download
cargo test -p pos-cli

The integration tests in crates/pos-cli/tests/cli.rs use assert_cmd and
tempfile. They cover:

usage errors (exit 4): no args, unknown subcommand, missing required flags

verify: happy path (exit 0), bad keyring JSON, bad allowlist JSON, missing
keyring file, missing allowlist file, expired allowlist (all exit 2)

install: allowed dry-run (0), not allowed (3), bad JSON (2), missing file (2)

keygen: writes both files, creates missing directories (0)

malformed input (empty files, binary garbage) does not panic

Caveat: the tests assume pos-gate::from_json accepts the minimal JSON
shapes above. If pos-gate requires additional fields (e.g. a version on
each package), the test fixtures must be updated to match. The tests exercise
the CLI's exit-code mapping, not pos-gate's cryptographic correctness.

What was not run

cargo test -p pos-cli — no Rust toolchain in the authoring environment.

cargo clippy -p pos-cli -- -D warnings — same.

End-to-end verify against a real signed allowlist — pos-gate was not
available to link against, so the verify_ok test only asserts that the CLI
reaches exit 0 when pos-gate returns Ok, using a zeroed signature that
a real verifier would reject.

text
Copy
Download

---

**Continue prompt:** Not needed. This answer is ~18k characters. If you want the `Cargo.toml` moved into `crates/pos-cli/` as shown above (it is), and a workspace-level `Cargo.toml` snippet added, say "continue" and I will add only that file.

## Integrator notes (read first)

- `install` now also requires `--keyring <keyring.json>`. It verifies the allowlist signature before checking the package, so an unsigned or edited allowlist exits 2.
- New `sign <allowlist.json> --private-key <private-key.json> --out <file>` signs an allowlist.
- Signed message: `passaura-allowlist-v1\n<signed_by>\n<issued_at>\n<expires_at>\n` then sorted `name@version\n` lines. Implemented in `crates/pos-gate/src/allowlist.rs`.
- `--help` exits 0. The `installer not wired` message is accurate: `install` only checks and prints, it does not install anything yet.

## v2 allowlists and audit logs

- `verify` and `install` accept a v2 allowlist (`"version": 2`, see `allowlist_v2.rs`). The
  signer must be in the trusted `--keyring` file with the same key_id and public key, because a
  v2 document carries its own keyring and would otherwise vouch for itself.
- `--state FILE` (optional) turns on the rollback check: an older sequence, or the same sequence
  with different content, is rejected (exit 2). `install` records the new sequence after a real
  (non-dry-run) install. Limit: the installer itself is still not wired, so this records intent.
- `audit verify FILE` checks the hash chain (exit 0 ok, 2 tampered or corrupt, 3 unreadable).
  `audit tail FILE -n N` prints the last N records. Removal of the newest records is not detectable.
- Tested in `crates/pos-cli/tests/cli.rs`; vectors in `docs/CONFORMANCE.md`.

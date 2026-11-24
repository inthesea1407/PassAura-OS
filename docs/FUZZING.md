# Fuzzing PassAura OS (`pos-gate`)

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets** in repository files, and keeps **PassAura** as the sole approved password/credential manager. Official releases are signed solely by the project owner, and testing runs in CI and emulators under the zero-budget constraint (`docs/ROADMAP_ZERO_BUDGET.md`).

## Fuzz Targets

- `fuzz/fuzz_targets/fuzz_allowlist_json.rs`: Feeds arbitrary byte slices into `AllowlistDoc::from_json` and `verify_allowlist` with deterministic/derived timestamps, ensuring malformed JSON, unexpected types, or invalid signatures never panic.
- `fuzz/fuzz_targets/fuzz_package_name.rs`: Feeds arbitrary byte slices (via `String::from_utf8_lossy`) into `validate_package_name` and `is_valid_package_name` (`crates/pos-gate/src/names.rs`), asserting consistency and invariants (`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$`, no leading dash, no path separators/traversal, no shell metacharacters).

## Running Locally with Free Tools (`cargo-fuzz`)

Requires nightly Rust and `cargo-fuzz` (`libFuzzer`):

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run fuzz_allowlist_json -- -max_total_time=30
cargo +nightly fuzz run fuzz_package_name -- -max_total_time=30

Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.

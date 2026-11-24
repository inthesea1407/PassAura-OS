Copy
Property-Based Tests for pos-core::policy
What this is

crates/pos-core/tests/policy_props.rs holds property-based tests for
the TOML policy engine, written with [proptest]
(https://crates.io/crates/proptest) (free, Apache-2.0/MIT-licensed).
Unlike the unit tests in policy.rs, which check hand-picked cases,
these run hundreds of generated inputs and search for counterexamples
to security properties.

Run them with the rest of the suite:

sh
cargo test -p pos-core

To persist a shrinking seed after a failure (recommended in CI):

sh
PROPTEST_CASES=2048 cargo test -p pos-core --test policy_props
Properties
ID	Property	Why it matters
P1	In audit mode, evaluate never returns Deny, and Deny/AuditOnly semantics track exactly which rule was violated.	The audit (shadow) rollout guarantee: flipping a policy to audit cannot block any install.
P2	In allowlist mode, any request with size_mb > max_package_size_mb returns Deny(SizeExceeded), regardless of signature state.	The oversize gate cannot be bypassed by a signed package or an allowed source.
P3	A TOML policy containing an unknown field is always rejected; generated policy values always parse.	deny_unknown_fields plus required-fields fail-closed loading, checked over generated typos and junk keys, not one example.
P4	evaluate is deterministic: repeated and cloned evaluation of the same inputs gives the same decision.	Auditable behavior; identical installs on identical inputs.
P5	For any representable Policy: from_toml_str(toml::to_string(p)) yields a Policy equal to p, and yields the same decisions as p.	Policy round-tripping (cache, transport, or text edit) cannot silently change enforcement.
P6	Differential oracle: evaluate matches an independent reference model written straight from docs/POLICY.md (order: size, source, signature; first failure wins; audit maps Deny to AuditOnly).	Catches drift between code, spec, and docs; the model is readable and reviewed, not clever.
Generation strategies
Source identifiers and package names come from fixed safe-ASCII alphabets via proptest::string::string_regex, so generated TOML is always well-formed (no quotes or special TOML characters inserted into values).
Sizes are bounded to 0..=100_000 (and oversize tests add slack), keeping arithmetic far from u64 limits while still hitting the boundary cases 0 (max zero budget) and equality with the limit.
Policies cover: both modes, empty and non-empty allowed_sources, both values of require_signature, and sizes at/below/above limits.
Requests are drawn with sources from the policy's own list half the time and from a fixed unknown source otherwise, so the allow, deny, and audit-only branches are all exercised every run.
Each property runs 512 generated cases by default; regressions are shrunk automatically by proptest and reported with a reproducible seed.
Assumptions the properties rest on
All Policy fields are required in TOML (fail-closed loading), with deny_unknown_fields.
evaluate check order is size, then source, then signature; the first failing check supplies the reason code.
Audit mode never produces Deny; a fully compliant request is Allow in both modes.
The public [Policy] and Mode types implement serde::Serialize (round-trip property P5 needs this; Request need not serialize).
Limits

These properties validate the engine module only, not the pos-gate
backend behavior (signatures, apt/flatpak/winget execution) or the
CLI. Engines from other sources feeding Request fields are trusted
attestations by design; see docs/POLICY.md for the threat model.

Summary: both files delivered; JSON proptest! macro blocks avoid the earlier placeholder mistake by regenerating the final file with only working strategies. Need a continue prompt? No, the two files are complete. Not run: cargo test, since no Rust toolchain is available in this sandbox (cargo and rustc absent). The round-trip property depends on Policy and Mode deriving Serialize, which the current policy.rs does not have; a one-line derive addition there is assumed (out of scope for this task, as only the two test files may be touched). Also assumed: toml::to_string emits allowed_sources = [] for empty vecs and lowercase mode strings, which holds for toml 0.8; assert-based checking of these assumptions is embedded in P5 and P3b.

10:11pm
Knowledge automatically saves key insights from your chats
Set up now

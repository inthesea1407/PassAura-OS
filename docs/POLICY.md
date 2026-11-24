PassAura OS Policy Engine (pos-core::policy)
Overview

pos-core::policy evaluates package installation requests against a
strictly validated TOML policy. It uses only std, serde, and
toml, contains no secrets, and is MIT-licensed like the rest of
PassAura OS. There is no I/O, no network, and no global state: a
Policy is a plain value you can hold, clone, and compare. The module
is compiled with #![forbid(unsafe_code)].

Policy file format

A policy is a TOML document with exactly these top-level fields.
Every field is required; omitting any of them is a load error, so a
truncated or hand-edited policy can never silently become more
permissive.

Field	Type	Required	Notes
mode	string	yes	Exactly "allowlist" or "audit"; any other value is a load error.
allowed_sources	array of strings	yes	Matched by exact string equality against Request.source. No wildcards or regex. An explicitly empty list is valid and, in allowlist mode, denies every source.
max_package_size_mb	integer (u64)	yes	A request whose size_mb is strictly greater than this is rejected. 0 rejects any nonzero payload.
require_signature	boolean	yes	When true, an unsigned request is rejected. Cannot default to false by omission: fail-closed.

Unknown fields are rejected, not ignored. This is enforced with
#[serde(deny_unknown_fields)] on the Policy struct, so a typo such
as reqire_signature = true fails policy loading rather than silently
leaving real signature checking misconfigured.

Example: strict allowlist

toml
mode = "allowlist"
allowed_sources = ["official-mirror", "internal-prod"]
max_package_size_mb = 2048
require_signature = true

Example: audit mode (observe only)

toml
mode = "audit"
allowed_sources = ["official-mirror"]
max_package_size_mb = 512
require_signature = true
The request
rust,ignore
pub struct Request {
    pub package_name: String,
    pub source: String,
    pub size_mb: u64,
    pub signed: bool,
}

Every field is required. size_mb is in megabytes to match the
policy's max_package_size_mb; callers are responsible for unit
conversion before constructing the request. signed is an attestation
produced upstream (for example by a GPG wrapper); this engine does not
verify signatures itself.

The decision
rust,ignore
pub enum Decision {
    Allow,               // proceed, in both modes
    Deny(ReasonCode),    // blocked; allowlist mode only
    AuditOnly(ReasonCode),
}

Reason codes are values of the ReasonCode enum. as_str() returns a
stable lowercase snake_case identifier for logs and audit trails:

as_str() value	Meaning
size_exceeded	size_mb is greater than max_package_size_mb.
source_not_allowed	source is not present in allowed_sources.
signature_required	require_signature is true and the request is unsigned.
Evaluation rules

evaluate(&policy, &request) applies checks in this fixed order, and
the first failing check wins:

Size: size_mb > max_package_size_mb gives size_exceeded.
Source: source not in allowed_sources gives source_not_allowed.
Signature: require_signature and not signed gives signature_required.

If all three checks pass, the decision is Allow in both modes. In
allowlist mode the first violation produces Deny(code); in audit mode
it produces AuditOnly(code) instead, and the request proceeds.

Audit mode never denies

This is a hard rule of the engine, covered by unit tests. In audit mode
every violation that would be a Deny under allowlist mode becomes
AuditOnly with the same reason code, and a request that violates every
rule at once still produces AuditOnly, never Deny. This lets
operators roll out a new policy in shadow mode, collect the would-be
denies from the audit log, and only then flip mode to "allowlist". A
compliant request in audit mode is Allow with no reason code: it is
not a finding.

Loading a policy
rust,ignore
use pos_core::policy::{Policy, Decision, evaluate, Request};

let policy = Policy::from_toml_str(&std::fs::read_to_string("/etc/pos/policy.toml")?)?;
let request = Request {
    package_name: "kernel-6.9.2".into(),
    source: "official-mirror".into(),
    size_mb: 180,
    signed: true,
};
match evaluate(&policy, &request) {
    Decision::Allow => { /* proceed */ }
    Decision::Deny(code) => { /* block and log code.as_str() */ }
    Decision::AuditOnly(code) => { /* proceed and log code.as_str() */ }
}

Policy::from_toml_str returns PolicyError, whose Display output
includes the toml crate's message with the exact line and column of a
malformed or unknown field. PolicyError wraps formatted text so the
public API does not depend on a specific toml version's error type.
The example's ? assumes a fallible calling context, as any real
install-gate entry point should be.

Threat model and limitations

The policy engine makes decisions about what to install; it does not
enforce them. The caller is responsible for acting on the returned
Decision. In particular:

The engine does not verify signatures itself. signed is an upstream attestation; the engine only checks whether the policy requires one to be present.
The engine does not fetch or hash the package. size_mb and source are caller-supplied and trusted as-is.
The engine does not cache the policy. Reloading on change is the caller's responsibility.
allowed_sources supports exact string equality only, no wildcards or regex. This is deliberate: an allowlist that can match anything is not an allowlist.
License

pos-core is MIT-licensed. See the top-level LICENSE file.

Both files remain within scope and budget. No continue prompt needed.

10:05pm
Knowledge automatically saves key insights from your chats
Set up now

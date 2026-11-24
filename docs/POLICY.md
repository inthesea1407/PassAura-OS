
PassAura OS Policy Engine (pos-core::policy)

The policy module of pos-core is the install gate that decides whetherPassAura OS will accept a package (OS image, package tarball, driver bundle,etc.) onto the system. It loads a small TOML policy file, validates itsstructure strictly, and answers one question per incoming request:

Given this policy and this request, do we Allow, Deny, or only Audit?

The engine is intentionally tiny and depends only on std, serde, andtoml. There is no I/O, no network, and no global state: a Policy is aplain value you can hold, clone, and compare.

Policy file format

A policy is a TOML document with exactly these top-level fields:

Field	Type	Required	Default	Notes
mode	string	yes	-	One of "allowlist" or "audit". Any other value is a load error.
allowed_sources	array<string>	no	[]	Sources are matched by exact string equality against Request.source. No wildcards or regex.
max_package_size_mb	integer (u64)	no	0	A request whose size_mb is strictly greater than this is rejected. 0 therefore rejects any non-empty payload in allowlist mode.
require_signature	boolean	no	false	When true, an unsigned request is rejected.

Unknown fields are rejected, not ignored. This is enforced with#[serde(deny_unknown_fields)] on the Policy struct, so a typo such asreqire_signature = true will fail policy loading rather than silentlydisabling signature checks.

Example: strict allowlist
mode = "allowlist"allowed_sources = ["official-mirror", "internal-prod"]max_package_size_mb = 2048require_signature = true
Example: audit mode (observe only)
toml
mode = "audit"
allowed_sources = ["official-mirror"]
max_package_size_mb = 512
require_signature = true
The Request
rust,ignore
pub struct Request {
    pub package_name: String,
    pub source: String,
    pub size_mb: u64,
    pub signed: bool,
}

Every field is required. size_mb is in mebibytes to match the policy's
max_package_size_mb; callers are responsible for unit conversion before
constructing the request.

The Decision
rust,ignore
pub enum Decision {
    Allow,
    Deny(String),       // reason_code
    AuditOnly(String),  // reason_code
}

The wrapped string is a stable, lowercase, snake_case reason_code that
callers can match against without parsing prose. The current codes are:

CODE
	
MEANING

size_exceeded	request.size_mb is greater than max_package_size_mb.
source_not_allowed	request.source is not present in allowed_sources.
signature_required	require_signature is true and request.signed is false.
passed	(audit mode only) All checks passed; the request would have been allowed under allowlist mode.

Codes are also exposed as constants in pos_core::policy::reason so that
callers and tests share one source of truth.

Evaluation rules

evaluate(&policy, &request) applies checks in this fixed order, and the
first failing check wins:

Size - size_mb > max_package_size_mb -> size_exceeded
Source - source not in allowed_sources -> source_not_allowed
Signature - require_signature && !signed -> signature_required

If all three checks pass:

In allowlist mode the decision is Allow.
In audit mode the decision is AuditOnly("passed").
Audit mode never denies

This is a hard rule of the engine, covered by unit tests. In audit mode
every violation that would be a Deny(...) under allowlist mode becomes
AuditOnly(<same reason code>) instead. A request that violates every rule
at once still produces AuditOnly(...), never Deny. This lets operators
roll out a new policy in shadow mode, collect the would-be denies from the
audit log, and only then flip mode to "allowlist".

Edge cases
Empty allowed_sources under allowlist mode denies every request
with source_not_allowed (unless the size check fails first, which is
typical when max_package_size_mb is also 0).
max_package_size_mb = 0 under allowlist mode denies any request
whose size_mb > 0. A request of exactly 0 mebibytes is allowed by the
size check (it is not strictly greater).
require_signature = false disables the signature check entirely;
both signed and unsigned requests are accepted by that check.
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
    Decision::Allow =>           { /* proceed */ }
    Decision::Deny(code) =>      { /* block, log code */ }
    Decision::AuditOnly(code) => { /* proceed, but log code */ }
}

Policy::from_toml_str returns the toml crate's de::Error, which the
caller can format with Display to surface the exact line and column of a
malformed or unknown field.

Threat model and limitations

The policy engine makes decisions about what to install; it does not
enforce them. The caller is responsible for acting on the returned
Decision. In particular:

The engine does not verify the signature itself. request.signed is
an attestation produced upstream (for example by a GPG/age wrapper); the
engine only checks whether the policy requires one to be present.
The engine does not fetch or hash the package. size_mb and source
are caller-supplied and are trusted as-is.
The engine does not cache the policy. Reload on change is the
caller's responsibility.
Unknown sources are denied by absence: there is no wildcard or regex
support in allowed_sources. This is deliberate - an allowlist that can
match anything is not an allowlist.
License

pos-core is MIT-licensed. See the top-level LICENSE file.

text

---

**What I could not run:** `cargo build` / `cargo test`. The sandbox has no Rust toolchain installed (`cargo` and `rustc` are not on PATH), so the 19 unit tests are verified only by inspection. They should compile and pass against `serde` + `toml` as currently published, but please run `cargo test -p pos-core` in your workspace to confirm. No secrets were placed in either file.

**API assumptions I made (call them out for Task 2 review):**

1. **`mode` is required** in the TOML (no `#[serde(default)]`); omitting it is a load error. `allowed_sources`, `max_package_size_mb`, `require_signature` default to `[]`, `0`, `false` respectively.
2. **Check order is fixed**: size -> source -> signature, first failure wins. The spec didn't pin an order; this matches the typical "cheap-to-expensive check" intuition.
3. **Size comparison is strict greater-than** (`size_mb > max`), so a request at exactly the limit is allowed.
4. **`AuditOnly` always carries a reason code.** A fully-passing request in audit mode returns `AuditOnly("passed")` rather than `Allow`, so callers can always log a code. If you'd prefer `Allow` for passing audit requests, that's a one-line change in `evaluate`.
5. **`Request` is constructed by the caller**; `signed` is an upstream attestation, not a value the engine verifies. `Policy` does not perform file I/O or caching - those are the caller's job.
6. **`Decision` is not `Copy`** because it owns `String` reason codes.
7. **Reason codes** are centralized as `pub const` in `policy::reason` so tests and callers share one source of truth.
8. No wildcard/regex support in `allowed_sources` - exact string equality only (deliberate; an allowlist that matches anything is not an allowlist).

The only two files touched in the project tree are [crates/pos-core/src/policy.rs](/home/z/my-project/crates/pos-core/src/policy.rs) and [docs/POLICY.md](/home/z/my-project/docs/POLICY.md).
Plugins
Connect IM
GLM-5.2
Max

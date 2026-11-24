//! PassAura OS policy engine.
//!
//! Loads a TOML policy, validates it strictly (unknown fields are rejected
//! by serde, and all fields are required so a truncated policy never
//! silently becomes permissive), and evaluates [`Request`] values against
//! it to produce a [`Decision`].
//!
//! Only depends on `std`, `serde`, and `toml`. No secrets, no I/O, no
//! global state.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A request to install / fetch / accept a package.
///
/// All fields are required: the engine needs all of them to decide.
/// `signed` is an attestation produced upstream; this engine does not
/// verify signatures itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub package_name: String,
    pub source: String,
    pub size_mb: u64,
    pub signed: bool,
}

/// Enforcement mode for the policy. Serialised as "allowlist" or "audit";
/// any other value is a load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Allowlist,
    Audit,
}

impl Serialize for Mode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Allowlist => "allowlist",
            Mode::Audit => "audit",
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "allowlist" => Ok(Mode::Allowlist),
            "audit" => Ok(Mode::Audit),
            other => Err(serde::de::Error::unknown_variant(other, &["allowlist", "audit"])),
        }
    }
}

/// The loaded policy. All fields are required in the TOML document;
/// missing values are a load error, never a silent permissive default.
///
/// This optionality is deliberate and fail-closed: an operator cannot
/// truncate the policy into a weaker one (for example by dropping
/// `require_signature`) without the load failing outright. An explicitly
/// empty `allowed_sources = []` is valid and, in allowlist mode, denies
/// every source by absence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    pub allowed_sources: Vec<String>,
    pub max_package_size_mb: u64,
    pub require_signature: bool,
}

impl Policy {
    /// Parse a policy from a TOML string. Fails on malformed TOML, unknown
    /// fields, unknown `mode`, or any missing field.
    pub fn from_toml_str(input: &str) -> Result<Self, PolicyError> {
        let p: Self = toml::from_str(input).map_err(|e| PolicyError(format!("{e}")))?;
        // An empty source entry would match an empty request source, which no
        // legitimate source has. Reject it instead of loading a wildcard.
        if p.allowed_sources.iter().any(|s| s.trim().is_empty()) {
            return Err(PolicyError("allowed_sources contains an empty entry".into()));
        }
        Ok(p)
    }
}

/// Error returned when a policy fails to load or validate. Wraps the
/// `toml` crate's error text so the crate's public API does not depend on
/// a specific `toml` version's error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid policy: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

/// Machine-readable reason codes attached to non-`Allow` decisions. Use
/// [`ReasonCode::as_str`] for a stable string identifier for logs and
/// audit trails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// `size_mb` is strictly greater than `max_package_size_mb`.
    SizeExceeded,
    /// `source` is not present in `allowed_sources`.
    SourceNotAllowed,
    /// `require_signature` is true and the request is unsigned.
    SignatureRequired,
}

impl ReasonCode {
    /// Stable lowercase snake_case identifier for logs and audit trails.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReasonCode::SizeExceeded => "size_exceeded",
            ReasonCode::SourceNotAllowed => "source_not_allowed",
            ReasonCode::SignatureRequired => "signature_required",
        }
    }
}

/// Outcome of evaluating a [`Request`] against a [`Policy`].
///
/// `Deny` is never produced in `audit` mode; violations become
/// `AuditOnly` instead. A fully-compliant request returns `Allow` in
/// both modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The request fully satisfies the policy; proceed.
    Allow,
    /// The request violated an enforceable rule in allowlist mode; block it.
    Deny(ReasonCode),
    /// The policy is in audit mode and the request violated a rule, so no
    /// blocking decision is made; record the finding and proceed.
    AuditOnly(ReasonCode),
}

/// Evaluate a [`Request`] against a [`Policy`]. Checks run in this fixed
/// order and the first failing check wins:
///   1. package size vs `max_package_size_mb` (strictly greater than)
///   2. source membership in `allowed_sources` (exact string equality)
///   3. signature presence if `require_signature`
///
/// If no check fails, the decision is [`Decision::Allow`] regardless of
/// mode. If a check fails: `Deny(reason)` in allowlist mode;
/// `AuditOnly(reason)` (never `Deny`) in audit mode.
pub fn evaluate(policy: &Policy, request: &Request) -> Decision {
    let violation = first_violation(policy, request);

    match policy.mode {
        Mode::Audit => match violation {
            Some(code) => Decision::AuditOnly(code),
            None => Decision::Allow,
        },
        Mode::Allowlist => match violation {
            Some(code) => Decision::Deny(code),
            None => Decision::Allow,
        },
    }
}

/// Reason code of the first violated rule, or `None` if all rules pass.
/// Independent of mode. Checks run in order: size, source, signature.
fn first_violation(policy: &Policy, request: &Request) -> Option<ReasonCode> {
    if request.size_mb > policy.max_package_size_mb {
        return Some(ReasonCode::SizeExceeded);
    }
    if !policy.allowed_sources.iter().any(|s| s == &request.source) {
        return Some(ReasonCode::SourceNotAllowed);
    }
    if policy.require_signature && !request.signed {
        return Some(ReasonCode::SignatureRequired);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_POLICY: &str = r#"
mode = "allowlist"
allowed_sources = ["https://repo.example.com", "https://mirror.example.org"]
max_package_size_mb = 500
require_signature = true
"#;

    fn base_request() -> Request {
        Request {
            package_name: "hello".to_string(),
            source: "https://repo.example.com".to_string(),
            size_mb: 10,
            signed: true,
        }
    }

    // ---- Loading / strict validation -----------------------------------

    #[test]
    fn parses_full_policy() {
        let p = Policy::from_toml_str(BASE_POLICY).unwrap();
        assert_eq!(p.mode, Mode::Allowlist);
        assert_eq!(p.allowed_sources, vec!["https://repo.example.com", "https://mirror.example.org"]);
        assert_eq!(p.max_package_size_mb, 500);
        assert!(p.require_signature);
    }

    #[test]
    fn rejects_unknown_field() {
        let bad = BASE_POLICY.replace(
            "require_signature = true",
            "require_signature = true\ninsecure_skip_checks = true",
        );
        let err = Policy::from_toml_str(&bad).unwrap_err();
        assert!(
            err.0.contains("unknown field") || err.0.contains("insecure_skip_checks"),
            "error should name the unknown field, got: {}",
            err.0
        );
    }

    #[test]
    fn rejects_unknown_mode_value() {
        assert!(Policy::from_toml_str(r#"mode = "paranoid""#).is_err());
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(Policy::from_toml_str("mode = ").is_err());
        assert!(Policy::from_toml_str("not toml at all {{{").is_err());
    }

    #[test]
    fn rejects_missing_mode() {
        let toml = "max_package_size_mb = 100\nrequire_signature = false";
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_missing_require_signature() {
        // Fail-closed: omitting a security-relevant field is an error,
        // never a permissive default.
        let toml = "mode = \"allowlist\"\nallowed_sources = [\"registry\"]\nmax_package_size_mb = 100\n";
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_missing_allowed_sources() {
        let toml = "mode = \"allowlist\"\nmax_package_size_mb = 100\nrequire_signature = false\n";
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_missing_max_package_size() {
        let toml = "mode = \"allowlist\"\nallowed_sources = [\"registry\"]\nrequire_signature = false\n";
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn allows_empty_allowed_sources_list() {
        // An explicitly empty list is valid and fail-closed in allowlist
        // mode (denies by absence), unlike a missing key.
        let p = Policy::from_toml_str(&BASE_POLICY.replace(
            "allowed_sources = [\"https://repo.example.com\", \"https://mirror.example.org\"]",
            "allowed_sources = []",
        ))
        .unwrap();
        assert_eq!(
            evaluate(&p, &base_request()),
            Decision::Deny(ReasonCode::SourceNotAllowed)
        );
    }

    // ---- Allowlist mode: allow / deny paths ------------------------------

    #[test]
    fn allowlist_allows_clean_request() {
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &base_request()),
            Decision::Allow
        );
    }

    #[test]
    fn allowlist_denies_oversize() {
        let mut req = base_request();
        req.size_mb = 501;
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Deny(ReasonCode::SizeExceeded)
        );
    }

    #[test]
    fn allowlist_denies_unknown_source() {
        let mut req = base_request();
        req.source = "https://evil.example.net".to_string();
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Deny(ReasonCode::SourceNotAllowed)
        );
    }

    #[test]
    fn allowlist_denies_unsigned_when_required() {
        let mut req = base_request();
        req.signed = false;
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Deny(ReasonCode::SignatureRequired)
        );
    }

    #[test]
    fn allowlist_allows_unsigned_when_not_required() {
        let p = Policy::from_toml_str(
            &BASE_POLICY.replace("require_signature = true", "require_signature = false"),
        )
        .unwrap();
        let mut req = base_request();
        req.signed = false;
        assert_eq!(evaluate(&p, &req), Decision::Allow);
    }

    #[test]
    fn size_equal_to_limit_is_allowed() {
        // Strictly-greater comparison: exactly at the limit is allowed.
        let mut req = base_request();
        req.size_mb = 500;
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Allow
        );
    }

    #[test]
    fn first_violation_wins_size_before_source() {
        let req = Request {
            package_name: "big".to_string(),
            source: "https://evil.example.net".to_string(),
            size_mb: 9999,
            signed: true,
        };
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Deny(ReasonCode::SizeExceeded)
        );
    }

    #[test]
    fn first_violation_ships_source_before_signature() {
        let req = Request {
            package_name: "libc".to_string(),
            source: "https://evil.example.net".to_string(),
            size_mb: 50,
            signed: false,
        };
        assert_eq!(
            evaluate(&Policy::from_toml_str(BASE_POLICY).unwrap(), &req),
            Decision::Deny(ReasonCode::SourceNotAllowed)
        );
    }

    // ---- Audit mode: never denies ----------------------------------------

    fn audit_policy() -> Policy {
        Policy::from_toml_str(&BASE_POLICY.replace("mode = \"allowlist\"", "mode = \"audit\""))
            .unwrap()
    }

    #[test]
    fn audit_mode_allows_compliant_request() {
        assert_eq!(evaluate(&audit_policy(), &base_request()), Decision::Allow);
    }

    #[test]
    fn audit_mode_never_denies_single_violations() {
        let p = audit_policy();

        let mut r = base_request();
        r.size_mb = 9999;
        assert_eq!(evaluate(&p, &r), Decision::AuditOnly(ReasonCode::SizeExceeded));

        let mut r = base_request();
        r.source = "https://evil.example.net".to_string();
        assert_eq!(
            evaluate(&p, &r),
            Decision::AuditOnly(ReasonCode::SourceNotAllowed)
        );

        let mut r = base_request();
        r.signed = false;
        assert_eq!(
            evaluate(&p, &r),
            Decision::AuditOnly(ReasonCode::SignatureRequired)
        );
    }

    #[test]
    fn audit_mode_never_denies_when_every_rule_fails() {
        let req = Request {
            package_name: "suspicious".to_string(),
            source: "https://evil.example.net".to_string(),
            size_mb: 9999,
            signed: false,
        };
        let d = evaluate(&audit_policy(), &req);
        assert_ne!(d, Decision::Deny(ReasonCode::SizeExceeded));
        assert_eq!(d, Decision::AuditOnly(ReasonCode::SizeExceeded));
    }

    #[test]
    fn audit_mode_empty_allowed_sources_reports_but_does_not_deny() {
        let toml_str = "mode = \"audit\"\nallowed_sources = []\nmax_package_size_mb = 500\nrequire_signature = false\n";
        let p = Policy::from_toml_str(toml_str).unwrap();
        let req = Request {
            package_name: "anything".to_string(),
            source: "https://anywhere.example.com".to_string(),
            size_mb: 1,
            signed: true,
        };
        let d = evaluate(&p, &req);
        assert_ne!(d, Decision::Deny(ReasonCode::SourceNotAllowed));
        assert_eq!(d, Decision::AuditOnly(ReasonCode::SourceNotAllowed));
    }

    // ---- Reason codes ------------------------------------------------------

    #[test]
    fn reason_codes_have_stable_strings() {
        assert_eq!(ReasonCode::SizeExceeded.as_str(), "size_exceeded");
        assert_eq!(ReasonCode::SourceNotAllowed.as_str(), "source_not_allowed");
        assert_eq!(ReasonCode::SignatureRequired.as_str(), "signature_required");
    }
}

#[cfg(test)]
mod empty_source_tests {
    use super::*;

    #[test]
    fn empty_allowed_source_is_rejected() {
        for entry in ["\"\"", "\"   \""] {
            let t = format!(
                "mode = \"allowlist\"\nallowed_sources = [{entry}]\nmax_package_size_mb = 100\nrequire_signature = false\n"
            );
            assert!(Policy::from_toml_str(&t).is_err(), "entry {entry}");
        }
    }
}

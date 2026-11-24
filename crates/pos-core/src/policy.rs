//! pos-core policy engine.
//!
//! Loads a TOML policy, validates its structure strictly (unknown fields are
//! rejected by serde), and evaluates [`Request`] values against it to produce
//! a [`Decision`].
//!
//! Only depends on `std`, `serde`, and `toml`.

use serde::{Deserialize, Serialize};

/// Outcome of evaluating a [`Request`] against a [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The request fully satisfies the policy; proceed.
    Allow,
    /// The request violated an enforceable rule; block it.
    ///
    /// The wrapped string is a stable, lowercase, snake_case `reason_code`
    /// that callers can match against without parsing prose.
    Deny(String),
    /// The request was evaluated but the policy is in audit mode, so no
    /// blocking decision is made. The `reason_code` reports the first
    /// violation that *would* have caused a deny in allowlist mode, or
    /// [`reason::PASSED`] when all checks succeeded.
    AuditOnly(String),
}

/// Enforcement mode for the policy.
///
/// Serialised in TOML as the lowercase string `"allowlist"` or `"audit"`.
/// Any other value is rejected at deserialisation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Allowlist,
    Audit,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Allowlist => "allowlist",
            Mode::Audit => "audit",
        }
    }
}

impl Serialize for Mode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
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

/// A request to install / fetch / accept a package.
///
/// All fields are required: the policy engine needs every one of them to
/// make a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub package_name: String,
    pub source: String,
    pub size_mb: u64,
    pub signed: bool,
}

/// The loaded policy.
///
/// Field names map 1:1 to TOML keys. `#[serde(deny_unknown_fields)]` makes
/// deserialisation fail on any unrecognised key, so a typo in the policy
/// file is a hard error rather than a silently-ignored rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default)]
    pub max_package_size_mb: u64,
    #[serde(default)]
    pub require_signature: bool,
}

impl Policy {
    /// Parse a policy from a TOML string.
    ///
    /// Fails on malformed TOML, unknown fields, or an unknown `mode` value.
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }
}

/// Stable reason codes. Centralised here so tests and callers agree on the
/// exact strings.
pub mod reason {
    pub const SIZE_EXCEEDED: &str = "size_exceeded";
    pub const SOURCE_NOT_ALLOWED: &str = "source_not_allowed";
    pub const SIGNATURE_REQUIRED: &str = "signature_required";
    pub const PASSED: &str = "passed";
}

/// Evaluate a [`Request`] against a [`Policy`] and return a [`Decision`].
///
/// Checks are applied in this fixed order, and the first failing check wins:
///   1. package size vs `max_package_size_mb`
///   2. source membership in `allowed_sources`
///   3. signature presence if `require_signature`
///
/// In `audit` mode no check ever produces [`Decision::Deny`]; violations are
/// reported as [`Decision::AuditOnly`] with the same reason code that an
/// allowlist-mode deny would have used, and a fully-passing request is
/// reported as `AuditOnly(reason::PASSED)`.
pub fn evaluate(policy: &Policy, request: &Request) -> Decision {
    let violation = first_violation(policy, request);

    match policy.mode {
        Mode::Audit => Decision::AuditOnly(violation.unwrap_or(reason::PASSED).to_string()),
        Mode::Allowlist => match violation {
            Some(code) => Decision::Deny(code.to_string()),
            None => Decision::Allow,
        },
    }
}

/// Returns the reason code of the first violated rule, or `None` if all
/// rules pass. Independent of `mode`.
fn first_violation(policy: &Policy, request: &Request) -> Option<&'static str> {
    if request.size_mb > policy.max_package_size_mb {
        return Some(reason::SIZE_EXCEEDED);
    }
    if !policy.allowed_sources.iter().any(|s| s == &request.source) {
        return Some(reason::SOURCE_NOT_ALLOWED);
    }
    if policy.require_signature && !request.signed {
        return Some(reason::SIGNATURE_REQUIRED);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, source: &str, size: u64, signed: bool) -> Request {
        Request {
            package_name: name.to_string(),
            source: source.to_string(),
            size_mb: size,
            signed,
        }
    }

    fn allowlist_policy() -> Policy {
        Policy {
            mode: Mode::Allowlist,
            allowed_sources: vec!["registry".to_string(), "mirror".to_string()],
            max_package_size_mb: 100,
            require_signature: true,
        }
    }

    fn audit_policy() -> Policy {
        Policy {
            mode: Mode::Audit,
            allowed_sources: vec!["registry".to_string()],
            max_package_size_mb: 100,
            require_signature: true,
        }
    }

    // ---- Loading / strict validation -----------------------------------

    #[test]
    fn parses_minimal_policy() {
        let p = Policy::from_toml_str(r#"mode = "allowlist""#).unwrap();
        assert_eq!(p.mode, Mode::Allowlist);
        assert!(p.allowed_sources.is_empty());
        assert_eq!(p.max_package_size_mb, 0);
        assert!(!p.require_signature);
    }

    #[test]
    fn parses_full_policy() {
        let toml = r#"
mode = "audit"
allowed_sources = ["registry", "mirror"]
max_package_size_mb = 256
require_signature = true
"#;
        let p = Policy::from_toml_str(toml).unwrap();
        assert_eq!(p.mode, Mode::Audit);
        assert_eq!(p.allowed_sources, vec!["registry", "mirror"]);
        assert_eq!(p.max_package_size_mb, 256);
        assert!(p.require_signature);
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = r#"
mode = "allowlist"
shiny_unknown_key = true
"#;
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_unknown_mode_value() {
        let toml = r#"mode = "paranoid""#;
        assert!(Policy::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(Policy::from_toml_str("mode = ").is_err());
    }

    #[test]
    fn rejects_missing_mode() {
        // `mode` has no serde default, so omitting it must fail.
        let toml = r#"max_package_size_mb = 100"#;
        assert!(Policy::from_toml_str(toml).is_err());
    }

    // ---- Allowlist mode: allow / deny paths ----------------------------

    #[test]
    fn allowlist_allows_clean_request() {
        let d = evaluate(&allowlist_policy(), &req("libc", "registry", 50, true));
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn allowlist_denies_oversize() {
        let d = evaluate(&allowlist_policy(), &req("big", "registry", 101, true));
        assert_eq!(d, Decision::Deny(reason::SIZE_EXCEEDED.to_string()));
    }

    #[test]
    fn allowlist_denies_unknown_source() {
        let d = evaluate(&allowlist_policy(), &req("libc", "evil", 50, true));
        assert_eq!(d, Decision::Deny(reason::SOURCE_NOT_ALLOWED.to_string()));
    }

    #[test]
    fn allowlist_denies_unsigned_when_required() {
        let d = evaluate(&allowlist_policy(), &req("libc", "registry", 50, false));
        assert_eq!(d, Decision::Deny(reason::SIGNATURE_REQUIRED.to_string()));
    }

    #[test]
    fn allowlist_allows_unsigned_when_not_required() {
        let mut p = allowlist_policy();
        p.require_signature = false;
        let d = evaluate(&p, &req("libc", "registry", 50, false));
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn allowlist_first_violation_wins_size_before_source() {
        // Oversize AND wrong source: size is checked first.
        let d = evaluate(&allowlist_policy(), &req("big", "evil", 999, true));
        assert_eq!(d, Decision::Deny(reason::SIZE_EXCEEDED.to_string()));
    }

    #[test]
    fn allowlist_first_violation_wins_source_before_signature() {
        // Wrong source AND unsigned: source is checked first.
        let d = evaluate(&allowlist_policy(), &req("libc", "evil", 50, false));
        assert_eq!(d, Decision::Deny(reason::SOURCE_NOT_ALLOWED.to_string()));
    }

    #[test]
    fn allowlist_empty_sources_denies_everything() {
        let p = Policy {
            mode: Mode::Allowlist,
            allowed_sources: vec![],
            max_package_size_mb: 1_000_000,
            require_signature: false,
        };
        let d = evaluate(&p, &req("libc", "registry", 1, false));
        assert_eq!(d, Decision::Deny(reason::SOURCE_NOT_ALLOWED.to_string()));
    }

    #[test]
    fn allowlist_zero_size_budget_denies_any_payload() {
        let p = Policy {
            mode: Mode::Allowlist,
            allowed_sources: vec!["registry".to_string()],
            max_package_size_mb: 0,
            require_signature: false,
        };
        let d = evaluate(&p, &req("libc", "registry", 1, false));
        assert_eq!(d, Decision::Deny(reason::SIZE_EXCEEDED.to_string()));
    }

    #[test]
    fn allowlist_exactly_at_size_limit_is_allowed() {
        // size_mb == max_package_size_mb is NOT strictly greater, so allowed.
        let d = evaluate(&allowlist_policy(), &req("libc", "registry", 100, true));
        assert_eq!(d, Decision::Allow);
    }

    // ---- Audit mode: never denies --------------------------------------

    #[test]
    fn audit_mode_passing_request_returns_audit_only_passed() {
        let d = evaluate(&audit_policy(), &req("libc", "registry", 50, true));
        assert_eq!(d, Decision::AuditOnly(reason::PASSED.to_string()));
    }

    #[test]
    fn audit_mode_oversize_is_audit_not_deny() {
        let d = evaluate(&audit_policy(), &req("big", "registry", 1_000, true));
        assert_eq!(d, Decision::AuditOnly(reason::SIZE_EXCEEDED.to_string()));
        assert!(!matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn audit_mode_unknown_source_is_audit_not_deny() {
        let d = evaluate(&audit_policy(), &req("libc", "evil", 50, true));
        assert_eq!(
            d,
            Decision::AuditOnly(reason::SOURCE_NOT_ALLOWED.to_string())
        );
        assert!(!matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn audit_mode_unsigned_when_required_is_audit_not_deny() {
        let d = evaluate(&audit_policy(), &req("libc", "registry", 50, false));
        assert_eq!(
            d,
            Decision::AuditOnly(reason::SIGNATURE_REQUIRED.to_string())
        );
        assert!(!matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn audit_mode_never_returns_deny_even_when_every_rule_fails() {
        // Oversize + unknown source + unsigned: still no Deny, and the first
        // violation (size) wins.
        let d = evaluate(&audit_policy(), &req("big", "evil", 999_999, false));
        assert!(!matches!(d, Decision::Deny(_)));
        assert_eq!(d, Decision::AuditOnly(reason::SIZE_EXCEEDED.to_string()));
    }
}

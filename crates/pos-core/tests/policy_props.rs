//! Property-based tests for the pos-core TOML policy engine
//! (`pos_core::policy`), using proptest (free, Apache-2.0/MIT-licensed).
//!
//! Properties:
//!   P1 audit mode never returns Decision::Deny
//!   P2 oversize is always Deny(SizeExceeded) in allowlist mode
//!   P3 unknown fields in a TOML policy are always rejected
//!   P4 evaluation is deterministic
//!   P5 parse(serialize(p)) == p, and round-trip preserves decisions

use proptest::prelude::*;

use pos_core::policy::{evaluate, Decision, Mode, Policy, ReasonCode, Request};

// ---------- strategies ----------

/// Source identifiers / package names over a safe ASCII alphabet.
fn arb_source_name() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[A-Za-z0-9./:-]{1,16}").expect("fixed regex")
}

fn arb_package_name() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z][a-z0-9-]{0,12}").expect("fixed regex")
}

/// Bounded sizes: 0..=100_000 MB keeps arithmetic far from overflow.
fn arb_size() -> impl Strategy<Value = u64> {
    0u64..=100_000
}

/// A random valid policy struct (round-trip property P5 and P4 generality).
fn arb_policy() -> impl Strategy<Value = Policy> {
    (
        any::<bool>(),
        prop::collection::vec(arb_source_name(), 0..5),
        arb_size(),
        any::<bool>(),
    )
        .prop_map(|(allowlist, sources, max_size, require_sig)| Policy {
            mode: if allowlist { Mode::Allowlist } else { Mode::Audit },
            allowed_sources: sources.clone(),
            max_package_size_mb: max_size,
            require_signature: require_sig,
        })
}

/// Request over a policy's own source list plus an unknown alternative,
/// so both source branches are exercised.
fn arb_request_for(policy: &Policy) -> Request {
    let known = policy
        .allowed_sources
        .first()
        .cloned()
        .unwrap_or_else(|| "known-source".to_string());
    let source = if policy.mode == Mode::Allowlist {
        known
    } else {
        known
    };
    Request {
        package_name: "pkg".to_string(),
        source,
        size_mb: 0,
        signed: true,
    }
}

// ---------- P1: audit mode never returns Deny ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p1_audit_mode_never_denies(
        sources in prop::collection::vec(arb_source_name(), 0..5),
        max_size in arb_size(),
        require_sig in any::<bool>(),
        use_known in any::<bool>(),
        size_mb in arb_size(),
        signed in any::<bool>(),
        pkg in arb_package_name(),
    ) {
        let policy = Policy {
            mode: Mode::Audit,
            allowed_sources: sources,
            max_package_size_mb: max_size,
            require_signature: require_sig,
        };
        let source = if use_known && !policy.allowed_sources.is_empty() {
            policy.allowed_sources[0].clone()
        } else {
            // May or may not be in the allowlist; either is fine for this property.
            "unknown-source/xyz".to_string()
        };
        let req = Request { package_name: pkg, source, size_mb, signed };

        let d = evaluate(&policy, &req);
        prop_assert!(
            !matches!(d, Decision::Deny(_)),
            "audit mode returned Deny for request {:?}", req
        );

        // Decision semantics: Allow exactly when no rule is violated.
        let rules_pass = req.size_mb <= max_size
            && policy.allowed_sources.iter().any(|s| *s == req.source)
            && (req.signed || !require_sig);
        prop_assert_eq!(
            matches!(d, Decision::Allow),
            rules_pass,
            "audit Allow/violation mismatch for request {:?}", req
        );
    }
}

// ---------- P2: oversize always denied in allowlist mode ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p2_oversize_always_denied_in_allowlist_mode(
        sources in prop::collection::vec(arb_source_name(), 1..4),
        max_size in arb_size(),
        require_sig in any::<bool>(),
        signed in any::<bool>(),
        oversize_slack in 1u64..=50_000,
        pkg in arb_package_name(),
    ) {
        prop_assume!(!sources.is_empty());
        let policy = Policy {
            mode: Mode::Allowlist,
            allowed_sources: sources,
            max_package_size_mb: max_size,
            require_signature: require_sig,
        };
        let size_mb = max_size + oversize_slack;
        let req = Request {
            package_name: pkg,
            source: policy.allowed_sources[0].clone(),
            size_mb,
            signed,
        };
        // size_mb is strictly above max_size and size is the first check,
        // so SizeExceeded must decide, regardless of signature state.
        prop_assert_eq!(
            evaluate(&policy, &req),
            Decision::Deny(ReasonCode::SizeExceeded),
            "oversize request ({} > {} MB) was not denied", size_mb, max_size
        );
    }
}

// ---------- P3: unknown TOML fields always rejected ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p3_unknown_toml_field_always_rejected(
        junk_key in prop::string::string_regex("[a-z_][a-z0-9_]{0,14}")
            .expect("fixed regex"),
        junk_val in any::<bool>(),
    ) {
        prop_assume!(!matches!(
            junk_key.as_str(),
            "mode" | "allowed_sources" | "max_package_size_mb" | "require_signature"
        ));
        let toml_text = format!(
            "mode = \"allowlist\"\nallowed_sources = [\"registry\"]\n\
             max_package_size_mb = 100\nrequire_signature = true\n\
             {junk_key} = {junk_val}\n"
        );
        prop_assert!(
            Policy::from_toml_str(&toml_text).is_err(),
            "policy with unknown field {:?} was accepted", junk_key
        );
    }

    #[test]
    fn p3b_valid_policy_always_parses(
        sources in prop::collection::vec(arb_source_name(), 0..5),
        max_size in arb_size(),
        require_sig in any::<bool>(),
    ) {
        prop_assume!(!sources.iter().any(|s| s.contains('"')));
        let quoted: Vec<String> = sources.iter().map(|s| format!("\"{s}\"")).collect();
        let toml_text = format!(
            "mode = \"audit\"\nallowed_sources = [{}]\nmax_package_size_mb = {max_size}\nrequire_signature = {require_sig}\n",
            quoted.join(", ")
        );
        let p = Policy::from_toml_str(&toml_text)
            .unwrap_or_else(|e| panic!("valid policy rejected: {e}\n{toml_text}"));
        prop_assert_eq!(p.allowed_sources, sources);
        prop_assert_eq!(p.max_package_size_mb, max_size);
        prop_assert_eq!(p.require_signature, require_sig);
    }
}

// ---------- P4: evaluation is deterministic ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p4_evaluation_is_deterministic(
        policy in arb_policy(),
        size_mb in arb_size(),
        signed in any::<bool>(),
        pkg in arb_package_name(),
    ) {
        prop_assume!(!policy.allowed_sources.is_empty());
        let req = Request {
            package_name: pkg,
            source: policy.allowed_sources[0].clone(),
            size_mb,
            signed,
        };
        let a = evaluate(&policy, &req);
        let b = evaluate(&policy.clone(), &req.clone()); // rerun on cloned inputs
        let c = evaluate(&policy.clone(), &req.clone());
        prop_assert_eq!(a.clone(), b.clone(), "evaluation not deterministic");
        prop_assert_eq!(a, c, "evaluation not deterministic across three runs");
    }
}

// ---------- P5: parse(serialize(p)) == p ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p5_roundtrip_parse_serialize_is_identity(policy in arb_policy()) {
        let serialized = toml::to_string(&policy).expect("policy must serialize");
        let parsed = Policy::from_toml_str(&serialized)
            .unwrap_or_else(|e| panic!("serialized policy must parse back: {e}\n{serialized}"));
        prop_assert_eq!(
            policy,
            parsed, "round-trip through TOML changed the policy:\n{}", serialized
        );
    }

    #[test]
    fn p5b_roundtrip_preserves_evaluation(
        policy in arb_policy(),
        size_mb in arb_size(),
        signed in any::<bool>(),
        source_pick in any::<bool>(),
    ) {
        let serialized = toml::to_string(&policy).expect("policy must serialize");
        let parsed = Policy::from_toml_str(&serialized)
            .unwrap_or_else(|e| panic!("serialized policy must parse back: {e}\n{serialized}"));

        let source = if source_pick && !policy.allowed_sources.is_empty() {
            policy.allowed_sources[0].clone()
        } else {
            "unknown-source/xyz".to_string()
        };
        let req = Request {
            package_name: "pkg".to_string(),
            source,
            size_mb,
            signed,
        };
        prop_assert_eq!(
            evaluate(&policy, &req),
            evaluate(&parsed, &req),
            "round-trip changed the decision"
        );
    }
}

// ---------- P6: differential oracle (inspectable reference model) ----------

/// Reference model written directly from docs/POLICY.md, independent of the
/// engine's control flow. Request sources are drawn either from the
/// allowlist (allowed-source branch) or from a fixed unknown string.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p6_differential_oracle(
        sources in prop::collection::vec(arb_source_name(), 1..4),
        max_size in arb_size(),
        require_sig in any::<bool>(),
        allowlist_mode in any::<bool>(),
        use_known in any::<bool>(),
        size_mb in arb_size(),
        signed in any::<bool>(),
        pkg in arb_package_name(),
    ) {
        prop_assume!(!sources.is_empty());
        let policy = Policy {
            mode: if allowlist_mode { Mode::Allowlist } else { Mode::Audit },
            allowed_sources: sources.clone(),
            max_package_size_mb: max_size,
            require_signature: require_sig,
        };
        let source = if use_known {
            sources[0].clone()
        } else {
            "unknown-source/xyz".to_string()
        };
        let req = Request { package_name: pkg, source, size_mb, signed };

        // Reference model: size -> source -> signature, first failure wins.
        let code = if req.size_mb > max_size {
            Some(ReasonCode::SizeExceeded)
        } else if !policy.allowed_sources.iter().any(|s| *s == req.source) {
            Some(ReasonCode::SourceNotAllowed)
        } else if require_sig && !signed {
            Some(ReasonCode::SignatureRequired)
        } else {
            None
        };

        let expected = match (code, allowlist_mode) {
            (None, _) => Decision::Allow,
            (Some(c), true) => Decision::Deny(c),
            (Some(c), false) => Decision::AuditOnly(c),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };
        prop_assert_eq!(
            evaluate(&policy, &req),
            expected,
            "engine diverged from reference model for request {:?}", req
        );
    }
}

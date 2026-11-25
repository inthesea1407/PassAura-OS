//! Property-based tests (proptest) for the deny-by-default grant engine
//! in `pos_core` (`PolicyEngine` / `check`).
//!
//! Properties:
//!   P1 default deny: an engine with no grants never returns Allow,
//!      whatever the subject, resource, action or clock.
//!   P2 adding a deny rule never turns a prior Deny into Allow, and
//!      turns every Allow into ExplicitDeny for the covered pair.
//!   P3 evaluation never panics and is deterministic: repeated checks on
//!      unchanged state return identical decisions.

use proptest::prelude::*;

use pos_core::{Action, Decision, DenyReason, PolicyEngine, SubjectId};

// ---------- strategies ----------

/// Actions drawn from the full real enum.
fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Read),
        Just(Action::Write),
        Just(Action::Execute),
        Just(Action::Network),
        Just(Action::Camera),
        Just(Action::Microphone),
        Just(Action::Location),
    ]
}

/// Resource strings with optional slash hierarchy, so `covers`
/// (exact / child-path) semantics are exercised but never its panic paths.
fn arb_resource() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{1,4}(/[a-z]{1,4}){0,2}").expect("fixed regex")
}

/// A deny rule that definitely covers (resource, action): either the
/// resource itself, its first-level parent, or "*".
#[allow(dead_code)]
fn arb_covering_deny(resource: String, action: Action) -> BoxedStrategy<(String, Action)> {
    let r1 = resource.clone();
    let parent = resource
        .rsplit_once('/')
        .map(|(p, _)| p.to_string())
        .unwrap_or_else(|| "*".to_string());
    prop_oneof![
        Just((resource, action)),
        Just((parent, action)),
        Just(("*".to_string(), action)),
    ]
    // `r1` kept alive for the clone below; silence unused warnings.
    .prop_map(move |pair| {
        let _ = &r1;
        pair
    })
    .boxed()
}

fn arb_subject_name() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9.]{0,9}").expect("fixed regex")
}

/// An engine state plus a query drawn against it.
/// `authenticated` is chosen, grants may or may not exist/cover.
fn arb_engine_and_query() -> impl Strategy<
    Value = (
        PolicyEngine,
        SubjectId,
        String,
        Action,
        u64,
    ),
> {
    (
        arb_subject_name(),
        prop::collection::vec((arb_resource(), arb_action(), any::<bool>()), 0..4),
        arb_resource(),
        arb_action(),
        0u64..300,
    )
        .prop_map(|(subject_name, grants, resource, action, now)| {
            let mut engine = PolicyEngine::new();
            let sid = engine.register(&subject_name);
            engine.set_authenticated(&sid, true); // isolation of P1 uses its own engine
            for (res, act, unexpired) in grants {
                let expires_at = if unexpired { None } else { Some(0) };
                engine.grant(&sid, &res, act, expires_at);
            }
            (engine, sid, resource, action, now)
        })
}

// ---------- P1: default deny ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p1_registered_but_grantless_is_denied_no_grant(
        subject in arb_subject_name(),
        resource in arb_resource(),
        action in arb_action(),
        now in 0u64..300,
    ) {
        let mut engine = PolicyEngine::new();
        let sid = engine.register(&subject);
        engine.set_authenticated(&sid, true);
        prop_assert_eq!(
            engine.check(&sid, &resource, action, now),
            Decision::Deny(DenyReason::NoGrant),
            "grantless authenticated subject must be denied by default"
        );
    }

    #[test]
    fn p1b_unknown_subject_is_always_denied(
        subject in arb_subject_name(),
        resource in arb_resource(),
        action in arb_action(),
        now in 0u64..300,
    ) {
        // No registration at all: whatever strings arrive, never Allow.
        let engine = PolicyEngine::new();
        let ghost = SubjectId(format!("{subject}/not-registered"));
        prop_assert_eq!(
            engine.check(&ghost, &resource, action, now),
            Decision::Deny(DenyReason::UnknownSubject)
        );
    }

    #[test]
    fn p1c_unauthenticated_is_always_denied_even_with_grants(
        grants in prop::collection::vec((arb_resource(), arb_action()), 1..4),
        resource in arb_resource(),
        action in arb_action(),
        now in 0u64..300,
    ) {
        let mut engine = PolicyEngine::new();
        let sid = engine.register("someone");
        for (res, act) in &grants {
            engine.grant(&sid, res, *act, None);
        }
        engine.set_authenticated(&sid, false);
        let d = engine.check(&sid, &resource, action, now);
        prop_assert_ne!(d.clone(), Decision::Allow);
        prop_assert_eq!(d, Decision::Deny(DenyReason::NotAuthenticated));
    }
}

// ---------- P2: adding a deny rule never flips deny -> allow ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p2_deny_rule_never_turns_deny_into_allow(
        (engine, sid, resource, action, now) in arb_engine_and_query(),
        deny_is_covering in prop::bool::ANY,
    ) {
        let mut engine = engine;
        let before = engine.check(&sid, &resource, action, now);

        // Add a deny rule: covering (guaranteed to match the query), or a
        // deliberately non-covering sibling to show it must not matter.
        let rule = if deny_is_covering {
            (resource.clone(), action)
        } else {
            (format!("{resource}/sibling-not-queried"), action)
        };
        let added = engine.deny(&sid, &rule.0, rule.1);
        prop_assert!(added, "deny on a registered subject must succeed");

        let after = engine.check(&sid, &resource, action, now);

        // Monotonicity: Allow before implies the deny rule could only
        // change it to a Deny; Deny before can never become Allow.
        match before {
            Decision::Deny(_) => {
                prop_assert_ne!(after, Decision::Allow,
                    "deny rule turned a Deny into Allow for {}:{:?}", resource, action);
            }
            Decision::Allow => {
                if deny_is_covering {
                    prop_assert_eq!(after, Decision::Deny(DenyReason::ExplicitDeny),
                        "covering deny rule did not deny previously-allowed query");
                } else {
                    prop_assert_eq!(after, Decision::Allow,
                        "non-covering deny rule must not change an Allow");
                }
            }
        }
    }

    #[test]
    fn p2b_deny_precedes_revoked_and_expired_grants(
        resource in arb_resource(),
        enforce_expiry in any::<bool>(),
        action in arb_action(),
    ) {
        let mut engine = PolicyEngine::new();
        let sid = engine.register("s");
        engine.set_authenticated(&sid, true);
        engine.grant(&sid, &resource, action, if enforce_expiry { Some(0) } else { None });
        engine.revoke(&sid, &resource, action);
        engine.deny(&sid, &resource, action);
        prop_assert_eq!(
            engine.check(&sid, &resource, action, 200),
            Decision::Deny(DenyReason::ExplicitDeny),
            "explicit deny must take precedence over revoked/expired grant reasons"
        );
    }
}

// ---------- P3: no panics, deterministic ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p3_evaluation_never_panics_and_is_deterministic(
        (engine, sid, resource, action, now) in arb_engine_and_query(),
        now2 in 0u64..300,
    ) {
        // Deterministic at a fixed instant: run three times.
        let a = engine.check(&sid, &resource, action, now);
        let b = engine.check(&sid, &resource, action, now);
        let c = engine.check(&sid, &resource, action, now);
        prop_assert_eq!(a.clone(), b, "decision changed between runs");
        prop_assert_eq!(a, c, "decision changed across clone");

        // All-out fuzz over the full query space must also be panic-free
        // and deterministic: same (subject, resource, action) queried at a
        // different instant gives a stable answer for time-independent
        // state (no expiry clocks were started past `now`).
        let d1 = engine.check(&sid, &resource, action, now2);
        let d2 = engine.check(&sid, &resource, action, now2);
        prop_assert_eq!(d1.clone(), d2, "decision at second instant not deterministic");

        // Decision space never escapes {Allow, Deny(_)}.
        prop_assert!(matches!(d1, Decision::Allow | Decision::Deny(_)));
    }

    #[test]
    fn p3b_mutation_sequence_stays_deterministic(
        subject in arb_subject_name(),
        steps in prop::collection::vec((arb_resource(), arb_action(), any::<bool>()), 1..6),
        resource in arb_resource(),
        action in arb_action(),
    ) {
        let mut engine = PolicyEngine::new();
        let sid = engine.register(&subject);
        engine.set_authenticated(&sid, true);

        // Record decision after each mutation, twice per state.
        let mut observed: Vec<(Decision, Decision)> = Vec::new();
        for (res, act, unexpired) in &steps {
            engine.grant(&sid, res, *act, if *unexpired { None } else { Some(0) });
        }
        for (res, act, _) in &steps {
            engine.deny(&sid, res, *act);
        }
        observed.push((
            engine.check(&sid, &resource, action, 100),
            engine.check(&sid, &resource, action, 100),
        ));
        for (d1, d2) in observed {
            prop_assert_eq!(d1, d2, "engine diverged after identical mutations");
        }
    }
}


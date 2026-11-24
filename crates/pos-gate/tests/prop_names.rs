//! Property-based tests (proptest) for the package-name validator in
//! `pos_gate::names`, pinning the security contract:
//!
//!   P1 every ACCEPTED name matches ^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$
//!   P2 names containing shell metacharacters, path separators, NUL, or
//!      any non-ASCII (unicode lookalikes) are NEVER accepted
//!   P3 `is_valid_package_name` agrees with `validate_package_name`
//!   P4 validation is deterministic and panic-free over arbitrary input
//!   P5 names from the "valid" generator are always accepted (the
//!      generator, not the validator, defines the regex literal)
//!
//! Constraint honored: this file asserts the one-way implication
//! accepted => regex. The implementation additionally rejects names with
//! `..` (see docs/NAMES_REVIEW.md, N1), so violating-names => rejected is
//! only asserted for the documented blacklist classes, not for every
//! regex-match.

use proptest::prelude::*;

use pos_gate::names::{
    is_valid_package_name, validate_package_name, NameError, MAX_PACKAGE_NAME_LEN,
};

/// The contracted character classes, expressed without a regex crate.
fn is_regex_legal_byte(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-')
}

/// ^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$ by direct inspection.
fn matches_contract_regex(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {
            let extra = chars.count();
            extra <= 99 && name.chars().all(is_regex_legal_byte)
        }
        _ => false,
    }
}

/// Shell metacharacters and whitespace that must never survive.
const SHELL_METACHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '<', '>', '\\', '"', '\'', '*', '?',
    '[', ']', '#', '~', '!', '{', '}', ',', ':', '=', '%', '@', '^', ' ',
    '\t', '\n', '\r', '\0',
];

// ---------- strategies ----------

/// Arbitrary unicode strings (may be empty, may be garbage).
fn arb_any_string() -> impl Strategy<Value = String> {
    prop::string::string_regex(".{0,140}").expect("fixed regex")
}

/// Strings guaranteed to violate the contract in a blacklisted way:
/// at least one shell metachar / separator / NUL / non-ASCII char is
/// spliced into an otherwise benign name.
fn arb_blacklisted_string() -> impl Strategy<Value = String> {
    (arb_any_string(), prop::option::weighted(0.4, prop_oneof![
        Just(SHELL_METACHARS.to_vec()),
        Just(vec!['/', '\\']),
        Just(vec!['\u{0}']),
        // Unicode lookalikes and invisibles: Cyrillic homoglyphs of
        // "r" and "a", fullwidth letters, zero-width chars, combining marks.
        Just(vec!['\u{0430}', '\u{0440}', '\u{FF41}', '\u{200B}', '\u{0301}']),
    ]))
    .prop_map(|(base, pool)| {
        let bad = pool;
        let mut chars: Vec<char> = base.chars().take(60).collect();
        // Splice every bad char in; a name carrying any of them can never
        // legitimately pass.
        for (i, c) in bad.iter().flatten().enumerate() {
            chars.insert((i * 3).min(chars.len()), *c);
        }
        let mut name: String = chars.into_iter().collect();
        // Also append tail metachars to catch suffix-injection attempts.
        name.push('|');
        name
    })
}

/// Names conforming to the contract regex.
fn arb_valid_name() -> impl Strategy<Value = String> {
    (prop::string::string_regex("[A-Za-z0-9]").expect("first-char regex"),
     prop::string::string_regex("[A-Za-z0-9.+_-]{0,99}").expect("rest regex"))
        .prop_map(|(first, rest)| format!("{first}{rest}"))
}

// ---------- P1: accepted implies regex-conformant ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn p1_accepted_names_always_match_contract_regex(name in arb_any_string()) {
        if is_valid_package_name(&name) {
            prop_assert!(
                matches_contract_regex(&name),
                "accepted name {name:?} does not match the contract regex"
            );
            prop_assert!(
                name.len() <= MAX_PACKAGE_NAME_LEN,
                "accepted name {name:?} exceeds byte budget"
            );
        }
    }
}

// ---------- P2: blacklisted content is never accepted ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn p2_blacklisted_content_never_accepted(name in arb_blacklisted_string()) {
        // The generator guarantees at least one violating char.
        prop_assert!(
            validate_package_name(&name).is_err(),
            "violating name {name:?} was accepted"
        );
        prop_assert!(!is_valid_package_name(&name), "boolean wrapper disagreed");
    }

    #[test]
    fn p2b_shell_metachar_position_independent(
        meta in prop::sample::select(SHELL_METACHARS.to_vec()),
        prefix in prop::string::string_regex("[A-Za-z0-9]{1,20}").expect("regex"),
        suffix in prop::string::string_regex("[A-Za-z0-9]{0,20}").expect("regex"),
        at_start in any::<bool>(),
    ) {
        let name = if at_start {
            format!("{meta}{prefix}{suffix}")
        } else {
            format!("{prefix}{meta}{suffix}")
        };
        prop_assert!(
            validate_package_name(&name).is_err(),
            "metachar {meta:?} at {} position was accepted: {name:?}",
            if at_start { "start" } else { "middle" }
        );
    }

    #[test]
    fn p2c_non_ascii_never_accepted(
        unicode_char in prop::char::range('\u{80}', '\u{10FFFF}'),
        prefix in prop::string::string_regex("[A-Za-z0-9]{1,20}").expect("regex"),
    ) {
        prop_assume!(unicode_char as u32 <= 0x10FFFF && !(0xD800..0xE000).contains(&(unicode_char as u32)));
        let name = format!("{prefix}{unicode_char}");
        prop_assert!(
            validate_package_name(&name).is_err(),
            "unicode char {unicode_char:?} (potential lookalike) was accepted"
        );
    }

    #[test]
    fn p2d_overlong_name_never_accepted(
        n in (MAX_PACKAGE_NAME_LEN + 1)..(MAX_PACKAGE_NAME_LEN + 500),
    ) {
        prop_assume!(n <= 2048);
        let name = "a".repeat(n);
        prop_assert!(matches!(
            validate_package_name(&name),
            Err(NameError::TooLong(_))
        ));
    }
}

// ---------- P3: boolean wrapper agrees with Result API ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p3_wrapper_agrees_with_validator(name in arb_any_string()) {
        prop_assert_eq!(
            is_valid_package_name(&name),
            validate_package_name(&name).is_ok(),
            "boolean wrapper diverged for {:?}", name
        );
    }
}

// ---------- P4: deterministic, panic-free ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p4_validation_deterministic(name in arb_any_string()) {
        let a = validate_package_name(&name);
        let b = validate_package_name(&name);
        let c = validate_package_name(&name.clone());
        prop_assert_eq!(a.clone(), b.clone(), "validator verdict changed between runs");
        prop_assert_eq!(b.clone(), c, "validator verdict changed across clone");
    }
}

// ---------- P5: regex-conformant generator is always accepted ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn p5_contract_conforming_names_accepted(name in arb_valid_name()) {
        prop_assert!(
            matches_contract_regex(&name),
            "generator produced a non-conforming name: {name:?}"
        );
        // Note: names containing ".." are rejected per N1 in the review
        // doc, so the assertion excludes that deliberately-stricter rule.
        prop_assume!(!name.contains(".."));
        prop_assert!(
            validate_package_name(&name).is_ok(),
            "regex-conformant name {name:?} was rejected: {:?}",
            validate_package_name(&name)
        );
    }
}

use ed25519_dalek::{Signer, SigningKey};
use pos_gate::allowlist::{AllowlistDoc, KeyEntry, Keyring, PackageEntry};
use pos_gate::allowlist_v2::{
    canonical_payload_bytes, derive_key_id, parse_v2, verify_v2, verify_v2_trusted, V2Error,
};
use pos_gate::migrate::{migrate_text_v1, parse_sha256_map, MigrateError};
use std::collections::BTreeMap;

const NOW: u64 = 200;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn trusted(sk: &SigningKey) -> Keyring {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    Keyring { keys: vec![KeyEntry { key_id: derive_key_id(&pk), public_key_hex: pk }] }
}

fn v1_bytes(sk: &SigningKey) -> Vec<u8> {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let mut d = AllowlistDoc {
        signed_by: derive_key_id(&pk),
        signature_hex: String::new(),
        issued_at: 100,
        expires_at: 500,
        packages: vec![
            PackageEntry { name: "curl".into(), version: "8".into() },
            PackageEntry { name: "ripgrep".into(), version: "14".into() },
        ],
    };
    d.sign(sk);
    serde_json::to_vec(&d).unwrap()
}

fn hashes() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("curl@8".to_string(), "aa".repeat(32));
    m.insert("ripgrep@14".to_string(), "bb".repeat(32));
    m
}

#[test]
fn migrates_valid_v1_to_unsigned_v2_with_sequence_zero() {
    let sk = key();
    let v2 = migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &hashes(), NOW).unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(v2.sequence, 0);
    assert_eq!(v2.signature_hex, "");
    assert_eq!(v2.entries.len(), 2);
    assert_eq!(v2.entries[0].sha256, "aa".repeat(32));
    // The v1 signature is not carried over.
    assert_eq!(verify_v2(&v2, 200, None).unwrap_err(), V2Error::SignatureInvalid);
    let trusted_ring = trusted(&sk);
    assert!(verify_v2_trusted(&v2, &trusted_ring, 200, None).is_err());
}

#[test]
fn migrated_document_verifies_only_after_fresh_signing() {
    let sk = key();
    let mut v2 = migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &hashes(), NOW).unwrap();
    v2.signature_hex = hex::encode(sk.sign(&canonical_payload_bytes(&v2).unwrap()).to_bytes());
    assert!(verify_v2_trusted(&v2, &trusted(&sk), 200, None).is_ok());
    // And it round-trips through the strict runtime parser.
    let bytes = serde_json::to_vec(&v2).unwrap();
    assert!(parse_v2(&bytes).is_ok());
}

#[test]
fn missing_hashes_fail_and_list_every_missing_entry() {
    let sk = key();
    let r = migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &BTreeMap::new(), NOW);
    assert_eq!(
        r.unwrap_err(),
        MigrateError::MissingHashes(vec!["curl@8".into(), "ripgrep@14".into()])
    );
    let mut partial = hashes();
    partial.remove("ripgrep@14");
    assert_eq!(
        migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &partial, NOW).unwrap_err(),
        MigrateError::MissingHashes(vec!["ripgrep@14".into()])
    );
}

#[test]
fn hash_map_format_is_validated() {
    assert!(parse_sha256_map(br#"{"curl@8":"abc"}"#).is_err());
    assert!(parse_sha256_map(format!(r#"{{"curl@8":"{}"}}"#, "AA".repeat(32)).as_bytes()).is_err());
    assert!(parse_sha256_map(br#"["x"]"#).is_err());
    assert!(parse_sha256_map(format!(r#"{{"curl@8":"{}"}}"#, "aa".repeat(32)).as_bytes()).is_ok());
}

#[test]
fn untrusted_or_wrong_key_is_rejected() {
    let sk = key();
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let r = migrate_text_v1(&v1_bytes(&sk), &trusted(&other), &hashes(), NOW);
    assert!(matches!(r, Err(MigrateError::Legacy(_))), "{r:?}");
    let r = migrate_text_v1(&v1_bytes(&sk), &Keyring { keys: vec![] }, &hashes(), NOW);
    assert!(matches!(r, Err(MigrateError::Legacy(_))), "{r:?}");
}

#[test]
fn tampered_or_expired_v1_is_rejected() {
    let sk = key();
    let mut d: AllowlistDoc = serde_json::from_slice(&v1_bytes(&sk)).unwrap();
    d.packages.push(PackageEntry { name: "evil".into(), version: "1".into() });
    let tampered = serde_json::to_vec(&d).unwrap();
    let mut h = hashes();
    h.insert("evil@1".into(), "cc".repeat(32));
    assert!(matches!(
        migrate_text_v1(&tampered, &trusted(&sk), &h, NOW),
        Err(MigrateError::Legacy(_))
    ));
    assert!(matches!(
        migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &hashes(), 500),
        Err(MigrateError::Legacy(_))
    ));
    assert!(matches!(
        migrate_text_v1(&v1_bytes(&sk), &trusted(&sk), &hashes(), 50),
        Err(MigrateError::Legacy(_))
    ));
}

#[test]
fn json_shapes_with_version_key_are_rejected_for_migration() {
    let sk = key();
    // Signing-module JSON shape.
    let b = br#"{"version":1,"issued_at":1,"expires_at":9,"key_id":"k","entries":[{"name":"a","publisher":"p","sha256":"00"}],"signature":"AA=="}"#;
    assert!(matches!(migrate_text_v1(b, &trusted(&sk), &hashes(), NOW), Err(MigrateError::NotTextV1(_))));
    // parse_any-style JSON v1 shape.
    let c = br#"{"version":1,"issued_at":1,"expires_at":9,"key_id":"k","entries":[],"signature":"00"}"#;
    assert!(matches!(migrate_text_v1(c, &trusted(&sk), &hashes(), NOW), Err(MigrateError::NotTextV1(_))));
    // A v2 document is not v1 input either.
    let v2 = br#"{"format":"passaura-allowlist","version":2}"#;
    assert!(matches!(migrate_text_v1(v2, &trusted(&sk), &hashes(), NOW), Err(MigrateError::NotTextV1(_))));
    // Valid text-v1 plus an injected version key is refused (signature irrelevant).
    let mut v: serde_json::Value = serde_json::from_slice(&v1_bytes(&sk)).unwrap();
    v["version"] = serde_json::json!(1);
    let injected = serde_json::to_vec(&v).unwrap();
    assert!(matches!(migrate_text_v1(&injected, &trusted(&sk), &hashes(), NOW), Err(MigrateError::NotTextV1(_))));
}

#[test]
fn key_with_mismatched_id_is_rejected() {
    let sk = key();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let mut d = AllowlistDoc {
        signed_by: "ed25519:custom-name".into(),
        signature_hex: String::new(),
        issued_at: 100,
        expires_at: 500,
        packages: vec![PackageEntry { name: "curl".into(), version: "8".into() }],
    };
    d.sign(&sk);
    let kr = Keyring { keys: vec![KeyEntry { key_id: "ed25519:custom-name".into(), public_key_hex: pk }] };
    let mut h = BTreeMap::new();
    h.insert("curl@8".to_string(), "aa".repeat(32));
    assert!(matches!(
        migrate_text_v1(&serde_json::to_vec(&d).unwrap(), &kr, &h, NOW),
        Err(MigrateError::KeyIdMismatch(_))
    ));
}

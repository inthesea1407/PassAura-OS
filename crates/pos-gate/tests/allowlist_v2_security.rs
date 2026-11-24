use pos_gate::allowlist_v2::{
    parse_any, verify_v2, V2Allowlist, V2Entry, V2Key, V2Keyring,
    V2Error, canonical_payload_bytes, derive_key_id,
};
use ed25519_dalek::{Signer, SigningKey};
use std::sync::atomic::{AtomicU8, Ordering};

static SEED: AtomicU8 = AtomicU8::new(50);

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(
        &[SEED.fetch_add(1, Ordering::SeqCst); 32]
    )
}

fn sample(sk: &SigningKey, sequence: u64) -> V2Allowlist {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let key_id = derive_key_id(&pk);

    V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence,
        issued_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        signed_by: key_id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id,
                public_key_hex: pk,
                valid_from: 0,
                valid_until: 1_700_086_400,
                retired: false,
            }],
        },
        entries: vec![V2Entry {
            name: "ripgrep".into(),
            version: Some("14.1.0".into()),
            sha256: "a".repeat(64),
        }],
        signature_hex: String::new(),
    }
}

fn sign(doc: &mut V2Allowlist, sk: &SigningKey) {
    let payload = canonical_payload_bytes(doc).unwrap();
    doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
}

#[test]
fn duplicate_json_keys_must_be_rejected() {
    let bytes = br#"{
        "version": 2,
        "version": 1
    }"#;

    assert!(
        parse_any(bytes).is_err(),
        "duplicate JSON keys must not be silently accepted"
    );
}

#[test]
fn unsigned_downgrade_candidate_must_not_trigger_sequence_decision() {
    let sk = signing_key();
    let doc = sample(&sk, 1);

    // Deliberately leave the document unsigned.
    let result = verify_v2(
        &doc,
        1_700_000_100,
        Some((10, "stored-digest")),
    );

    assert!(
        matches!(result, Err(V2Error::SignatureInvalid)),
        "sequence decisions should not be made from unauthenticated content"
    );
}

#[test]
fn duplicate_signing_key_ids_must_be_rejected() {
    let sk = signing_key();
    let mut doc = sample(&sk, 1);
    sign(&mut doc, &sk);

    let duplicate = doc.keyring.keys[0].clone();
    doc.keyring.keys.push(duplicate);

    // Re-sign so this is a keyring-validation test rather than a
    // signature-tampering test.
    sign(&mut doc, &sk);

    assert!(
        verify_v2(&doc, 1_700_000_100, None).is_err(),
        "duplicate key IDs should be rejected"
    );
}

#[test]
fn invalid_key_validity_window_must_be_rejected() {
    let sk = signing_key();
    let mut doc = sample(&sk, 1);

    doc.keyring.keys[0].valid_from = 100;
    doc.keyring.keys[0].valid_until = 50;

    sign(&mut doc, &sk);

    assert!(
        verify_v2(&doc, 1_700_000_100, None).is_err(),
        "invalid key validity windows must be rejected"
    );
}

#[test]
fn unsigned_candidate_does_not_reveal_sequence_state_and_signed_downgrade_still_rejected() {
    let sk = signing_key();
    let mut doc = sample(&sk, 1);
    sign(&mut doc, &sk);
    assert!(matches!(
        verify_v2(&doc, 1_700_000_100, Some((10, "x"))),
        Err(V2Error::DowngradeRejected { .. })
    ));
}

#[test]
fn non_canonical_signature_is_rejected() {
    // ed25519 s + L is a valid-looking but non-canonical encoding.
    let sk = signing_key();
    let mut doc = sample(&sk, 1);
    sign(&mut doc, &sk);
    let mut sig = hex::decode(&doc.signature_hex).unwrap();
    // L = 2^252 + 27742317777372353535851937790883648493 (little endian)
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + l[i] as u16 + carry;
        sig[32 + i] = v as u8;
        carry = v >> 8;
    }
    doc.signature_hex = hex::encode(sig);
    assert!(verify_v2(&doc, 1_700_000_100, None).is_err());
}

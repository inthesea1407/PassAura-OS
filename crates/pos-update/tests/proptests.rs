//! Property tests (proptest). Test-only keys, never real ones.
use ed25519_dalek::{Signer, SigningKey};
use pos_update::*;
use proptest::prelude::*;

const NOW: u64 = 1_000_000;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn tkey(id: &str, seed: u8) -> TrustedKey {
    TrustedKey {
        key_id: id.into(),
        public_key: sk(seed).verifying_key().to_bytes(),
        valid_from: 0,
        valid_until: u64::MAX,
        retired: false,
    }
}
fn keys() -> Vec<TrustedKey> {
    vec![tkey("a", 1), tkey("b", 2), tkey("c", 3)]
}
fn sign(m: &Manifest) -> Vec<u8> {
    let msg = signed_bytes(m).unwrap();
    let signatures = [("a", 1u8), ("b", 2u8)]
        .iter()
        .map(|(id, seed)| SignatureEntry {
            key_id: (*id).into(),
            sig_hex: hex::encode(sk(*seed).sign(&msg).to_bytes()),
        })
        .collect();
    serde_json::to_vec(&Envelope {
        manifest: m.clone(),
        signatures,
    })
    .unwrap()
}

fn artifact() -> impl Strategy<Value = Artifact> {
    (
        "[A-Za-z0-9][A-Za-z0-9._-]{0,20}",
        ".{0,12}",
        "[0-9a-f]{64}",
        any::<u64>(),
    )
        .prop_map(|(name, version, sha256, size)| Artifact {
            name,
            version,
            sha256,
            size,
        })
}

fn manifest() -> impl Strategy<Value = Manifest> {
    (
        any::<u64>(),
        1u64..5000,
        proptest::collection::vec(artifact(), 1..4),
    )
        .prop_map(|(sequence, span, artifacts)| {
            // unique names
            let artifacts = artifacts
                .into_iter()
                .enumerate()
                .map(|(i, mut a)| {
                    a.name = format!("{}-{i}", a.name);
                    a
                })
                .collect();
            Manifest {
                format: FORMAT.into(),
                channel: "stable".into(),
                sequence,
                issued_at: NOW - span.min(NOW - 1),
                expires_at: NOW + 1000,
                artifacts,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any well-formed manifest signed by two trusted keys verifies and returns the same manifest.
    #[test]
    fn valid_signed_manifests_roundtrip(m in manifest()) {
        let k = keys();
        let v = verify_envelope(&sign(&m), &VerifyPolicy::new(&k, 2, NOW, "stable"), None).unwrap();
        prop_assert_eq!(v.manifest, m.clone());
        prop_assert_eq!(v.state.sequence, m.sequence);
    }

    /// Arbitrary bytes never panic and are never accepted.
    #[test]
    fn arbitrary_bytes_are_rejected(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let k = keys();
        prop_assert!(verify_envelope(&b, &VerifyPolicy::new(&k, 2, NOW, "stable"), None).is_err());
    }

    /// Changing any single byte of a valid envelope never yields an envelope with different content that verifies.
    #[test]
    fn single_byte_changes_never_verify_other_content(m in manifest(), idx in any::<usize>(), x in 1u8..=255) {
        let k = keys();
        let mut b = sign(&m);
        let i = idx % b.len();
        b[i] ^= x;
        if let Ok(v) = verify_envelope(&b, &VerifyPolicy::new(&k, 2, NOW, "stable"), None) {
            // Only allowed outcome: the change did not alter the signed manifest (e.g. whitespace-free
            // JSON offers none, so this is expected to be unreachable; if it is reached, content must be equal).
            prop_assert_eq!(v.manifest, m);
        }
    }

    /// Rollback logic: for accepted state `s` and a manifest with sequence `q`,
    /// q < s is Rollback, q == s with a different digest is Fork, q > s is accepted.
    #[test]
    fn rollback_order(s in any::<u64>(), q in any::<u64>(), m in manifest()) {
        let k = keys();
        let mut m = m;
        m.sequence = q;
        let prev = AcceptedState { channel: "stable".into(), sequence: s, digest: [7u8; 32] };
        let r = verify_envelope(&sign(&m), &VerifyPolicy::new(&k, 2, NOW, "stable"), Some(&prev));
        if q < s {
            prop_assert_eq!(r.unwrap_err(), UpdateError::Rollback);
        } else if q == s {
            prop_assert_eq!(r.unwrap_err(), UpdateError::Fork);
        } else {
            prop_assert!(r.is_ok());
        }
    }

    /// A manifest is never accepted for any channel other than the expected one.
    #[test]
    fn wrong_channel_never_accepted(m in manifest(), ch in "[a-z]{1,10}") {
        prop_assume!(ch != "stable");
        let k = keys();
        prop_assert_eq!(verify_envelope(&sign(&m), &VerifyPolicy::new(&k, 2, NOW, &ch), None).unwrap_err(), UpdateError::WrongChannel);
    }
}

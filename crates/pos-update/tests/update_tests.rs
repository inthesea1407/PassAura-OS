//! Test-only keys: deterministic seeds generated here, never real keys.
use ed25519_dalek::{Signer, SigningKey};
use pos_update::*;

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
fn manifest(seq: u64) -> Manifest {
    Manifest {
        format: FORMAT.into(),
        channel: "stable".into(),
        sequence: seq,
        issued_at: NOW - 10,
        expires_at: NOW + 1000,
        artifacts: vec![Artifact {
            name: "pos-cli".into(),
            version: "1.2.3-label".into(),
            sha256: "ab".repeat(32),
            size: 42,
        }],
    }
}
fn sign(m: &Manifest, signers: &[(&str, u8)]) -> Vec<u8> {
    let msg = signed_bytes(m).unwrap();
    let signatures = signers
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
fn ok2(m: &Manifest) -> Vec<u8> {
    sign(m, &[("a", 1), ("b", 2)])
}
fn pol(k: &[TrustedKey], t: usize) -> VerifyPolicy<'_> {
    VerifyPolicy::new(k, t, NOW, "stable")
}

#[test]
fn accepts_threshold_and_is_deterministic() {
    let k = keys();
    let v = verify_envelope(&ok2(&manifest(5)), &pol(&k, 2), None).unwrap();
    assert_eq!(v.state.sequence, 5);
    assert!(!v.idempotent);
    assert_eq!(v.state.digest, manifest_digest(&manifest(5)).unwrap());
}

#[test]
fn signed_bytes_have_prefix_and_sorted_keys() {
    let b = signed_bytes(&manifest(1)).unwrap();
    assert!(b.starts_with(b"pos-update-manifest-v1\n{\"artifacts\":"));
    let s = String::from_utf8(b).unwrap();
    assert!(s.find("\"channel\"").unwrap() < s.find("\"expires_at\"").unwrap());
    assert!(s.find("\"issued_at\"").unwrap() < s.find("\"sequence\"").unwrap());
    assert!(!s.contains("signatures"));
}

#[test]
fn threshold_edges() {
    let k = keys();
    let one = sign(&manifest(1), &[("a", 1)]);
    assert_eq!(
        verify_envelope(&one, &pol(&k, 2), None),
        Err(UpdateError::ThresholdNotMet)
    );
    assert!(verify_envelope(&one, &pol(&k, 1), None).is_ok());
    assert_eq!(
        verify_envelope(&one, &pol(&k, 0), None),
        Err(UpdateError::BadThreshold)
    );
    assert_eq!(
        verify_envelope(&one, &pol(&k, 4), None),
        Err(UpdateError::BadThreshold)
    );
    let none = sign(&manifest(1), &[]);
    assert_eq!(
        verify_envelope(&none, &pol(&k, 1), None),
        Err(UpdateError::ThresholdNotMet)
    );
}

#[test]
fn duplicate_signer_id_rejected() {
    let k = keys();
    let d = sign(&manifest(1), &[("a", 1), ("a", 1)]);
    assert_eq!(
        verify_envelope(&d, &pol(&k, 2), None),
        Err(UpdateError::DuplicateSignerId)
    );
}

#[test]
fn same_public_key_under_two_ids_is_bad_keyset() {
    let mut k = keys();
    k.push(tkey("a2", 1));
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::BadKeySet)
    );
    let mut k = keys();
    k.push(tkey("a", 9));
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::BadKeySet)
    );
}

#[test]
fn unknown_retired_and_out_of_window_not_counted() {
    let mut k = keys();
    let e = sign(&manifest(1), &[("a", 1), ("zz", 7)]);
    assert_eq!(
        verify_envelope(&e, &pol(&k, 2), None),
        Err(UpdateError::ThresholdNotMet)
    );
    k[1].retired = true;
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::ThresholdNotMet)
    );
    k[1].retired = false;
    k[1].valid_until = NOW; // now >= valid_until
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::ThresholdNotMet)
    );
    k[1].valid_until = u64::MAX;
    k[1].valid_from = NOW + 1;
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::ThresholdNotMet)
    );
    k[1].valid_from = NOW; // boundary: valid
    assert!(verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None).is_ok());
}

#[test]
fn bad_signature_from_trusted_key_rejects_whole_even_if_threshold_met() {
    let k = keys();
    // c signs with the wrong key; a, b, would already meet threshold 2.
    let e = sign(&manifest(1), &[("a", 1), ("b", 2), ("c", 99)]);
    assert_eq!(
        verify_envelope(&e, &pol(&k, 2), None),
        Err(UpdateError::BadSignature)
    );
}

#[test]
fn signature_over_other_manifest_or_uppercase_hex_rejected() {
    let k = keys();
    let mut env: Envelope = serde_json::from_slice(&ok2(&manifest(1))).unwrap();
    env.signatures[0].sig_hex = env.signatures[0].sig_hex.to_uppercase();
    let b = serde_json::to_vec(&env).unwrap();
    assert_eq!(
        verify_envelope(&b, &pol(&k, 2), None),
        Err(UpdateError::BadSignature)
    );
    let mut env: Envelope = serde_json::from_slice(&ok2(&manifest(1))).unwrap();
    env.manifest.sequence = 2;
    let b = serde_json::to_vec(&env).unwrap();
    assert_eq!(
        verify_envelope(&b, &pol(&k, 2), None),
        Err(UpdateError::BadSignature)
    );
}

#[test]
fn time_edges() {
    let k = keys();
    let mut m = manifest(1);
    m.issued_at = NOW; // == now: ok
    assert!(verify_envelope(&ok2(&m), &pol(&k, 2), None).is_ok());
    m.issued_at = NOW + 1;
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::IssuedInFuture)
    );
    let mut p = pol(&k, 2);
    p.skew_secs = 1;
    assert!(verify_envelope(&ok2(&m), &p, None).is_ok());
    p.skew_secs = 0;
    let mut m = manifest(1);
    m.expires_at = NOW; // now >= expires_at
    assert_eq!(
        verify_envelope(&ok2(&m), &p, None),
        Err(UpdateError::Expired)
    );
    m.expires_at = NOW + 1;
    assert!(verify_envelope(&ok2(&m), &p, None).is_ok());
    m.expires_at = m.issued_at; // not after issued_at
    assert_eq!(
        verify_envelope(&ok2(&m), &p, None),
        Err(UpdateError::InconsistentTimes)
    );
}

#[test]
fn max_validity_default_90_days_and_explicit_disable() {
    let k = keys();
    let day = 86_400u64;
    let mut m = manifest(1);
    m.issued_at = NOW - 10;
    m.expires_at = m.issued_at + 90 * day;
    assert!(verify_envelope(&ok2(&m), &pol(&k, 2), None).is_ok());
    m.expires_at += 1;
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::ValidityTooLong)
    );
    let mut p = pol(&k, 2);
    p.max_validity = MaxValidity::Disabled;
    assert!(verify_envelope(&ok2(&m), &p, None).is_ok());
    p.max_validity = MaxValidity::Secs(10);
    assert_eq!(
        verify_envelope(&ok2(&m), &p, None),
        Err(UpdateError::ValidityTooLong)
    );
}

#[test]
fn overflow_is_checked() {
    let k = keys();
    let mut p = VerifyPolicy::new(&k, 2, u64::MAX, "stable");
    p.skew_secs = 5;
    let mut m = manifest(1);
    m.issued_at = 1;
    m.expires_at = u64::MAX;
    p.max_validity = MaxValidity::Disabled;
    // now + skew overflows: rejected, no panic
    assert_eq!(
        verify_envelope(&ok2(&m), &p, None),
        Err(UpdateError::IssuedInFuture)
    );
    // max u64 times everywhere: expired, no panic
    p.skew_secs = 0;
    assert_eq!(
        verify_envelope(&ok2(&m), &p, None),
        Err(UpdateError::Expired)
    );
}

#[test]
fn rollback_matrix() {
    let k = keys();
    let v5 = verify_envelope(&ok2(&manifest(5)), &pol(&k, 2), None).unwrap();
    let prev = v5.state;
    // same sequence, same digest: idempotent
    let again = verify_envelope(&ok2(&manifest(5)), &pol(&k, 2), Some(&prev)).unwrap();
    assert!(again.idempotent);
    // same sequence, different content: fork
    let mut other = manifest(5);
    other.artifacts[0].size = 43;
    assert_eq!(
        verify_envelope(&ok2(&other), &pol(&k, 2), Some(&prev)),
        Err(UpdateError::Fork)
    );
    // lower: rollback
    assert_eq!(
        verify_envelope(&ok2(&manifest(4)), &pol(&k, 2), Some(&prev)),
        Err(UpdateError::Rollback)
    );
    // higher: ok
    let up = verify_envelope(&ok2(&manifest(6)), &pol(&k, 2), Some(&prev)).unwrap();
    assert!(!up.idempotent);
    assert_eq!(up.state.sequence, 6);
    // no state (state loss) resets the counter: documented limitation
    assert!(verify_envelope(&ok2(&manifest(4)), &pol(&k, 2), None).is_ok());
    // a failed verification never yields a state
    assert!(verify_envelope(&sign(&manifest(9), &[("a", 1)]), &pol(&k, 2), Some(&prev)).is_err());
}

#[test]
fn artifact_downgrade_is_not_checked() {
    // Documented non-goal: a higher sequence may carry a lower-labelled artifact.
    let k = keys();
    let v5 = verify_envelope(&ok2(&manifest(5)), &pol(&k, 2), None).unwrap();
    let mut m6 = manifest(6);
    m6.artifacts[0].version = "0.0.1-older".into();
    assert!(verify_envelope(&ok2(&m6), &pol(&k, 2), Some(&v5.state)).is_ok());
}

#[test]
fn rejects_unknown_and_duplicate_fields_and_bad_input() {
    let k = keys();
    let good = String::from_utf8(ok2(&manifest(1))).unwrap();
    let unk = good.replacen("\"channel\"", "\"extra\":1,\"channel\"", 1);
    assert_eq!(
        verify_envelope(unk.as_bytes(), &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
    let dup = good.replacen(
        "\"channel\":\"stable\"",
        "\"channel\":\"stable\",\"channel\":\"stable\"",
        1,
    );
    assert_ne!(dup, good);
    assert_eq!(
        verify_envelope(dup.as_bytes(), &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
    let trailing = format!("{good} x");
    assert_eq!(
        verify_envelope(trailing.as_bytes(), &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
    for junk in [&b""[..], b"{}", b"null", b"\xff\xfe", b"[1]"] {
        assert_eq!(
            verify_envelope(junk, &pol(&k, 2), None),
            Err(UpdateError::Malformed)
        );
    }
}

#[test]
fn manifest_field_validation() {
    let k = keys();
    let mut m = manifest(1);
    m.format = "other".into();
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::BadFormat)
    );
    let mut m = manifest(1);
    m.artifacts[0].sha256 = "AB".repeat(32);
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::BadManifestField)
    );
    let mut m = manifest(1);
    m.artifacts.push(m.artifacts[0].clone());
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::BadManifestField)
    );
    let mut m = manifest(1);
    m.artifacts.clear();
    assert_eq!(
        verify_envelope(&ok2(&m), &pol(&k, 2), None),
        Err(UpdateError::BadManifestField)
    );
}

#[test]
fn size_cap_exact() {
    let k = keys();
    let big = vec![b' '; MAX_ENVELOPE_BYTES + 1];
    assert_eq!(
        verify_envelope(&big, &pol(&k, 2), None),
        Err(UpdateError::TooLarge)
    );
    let at = vec![b' '; MAX_ENVELOPE_BYTES];
    assert_eq!(
        verify_envelope(&at, &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
}

#[test]
fn every_byte_tamper_is_rejected() {
    let k = keys();
    let good = ok2(&manifest(3));
    assert!(verify_envelope(&good, &pol(&k, 2), None).is_ok());
    for i in 0..good.len() {
        for mask in [0x01u8, 0x20, 0x80] {
            let mut b = good.clone();
            b[i] ^= mask;
            assert!(
                verify_envelope(&b, &pol(&k, 2), None).is_err(),
                "tamper at byte {i} mask {mask:#x} accepted"
            );
        }
    }
    for cut in 0..good.len() {
        assert!(verify_envelope(&good[..cut], &pol(&k, 2), None).is_err());
    }
}

#[test]
fn file_roundtrip_and_state_handoff() {
    let k = keys();
    let dir = tempfile::tempdir().unwrap();
    let f1 = dir.path().join("m1.json");
    let f2 = dir.path().join("m2.json");
    std::fs::write(&f1, ok2(&manifest(1))).unwrap();
    std::fs::write(&f2, ok2(&manifest(2))).unwrap();
    let v1 = verify_envelope(&std::fs::read(&f1).unwrap(), &pol(&k, 2), None).unwrap();
    let v2 = verify_envelope(&std::fs::read(&f2).unwrap(), &pol(&k, 2), Some(&v1.state)).unwrap();
    assert_eq!(v2.state.sequence, 2);
    assert_eq!(
        verify_envelope(&std::fs::read(&f1).unwrap(), &pol(&k, 2), Some(&v2.state)),
        Err(UpdateError::Rollback)
    );
    // truncated file on disk
    let t = std::fs::read(&f2).unwrap();
    std::fs::write(&f2, &t[..t.len() / 2]).unwrap();
    assert!(verify_envelope(&std::fs::read(&f2).unwrap(), &pol(&k, 2), None).is_err());
}

#[test]
fn bad_keyset_entries() {
    let mut k = keys();
    k[0].valid_from = 10;
    k[0].valid_until = 5;
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::BadKeySet)
    );
    let mut k = keys();
    k[0].key_id = String::new();
    assert_eq!(
        verify_envelope(&ok2(&manifest(1)), &pol(&k, 2), None),
        Err(UpdateError::BadKeySet)
    );
}

fn mk_chan(seq: u64, chan: &str) -> Manifest {
    let mut m = manifest(seq);
    m.channel = chan.into();
    m
}

#[test]
fn wrong_channel_rejected_before_signatures() {
    let k = keys();
    let e = ok2(&mk_chan(1, "beta"));
    assert_eq!(
        verify_envelope(&e, &pol(&k, 2), None),
        Err(UpdateError::WrongChannel)
    );
    // validly signed, but also garbage signature from an active key: channel error wins
    let bad = sign(&mk_chan(1, "beta"), &[("a", 99)]);
    assert_eq!(
        verify_envelope(&bad, &pol(&k, 2), None),
        Err(UpdateError::WrongChannel)
    );
    let p = VerifyPolicy::new(&k, 2, NOW, "beta");
    assert!(verify_envelope(&e, &p, None).is_ok());
}

#[test]
fn state_is_per_channel() {
    let k = keys();
    let a = verify_envelope(&ok2(&manifest(9)), &pol(&k, 2), None).unwrap();
    assert_eq!(a.state.channel, "stable");
    let pb = VerifyPolicy::new(&k, 2, NOW, "beta");
    let b_env = ok2(&mk_chan(1, "beta"));
    // A's state does not constrain B and is not silently ignored
    assert_eq!(
        verify_envelope(&b_env, &pb, Some(&a.state)),
        Err(UpdateError::StateChannelMismatch)
    );
    // caller passes None for a first-seen channel: seq 1 is fine although A is at 9
    let b = verify_envelope(&b_env, &pb, None).unwrap();
    assert_eq!(b.state.channel, "beta");
    assert!(
        verify_envelope(&ok2(&mk_chan(1, "beta")), &pb, Some(&b.state))
            .unwrap()
            .idempotent
    );
    // state for stable still works for stable
    assert_eq!(
        verify_envelope(&ok2(&manifest(8)), &pol(&k, 2), Some(&a.state)),
        Err(UpdateError::Rollback)
    );
}

#[test]
fn invalid_expected_channel_is_bad_policy_channel() {
    let k = keys();
    for c in ["", ".", "..", ".x", "a/b", "a b", "é", &"x".repeat(65)] {
        let p = VerifyPolicy::new(&k, 2, NOW, c);
        assert_eq!(
            verify_envelope(&ok2(&manifest(1)), &p, None),
            Err(UpdateError::BadPolicyChannel),
            "{c:?}"
        );
    }
}

#[test]
fn channel_and_name_and_count_limits() {
    let k = keys();
    for (c, good) in [
        ("a", true),
        ("A-z_0.9", true),
        (&"x".repeat(64)[..], true),
        (&"x".repeat(65)[..], false),
        ("", false),
        (".", false),
        ("..", false),
        (".hid", false),
        ("a/b", false),
        ("a b", false),
        ("é", false),
        ("a\nb", false),
    ] {
        let m = mk_chan(1, c);
        let p = VerifyPolicy::new(&k, 2, NOW, c);
        let r = verify_envelope(&ok2(&m), &p, None);
        if good {
            // the policy itself must be valid for the expected channel
            assert!(r.is_ok(), "{c:?} {r:?}");
        } else {
            assert_eq!(r, Err(UpdateError::BadManifestField), "{c:?}");
        }
    }
    for (n, good) in [
        ("a", true),
        ("pos-cli_1.2.tar.gz", true),
        (&"n".repeat(128)[..], true),
        (&"n".repeat(129)[..], false),
        ("", false),
        (".", false),
        ("..", false),
        (".hidden", false),
        ("a/b", false),
        ("a b", false),
        ("é", false),
        ("a\u{0}b", false),
    ] {
        let mut m = manifest(1);
        m.artifacts[0].name = n.into();
        let r = verify_envelope(&ok2(&m), &pol(&k, 2), None);
        if good {
            assert!(r.is_ok(), "{n:?} {r:?}");
        } else {
            assert_eq!(r, Err(UpdateError::BadManifestField), "{n:?}");
        }
    }
    let many = |n: usize| {
        let mut m = manifest(1);
        m.artifacts = (0..n)
            .map(|i| Artifact {
                name: format!("f{i}"),
                version: "v".into(),
                sha256: "cd".repeat(32),
                size: 1,
            })
            .collect();
        m
    };
    assert!(verify_envelope(&ok2(&many(1024)), &pol(&k, 2), None).is_ok());
    assert_eq!(
        verify_envelope(&ok2(&many(1025)), &pol(&k, 2), None),
        Err(UpdateError::BadManifestField)
    );
}

#[test]
fn signature_count_cap_boundary() {
    let k = keys();
    let m = manifest(1);
    let msg = signed_bytes(&m).unwrap();
    let mk = |extra: usize| {
        let mut sigs = vec![
            SignatureEntry {
                key_id: "a".into(),
                sig_hex: hex::encode(sk(1).sign(&msg).to_bytes()),
            },
            SignatureEntry {
                key_id: "b".into(),
                sig_hex: hex::encode(sk(2).sign(&msg).to_bytes()),
            },
        ];
        for i in 0..extra {
            sigs.push(SignatureEntry {
                key_id: format!("unknown{i}"),
                sig_hex: "00".repeat(64),
            });
        }
        serde_json::to_vec(&Envelope {
            manifest: m.clone(),
            signatures: sigs,
        })
        .unwrap()
    };
    assert!(verify_envelope(&mk(254), &pol(&k, 2), None).is_ok()); // exactly 256 entries
    assert_eq!(
        verify_envelope(&mk(255), &pol(&k, 2), None),
        Err(UpdateError::TooManySignatures)
    ); // 257
}

#[test]
fn inactive_known_key_garbage_ignored_active_garbage_rejects() {
    let mut k = keys();
    let m = manifest(1);
    let msg = signed_bytes(&m).unwrap();
    let good = |id: &str, seed: u8| SignatureEntry {
        key_id: id.into(),
        sig_hex: hex::encode(sk(seed).sign(&msg).to_bytes()),
    };
    let garbage = |id: &str| SignatureEntry {
        key_id: id.into(),
        sig_hex: "zz".into(),
    };
    let enc = |s: Vec<SignatureEntry>| {
        serde_json::to_vec(&Envelope {
            manifest: m.clone(),
            signatures: s,
        })
        .unwrap()
    };
    k[2].retired = true;
    assert!(verify_envelope(
        &enc(vec![good("a", 1), good("b", 2), garbage("c")]),
        &pol(&k, 2),
        None
    )
    .is_ok());
    k[2].retired = false;
    k[2].valid_until = NOW; // out of window
    assert!(verify_envelope(
        &enc(vec![good("a", 1), good("b", 2), garbage("c")]),
        &pol(&k, 2),
        None
    )
    .is_ok());
    k[2].valid_until = u64::MAX;
    assert_eq!(
        verify_envelope(
            &enc(vec![good("a", 1), good("b", 2), garbage("c")]),
            &pol(&k, 2),
            None
        ),
        Err(UpdateError::BadSignature)
    );
}

#[test]
fn valid_manifest_at_exact_size_cap_and_one_over() {
    let k = keys();
    let build = |pad: usize| {
        let mut m = manifest(1);
        m.artifacts[0].version = "v".repeat(pad);
        ok2(&m)
    };
    let base = build(0).len();
    let at = build(MAX_ENVELOPE_BYTES - base);
    assert_eq!(at.len(), MAX_ENVELOPE_BYTES);
    assert!(verify_envelope(&at, &pol(&k, 2), None).is_ok());
    let over = build(MAX_ENVELOPE_BYTES - base + 1);
    assert_eq!(over.len(), MAX_ENVELOPE_BYTES + 1);
    assert_eq!(
        verify_envelope(&over, &pol(&k, 2), None),
        Err(UpdateError::TooLarge)
    );
}

#[test]
fn deeply_nested_json_is_malformed_not_a_crash() {
    let k = keys();
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(
        verify_envelope(deep.as_bytes(), &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
    let deep_obj = format!("{{\"manifest\":{}{}", "{\"a\":".repeat(50_000), "1");
    assert_eq!(
        verify_envelope(deep_obj.as_bytes(), &pol(&k, 2), None),
        Err(UpdateError::Malformed)
    );
}

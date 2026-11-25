use pos_crypto_suites::aead::{open, seal, Suite};
use pos_crypto_suites::argon::{derive_key, ArgonParams, Tier, FLOOR_M_KIB};
use pos_crypto_suites::hybrid::{self, HybridSecret};
use pos_crypto_suites::CryptoError;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
const DEK: [u8; 32] = [7u8; 32];

#[test]
fn x25519_rfc7748_vector() {
    let k: [u8; 32] = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        .try_into()
        .unwrap();
    let u: [u8; 32] = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        .try_into()
        .unwrap();
    let out = x25519_dalek::x25519(k, u);
    assert_eq!(
        out.to_vec(),
        hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );
}

#[test]
fn hkdf_rfc5869_case1() {
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha256>::new(Some(&hex("000102030405060708090a0b0c")), &[0x0b; 22]);
    let mut okm = [0u8; 42];
    hk.expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn roundtrip_each_suite() {
    for s in [Suite::V1, Suite::L1] {
        for pt in [&b""[..], b"x", &[0xAB; 5000][..]] {
            let b = seal(s, &DEK, b"hdr", pt).unwrap();
            assert_eq!(open(s, &DEK, b"hdr", &b).unwrap(), pt);
        }
    }
}

#[test]
fn nonces_are_fresh() {
    let a = seal(Suite::L1, &DEK, b"", b"same").unwrap();
    let b = seal(Suite::L1, &DEK, b"", b"same").unwrap();
    assert_ne!(a, b);
}

#[test]
fn every_bit_flip_is_rejected() {
    for s in [Suite::V1, Suite::L1] {
        let b = seal(s, &DEK, b"hdr", b"secret data").unwrap();
        for i in 0..b.len() {
            let mut t = b.clone();
            t[i] ^= 1;
            assert!(
                open(s, &DEK, b"hdr", &t).is_err(),
                "suite {:?} byte {}",
                s,
                i
            );
        }
        assert!(open(s, &DEK, b"hdr", &b[..b.len() - 1]).is_err());
        assert!(open(s, &DEK, b"hdr", &[]).is_err());
    }
}

#[test]
fn wrong_aad_or_key_rejected() {
    for s in [Suite::V1, Suite::L1] {
        let b = seal(s, &DEK, b"hdr", b"p").unwrap();
        assert!(open(s, &DEK, b"hdR", &b).is_err());
        assert!(open(s, &[8u8; 32], b"hdr", &b).is_err());
    }
}

#[test]
fn downgrade_and_upgrade_rejected() {
    let l1 = seal(Suite::L1, &DEK, b"h", b"p").unwrap();
    assert!(open(Suite::V1, &DEK, b"h", &l1).is_err());
    let v1 = seal(Suite::V1, &DEK, b"h", b"p").unwrap();
    assert!(open(Suite::L1, &DEK, b"h", &v1).is_err());
    // relabel the suite byte: still rejected
    let mut forged = l1.clone();
    forged[0] = Suite::V1.id();
    assert!(open(Suite::V1, &DEK, b"h", &forged).is_err());
}

#[test]
fn suite_ids() {
    assert_eq!(Suite::from_id(1), Some(Suite::V1));
    assert_eq!(Suite::from_id(2), Some(Suite::L1));
    assert_eq!(Suite::from_id(0), None);
    assert_eq!(Suite::from_id(255), None);
}

#[test]
fn hybrid_roundtrip_and_keys_serialize() {
    let (sk, pk) = hybrid::generate().unwrap();
    assert_eq!(pk.mlkem_ek.len(), 1184);
    let w = hybrid::wrap_dek(&pk, &DEK).unwrap();
    assert_eq!(*hybrid::unwrap_dek(&sk, &w).unwrap(), DEK);
    let sk2 = HybridSecret::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(*hybrid::unwrap_dek(&sk2, &w).unwrap(), DEK);
    assert!(sk2.public() == pk);
    assert!(HybridSecret::from_bytes(&[0u8; 95]).is_err());
}

#[test]
fn hybrid_wrong_recipient_and_tamper() {
    let (sk, pk) = hybrid::generate().unwrap();
    let (other, _) = hybrid::generate().unwrap();
    let w = hybrid::wrap_dek(&pk, &DEK).unwrap();
    assert_eq!(hybrid::unwrap_dek(&other, &w), Err(CryptoError::Open));
    // flip a sample of bytes across every region: version, x25519 pub, ML-KEM ct, AEAD part
    for i in (0..w.len())
        .step_by(7)
        .chain([0, 1, 32, 33, 1120, 1121, w.len() - 1])
    {
        let mut t = w.clone();
        t[i] ^= 1;
        assert!(hybrid::unwrap_dek(&sk, &t).is_err(), "byte {i}");
    }
    assert!(hybrid::unwrap_dek(&sk, &w[..100]).is_err());
}

#[test]
fn hybrid_rejects_bad_public_keys() {
    let (_, mut pk) = hybrid::generate().unwrap();
    pk.mlkem_ek.pop();
    assert!(hybrid::wrap_dek(&pk, &DEK).is_err());
    let (_, mut pk) = hybrid::generate().unwrap();
    pk.x25519 = [0u8; 32]; // low-order point
    assert!(hybrid::wrap_dek(&pk, &DEK).is_err());
}

#[test]
fn argon_floor_and_ceiling() {
    let ok = ArgonParams {
        m_kib: FLOOR_M_KIB,
        t: 2,
        p: 1,
    };
    assert!(ok.check(Tier::Gb2).is_ok());
    assert!(ArgonParams {
        m_kib: FLOOR_M_KIB - 1,
        ..ok
    }
    .check(Tier::Gb64)
    .is_err());
    assert!(ArgonParams { t: 1, ..ok }.check(Tier::Gb64).is_err());
    assert!(ArgonParams { p: 0, ..ok }.check(Tier::Gb64).is_err());
    assert!(ArgonParams { t: 11, ..ok }.check(Tier::Gb64).is_err());
    assert!(ArgonParams { p: 9, ..ok }.check(Tier::Gb64).is_err());
    // memory ceiling is RAM/8 of the reader
    assert_eq!(Tier::Gb2.ceiling_m_kib(), 256 * 1024);
    assert_eq!(Tier::Gb64.ceiling_m_kib(), 8 * 1024 * 1024);
    assert!(ArgonParams {
        m_kib: 256 * 1024,
        ..ok
    }
    .check(Tier::Gb2)
    .is_ok());
    assert!(ArgonParams {
        m_kib: 256 * 1024 + 1,
        ..ok
    }
    .check(Tier::Gb2)
    .is_err());
}

#[test]
fn argon_tiers_scale_and_default_fits_2gb() {
    let tiers = [
        Tier::Gb2,
        Tier::Gb4,
        Tier::Gb8,
        Tier::Gb16,
        Tier::Gb32,
        Tier::Gb64,
    ];
    let mut prev = 0;
    for t in tiers {
        let h = ArgonParams::high(t);
        assert!(h.check(t).is_ok());
        assert!(h.m_kib > prev);
        prev = h.m_kib;
    }
    assert!(ArgonParams::DEFAULT.check(Tier::Gb2).is_ok());
    // a 64 GB device's "high" file is refused by a 2 GB phone, before any derivation
    assert!(ArgonParams::high(Tier::Gb64).check(Tier::Gb2).is_err());
    assert_eq!(ArgonParams::high(Tier::Gb2).m_kib, 128 * 1024);
}

#[test]
fn argon_header_encoding() {
    let p = ArgonParams::high(Tier::Gb16);
    assert_eq!(ArgonParams::from_bytes(&p.to_bytes()).unwrap(), p);
    assert!(ArgonParams::from_bytes(&[0u8; 11]).is_err());
}

#[test]
fn derive_is_deterministic_and_checked() {
    let p = ArgonParams {
        m_kib: FLOOR_M_KIB,
        t: 2,
        p: 1,
    };
    let salt = [9u8; 16];
    let a = derive_key(b"pw", &salt, &p, Tier::Gb2).unwrap();
    let b = derive_key(b"pw", &salt, &p, Tier::Gb2).unwrap();
    assert_eq!(*a, *b);
    assert_ne!(*a, *derive_key(b"pW", &salt, &p, Tier::Gb2).unwrap());
    assert_ne!(*a, *derive_key(b"pw", &[8u8; 16], &p, Tier::Gb2).unwrap());
    assert!(derive_key(b"pw", &salt[..8], &p, Tier::Gb2).is_err());
    assert!(derive_key(b"", &salt, &p, Tier::Gb2).is_err());
    let huge = ArgonParams {
        m_kib: 4 * 1024 * 1024,
        t: 2,
        p: 1,
    };
    assert!(derive_key(b"pw", &salt, &huge, Tier::Gb2).is_err());
}

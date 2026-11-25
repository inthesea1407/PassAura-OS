//! Property tests (proptest). Few cases: every case runs real Argon2 at the floor parameters.
use pos_vault_store::*;
use proptest::prelude::*;

struct Seq(u8);
impl Random for Seq {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        for x in b.iter_mut() {
            self.0 = self.0.wrapping_add(1);
            *x = self.0;
        }
        Ok(())
    }
}
const F: ArgonParams = ArgonParams {
    m_kib: FLOOR_M_KIB,
    t: FLOOR_T,
    p: FLOOR_P,
};
const T: Tier = Tier::Gb2;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// seal then open returns the plaintext, for both suites, with the right passphrase only.
    #[test]
    fn roundtrip_and_wrong_passphrase(pt in proptest::collection::vec(any::<u8>(), 0..2048), pw in proptest::collection::vec(any::<u8>(), 1..40), l1 in any::<bool>()) {
        let suite = if l1 { Suite::L1 } else { Suite::V1 };
        let f = seal(&pw, &pt, suite, &F, &WriteLimits::new(T), &mut Seq(0)).unwrap();
        prop_assert_eq!(&open(&pw, &f, suite, T).unwrap()[..], &pt[..]);
        let mut other = pw.clone();
        other.push(1);
        prop_assert!(open(&other, &f, suite, T).is_err());
        // the other suite id is refused
        let wrong = if l1 { Suite::V1 } else { Suite::L1 };
        prop_assert!(open(&pw, &f, wrong, T).is_err());
    }

    /// Replacing the payload region with random bytes never panics and is never accepted.
    #[test]
    fn random_payload_is_rejected(junk in proptest::collection::vec(any::<u8>(), 0..300), l1 in any::<bool>()) {
        let suite = if l1 { Suite::L1 } else { Suite::V1 };
        let f = seal(b"pw", b"data", suite, &F, &WriteLimits::new(T), &mut Seq(0)).unwrap();
        let mut g = f[..HEADER_LEN + ENVELOPE_LEN].to_vec();
        g.extend_from_slice(&junk);
        prop_assert!(open(b"pw", &g, suite, T).is_err());
    }

    /// Arbitrary bytes never panic and are never accepted (they stop at the header, before any KDF).
    #[test]
    fn arbitrary_bytes_rejected(b in proptest::collection::vec(any::<u8>(), 0..400)) {
        prop_assert!(open(b"pw", &b, Suite::V1, T).is_err());
    }

    /// rewrap keeps the plaintext and the old passphrase stops working on the new file.
    #[test]
    fn rewrap_roundtrip(pt in proptest::collection::vec(any::<u8>(), 0..512)) {
        let f = seal(b"old", &pt, Suite::V1, &F, &WriteLimits::new(T), &mut Seq(0)).unwrap();
        let g = rewrap(b"old", b"new", &f, Suite::V1, &F, &WriteLimits::new(T), &mut Seq(100)).unwrap();
        prop_assert_eq!(&open(b"new", &g, Suite::V1, T).unwrap()[..], &pt[..]);
        prop_assert!(open(b"old", &g, Suite::V1, T).is_err());
    }
}

use pos_vault_store::*;

struct Fixed(u8);
impl Random for Fixed {
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
const PW: &[u8] = b"test-passphrase-not-a-real-secret";
const T: Tier = Tier::Gb2;
const V1: Suite = Suite::V1;
const L1: Suite = Suite::L1;

fn lim() -> WriteLimits {
    WriteLimits::new(T)
}
fn cap_m() -> u32 {
    T.ceiling_m_kib()
}
fn sample() -> Vec<u8> {
    seal(PW, b"hello vault", V1, &F, &lim(), &mut Fixed(0)).unwrap()
}
fn sample_l1() -> Vec<u8> {
    seal(PW, b"hello vault", L1, &F, &lim(), &mut Fixed(0)).unwrap()
}
fn op(pw: &[u8], f: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    open(pw, f, V1, T)
}

#[test]
fn roundtrip_and_layout_v1() {
    let f = sample();
    assert_eq!(&f[..4], b"PAVS");
    assert_eq!(f[6], 1);
    assert_eq!(
        f.len(),
        HEADER_LEN + ENVELOPE_LEN + NONCE_LEN + b"hello vault".len() + TAG_LEN
    );
    assert_eq!(&*op(PW, &f).unwrap(), b"hello vault");
    assert_eq!(op(b"wrong", &f).unwrap_err(), Error::EnvelopeAuth);
}

#[test]
fn v1_payload_bytes_are_the_original_layout() {
    // id 1 files keep the pre-L1 payload layout: nonce (24) | ciphertext | tag. Deterministic RNG pins the bytes.
    let f = sample();
    let p = &f[HEADER_LEN + ENVELOPE_LEN..];
    assert_eq!(p.len(), 24 + 11 + 16);
    let again = sample();
    assert_eq!(f, again);
}

#[test]
fn roundtrip_l1_and_header_id() {
    let f = sample_l1();
    assert_eq!(f[6], 2);
    let p = &f[HEADER_LEN + ENVELOPE_LEN..];
    assert_eq!(
        p[0], 2,
        "payload is the suites L1 blob (starts with the suite id)"
    );
    assert_eq!(&*open(PW, &f, L1, T).unwrap(), b"hello vault");
    assert_eq!(open(b"wrong", &f, L1, T).unwrap_err(), Error::EnvelopeAuth);
}

#[test]
fn expected_suite_mismatch_is_refused_before_kdf_both_ways() {
    // Wrong passphrase would give EnvelopeAuth if the KDF ran; SuiteMismatch proves the header check won.
    let v1 = sample();
    let l1 = sample_l1();
    assert_eq!(
        open(b"wrong", &v1, L1, T).unwrap_err(),
        Error::SuiteMismatch {
            expected: 2,
            found: 1
        }
    );
    assert_eq!(
        open(b"wrong", &l1, V1, T).unwrap_err(),
        Error::SuiteMismatch {
            expected: 1,
            found: 2
        }
    );
    assert_eq!(
        rewrap(PW, b"n", &v1, L1, &F, &lim(), &mut Fixed(1)).unwrap_err(),
        Error::SuiteMismatch {
            expected: 2,
            found: 1
        }
    );
}

#[test]
fn relabel_attack_changes_header_and_fails_authentication() {
    // An attacker flips the header suite id and the reader expects the new id: the wrap tag (header-bound) fails.
    let mut v1 = sample();
    v1[6] = 2;
    assert_eq!(open(PW, &v1, L1, T).unwrap_err(), Error::EnvelopeAuth);
    let mut l1 = sample_l1();
    l1[6] = 1;
    assert_eq!(open(PW, &l1, V1, T).unwrap_err(), Error::EnvelopeAuth);
    // Unknown id.
    let mut g = sample();
    g[6] = 9;
    assert_eq!(open(PW, &g, V1, T).unwrap_err(), Error::UnsupportedAead(9));
}

#[test]
fn downgrade_by_swapping_payload_between_suites_fails() {
    // v1 header+envelope with an L1 payload (and the reverse) must not open.
    let v1 = sample();
    let l1 = sample_l1();
    let s = HEADER_LEN + ENVELOPE_LEN;
    let mut a = v1[..s].to_vec();
    a.extend_from_slice(&l1[s..]);
    assert_eq!(open(PW, &a, V1, T).unwrap_err(), Error::PayloadAuth);
    let mut b = l1[..s].to_vec();
    b.extend_from_slice(&v1[s..]);
    assert_eq!(open(PW, &b, L1, T).unwrap_err(), Error::PayloadAuth);
}

#[test]
fn empty_plaintext_and_empty_passphrase() {
    let f = seal(PW, b"", V1, &F, &lim(), &mut Fixed(9)).unwrap();
    assert_eq!(op(PW, &f).unwrap().len(), 0);
    assert_eq!(
        seal(b"", b"x", V1, &F, &lim(), &mut Fixed(0)).unwrap_err(),
        Error::EmptyPassphrase
    );
}

#[test]
fn header_byte_tamper_rejected() {
    for f in [sample(), sample_l1()] {
        let suite = if f[6] == 1 { V1 } else { L1 };
        for i in [0usize, 1, 2, 3, 4, 5, 6, 7, HEADER_LEN - 1] {
            let mut g = f.clone();
            g[i] ^= 1;
            assert!(open(PW, &g, suite, T).is_err(), "header byte {i} accepted");
        }
    }
}

#[test]
fn envelope_tamper_rejected() {
    let f = sample();
    let e = HEADER_LEN;
    let mut idx: Vec<usize> = (e..e + 13).collect();
    idx.extend([
        e + 13,
        e + 28,
        e + 29,
        e + 52,
        e + 53,
        e + 84,
        e + 85,
        e + 100,
    ]);
    for i in idx {
        let mut g = f.clone();
        g[i] ^= 1;
        assert!(op(PW, &g).is_err(), "envelope byte {i} accepted");
    }
}

#[test]
fn payload_tamper_rejected() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        let start = HEADER_LEN + ENVELOPE_LEN;
        let mid = start + (f.len() - start) / 2;
        for i in [
            start,
            start + 1,
            start + 23,
            start + 24,
            mid,
            f.len() - 17,
            f.len() - 16,
            f.len() - 1,
        ] {
            let mut g = f.clone();
            g[i] ^= 1;
            assert_eq!(
                open(PW, &g, suite, T).unwrap_err(),
                Error::PayloadAuth,
                "{suite:?} payload byte {i}"
            );
        }
    }
}

#[test]
fn truncation_and_extension_rejected() {
    let f = sample();
    for n in [0, 3, HEADER_LEN, MIN_FILE_LEN - 1] {
        assert_eq!(op(PW, &f[..n]).unwrap_err(), Error::Truncated);
    }
    assert_eq!(op(PW, &f[..f.len() - 1]).unwrap_err(), Error::PayloadAuth);
    let mut g = f.clone();
    g.push(0);
    assert_eq!(op(PW, &g).unwrap_err(), Error::PayloadAuth);
    let l = sample_l1();
    assert_eq!(
        open(PW, &l[..l.len() - 1], L1, T).unwrap_err(),
        Error::PayloadAuth
    );
}

#[test]
fn header_field_errors_are_distinct() {
    let f = sample();
    let mut g = f.clone();
    g[0] = b'X';
    assert_eq!(op(PW, &g).unwrap_err(), Error::BadMagic);
    let mut g = f.clone();
    g[5] = 3;
    assert_eq!(op(PW, &g).unwrap_err(), Error::UnsupportedVersion(3));
    // The previous format (v1, no envelope version) is refused, not guessed at.
    let mut g = f.clone();
    g[5] = 1;
    assert_eq!(op(PW, &g).unwrap_err(), Error::UnsupportedVersion(1));
    let mut g = f.clone();
    g[HEADER_LEN] = 7;
    assert_eq!(op(PW, &g).unwrap_err(), Error::UnsupportedKdf(7));
}

fn set_params(f: &mut [u8], m: u32, t: u32, p: u32) {
    f[HEADER_LEN + 1..HEADER_LEN + 5].copy_from_slice(&m.to_be_bytes());
    f[HEADER_LEN + 5..HEADER_LEN + 9].copy_from_slice(&t.to_be_bytes());
    f[HEADER_LEN + 9..HEADER_LEN + 13].copy_from_slice(&p.to_be_bytes());
}

#[test]
fn params_outside_bounds_rejected_with_distinct_errors() {
    // The unit test in src/lib.rs proves with a counting KDF that none of these reach the KDF.
    let base = sample();
    let cases = [
        (
            (F.m_kib - 1, F.t, F.p),
            Error::ParamBelowFloor(Param::Memory),
        ),
        ((F.m_kib, F.t - 1, F.p), Error::ParamBelowFloor(Param::Time)),
        (
            (F.m_kib, F.t, 0),
            Error::ParamBelowFloor(Param::Parallelism),
        ),
        ((cap_m() + 1, F.t, F.p), Error::ParamAboveCap(Param::Memory)),
        ((u32::MAX, F.t, F.p), Error::ParamAboveCap(Param::Memory)),
        ((F.m_kib, CAP_T + 1, F.p), Error::ParamAboveCap(Param::Time)),
        ((F.m_kib, u32::MAX, F.p), Error::ParamAboveCap(Param::Time)),
        (
            (F.m_kib, F.t, CAP_P + 1),
            Error::ParamAboveCap(Param::Parallelism),
        ),
    ];
    for ((m, t, p), want) in cases {
        let mut g = base.clone();
        set_params(&mut g, m, t, p);
        assert_eq!(op(PW, &g).unwrap_err(), want);
        assert_eq!(
            rewrap(PW, PW, &g, V1, &F, &lim(), &mut Fixed(1)).unwrap_err(),
            want
        );
    }
}

#[test]
fn tier_ceiling_is_one_eighth_of_ram_and_reader_decides() {
    assert_eq!(Tier::Gb2.ceiling_m_kib(), 262_144);
    assert_eq!(Tier::Gb64.ceiling_m_kib(), 8 * 1024 * 1024);
    // A file whose memory cost is the Gb4 ceiling is refused by a Gb2 reader, and not by a Gb4 reader
    // (the Gb4 read then fails later only because the stored params no longer match the real key).
    let mut g = sample();
    set_params(&mut g, Tier::Gb4.ceiling_m_kib(), F.t, F.p);
    assert_eq!(
        open(PW, &g, V1, Tier::Gb2).unwrap_err(),
        Error::ParamAboveCap(Param::Memory)
    );
}

#[test]
fn writer_rejects_out_of_bounds_params() {
    let low = ArgonParams {
        m_kib: F.m_kib - 1,
        ..F
    };
    let high = ArgonParams { p: CAP_P + 1, ..F };
    assert_eq!(
        seal(PW, b"x", V1, &low, &lim(), &mut Fixed(0)).unwrap_err(),
        Error::ParamBelowFloor(Param::Memory)
    );
    assert_eq!(
        seal(PW, b"x", V1, &high, &lim(), &mut Fixed(0)).unwrap_err(),
        Error::ParamAboveCap(Param::Parallelism)
    );
    let over = ArgonParams {
        m_kib: cap_m() + 1,
        ..F
    };
    assert_eq!(
        seal(PW, b"x", V1, &over, &lim(), &mut Fixed(0)).unwrap_err(),
        Error::ParamAboveCap(Param::Memory)
    );
    assert_eq!(
        (
            ArgonParams::DEFAULT.m_kib,
            ArgonParams::DEFAULT.t,
            ArgonParams::DEFAULT.p
        ),
        (65536, 3, 4)
    );
    assert!(check_params(&ArgonParams::DEFAULT, Tier::Gb2).is_ok());
    for tier in [
        Tier::Gb2,
        Tier::Gb4,
        Tier::Gb8,
        Tier::Gb16,
        Tier::Gb32,
        Tier::Gb64,
    ] {
        assert!(check_params(
            &ArgonParams {
                m_kib: tier.ceiling_m_kib(),
                t: CAP_T,
                p: CAP_P
            },
            tier
        )
        .is_ok());
        assert!(check_params(
            &ArgonParams {
                m_kib: tier.ceiling_m_kib() + 1,
                t: F.t,
                p: F.p
            },
            tier
        )
        .is_err());
    }
}

#[test]
fn rewrap_preserves_payload_and_header_and_changes_envelope() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        let new_params = ArgonParams { t: 3, ..F };
        let g = rewrap(
            PW,
            b"new-passphrase",
            &f,
            suite,
            &new_params,
            &lim(),
            &mut Fixed(100),
        )
        .unwrap();
        let pstart = HEADER_LEN + ENVELOPE_LEN;
        assert_eq!(f.len(), g.len());
        assert_eq!(&f[..HEADER_LEN], &g[..HEADER_LEN]);
        assert_eq!(
            &f[pstart..],
            &g[pstart..],
            "payload bytes must be byte-identical"
        );
        assert_ne!(&f[HEADER_LEN..pstart], &g[HEADER_LEN..pstart]);
        assert_eq!(
            &*open(b"new-passphrase", &g, suite, T).unwrap(),
            b"hello vault"
        );
        assert_eq!(open(PW, &g, suite, T).unwrap_err(), Error::EnvelopeAuth);
        assert_eq!(&g[HEADER_LEN + 5..HEADER_LEN + 9], &3u32.to_be_bytes());
    }
}

#[test]
fn rewrap_authenticates_payload_before_writing() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        let mut g = f.clone();
        let last = g.len() - 1;
        g[last] ^= 1;
        assert_eq!(
            rewrap(PW, b"new", &g, suite, &F, &lim(), &mut Fixed(1)).unwrap_err(),
            Error::PayloadAuth
        );
        let mut g = f.clone();
        g[HEADER_LEN + ENVELOPE_LEN + 1] ^= 1;
        assert_eq!(
            rewrap(PW, b"new", &g, suite, &F, &lim(), &mut Fixed(1)).unwrap_err(),
            Error::PayloadAuth
        );
    }
}

#[test]
fn rewrap_with_wrong_old_passphrase_fails() {
    let f = sample();
    assert_eq!(
        rewrap(b"nope", b"x", &f, V1, &F, &lim(), &mut Fixed(1)).unwrap_err(),
        Error::EnvelopeAuth
    );
}

#[test]
fn rewrap_does_not_invalidate_the_old_copy() {
    let f = sample();
    let _g = rewrap(PW, b"new-passphrase", &f, V1, &F, &lim(), &mut Fixed(100)).unwrap();
    assert_eq!(&*op(PW, &f).unwrap(), b"hello vault");
}

#[test]
fn envelope_and_payload_from_different_files_do_not_mix() {
    let a = seal(PW, b"AAAA", V1, &F, &lim(), &mut Fixed(0)).unwrap();
    let b = seal(PW, b"BBBB", V1, &F, &lim(), &mut Fixed(50)).unwrap();
    let mut mixed = a[..HEADER_LEN + ENVELOPE_LEN].to_vec();
    mixed.extend_from_slice(&b[HEADER_LEN + ENVELOPE_LEN..]);
    assert_eq!(op(PW, &mixed).unwrap_err(), Error::PayloadAuth);
    let mut hdr = b[..HEADER_LEN].to_vec();
    hdr.extend_from_slice(&a[HEADER_LEN..]);
    assert_eq!(op(PW, &hdr).unwrap_err(), Error::EnvelopeAuth);
}

#[test]
fn os_random_gives_distinct_files_for_same_input() {
    for suite in [V1, L1] {
        let a = seal(PW, b"same", suite, &F, &lim(), &mut OsRandom).unwrap();
        let b = seal(PW, b"same", suite, &F, &lim(), &mut OsRandom).unwrap();
        assert_ne!(a, b);
        assert_ne!(&a[7..HEADER_LEN], &b[7..HEADER_LEN]);
        assert_eq!(&*open(PW, &b, suite, T).unwrap(), b"same");
    }
}

#[test]
fn fixed_rng_is_deterministic_for_v1_only() {
    assert_eq!(sample(), sample());
    // L1 payload nonces come from pos-crypto-suites' OS randomness, not the injected source.
    assert_ne!(sample_l1(), sample_l1());
}

#[test]
fn rng_failure_is_reported() {
    struct Bad;
    impl Random for Bad {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Random)
        }
    }
    assert_eq!(
        seal(PW, b"x", V1, &F, &lim(), &mut Bad).unwrap_err(),
        Error::Random
    );
}

#[test]
fn oversized_plaintext_rejected() {
    let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        seal(PW, &big, V1, &F, &lim(), &mut Fixed(0)).unwrap_err(),
        Error::PlaintextTooLarge
    );
}

#[test]
fn file_roundtrip_atomic_write() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pavs");
    write_file_atomic(&p, &sample()).unwrap();
    let r = read_file(&p).unwrap();
    assert_eq!(&*op(PW, &r).unwrap(), b"hello vault");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let g = rewrap(PW, b"n", &r, V1, &F, &lim(), &mut Fixed(7)).unwrap();
    write_file_atomic(&p, &g).unwrap();
    assert_eq!(&*op(b"n", &read_file(&p).unwrap()).unwrap(), b"hello vault");
    let names: Vec<_> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
}

#[test]
fn failed_write_keeps_old_file_and_leaves_no_temp() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.pavs");
    write_file_atomic(&p, b"old").unwrap();
    let q = d.path().join("dirdest");
    std::fs::create_dir(&q).unwrap();
    std::fs::write(q.join("x"), b"x").unwrap();
    assert!(write_file_atomic(&q, b"new").is_err());
    assert_eq!(std::fs::read(&p).unwrap(), b"old");
    assert_eq!(
        std::fs::read_dir(d.path()).unwrap().count(),
        2,
        "no temp file may remain"
    );
    assert!(write_file_atomic(&d.path().join("nope/v"), b"x").is_err());
}

#[test]
fn read_file_rejects_missing() {
    assert_eq!(
        read_file(std::path::Path::new("/nonexistent/zzz")).unwrap_err(),
        Error::Io(std::io::ErrorKind::NotFound)
    );
}

// ---- monotonic envelope version (rollback detection) ----

const VOFF: usize = HEADER_LEN + 1 + 12 + SALT_LEN + NONCE_LEN;

fn omv(f: &[u8], suite: Suite, min: u64) -> Result<(zeroize::Zeroizing<Vec<u8>>, u64), Error> {
    open_min_version(PW, f, suite, T, min)
}

fn rw(f: &[u8], suite: Suite, pw_old: &[u8], pw_new: &[u8], seed: u8) -> Vec<u8> {
    rewrap(pw_old, pw_new, f, suite, &F, &lim(), &mut Fixed(seed)).unwrap()
}

#[test]
fn seal_starts_at_version_one_and_stores_it_in_the_envelope() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        assert_eq!(&f[VOFF..VOFF + 8], &1u64.to_be_bytes());
        let (plain, v) = omv(&f, suite, 0).unwrap();
        assert_eq!(&*plain, b"hello vault");
        assert_eq!(v, 1);
        assert_eq!(v, INITIAL_VERSION);
    }
}

#[test]
fn open_min_version_accepts_equal_and_higher_and_rejects_older() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        assert!(omv(&f, suite, 1).is_ok());
        assert_eq!(
            omv(&f, suite, 2).unwrap_err(),
            Error::RollbackDetected { found: 1, min: 2 }
        );
        assert_eq!(
            omv(&f, suite, u64::MAX).unwrap_err(),
            Error::RollbackDetected {
                found: 1,
                min: u64::MAX
            }
        );
    }
}

#[test]
fn rewrap_increments_version_and_it_persists_across_rewraps() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        let g = rw(&f, suite, PW, b"p2", 10);
        let h = rw(&g, suite, b"p2", b"p3", 20);
        let i = rw(&h, suite, b"p3", PW, 30);
        for (file, pw, want) in [(&g, &b"p2"[..], 2u64), (&h, b"p3", 3), (&i, PW, 4)] {
            assert_eq!(&file[VOFF..VOFF + 8], &want.to_be_bytes());
            let (plain, v) = open_min_version(pw, file, suite, T, want).unwrap();
            assert_eq!(&*plain, b"hello vault");
            assert_eq!(v, want);
        }
    }
}

#[test]
fn old_copy_is_rejected_when_caller_holds_a_higher_minimum() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        let g = rw(&f, suite, PW, b"new-pass", 10);
        // The caller saw version 2, then an attacker restores the old file (version 1).
        assert_eq!(
            open_min_version(PW, &f, suite, T, 2).unwrap_err(),
            Error::RollbackDetected { found: 1, min: 2 }
        );
        assert!(open_min_version(b"new-pass", &g, suite, T, 2).is_ok());
        // Plain `open` has no minimum and still opens the old copy (the caller must use open_min_version).
        assert!(open(PW, &f, suite, T).is_ok());
    }
}

#[test]
fn wrong_passphrase_never_reports_a_version() {
    let f = sample();
    assert_eq!(
        open_min_version(b"nope", &f, V1, T, 99).unwrap_err(),
        Error::EnvelopeAuth
    );
}

#[test]
fn every_version_byte_is_authenticated_by_the_envelope_tag() {
    for (f, suite) in [(sample(), V1), (sample_l1(), L1)] {
        for i in VOFF..VOFF + 8 {
            for bit in 0..8 {
                let mut g = f.clone();
                g[i] ^= 1 << bit;
                assert_eq!(
                    omv(&g, suite, 0).unwrap_err(),
                    Error::EnvelopeAuth,
                    "byte {i} bit {bit}"
                );
            }
        }
        // Raising the version to dodge a minimum, or lowering a rewrapped file, fails the same way.
        let g = rw(&f, suite, PW, b"x", 10);
        let mut h = g.clone();
        h[VOFF..VOFF + 8].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(
            open_min_version(b"x", &h, suite, T, 0).unwrap_err(),
            Error::EnvelopeAuth
        );
    }
}

#[test]
fn envelope_with_old_version_cannot_be_spliced_onto_a_newer_file() {
    // Same header and payload, envelope taken from the older state of the same file.
    let f = sample();
    let g = rw(&f, V1, PW, PW, 10);
    let mut spliced = g[..HEADER_LEN].to_vec();
    spliced.extend_from_slice(&f[HEADER_LEN..HEADER_LEN + ENVELOPE_LEN]);
    spliced.extend_from_slice(&g[HEADER_LEN + ENVELOPE_LEN..]);
    // It authenticates (same DEK, same header), and reports version 1, so a held minimum of 2 rejects it.
    assert_eq!(
        open_min_version(PW, &spliced, V1, T, 2).unwrap_err(),
        Error::RollbackDetected { found: 1, min: 2 }
    );
}

#[test]
fn rewrap_failure_does_not_change_the_input_or_version() {
    let f = sample();
    let before = f.clone();
    assert_eq!(
        rewrap(b"nope", b"x", &f, V1, &F, &lim(), &mut Fixed(1)).unwrap_err(),
        Error::EnvelopeAuth
    );
    assert_eq!(f, before);
}

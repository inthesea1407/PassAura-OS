//! Known-answer tests for the v2 store format.
//!
//! These tests lock the on-disk byte layout and the full crypto construction
//! (Argon2id KEK derivation, XChaCha20-Poly1305 wrapping, AAD wiring) against
//! accidental change. The golden vectors are produced by sealing with a fixed
//! randomness source, a fixed passphrase and the floor parameters, so the
//! output is fully deterministic. If any of them breaks, the format changed:
//! bump FORMAT_VERSION and add explicit migration instead of editing the
//! vectors.
//!
//! `GOLDEN_DUMP=1 cargo test -p pos-vault-store --test format_vectors -- --nocapture`
//! prints the current vectors (only ever used when deliberately re-cutting them).

use pos_vault_store::*;

/// Deterministic byte source: hands out 1, 2, 3, ... wrapping at 255.
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

/// Bytes `start..=start+n-1` (wrapping), the sequence `Fixed(start-1)` produces next.
fn seq(start: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

const F: ArgonParams = ArgonParams {
    m_kib: FLOOR_M_KIB,
    t: FLOOR_T,
    p: FLOOR_P,
};
const PW: &[u8] = b"format-vector-passphrase";
const PW2: &[u8] = b"format-vector-passphrase-two";
const PLAIN: &[u8] = b"hello vault";
const T: Tier = Tier::Gb2;

fn lim() -> WriteLimits {
    WriteLimits::new(T)
}

fn sealed() -> Vec<u8> {
    seal(PW, PLAIN, Suite::V1, &F, &lim(), &mut Fixed(0)).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Header: magic, format version (BE u16), suite id, 16-byte file id.
#[test]
fn header_layout_matches_spec() {
    let f = sealed();
    assert_eq!(&f[0..4], &MAGIC);
    assert_eq!(&f[4..6], &FORMAT_VERSION.to_be_bytes());
    assert_eq!(f[6], Suite::V1.id());
    // First 16 bytes out of the rng become the file id.
    assert_eq!(&f[7..23], &seq(1, FILE_ID_LEN)[..]);
    assert_eq!(HEADER_LEN, 23);
}

/// Envelope: kdf id, BE argon params, salt, wrap nonce, BE version, wrapped DEK + tag.
#[test]
fn envelope_layout_matches_spec() {
    let f = sealed();
    let env = &f[HEADER_LEN..HEADER_LEN + ENVELOPE_LEN];
    assert_eq!(env[0], KDF_ARGON2ID_V13);
    // Params are three big-endian u32s: m_kib, t, p.
    assert_eq!(&env[1..5], &FLOOR_M_KIB.to_be_bytes());
    assert_eq!(&env[5..9], &FLOOR_T.to_be_bytes());
    assert_eq!(&env[9..13], &FLOOR_P.to_be_bytes());
    // Rng consumption order: file id (16), DEK (32), then salt, then wrap nonce.
    assert_eq!(&env[13..13 + SALT_LEN], &seq(0x31, SALT_LEN)[..]);
    let no = 13 + SALT_LEN;
    assert_eq!(&env[no..no + NONCE_LEN], &seq(0x41, NONCE_LEN)[..]);
    let vo = no + NONCE_LEN;
    assert_eq!(&env[vo..vo + VERSION_LEN], &INITIAL_VERSION.to_be_bytes());
    assert_eq!(ENVELOPE_LEN, 109);
}

/// V1 payload: payload nonce (the next 24 rng bytes), then ciphertext + tag.
#[test]
fn payload_layout_v1() {
    let f = sealed();
    let payload = &f[HEADER_LEN + ENVELOPE_LEN..];
    assert_eq!(&payload[..NONCE_LEN], &seq(0x59, NONCE_LEN)[..]);
    assert_eq!(payload.len(), NONCE_LEN + PLAIN.len() + TAG_LEN);
}

/// Same inputs, same bytes: seal is a pure function of (pass, plaintext, suite,
/// params, randomness). This is what makes the golden vectors meaningful.
#[test]
fn seal_is_deterministic_under_fixed_randomness() {
    assert_eq!(sealed(), sealed());
}

/// The full file, byte for byte. Generated once with GOLDEN_DUMP=1 and frozen here.
#[test]
fn golden_vector_seal_v1() {
    const EXPECTED: &str = concat!(
        "504156530002010102030405060708090a0b0c0d0e0f1001",
        "00004c0000000002000000013132333435363738393a3b3c",
        "3d3e3f404142434445464748494a4b4c4d4e4f5051525354",
        "5556575800000000000000017de319a0eae1786533077a83",
        "5dabf3ebdbd254c89f87b429cd76ae298bdd186ac409a645",
        "afc42e0dc6ab733ba006c808595a5b5c5d5e5f6061626364",
        "65666768696a6b6c6d6e6f7017dabf6e134548ad7eacb8c5",
        "df901d7fda537409837b916a965eef",
    );
    let f = sealed();
    if std::env::var("GOLDEN_DUMP").is_ok() {
        println!("seal v1 ({} bytes):\n{}", f.len(), hex(&f));
        return;
    }
    assert_eq!(hex(&f), EXPECTED);
    // And it opens back to the original plaintext.
    assert_eq!(&*open(PW, &f, Suite::V1, T).unwrap(), PLAIN);
}

/// Rewrap: header and payload are preserved bit for bit, the envelope is rebuilt
/// (new salt/nonce from the rng, version bumped to 2), and the file then opens
/// only under the new passphrase.
#[test]
fn golden_vector_rewrap_v1() {
    const EXPECTED: &str = concat!(
        "504156530002010102030405060708090a0b0c0d0e0f1001",
        "00004c0000000002000000010102030405060708090a0b0c",
        "0d0e0f101112131415161718191a1b1c1d1e1f2021222324",
        "2526272800000000000000023184760e3c7e6c35f80b9e45",
        "feba4ee578c1dd93514fe5e331b1587bb0bfae9905896902",
        "262b7e11c37ec402116e3951595a5b5c5d5e5f6061626364",
        "65666768696a6b6c6d6e6f7017dabf6e134548ad7eacb8c5",
        "df901d7fda537409837b916a965eef",
    );
    let f = sealed();
    let r = rewrap(PW, PW2, &f, Suite::V1, &F, &lim(), &mut Fixed(0)).unwrap();
    if std::env::var("GOLDEN_DUMP").is_ok() {
        println!("rewrap v1 ({} bytes):\n{}", r.len(), hex(&r));
        return;
    }
    assert_eq!(hex(&r), EXPECTED);
    // Header and payload unchanged; only the envelope differs.
    assert_eq!(&r[..HEADER_LEN], &f[..HEADER_LEN]);
    assert_eq!(
        &r[HEADER_LEN + ENVELOPE_LEN..],
        &f[HEADER_LEN + ENVELOPE_LEN..]
    );
    // New envelope carries version 2.
    let vo = HEADER_LEN + 13 + SALT_LEN + NONCE_LEN;
    assert_eq!(&r[vo..vo + VERSION_LEN], &2u64.to_be_bytes());
    assert_eq!(&*open(PW2, &r, Suite::V1, T).unwrap(), PLAIN);
    assert!(open(PW, &r, Suite::V1, T).is_err());
}

/// The version counter refuses to move backwards: a file sealed now does not open
/// under a minimum-version policy above its authenticated version.
#[test]
fn open_min_version_rejects_lower_stored_version() {
    let f = sealed();
    let e = open_min_version(PW, &f, Suite::V1, T, INITIAL_VERSION + 1).unwrap_err();
    assert!(matches!(e, Error::RollbackDetected { .. }));
    assert!(open_min_version(PW, &f, Suite::V1, T, INITIAL_VERSION).is_ok());
}

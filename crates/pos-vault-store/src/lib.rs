//! Encrypted single-file store (format v1).
//!
//! ```text
//! file     = header | envelope | payload
//! header   = "PAVS" | version u16 BE | aead id u8 | file id [16]           (23 bytes, immutable)
//! envelope = kdf id u8 | m_kib u32 | t u32 | p u32 | salt [16] | wrap nonce [24] | wrapped DEK [48]   (101 bytes, mutable)
//! payload  = aead id 1: nonce [24] | ciphertext | tag [16]      AAD = header
//!            aead id 2: pos-crypto-suites L1 blob               caller AAD = header
//! ```
//! The DEK encrypts the payload. A key from Argon2id (the KEK) wraps the DEK with XChaCha20-Poly1305.
//! The wrap AAD is a domain label, the header, and the envelope bytes before the wrapped DEK, so the
//! envelope tag covers the header (including the AEAD id), the KDF parameters, the salt and the nonce.
//! `rewrap` replaces only the envelope: payload bytes are copied unchanged.
//!
//! AEAD id 1 is XChaCha20-Poly1305 and id 2 is the layered L1 suite of `pos-crypto-suites`. The reader
//! states which suite it expects; any other id is refused before the KDF runs.
//!
//! Argon2id bounds: the floor is fixed, the memory ceiling is one eighth of the RAM `Tier` that the
//! CALLER asserts for the device doing the work. No hardware detection happens here.
//!
//! This is integrity protection plus confidentiality from the cited RustCrypto primitives.
//! Nothing here is audited or certified. See docs/ENCRYPTED_STORAGE.md for the limits.
#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
pub use pos_crypto_suites::aead::Suite;
pub use pos_crypto_suites::argon::{ArgonParams, Tier};
use pos_crypto_suites::argon::{derive_key, FLOOR_M_KIB as S_FLOOR_M, FLOOR_P as S_FLOOR_P, FLOOR_T as S_FLOOR_T, MAX_P, MAX_T};
use std::fmt;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"PAVS";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID_V13: u8 = 1;

pub const FILE_ID_LEN: usize = 16;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const DEK_LEN: usize = 32;
pub const HEADER_LEN: usize = 4 + 2 + 1 + FILE_ID_LEN;
pub const ENVELOPE_LEN: usize = 1 + 12 + SALT_LEN + NONCE_LEN + DEK_LEN + TAG_LEN;
const ENVELOPE_AUTH_PREFIX: usize = ENVELOPE_LEN - (DEK_LEN + TAG_LEN);
/// Shortest possible file (aead id 1, empty plaintext). L1 files are longer.
pub const MIN_FILE_LEN: usize = HEADER_LEN + ENVELOPE_LEN + NONCE_LEN + TAG_LEN;
/// Payload size cap (plaintext). Accepted after an engineering review, not an audit.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;
/// Extra bytes an L1 payload can add over the plaintext (suite byte, two nonces, two tags), rounded up.
const L1_OVERHEAD: usize = 1 + 12 + 24 + 16 + 16;

const WRAP_DOMAIN: &[u8] = b"pos-vault-store/v1/dek-wrap";

/// Argon2id floor, the same for every tier: OWASP Password Storage Cheat Sheet minimum configuration.
pub const FLOOR_M_KIB: u32 = S_FLOOR_M;
pub const FLOOR_T: u32 = S_FLOOR_T;
pub const FLOOR_P: u32 = S_FLOOR_P;
/// Time and parallelism caps (an operational resource decision, not a standard).
pub const CAP_T: u32 = MAX_T;
pub const CAP_P: u32 = MAX_P;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    Memory,
    Time,
    Parallelism,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    /// The header names an AEAD id this crate does not know.
    UnsupportedAead(u8),
    /// The header names a known suite, but not the one the caller expects. Checked before the KDF.
    SuiteMismatch { expected: u8, found: u8 },
    UnsupportedKdf(u8),
    ParamBelowFloor(Param),
    ParamAboveCap(Param),
    /// The wrapped-DEK tag failed: wrong passphrase, or the header/envelope was altered.
    /// These cases cannot be told apart.
    EnvelopeAuth,
    /// The payload tag failed: payload or header was altered, or the file mixes parts of different files.
    PayloadAuth,
    EmptyPassphrase,
    PlaintextTooLarge,
    Random,
    Kdf,
    /// AEAD encryption failed (should not happen for valid inputs).
    Seal,
    Io(std::io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

/// Who is doing the write and which smaller reader the file must still fit.
/// Both tiers are asserted by the caller and trusted as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteLimits {
    pub writer: Tier,
    pub target_reader: Tier,
}

impl WriteLimits {
    /// Target reader defaults to the writer's own tier.
    pub fn new(writer: Tier) -> WriteLimits {
        WriteLimits { writer, target_reader: writer }
    }
    /// Explicit target. Whether the target may be above the writer is NOT restricted here: params must
    /// fit both ceilings in any case, so the smaller ceiling decides.
    pub fn with_target(writer: Tier, target_reader: Tier) -> WriteLimits {
        WriteLimits { writer, target_reader }
    }
}

/// Floor and cap check with distinct errors. Memory ceiling is one eighth of the tier's RAM.
/// Runs before any key derivation, on write and on read.
pub fn check_params(p: &ArgonParams, tier: Tier) -> Result<(), Error> {
    // The accept/reject decision belongs to pos-crypto-suites so the two policies cannot drift.
    // The branches below only choose a distinct error for the caller.
    if p.check(tier).is_ok() {
        return Ok(());
    }
    if p.m_kib < FLOOR_M_KIB {
        return Err(Error::ParamBelowFloor(Param::Memory));
    }
    if p.t < FLOOR_T {
        return Err(Error::ParamBelowFloor(Param::Time));
    }
    if p.p < FLOOR_P {
        return Err(Error::ParamBelowFloor(Param::Parallelism));
    }
    if p.m_kib > tier.ceiling_m_kib() {
        return Err(Error::ParamAboveCap(Param::Memory));
    }
    if p.t > CAP_T {
        return Err(Error::ParamAboveCap(Param::Time));
    }
    if p.p > CAP_P {
        return Err(Error::ParamAboveCap(Param::Parallelism));
    }
    // The suites policy refused something this crate cannot classify: fail closed.
    Err(Error::Kdf)
}

/// Source of random bytes. Production code uses `OsRandom`; tests may inject a fixed source.
/// L1 payload nonces come from `pos-crypto-suites` (OS randomness) and do not use this trait.
pub trait Random {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// Operating-system randomness through `getrandom`.
pub struct OsRandom;
impl Random for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(buf).map_err(|_| Error::Random)
    }
}

fn rand_array<const N: usize>(rng: &mut dyn Random) -> Result<[u8; N], Error> {
    let mut a = [0u8; N];
    rng.fill(&mut a)?;
    Ok(a)
}

type Key32 = Zeroizing<[u8; 32]>;
type KdfFn<'a> = &'a dyn Fn(&[u8], &[u8; SALT_LEN], &ArgonParams) -> Result<Key32, Error>;

/// Production KDF: bounds check for `tier`, then `pos-crypto-suites` Argon2id (which checks again).
fn derive_kek(tier: Tier) -> impl Fn(&[u8], &[u8; SALT_LEN], &ArgonParams) -> Result<Key32, Error> {
    move |pass, salt, p| {
        check_params(p, tier)?;
        if pass.is_empty() {
            return Err(Error::EmptyPassphrase);
        }
        derive_key(pass, salt, p, tier).map_err(|_| Error::Kdf)
    }
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| Error::Seal)
}

fn aead_open(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| ())
}

fn wrap_aad(header: &[u8], env_prefix: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(WRAP_DOMAIN.len() + header.len() + env_prefix.len());
    a.extend_from_slice(WRAP_DOMAIN);
    a.extend_from_slice(header);
    a.extend_from_slice(env_prefix);
    a
}

/// Builds an envelope: new salt, new wrap nonce, DEK wrapped under a KEK from `pass`.
fn build_envelope(
    pass: &[u8],
    params: &ArgonParams,
    header: &[u8],
    dek: &[u8; 32],
    rng: &mut dyn Random,
    kdf: KdfFn<'_>,
) -> Result<Vec<u8>, Error> {
    let salt = rand_array::<SALT_LEN>(rng)?;
    let nonce = rand_array::<NONCE_LEN>(rng)?;
    let kek = kdf(pass, &salt, params)?;
    let mut env = Vec::with_capacity(ENVELOPE_LEN);
    env.push(KDF_ARGON2ID_V13);
    env.extend_from_slice(&params.to_bytes());
    env.extend_from_slice(&salt);
    env.extend_from_slice(&nonce);
    let wrapped = aead_seal(&kek, &nonce, &wrap_aad(header, &env), dek)?;
    env.extend_from_slice(&wrapped);
    debug_assert_eq!(env.len(), ENVELOPE_LEN);
    Ok(env)
}

struct Parsed<'a> {
    header: &'a [u8],
    envelope: &'a [u8],
    payload: &'a [u8],
}

/// Parses the header and refuses any suite other than `expected`, before anything is derived.
fn parse_header(file: &[u8], expected: Suite) -> Result<Parsed<'_>, Error> {
    if file.len() < MIN_FILE_LEN {
        return Err(Error::Truncated);
    }
    let (header, rest) = file.split_at(HEADER_LEN);
    if header[0..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    let ver = u16::from_be_bytes([header[4], header[5]]);
    if ver != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(ver));
    }
    if Suite::from_id(header[6]).is_none() {
        return Err(Error::UnsupportedAead(header[6]));
    }
    if header[6] != expected.id() {
        return Err(Error::SuiteMismatch { expected: expected.id(), found: header[6] });
    }
    let (envelope, payload) = rest.split_at(ENVELOPE_LEN);
    Ok(Parsed { header, envelope, payload })
}

fn parse_envelope_params(env: &[u8]) -> Result<(ArgonParams, [u8; SALT_LEN]), Error> {
    if env[0] != KDF_ARGON2ID_V13 {
        return Err(Error::UnsupportedKdf(env[0]));
    }
    let params = ArgonParams::from_bytes(&env[1..13]).map_err(|_| Error::Truncated)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&env[13..13 + SALT_LEN]);
    Ok((params, salt))
}

/// Checks bounds first, then derives the KEK and unwraps the DEK. `kdf` is a parameter only so a unit
/// test can count calls; production passes `derive_kek(tier)`.
fn unwrap_dek_with(pass: &[u8], p: &Parsed<'_>, tier: Tier, kdf: KdfFn<'_>) -> Result<Zeroizing<[u8; 32]>, Error> {
    let (params, salt) = parse_envelope_params(p.envelope)?;
    check_params(&params, tier)?; // before the KDF
    let kek = kdf(pass, &salt, &params)?;
    let nonce = &p.envelope[13 + SALT_LEN..ENVELOPE_AUTH_PREFIX];
    let dek = aead_open(
        &kek,
        nonce,
        &wrap_aad(p.header, &p.envelope[..ENVELOPE_AUTH_PREFIX]),
        &p.envelope[ENVELOPE_AUTH_PREFIX..],
    )
    .map_err(|_| Error::EnvelopeAuth)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&dek);
    Ok(out)
}

fn open_payload(suite: Suite, dek: &[u8; 32], p: &Parsed<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    match suite {
        Suite::V1 => {
            let (nonce, ct) = p.payload.split_at(NONCE_LEN);
            aead_open(dek, nonce, p.header, ct).map_err(|_| Error::PayloadAuth)
        }
        Suite::L1 => pos_crypto_suites::aead::open(Suite::L1, dek, p.header, p.payload)
            .map(Zeroizing::new)
            .map_err(|_| Error::PayloadAuth),
    }
}

/// Creates a new file. Fresh file id, DEK, salt and nonces. `params` must fit BOTH the writer tier and
/// the target reader tier in `limits`; nothing is adjusted silently.
pub fn seal(
    pass: &[u8],
    plaintext: &[u8],
    suite: Suite,
    params: &ArgonParams,
    limits: &WriteLimits,
    rng: &mut dyn Random,
) -> Result<Vec<u8>, Error> {
    seal_with(pass, plaintext, suite, params, limits, rng, &derive_kek(limits.writer))
}

fn seal_with(
    pass: &[u8],
    plaintext: &[u8],
    suite: Suite,
    params: &ArgonParams,
    limits: &WriteLimits,
    rng: &mut dyn Random,
    kdf: KdfFn<'_>,
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Error::PlaintextTooLarge);
    }
    check_params(params, limits.writer)?;
    check_params(params, limits.target_reader)?;
    let file_id = rand_array::<FILE_ID_LEN>(rng)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header.push(suite.id());
    header.extend_from_slice(&file_id);
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rng.fill(&mut *dek)?;
    let envelope = build_envelope(pass, params, &header, &dek, rng, kdf)?;
    let payload = match suite {
        Suite::V1 => {
            let pnonce = rand_array::<NONCE_LEN>(rng)?;
            let ct = aead_seal(&dek, &pnonce, &header, plaintext)?;
            let mut v = Vec::with_capacity(NONCE_LEN + ct.len());
            v.extend_from_slice(&pnonce);
            v.extend_from_slice(&ct);
            v
        }
        Suite::L1 => pos_crypto_suites::aead::seal(Suite::L1, &dek, &header, plaintext).map_err(|_| Error::Seal)?,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + ENVELOPE_LEN + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&envelope);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Opens a file on a device of RAM tier `reader`, which must be the suite `expected`. The suite check and
/// the parameter bounds both happen before the KDF runs.
pub fn open(pass: &[u8], file: &[u8], expected: Suite, reader: Tier) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_with(pass, file, expected, reader, &derive_kek(reader))
}

fn open_with(pass: &[u8], file: &[u8], expected: Suite, reader: Tier, kdf: KdfFn<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let p = parse_header(file, expected)?;
    let dek = unwrap_dek_with(pass, &p, reader, kdf)?;
    open_payload(expected, &dek, &p)
}

/// Replaces the envelope (new passphrase, new salt, new nonce, chosen params). The header and the
/// payload bytes are copied unchanged. The payload IS authenticated first (decrypted with the DEK,
/// the plaintext is a `Zeroizing` buffer dropped at once); failure returns `PayloadAuth` and nothing is written.
/// The old envelope is read on the writer tier; `new_params` must fit the writer and target tiers.
/// The DEK stays the same: an old copy of the file and an old passphrase remain valid against that old copy.
pub fn rewrap(
    old_pass: &[u8],
    new_pass: &[u8],
    file: &[u8],
    expected: Suite,
    new_params: &ArgonParams,
    limits: &WriteLimits,
    rng: &mut dyn Random,
) -> Result<Vec<u8>, Error> {
    rewrap_with(old_pass, new_pass, file, expected, new_params, limits, rng, &derive_kek(limits.writer))
}

#[allow(clippy::too_many_arguments)]
fn rewrap_with(
    old_pass: &[u8],
    new_pass: &[u8],
    file: &[u8],
    expected: Suite,
    new_params: &ArgonParams,
    limits: &WriteLimits,
    rng: &mut dyn Random,
    kdf: KdfFn<'_>,
) -> Result<Vec<u8>, Error> {
    check_params(new_params, limits.writer)?;
    check_params(new_params, limits.target_reader)?;
    let p = parse_header(file, expected)?;
    let dek = unwrap_dek_with(old_pass, &p, limits.writer, kdf)?;
    {
        let _plain = open_payload(expected, &dek, &p)?;
    }
    let env = build_envelope(new_pass, new_params, p.header, &dek, rng, kdf)?;
    let mut out = Vec::with_capacity(file.len());
    out.extend_from_slice(p.header);
    out.extend_from_slice(&env);
    out.extend_from_slice(p.payload);
    Ok(out)
}

/// Reads a store file, refusing anything larger than the format maximum.
pub fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let max = (MIN_FILE_LEN + MAX_PLAINTEXT_LEN + L1_OVERHEAD) as u64;
    let f = std::fs::File::open(path).map_err(|e| Error::Io(e.kind()))?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf).map_err(|e| Error::Io(e.kind()))?;
    if buf.len() as u64 > max {
        return Err(Error::PlaintextTooLarge);
    }
    Ok(buf)
}

/// Replaces `path` with `bytes`: random-suffix temp file in the same directory created with
/// `create_new` (exclusive, mode 0600 on unix), `write_all`, `sync_all`, `rename`, then parent-directory
/// fsync on unix. The temp file is removed on error. See docs/ENCRYPTED_STORAGE.md for limits.
pub fn write_file_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), Error> {
    let mut last = Error::Io(std::io::ErrorKind::AlreadyExists);
    for _ in 0..4 {
        let suffix = rand_array::<8>(&mut OsRandom)?.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match write_atomic_with_suffix(path, bytes, &suffix) {
            Err(Error::Io(std::io::ErrorKind::AlreadyExists)) => last = Error::Io(std::io::ErrorKind::AlreadyExists),
            other => return other,
        }
    }
    Err(last)
}

fn write_atomic_with_suffix(path: &std::path::Path, bytes: &[u8], suffix: &str) -> Result<(), Error> {
    use std::io::Write;
    let io = |e: std::io::Error| Error::Io(e.kind());
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let name = path.file_name().ok_or(Error::Io(std::io::ErrorKind::InvalidInput))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(".pavs-tmp-{suffix}"));
    let tmp = dir.join(tmp_name);
    let mut oo = std::fs::OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    // create_new fails if the name exists (including as a symlink), so nothing is truncated or followed.
    let mut f = oo.open(&tmp).map_err(io)?;
    let res = (|| {
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
        Ok(())
    })();
    // Close the handle before rename: Windows cannot rename a file that is still open.
    drop(f);
    let res = res.and_then(|()| {
        std::fs::rename(&tmp, path).map_err(io)?;
        #[cfg(unix)]
        {
            std::fs::File::open(&dir).map_err(io)?.sync_all().map_err(io)?;
        }
        Ok(())
    });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    const F: ArgonParams = ArgonParams { m_kib: FLOOR_M_KIB, t: FLOOR_T, p: FLOOR_P };

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

    fn lim() -> WriteLimits {
        WriteLimits::new(Tier::Gb2)
    }

    /// Real Argon2 output, memoized per (pass, salt, params). Same results as the real KDF for every
    /// input, so a flip in salt or params still gets a different, real KEK. Only repeated work is skipped.
    fn memo_kdf(tier: Tier) -> impl Fn(&[u8], &[u8; SALT_LEN], &ArgonParams) -> Result<Key32, Error> {
        type CacheKey = (Vec<u8>, [u8; SALT_LEN], u32, u32, u32);
        let cache: RefCell<HashMap<CacheKey, [u8; 32]>> = RefCell::new(HashMap::new());
        let real = derive_kek(tier);
        move |pass, salt, p| {
            let key = (pass.to_vec(), *salt, p.m_kib, p.t, p.p);
            if let Some(k) = cache.borrow().get(&key) {
                return Ok(Zeroizing::new(*k));
            }
            let k = real(pass, salt, p)?;
            cache.borrow_mut().insert(key, *k);
            Ok(k)
        }
    }

    fn class_ok(i: usize, e: &Error) -> bool {
        let env = HEADER_LEN;
        let pay = HEADER_LEN + ENVELOPE_LEN;
        match i {
            0..=3 => *e == Error::BadMagic,
            4 | 5 => matches!(e, Error::UnsupportedVersion(_)),
            // Byte 6 flips 1 to 0/3/5/9... (unknown id) or to the other suite id (mismatch, before the KDF).
            6 => matches!(e, Error::UnsupportedAead(_) | Error::SuiteMismatch { .. }),
            7..=22 => *e == Error::EnvelopeAuth,
            _ if i == env => matches!(e, Error::UnsupportedKdf(_)),
            _ if i < env + 13 => matches!(e, Error::EnvelopeAuth | Error::ParamBelowFloor(_) | Error::ParamAboveCap(_)),
            _ if i < pay => *e == Error::EnvelopeAuth,
            _ => *e == Error::PayloadAuth,
        }
    }

    fn tiny() -> Vec<u8> {
        seal(b"pw", b"", Suite::V1, &F, &lim(), &mut Seq(0)).unwrap()
    }

    /// One-bit flip at EVERY byte offset of a tiny container (empty plaintext, floor params, fixed RNG).
    /// Must always be Err, with the expected error class for the region. Uses `open_with` and a memoized
    /// real-Argon2 KDF (see `memo_kdf`) to keep the run short.
    #[test]
    fn every_byte_offset_bit_flip_is_rejected_with_region_class() {
        let file = tiny();
        assert_eq!(file.len(), MIN_FILE_LEN);
        let kdf = memo_kdf(Tier::Gb2);
        assert!(open_with(b"pw", &file, Suite::V1, Tier::Gb2, &kdf).is_ok());
        for i in 0..file.len() {
            for bit in [0u8, 7] {
                let mut g = file.clone();
                g[i] ^= 1 << bit;
                let e = open_with(b"pw", &g, Suite::V1, Tier::Gb2, &kdf).expect_err(&format!("offset {i} bit {bit} accepted"));
                assert!(class_ok(i, &e), "offset {i} bit {bit}: unexpected class {e:?}");
            }
        }
    }

    /// Same for an L1 container (payload checked through the suites L1 open).
    #[test]
    fn every_byte_offset_bit_flip_l1() {
        let file = seal(b"pw", b"", Suite::L1, &F, &lim(), &mut Seq(0)).unwrap();
        let kdf = memo_kdf(Tier::Gb2);
        assert!(open_with(b"pw", &file, Suite::L1, Tier::Gb2, &kdf).is_ok());
        for i in 0..file.len() {
            for bit in [0u8, 7] {
                let mut g = file.clone();
                g[i] ^= 1 << bit;
                let e = open_with(b"pw", &g, Suite::L1, Tier::Gb2, &kdf).expect_err(&format!("L1 offset {i} bit {bit} accepted"));
                assert!(class_ok(i, &e), "L1 offset {i} bit {bit}: {e:?}");
            }
        }
    }

    /// Bridge: `open` is `open_with(.., &derive_kek(reader))` (one line) and `memo_kdf` only caches that
    /// same function. This runs the PUBLIC `open` and the memoized path side by side at several offsets
    /// per region and requires equal errors and the expected class.
    #[test]
    fn public_open_matches_memoized_path_per_region() {
        let file = tiny();
        let kdf = memo_kdf(Tier::Gb2);
        let pay = HEADER_LEN + ENVELOPE_LEN;
        for i in [0, 4, 7, 22, HEADER_LEN, HEADER_LEN + 1, HEADER_LEN + 4, HEADER_LEN + 8, HEADER_LEN + 12, HEADER_LEN + 13, HEADER_LEN + 29, HEADER_LEN + 53, HEADER_LEN + 54, HEADER_LEN + 100, pay, pay + 24, file.len() - 1] {
            let mut g = file.clone();
            g[i] ^= 1;
            let a = open(b"pw", &g, Suite::V1, Tier::Gb2).unwrap_err();
            let b = open_with(b"pw", &g, Suite::V1, Tier::Gb2, &kdf).unwrap_err();
            assert_eq!(a, b, "offset {i}");
            assert!(class_ok(i, &a), "offset {i}: {a:?}");
        }
    }

    /// Slow: every byte offset, bits 0 and 7, through the PUBLIC `open` with the real KDF every time, V1 and L1.
    /// Run with `cargo test -p pos-vault-store -- --ignored`. Not part of the default run.
    #[test]
    #[ignore = "slow: runs Argon2 once per offset that reaches the KDF"]
    fn every_byte_offset_bit_flip_through_public_open() {
        for suite in [Suite::V1, Suite::L1] {
            let file = seal(b"pw", b"", suite, &F, &lim(), &mut Seq(0)).unwrap();
            for i in 0..file.len() {
                for bit in [0u8, 7] {
                    let mut g = file.clone();
                    g[i] ^= 1 << bit;
                    let e = open(b"pw", &g, suite, Tier::Gb2).expect_err(&format!("{suite:?} offset {i} bit {bit} accepted"));
                    assert!(class_ok(i, &e), "{suite:?} offset {i} bit {bit}: {e:?}");
                }
            }
        }
    }

    fn counting(calls: &Cell<u32>) -> impl Fn(&[u8], &[u8; SALT_LEN], &ArgonParams) -> Result<Key32, Error> + '_ {
        move |_, _, _| {
            calls.set(calls.get() + 1);
            Ok(Zeroizing::new([0u8; 32]))
        }
    }

    fn with_params(file: &[u8], m: u32, t: u32, p: u32) -> Vec<u8> {
        let mut g = file.to_vec();
        g[HEADER_LEN + 1..HEADER_LEN + 5].copy_from_slice(&m.to_be_bytes());
        g[HEADER_LEN + 5..HEADER_LEN + 9].copy_from_slice(&t.to_be_bytes());
        g[HEADER_LEN + 9..HEADER_LEN + 13].copy_from_slice(&p.to_be_bytes());
        g
    }

    /// Instrumented check with a counting fake KDF (no Argon2 time): zero calls for out-of-bounds params
    /// or a wrong expected suite, one call for in-bounds params, for several reader tiers.
    #[test]
    fn kdf_is_not_called_for_out_of_bounds_params_or_wrong_suite() {
        let file = tiny();
        let g2 = Tier::Gb2.ceiling_m_kib();
        let bounds = [
            (Tier::Gb2, FLOOR_M_KIB - 1, FLOOR_T, FLOOR_P),
            (Tier::Gb2, FLOOR_M_KIB, FLOOR_T - 1, FLOOR_P),
            (Tier::Gb2, FLOOR_M_KIB, FLOOR_T, 0),
            (Tier::Gb2, g2 + 1, FLOOR_T, FLOOR_P),
            (Tier::Gb2, u32::MAX, FLOOR_T, FLOOR_P),
            (Tier::Gb2, FLOOR_M_KIB, CAP_T + 1, FLOOR_P),
            (Tier::Gb2, FLOOR_M_KIB, FLOOR_T, CAP_P + 1),
            (Tier::Gb4, Tier::Gb4.ceiling_m_kib() + 1, FLOOR_T, FLOOR_P),
            (Tier::Gb64, Tier::Gb64.ceiling_m_kib() + 1, FLOOR_T, FLOOR_P),
        ];
        for (tier, m, t, p) in bounds {
            let g = with_params(&file, m, t, p);
            let calls = Cell::new(0);
            let parsed = parse_header(&g, Suite::V1).unwrap();
            let r = unwrap_dek_with(b"pw", &parsed, tier, &counting(&calls));
            assert!(matches!(r, Err(Error::ParamBelowFloor(_)) | Err(Error::ParamAboveCap(_))), "{tier:?} {m} {t} {p}");
            assert_eq!(calls.get(), 0, "KDF ran for {tier:?} m={m} t={t} p={p}");
        }
        // Wrong expected suite: refused at the header, before any KDF closure could run.
        let calls = Cell::new(0);
        assert_eq!(
            open_with(b"pw", &file, Suite::L1, Tier::Gb2, &counting(&calls)).unwrap_err(),
            Error::SuiteMismatch { expected: 2, found: 1 }
        );
        assert_eq!(calls.get(), 0);
        // In bounds at the edges of each tier: exactly one call (the fake key then fails the tag).
        for tier in [Tier::Gb2, Tier::Gb4, Tier::Gb8, Tier::Gb16, Tier::Gb32, Tier::Gb64] {
            let g = with_params(&file, tier.ceiling_m_kib(), CAP_T, CAP_P);
            let calls = Cell::new(0);
            let parsed = parse_header(&g, Suite::V1).unwrap();
            assert_eq!(unwrap_dek_with(b"pw", &parsed, tier, &counting(&calls)).unwrap_err(), Error::EnvelopeAuth);
            assert_eq!(calls.get(), 1, "{tier:?}");
        }
        // A file at the Gb4 ceiling is refused by a Gb2 reader before the KDF.
        let g = with_params(&file, Tier::Gb4.ceiling_m_kib(), FLOOR_T, FLOOR_P);
        let calls = Cell::new(0);
        let parsed = parse_header(&g, Suite::V1).unwrap();
        assert_eq!(
            unwrap_dek_with(b"pw", &parsed, Tier::Gb2, &counting(&calls)).unwrap_err(),
            Error::ParamAboveCap(Param::Memory)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn writer_params_must_fit_writer_and_target() {
        let big = ArgonParams { m_kib: Tier::Gb4.ceiling_m_kib(), t: 3, p: 4 };
        let calls = Cell::new(0);
        let k = counting(&calls);
        // Writer Gb4, target Gb4: fits. Target Gb2: does not fit the target, error, no adjustment.
        assert!(seal_with(b"pw", b"x", Suite::V1, &big, &WriteLimits::new(Tier::Gb4), &mut Seq(0), &k).is_ok());
        assert_eq!(calls.get(), 1);
        let lower = WriteLimits::with_target(Tier::Gb4, Tier::Gb2);
        assert_eq!(
            seal_with(b"pw", b"x", Suite::V1, &big, &lower, &mut Seq(0), &k).unwrap_err(),
            Error::ParamAboveCap(Param::Memory)
        );
        assert_eq!(calls.get(), 1, "no KDF call for rejected params");
        // Writer Gb2 cannot use Gb4-sized params even with a bigger target; the smaller ceiling decides.
        let above = WriteLimits::with_target(Tier::Gb2, Tier::Gb4);
        assert_eq!(
            seal_with(b"pw", b"x", Suite::V1, &big, &above, &mut Seq(0), &k).unwrap_err(),
            Error::ParamAboveCap(Param::Memory)
        );
    }

    #[test]
    fn symlink_at_temp_name_is_not_followed_or_truncated() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("victim");
        std::fs::write(&target, b"keep").unwrap();
        let dest = d.path().join("vault.pavs");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, d.path().join("vault.pavs.pavs-tmp-aa")).unwrap();
            let e = write_atomic_with_suffix(&dest, b"new", "aa").unwrap_err();
            assert_eq!(e, Error::Io(std::io::ErrorKind::AlreadyExists));
            assert_eq!(std::fs::read(&target).unwrap(), b"keep");
            assert!(!dest.exists());
            assert!(d.path().join("vault.pavs.pavs-tmp-aa").symlink_metadata().is_ok());
        }
    }

    #[test]
    fn dest_symlink_is_replaced_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("victim");
        std::fs::write(&target, b"keep").unwrap();
        let dest = d.path().join("vault.pavs");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &dest).unwrap();
            write_file_atomic(&dest, b"new").unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"keep");
            assert_eq!(std::fs::read(&dest).unwrap(), b"new");
            assert!(!dest.symlink_metadata().unwrap().file_type().is_symlink());
        }
    }
}

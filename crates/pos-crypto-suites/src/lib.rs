//! Pure-function cipher suites for POS. No file I/O, no network, no key storage.
//!
//! Everything here is built from existing RustCrypto crates (AES-GCM, XChaCha20-Poly1305,
//! Argon2id, HKDF-SHA256, ML-KEM-768) and dalek's X25519. There are no home-made primitives.
//! This crate is not audited, and the `ml-kem` crate's own README says it has never been
//! independently audited. See `docs/CRYPTO_SUITES.md` for what is and is not claimed.
#![forbid(unsafe_code)]

pub mod aead;
pub mod argon;
pub mod hybrid;

/// Errors never carry key material, plaintext or passphrases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication failed, the blob is malformed, or the wrong suite or key was used.
    Open,
    /// Input has the wrong length or shape.
    BadInput(&'static str),
    /// Argon2 parameters are outside the allowed floor or ceiling.
    ParamsOutOfPolicy(&'static str),
    /// The operating system random source failed.
    Random,
    /// Underlying primitive refused the operation.
    Primitive(&'static str),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Open => f.write_str("decryption failed"),
            CryptoError::BadInput(m) => write!(f, "bad input: {m}"),
            CryptoError::ParamsOutOfPolicy(m) => write!(f, "argon2 parameters out of policy: {m}"),
            CryptoError::Random => f.write_str("random source failed"),
            CryptoError::Primitive(m) => write!(f, "primitive error: {m}"),
        }
    }
}
impl std::error::Error for CryptoError {}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| CryptoError::Random)?;
    Ok(b)
}

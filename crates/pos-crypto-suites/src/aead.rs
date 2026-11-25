//! AEAD suites over a 32-byte data key (DEK).
//!
//! Blob layout: `suite(1) || nonces || ciphertext||tag`.
//! - `V1`: XChaCha20-Poly1305. nonce 24.
//! - `L1`: layered. Inner AES-256-GCM (nonce 12), outer XChaCha20-Poly1305 (nonce 24).
//!   The two layer keys are derived from the DEK with HKDF-SHA256 and different `info` labels.
//!
//! The suite id is bound into the AAD, and the caller passes the suite it EXPECTS, so a blob
//! cannot be silently downgraded from L1 to V1 (or the reverse).

use crate::{random_bytes, CryptoError};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    V1,
    L1,
}

impl Suite {
    pub fn id(self) -> u8 {
        match self {
            Suite::V1 => 1,
            Suite::L1 => 2,
        }
    }
    pub fn from_id(b: u8) -> Option<Suite> {
        match b {
            1 => Some(Suite::V1),
            2 => Some(Suite::L1),
            _ => None,
        }
    }
}

const AAD_PREFIX: &[u8] = b"pos-crypto-suites/aead/v1";
const TAG: usize = 16;

fn full_aad(suite: Suite, aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(AAD_PREFIX.len() + 9 + aad.len());
    v.extend_from_slice(AAD_PREFIX);
    v.push(suite.id());
    v.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    v.extend_from_slice(aad);
    v
}

fn layer_keys(dek: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut a = Zeroizing::new([0u8; 32]);
    let mut c = Zeroizing::new([0u8; 32]);
    hk.expand(b"pos-crypto-suites/L1/aes-256-gcm", &mut *a).map_err(|_| CryptoError::Primitive("hkdf"))?;
    hk.expand(b"pos-crypto-suites/L1/xchacha20-poly1305", &mut *c).map_err(|_| CryptoError::Primitive("hkdf"))?;
    Ok((a, c))
}

fn x_seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::Primitive("xchacha20poly1305 seal"))
}

fn x_open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Open)
}

/// Encrypts `plaintext` under `dek` with a fresh random nonce per layer.
pub fn seal(suite: Suite, dek: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let aad = full_aad(suite, aad);
    let mut out = vec![suite.id()];
    match suite {
        Suite::V1 => {
            let n = random_bytes::<24>()?;
            out.extend_from_slice(&n);
            out.extend_from_slice(&x_seal(dek, &n, &aad, plaintext)?);
        }
        Suite::L1 => {
            let (ka, kc) = layer_keys(dek)?;
            let n_a = random_bytes::<12>()?;
            let n_x = random_bytes::<24>()?;
            let inner = Aes256Gcm::new_from_slice(&*ka)
                .map_err(|_| CryptoError::Primitive("aes key"))?
                .encrypt(GcmNonce::from_slice(&n_a), Payload { msg: plaintext, aad: &aad })
                .map_err(|_| CryptoError::Primitive("aes-gcm seal"))?;
            out.extend_from_slice(&n_a);
            out.extend_from_slice(&n_x);
            out.extend_from_slice(&x_seal(&kc, &n_x, &aad, &inner)?);
        }
    }
    Ok(out)
}

/// Decrypts a blob. `expected` is the suite the caller requires; any other suite id fails.
pub fn open(expected: Suite, dek: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.first().copied() != Some(expected.id()) {
        return Err(CryptoError::Open);
    }
    let aad = full_aad(expected, aad);
    let body = &blob[1..];
    match expected {
        Suite::V1 => {
            if body.len() < 24 + TAG {
                return Err(CryptoError::Open);
            }
            let (n, ct) = body.split_at(24);
            x_open(dek, n.try_into().map_err(|_| CryptoError::Open)?, &aad, ct)
        }
        Suite::L1 => {
            if body.len() < 12 + 24 + TAG + TAG {
                return Err(CryptoError::Open);
            }
            let (ka, kc) = layer_keys(dek)?;
            let (n_a, rest) = body.split_at(12);
            let (n_x, ct) = rest.split_at(24);
            let inner = x_open(&kc, n_x.try_into().map_err(|_| CryptoError::Open)?, &aad, ct)?;
            Aes256Gcm::new_from_slice(&*ka)
                .map_err(|_| CryptoError::Open)?
                .decrypt(GcmNonce::from_slice(n_a), Payload { msg: &inner, aad: &aad })
                .map_err(|_| CryptoError::Open)
        }
    }
}

//! Hybrid key wrap for a 32-byte DEK: X25519 plus ML-KEM-768.
//!
//! The wrapping key is HKDF-SHA256 over BOTH shared secrets, with the ephemeral X25519 public key,
//! the ML-KEM ciphertext and both recipient public keys as context. An attacker has to break both
//! X25519 and ML-KEM to recover it. This is a design choice for defense in depth. It is not a
//! claim that the construction is quantum-safe or unbreakable, and neither crate is audited.
//!
//! Blob: `version(1) || x25519_eph_pub(32) || mlkem_ct(1088) || aead_blob(V1 over the DEK)`.

use crate::aead::{open, seal, Suite};
use crate::{random_bytes, CryptoError};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use sha2::Sha256;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
pub const X_PUB: usize = 32;
pub const KEM_EK: usize = 1184;
pub const KEM_CT: usize = 1088;
pub const SEED: usize = 64;

/// Public half given to whoever wraps a DEK.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublic {
    pub x25519: [u8; X_PUB],
    pub mlkem_ek: Vec<u8>,
}

/// Secret half. Both parts are kept as seeds/scalars and zeroized on drop.
pub struct HybridSecret {
    x25519: Zeroizing<[u8; 32]>,
    mlkem_seed: Zeroizing<[u8; SEED]>,
}

fn kem_from_seed(seed: &[u8; SEED]) -> DecapsulationKey<MlKem768> {
    DecapsulationKey::<MlKem768>::from_seed((*seed).into())
}

pub fn generate() -> Result<(HybridSecret, HybridPublic), CryptoError> {
    let x_sk = Zeroizing::new(random_bytes::<32>()?);
    let x_pk = x25519(*x_sk, X25519_BASEPOINT_BYTES);
    let seed = Zeroizing::new(random_bytes::<SEED>()?);
    let dk = kem_from_seed(&seed);
    let ek = dk.encapsulation_key().to_bytes();
    let ek: &[u8] = ek.as_ref();
    Ok((
        HybridSecret { x25519: x_sk, mlkem_seed: seed },
        HybridPublic { x25519: x_pk, mlkem_ek: ek.to_vec() },
    ))
}

impl HybridSecret {
    pub fn public(&self) -> HybridPublic {
        let dk = kem_from_seed(&self.mlkem_seed);
        let ek = dk.encapsulation_key().to_bytes();
        let ek: &[u8] = ek.as_ref();
        HybridPublic { x25519: x25519(*self.x25519, X25519_BASEPOINT_BYTES), mlkem_ek: ek.to_vec() }
    }
    /// 96 bytes: x25519 scalar (32) then ML-KEM seed (64).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(32 + SEED));
        v.extend_from_slice(&*self.x25519);
        v.extend_from_slice(&*self.mlkem_seed);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<HybridSecret, CryptoError> {
        if b.len() != 32 + SEED {
            return Err(CryptoError::BadInput("hybrid secret must be 96 bytes"));
        }
        let mut x = Zeroizing::new([0u8; 32]);
        x.copy_from_slice(&b[..32]);
        let mut s = Zeroizing::new([0u8; SEED]);
        s.copy_from_slice(&b[32..]);
        Ok(HybridSecret { x25519: x, mlkem_seed: s })
    }
}

fn wrap_key(
    ss_x: &[u8; 32],
    ss_k: &[u8],
    eph_pub: &[u8; 32],
    ct: &[u8],
    rcpt_x: &[u8; 32],
    rcpt_ek: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + ss_k.len()));
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_k);
    let mut info = Vec::new();
    info.extend_from_slice(b"pos-crypto-suites/hybrid/v1");
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(ct);
    info.extend_from_slice(rcpt_x);
    info.extend_from_slice(rcpt_ek);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&info, &mut *out)
        .map_err(|_| CryptoError::Primitive("hkdf"))?;
    Ok(out)
}

/// Wraps a DEK for the holder of `to`.
pub fn wrap_dek(to: &HybridPublic, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if to.mlkem_ek.len() != KEM_EK {
        return Err(CryptoError::BadInput("ML-KEM-768 encapsulation key must be 1184 bytes"));
    }
    let ek_arr = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(to.mlkem_ek.as_slice())
        .map_err(|_| CryptoError::BadInput("ML-KEM encapsulation key length"))?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_arr)
        .map_err(|_| CryptoError::BadInput("invalid ML-KEM encapsulation key"))?;

    let eph = Zeroizing::new(random_bytes::<32>()?);
    let eph_pub = x25519(*eph, X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519(*eph, to.x25519));
    if ss_x.iter().all(|b| *b == 0) {
        return Err(CryptoError::BadInput("X25519 public key is a low-order point"));
    }
    let (ct, ss_k) = ek.encapsulate();
    let ct: &[u8] = ct.as_ref();
    let ss_k: &[u8] = ss_k.as_ref();
    let key = wrap_key(&ss_x, ss_k, &eph_pub, ct, &to.x25519, &to.mlkem_ek)?;
    let sealed = seal(Suite::V1, &key, b"pos-hybrid-wrap", dek)?;
    let mut out = Vec::with_capacity(1 + X_PUB + KEM_CT + sealed.len());
    out.push(VERSION);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(ct);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Unwraps a DEK. Any malformed or tampered blob returns `CryptoError::Open`.
pub fn unwrap_dek(sk: &HybridSecret, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if blob.len() < 1 + X_PUB + KEM_CT || blob[0] != VERSION {
        return Err(CryptoError::Open);
    }
    let eph_pub: [u8; 32] = blob[1..1 + X_PUB].try_into().map_err(|_| CryptoError::Open)?;
    let ct = &blob[1 + X_PUB..1 + X_PUB + KEM_CT];
    let sealed = &blob[1 + X_PUB + KEM_CT..];

    let ss_x = Zeroizing::new(x25519(*sk.x25519, eph_pub));
    if ss_x.iter().all(|b| *b == 0) {
        return Err(CryptoError::Open);
    }
    let dk = kem_from_seed(&sk.mlkem_seed);
    // ML-KEM decapsulation never fails on a well-sized ciphertext (implicit rejection): a wrong
    // ciphertext yields an unrelated secret and the AEAD below then fails.
    let ss_k = dk.decapsulate_slice(ct).map_err(|_| CryptoError::Open)?;
    let ss_k: &[u8] = ss_k.as_ref();
    let public = sk.public();
    let key = wrap_key(&ss_x, ss_k, &eph_pub, ct, &public.x25519, &public.mlkem_ek)?;
    let dek = open(Suite::V1, &key, b"pos-hybrid-wrap", sealed)?;
    if dek.len() != 32 {
        return Err(CryptoError::Open);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&dek);
    Ok(out)
}

//! LEGACY text-v1 allowlist (Ed25519). MIGRATION INPUT ONLY.
//!
//! Not accepted at runtime: the gate, Linux backend and CLI take v2 only
//! (see `allowlist_v2`). This module stays so `crate::migrate` can verify an
//! old document, under its original rules, before converting it offline.
//! `Keyring` (the trusted-key file format) is still used by every path.
//!
//! The signed message is domain-separated and canonical:
//! `passaura-allowlist-v1\n<signed_by>\n<issued_at>\n<expires_at>\n` followed by
//! one `name@version\n` line per package, sorted. Fail-closed: unknown key,
//! bad hex, bad signature, not-yet-valid or expired all return an error.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    Json(String),
    UnknownKey(String),
    BadKey(String),
    BadSignature,
    NotYetValid,
    Expired,
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::Json(m) => write!(f, "invalid JSON: {m}"),
            GateError::UnknownKey(k) => write!(f, "signer {k} is not in the keyring"),
            GateError::BadKey(m) => write!(f, "bad key material: {m}"),
            GateError::BadSignature => write!(f, "signature does not match"),
            GateError::NotYetValid => write!(f, "allowlist is not valid yet"),
            GateError::Expired => write!(f, "allowlist has expired"),
        }
    }
}
impl std::error::Error for GateError {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyEntry {
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Keyring {
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowlistDoc {
    pub signed_by: String,
    pub signature_hex: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub packages: Vec<PackageEntry>,
}

impl Keyring {
    pub fn from_json(b: &[u8]) -> Result<Self, GateError> {
        serde_json::from_slice(b).map_err(|e| GateError::Json(e.to_string()))
    }
}
impl AllowlistDoc {
    pub fn from_json(b: &[u8]) -> Result<Self, GateError> {
        serde_json::from_slice(b).map_err(|e| GateError::Json(e.to_string()))
    }
    pub fn message(&self) -> Vec<u8> {
        let mut pk: Vec<String> = self
            .packages
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        pk.sort();
        let mut m = format!(
            "passaura-allowlist-v1\n{}\n{}\n{}\n",
            self.signed_by, self.issued_at, self.expires_at
        );
        for p in pk {
            m.push_str(&p);
            m.push('\n');
        }
        m.into_bytes()
    }
    /// Sign in place with the given key (sets signature_hex).
    pub fn sign(&mut self, key: &SigningKey) {
        self.signature_hex = hex::encode(key.sign(&self.message()).to_bytes());
    }
}

pub fn verify_allowlist(kr: &Keyring, doc: &AllowlistDoc, now: u64) -> Result<(), GateError> {
    let entry = kr
        .keys
        .iter()
        .find(|k| k.key_id == doc.signed_by)
        .ok_or_else(|| GateError::UnknownKey(doc.signed_by.clone()))?;
    let pk: [u8; 32] = hex::decode(&entry.public_key_hex)
        .map_err(|e| GateError::BadKey(e.to_string()))?
        .try_into()
        .map_err(|_| GateError::BadKey("public key must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| GateError::BadKey(e.to_string()))?;
    let sig: [u8; 64] = hex::decode(&doc.signature_hex)
        .map_err(|_| GateError::BadSignature)?
        .try_into()
        .map_err(|_| GateError::BadSignature)?;
    vk.verify_strict(&doc.message(), &Signature::from_bytes(&sig))
        .map_err(|_| GateError::BadSignature)?;
    if now < doc.issued_at {
        return Err(GateError::NotYetValid);
    }
    if now >= doc.expires_at {
        return Err(GateError::Expired);
    }
    Ok(())
}

pub fn is_allowed(doc: &AllowlistDoc, pkg: &str) -> bool {
    doc.packages.iter().any(|p| p.name == pkg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SigningKey, Keyring, AllowlistDoc) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let kr = Keyring {
            keys: vec![KeyEntry {
                key_id: "ed25519:t".into(),
                public_key_hex: hex::encode(sk.verifying_key().to_bytes()),
            }],
        };
        let mut d = AllowlistDoc {
            signed_by: "ed25519:t".into(),
            signature_hex: String::new(),
            issued_at: 10,
            expires_at: 100,
            packages: vec![PackageEntry {
                name: "ripgrep".into(),
                version: "14".into(),
            }],
        };
        d.sign(&sk);
        (sk, kr, d)
    }
    #[test]
    fn valid_ok() {
        let (_, kr, d) = setup();
        assert_eq!(verify_allowlist(&kr, &d, 50), Ok(()));
        assert!(is_allowed(&d, "ripgrep"));
        assert!(!is_allowed(&d, "bitwarden"));
    }
    #[test]
    fn tampered_rejected() {
        let (_, kr, mut d) = setup();
        d.packages.push(PackageEntry {
            name: "evil".into(),
            version: "1".into(),
        });
        assert_eq!(verify_allowlist(&kr, &d, 50), Err(GateError::BadSignature));
    }
    #[test]
    fn expiry_and_notyet() {
        let (_, kr, d) = setup();
        assert_eq!(verify_allowlist(&kr, &d, 100), Err(GateError::Expired));
        assert_eq!(verify_allowlist(&kr, &d, 5), Err(GateError::NotYetValid));
    }
    #[test]
    fn unknown_key_and_garbage() {
        let (_, _, d) = setup();
        let empty = Keyring { keys: vec![] };
        assert!(matches!(
            verify_allowlist(&empty, &d, 50),
            Err(GateError::UnknownKey(_))
        ));
        let (_, kr, mut d2) = setup();
        d2.signature_hex = "00".into();
        assert_eq!(verify_allowlist(&kr, &d2, 50), Err(GateError::BadSignature));
    }
}

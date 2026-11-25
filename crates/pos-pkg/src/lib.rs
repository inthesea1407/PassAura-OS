//! Signed package: manifest (team, name, version, entitlements, payload
//! hash) signed with the store key, and the payload hash checked against the
//! payload bytes. `verify` returns a `Verified` value, the only way to get
//! `store_signed = true` into pos-core's install decision.
//!
//! Not yet: key rotation/revocation lists, timestamping, reproducible
//! builds, hardware-backed signing keys (the store key must live in an HSM).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pos_core::entitlements::{install_decision, Entitlement, InstallVerdict, Manifest};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifest {
    pub team: String,
    pub name: String,
    pub version: u32,
    pub entitlements: Vec<Entitlement>,
    pub payload_sha256: [u8; 32],
}

fn ent_name(e: Entitlement) -> &'static str {
    match e {
        Entitlement::Network => "network",
        Entitlement::Camera => "camera",
        Entitlement::CredentialProvider => "credential-provider",
        Entitlement::AutofillProvider => "autofill-provider",
        Entitlement::AccessibilityControl => "accessibility-control",
    }
}

impl PackageManifest {
    /// Canonical bytes that get signed. Fixed field order, newline separated.
    pub fn canonical(&self) -> Vec<u8> {
        let mut ents: Vec<&str> = self.entitlements.iter().map(|e| ent_name(*e)).collect();
        ents.sort();
        let hex: String = self.payload_sha256.iter().map(|b| format!("{b:02x}")).collect();
        format!("pos-pkg-v1\nteam={}\nname={}\nversion={}\nent={}\nsha256={}\n", self.team, self.name, self.version, ents.join(","), hex).into_bytes()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub struct SignedPackage {
    pub manifest: PackageManifest,
    pub signature: [u8; 64],
    pub payload: Vec<u8>,
}

/// Store-side: sign a manifest for a payload.
pub fn sign(key: &SigningKey, team: &str, name: &str, version: u32, ents: &[Entitlement], payload: &[u8]) -> SignedPackage {
    let manifest = PackageManifest {
        team: team.into(),
        name: name.into(),
        version,
        entitlements: ents.to_vec(),
        payload_sha256: sha256(payload),
    };
    let sig = key.sign(&manifest.canonical());
    SignedPackage { manifest, signature: sig.to_bytes(), payload: payload.to_vec() }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadSignature,
    PayloadHashMismatch,
    /// team or name has control characters, or is empty. The signed text is
    /// newline-separated, so such values could blur field boundaries.
    InvalidManifest,
}

/// Proof that signature and payload hash both checked out.
pub struct Verified<'a>(&'a SignedPackage);

pub fn verify<'a>(store_key: &VerifyingKey, p: &'a SignedPackage) -> Result<Verified<'a>, VerifyError> {
    let bad = |v: &str| v.is_empty() || v.chars().any(|c| c.is_control());
    if bad(&p.manifest.team) || bad(&p.manifest.name) {
        return Err(VerifyError::InvalidManifest);
    }
    let sig = Signature::from_bytes(&p.signature);
    store_key.verify_strict(&p.manifest.canonical(), &sig).map_err(|_| VerifyError::BadSignature)?;
    if sha256(&p.payload) != p.manifest.payload_sha256 {
        return Err(VerifyError::PayloadHashMismatch);
    }
    Ok(Verified(p))
}

/// Install decision for a verified package. `approved` is what store review
/// approved for this team (from the store database).
pub fn decide(v: &Verified, approved: &[Entitlement], sideloaded: bool) -> InstallVerdict {
    let m = &v.0.manifest;
    install_decision(&Manifest { team: &m.team, requested: &m.entitlements, approved, store_signed: true, sideloaded })
}

#[cfg(test)]
mod tests {
    #[test]
    fn newline_in_team_or_name_is_rejected() {
        let k = super::SigningKey::from_bytes(&[7u8; 32]);
        let p = super::sign(&k, "t\nname=x", "n", 1, &[], b"data");
        assert!(matches!(super::verify(&k.verifying_key(), &p), Err(super::VerifyError::InvalidManifest)));
        let p = super::sign(&k, "t", "", 1, &[], b"data");
        assert!(matches!(super::verify(&k.verifying_key(), &p), Err(super::VerifyError::InvalidManifest)));
    }

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn good_package_verifies_and_installs() {
        let k = key(1);
        let p = sign(&k, "dev.acme", "calc", 1, &[Entitlement::Network], b"payload");
        let v = verify(&k.verifying_key(), &p).unwrap();
        assert_eq!(decide(&v, &[Entitlement::Network], false), InstallVerdict::Install);
    }

    #[test]
    fn tampered_payload_rejected() {
        let k = key(1);
        let mut p = sign(&k, "dev.acme", "calc", 1, &[], b"payload");
        p.payload = b"evil".to_vec();
        assert!(matches!(verify(&k.verifying_key(), &p), Err(VerifyError::PayloadHashMismatch)));
    }

    #[test]
    fn tampered_manifest_entitlements_rejected() {
        let k = key(1);
        let mut p = sign(&k, "dev.acme", "calc", 1, &[Entitlement::Network], b"payload");
        p.manifest.entitlements.push(Entitlement::CredentialProvider);
        assert!(matches!(verify(&k.verifying_key(), &p), Err(VerifyError::BadSignature)));
    }

    #[test]
    fn wrong_signer_rejected() {
        let p = sign(&key(2), "dev.acme", "calc", 1, &[], b"payload");
        assert!(matches!(verify(&key(1).verifying_key(), &p), Err(VerifyError::BadSignature)));
    }

    #[test]
    fn signed_by_store_but_restricted_entitlement_for_other_team_still_rejected() {
        let k = key(1);
        let e = [Entitlement::CredentialProvider];
        let p = sign(&k, "dev.rival-pm", "rivalpm", 1, &e, b"x");
        let v = verify(&k.verifying_key(), &p).unwrap();
        assert!(matches!(decide(&v, &e, false), InstallVerdict::Reject(_)));
    }

    #[test]
    fn sideload_rejected_even_when_valid() {
        let k = key(1);
        let p = sign(&k, "dev.acme", "calc", 1, &[], b"x");
        let v = verify(&k.verifying_key(), &p).unwrap();
        assert!(matches!(decide(&v, &[], true), InstallVerdict::Reject(_)));
    }
}

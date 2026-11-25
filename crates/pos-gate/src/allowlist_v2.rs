//! Canonical allowlist format v2 (rotation format). The only runtime format.
//!
//! v2 has a signed keyring with per-key validity windows, a monotonic
//! sequence for downgrade rejection, and a `signed_by` field binding the
//! signature to a ring member. Older formats are never accepted at runtime;
//! the text-v1 format can only be converted offline by `crate::migrate`.
//! See docs/ALLOWLIST_FORMAT.md.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Error {
    Json(String),
    UnsupportedVersion(u64),
    /// Version 1 is accepted only by the offline migration tool.
    LegacyVersionMigrationOnly(u64),
    SignerNotTrusted(String),
    BadFormat(String),
    SignatureInvalid,
    SignedByUnknown(String),
    SignedByRetired(String),
    SignedByNotValidAt { key_id: String, issued_at: i64 },
    KeyringEmpty,
    KeyIdMismatch { key_id: String, public_key_hex: String },
    Expired { expires_at: i64, now: i64 },
    NotYetValid { issued_at: i64, now: i64 },
    InvalidWindow { issued_at: i64, expires_at: i64 },
    DowngradeRejected { stored: u64, candidate: u64 },
    DigestMismatch { stored_hex: String, candidate_hex: String },
    NoSequence,
    DuplicateKeyId(String),
    InvalidKeyWindow(String),
}

impl fmt::Display for V2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V2Error::Json(m) => write!(f, "v2 json error: {m}"),
            V2Error::UnsupportedVersion(v) => write!(f, "unsupported allowlist version {v}"),
            V2Error::LegacyVersionMigrationOnly(v) => write!(f, "allowlist version {v} is accepted only by the offline migration tool"),
            V2Error::SignerNotTrusted(k) => write!(f, "signer {k} is not in the trusted keyring"),
            V2Error::BadFormat(m) => write!(f, "bad allowlist format: {m}"),
            V2Error::SignatureInvalid => write!(f, "signature invalid"),
            V2Error::DuplicateKeyId(k) => write!(f, "duplicate key_id {k} in keyring"),
            V2Error::InvalidKeyWindow(k) => write!(f, "key {k} has an empty or inverted validity window"),
            V2Error::SignedByUnknown(k) => write!(f, "signed_by {k} not in keyring"),
            V2Error::SignedByRetired(k) => write!(f, "signed_by {k} is retired"),
            V2Error::SignedByNotValidAt { key_id, issued_at } => write!(
                f,
                "signed_by {key_id} not valid at issued_at {issued_at}"
            ),
            V2Error::KeyringEmpty => write!(f, "keyring has no keys"),
            V2Error::KeyIdMismatch { key_id, public_key_hex } => write!(
                f,
                "key_id {key_id} does not match public_key_hex {public_key_hex}"
            ),
            V2Error::Expired { expires_at, now } => {
                write!(f, "allowlist expired at {expires_at} (now {now})")
            }
            V2Error::NotYetValid { issued_at, now } => {
                write!(f, "allowlist not yet valid (issued_at {issued_at}, now {now})")
            }
            V2Error::InvalidWindow { issued_at, expires_at } => write!(
                f,
                "invalid window: issued_at {issued_at} >= expires_at {expires_at}"
            ),
            V2Error::DowngradeRejected { stored, candidate } => write!(
                f,
                "downgrade rejected: candidate sequence {candidate} < stored {stored}"
            ),
            V2Error::DigestMismatch { stored_hex, candidate_hex } => write!(
                f,
                "replay rejected: sequence matches but digest differs ({stored_hex} vs {candidate_hex})"
            ),
            V2Error::NoSequence => write!(f, "v2 document missing sequence"),
        }
    }
}

impl std::error::Error for V2Error {}

// ---------------------------------------------------------------------------
// v2 types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Key {
    pub key_id: String,
    pub public_key_hex: String,
    pub valid_from: i64,
    pub valid_until: i64,
    #[serde(default)]
    pub retired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Keyring {
    pub keys: Vec<V2Key>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Entry {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Allowlist {
    pub format: String,
    pub version: u64,
    pub sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signed_by: String,
    pub keyring: V2Keyring,
    pub entries: Vec<V2Entry>,
    pub signature_hex: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses a RUNTIME allowlist. Only version 2 is accepted.
///
/// Version 1 documents are migration-only (see `crate::migrate`): they are
/// rejected here with `LegacyVersionMigrationOnly`. Any other version is
/// `UnsupportedVersion`. A missing or duplicated `version` key is an error.
pub fn parse_v2(bytes: &[u8]) -> Result<V2Allowlist, V2Error> {
    // A struct probe (not a Value) so a duplicate `version` key is an error
    // instead of silently keeping the last one.
    #[derive(Deserialize)]
    struct Probe {
        version: Option<u64>,
    }
    let probe: Probe =
        serde_json::from_slice(bytes).map_err(|e| V2Error::Json(e.to_string()))?;
    let version = probe
        .version
        .ok_or_else(|| V2Error::BadFormat("missing version".into()))?;

    match version {
        2 => serde_json::from_slice(bytes).map_err(|e| V2Error::Json(e.to_string())),
        1 => Err(V2Error::LegacyVersionMigrationOnly(1)),
        other => Err(V2Error::UnsupportedVersion(other)),
    }
}

/// Verifies a v2 document against a TRUSTED keyring supplied by the caller.
///
/// The document carries its own keyring, so the signer must also appear
/// (same key_id and public key) in `trusted`; otherwise anyone could sign a
/// document with a keyring of their own. Then runs `verify_v2`, which checks
/// the signature over the canonical bytes before key validity and sequence.
pub fn verify_v2_trusted(
    doc: &V2Allowlist,
    trusted: &crate::allowlist::Keyring,
    now: i64,
    stored: Option<(u64, &str)>,
) -> Result<(), V2Error> {
    let signer = doc
        .keyring
        .keys
        .iter()
        .find(|k| k.key_id == doc.signed_by)
        .ok_or_else(|| V2Error::SignedByUnknown(doc.signed_by.clone()))?;
    if !trusted
        .keys
        .iter()
        .any(|t| t.key_id == signer.key_id && t.public_key_hex == signer.public_key_hex)
    {
        return Err(V2Error::SignerNotTrusted(signer.key_id.clone()));
    }
    verify_v2(doc, now, stored)
}

// ---------------------------------------------------------------------------
// Canonicalization + verification
// ---------------------------------------------------------------------------

/// SHA-256 of the canonical JSON (signature_hex removed, keys sorted).
pub fn canonical_digest_hex(doc: &V2Allowlist) -> Result<String, V2Error> {
    let v = canonical_value(doc)?;
    let bytes = serde_json::to_vec(&v).map_err(|e| V2Error::Json(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

fn canonical_value(doc: &V2Allowlist) -> Result<serde_json::Value, V2Error> {
    let mut v = serde_json::to_value(doc).map_err(|e| V2Error::Json(e.to_string()))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signature_hex");
    }
    Ok(sort_json(v))
}

fn sort_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, val)| (k, sort_json(val))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json).collect())
        }
        other => other,
    }
}

/// Verifies a v2 document. `stored` is `(sequence, canonical_digest_hex)` from
/// the previous accepted document, or `None` on first run.
pub fn verify_v2(
    doc: &V2Allowlist,
    now: i64,
    stored: Option<(u64, &str)>,
) -> Result<(), V2Error> {
    if doc.version != 2 {
        return Err(V2Error::UnsupportedVersion(doc.version));
    }
    if doc.format != "passaura-allowlist" {
        return Err(V2Error::BadFormat(format!("format {}", doc.format)));
    }
    if doc.issued_at >= doc.expires_at {
        return Err(V2Error::InvalidWindow {
            issued_at: doc.issued_at,
            expires_at: doc.expires_at,
        });
    }
    if now < doc.issued_at {
        return Err(V2Error::NotYetValid { issued_at: doc.issued_at, now });
    }
    if now >= doc.expires_at {
        return Err(V2Error::Expired { expires_at: doc.expires_at, now });
    }
    if doc.keyring.keys.is_empty() {
        return Err(V2Error::KeyringEmpty);
    }

    // Keyring sanity: unique ids and non-empty validity windows.
    let mut seen = std::collections::BTreeSet::new();
    for k in &doc.keyring.keys {
        if !seen.insert(k.key_id.as_str()) {
            return Err(V2Error::DuplicateKeyId(k.key_id.clone()));
        }
        if k.valid_from >= k.valid_until {
            return Err(V2Error::InvalidKeyWindow(k.key_id.clone()));
        }
    }

    // Find the signing key.
    let signer = doc
        .keyring
        .keys
        .iter()
        .find(|k| k.key_id == doc.signed_by)
        .ok_or_else(|| V2Error::SignedByUnknown(doc.signed_by.clone()))?;

    if signer.retired {
        return Err(V2Error::SignedByRetired(signer.key_id.clone()));
    }
    if !(doc.issued_at >= signer.valid_from && doc.issued_at < signer.valid_until) {
        return Err(V2Error::SignedByNotValidAt {
            key_id: signer.key_id.clone(),
            issued_at: doc.issued_at,
        });
    }

    // key_id must be consistent with the public key.
    if signer.public_key_hex.len() == 64 && is_hex64(&signer.public_key_hex) {
        let derived = derive_key_id(&signer.public_key_hex);
        if derived != signer.key_id {
            return Err(V2Error::KeyIdMismatch {
                key_id: signer.key_id.clone(),
                public_key_hex: signer.public_key_hex.clone(),
            });
        }
    } else if !signer.public_key_hex.is_empty() {
        return Err(V2Error::BadFormat("public_key_hex must be 64 hex".into()));
    } else {
        // Empty pubkey: unverifiable.
        return Err(V2Error::BadFormat("public_key_hex missing".into()));
    }

    // Signature verification.
    if doc.signature_hex.len() != 128 || !is_hex128(&doc.signature_hex) {
        return Err(V2Error::SignatureInvalid);
    }
    let pk_bytes = hex::decode(&signer.public_key_hex)
        .map_err(|_| V2Error::SignatureInvalid)?;
    let sig_bytes = hex::decode(&doc.signature_hex).map_err(|_| V2Error::SignatureInvalid)?;
    let payload = canonical_payload_bytes(doc)?;
    verify_ed25519(&pk_bytes, &payload, &sig_bytes)?;

    // Downgrade / replay check, run only after the signature verified.
    let digest = canonical_digest_hex(doc)?;
    if let Some((seq, stored_digest)) = stored {
        if doc.sequence < seq {
            return Err(V2Error::DowngradeRejected {
                stored: seq,
                candidate: doc.sequence,
            });
        }
        if doc.sequence == seq && digest != stored_digest {
            return Err(V2Error::DigestMismatch {
                stored_hex: stored_digest.to_string(),
                candidate_hex: digest,
            });
        }
    }

    Ok(())
}

pub fn canonical_payload_bytes(doc: &V2Allowlist) -> Result<Vec<u8>, V2Error> {
    let v = canonical_value(doc)?;
    serde_json::to_vec(&v).map_err(|e| V2Error::Json(e.to_string()))
}

fn verify_ed25519(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), V2Error> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let pk_arr: [u8; 32] = pk.try_into().map_err(|_| V2Error::SignatureInvalid)?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| V2Error::SignatureInvalid)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| V2Error::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &signature).map_err(|_| V2Error::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn derive_key_id(public_key_hex: &str) -> String {
    let prefix = public_key_hex.get(..16).unwrap_or(public_key_hex);
    format!("ed25519:{prefix}")
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_hex128(s: &str) -> bool {
    s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU8, Ordering};

    static SEED: AtomicU8 = AtomicU8::new(1);

    fn sign_doc(doc: &mut V2Allowlist, sk: &SigningKey) {
        let payload = canonical_payload_bytes(doc).expect("canonical bytes");
        let sig = sk.sign(&payload);
        doc.signature_hex = hex::encode(sig.to_bytes());
    }

    fn sample_v2(sk: &SigningKey, seq: u64, issued_at: i64) -> V2Allowlist {
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let key_id = derive_key_id(&pk_hex);
        V2Allowlist {
            format: "passaura-allowlist".into(),
            version: 2,
            sequence: seq,
            issued_at,
            expires_at: issued_at + 86400,
            signed_by: key_id.clone(),
            keyring: V2Keyring {
                keys: vec![V2Key {
                    key_id: key_id.clone(),
                    public_key_hex: pk_hex,
                    valid_from: 0,
                    valid_until: issued_at + 86400,
                    retired: false,
                }],
            },
            entries: vec![V2Entry {
                name: "ripgrep".into(),
                version: Some("14.1.0".into()),
                sha256: "a".repeat(64),
            }],
            signature_hex: String::new(),
        }
    }

    #[test]
    fn v2_roundtrip_verify() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        assert!(verify_v2(&doc, 1_700_000_100, None).is_ok());
    }

    #[test]
    fn v2_rejects_tampered_signature() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        doc.entries[0].name = "evil".into();
        let err = verify_v2(&doc, 1_700_000_100, None).unwrap_err();
        assert_eq!(err, V2Error::SignatureInvalid);
    }

    #[test]
    fn v2_rejects_expired() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let err = verify_v2(&doc, 1_700_000_000 + 86401, None).unwrap_err();
        assert!(matches!(err, V2Error::Expired { .. }));
    }

    #[test]
    fn v2_rejects_lower_sequence() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 5, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let err = verify_v2(&doc, 1_700_000_100, Some((10, "deadbeef"))).unwrap_err();
        assert_eq!(err, V2Error::DowngradeRejected { stored: 10, candidate: 5 });
    }

    #[test]
    fn v2_rejects_equal_sequence_different_digest() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 5, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let digest = canonical_digest_hex(&doc).unwrap();
        let other = "0".repeat(64);
        assert_ne!(digest, other);
        let err = verify_v2(&doc, 1_700_000_100, Some((5, &other))).unwrap_err();
        assert!(matches!(err, V2Error::DigestMismatch { .. }));
    }

    #[test]
    fn v2_rejects_unknown_signer() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        doc.signed_by = "ed25519:ffffffffffffffff".into();
        let err = verify_v2(&doc, 1_700_000_100, None).unwrap_err();
        assert!(matches!(err, V2Error::SignedByUnknown(_)));
    }

    #[test]
    fn v2_rejects_retired_signer() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        doc.keyring.keys[0].retired = true;
        let err = verify_v2(&doc, 1_700_000_100, None).unwrap_err();
        assert!(matches!(err, V2Error::SignedByRetired(_)));
    }

    #[test]
    fn parse_v2_accepts_v2_only() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let v2_bytes = serde_json::to_vec(&doc).unwrap();
        assert_eq!(parse_v2(&v2_bytes).unwrap().version, 2);
    }

    #[test]
    fn parse_v2_rejects_v1_at_runtime() {
        let v1_bytes = br#"{"version":1,"issued_at":1700000000,"expires_at":1700086400,"key_id":"ed25519:aaaaaaaaaaaaaaaa","entries":[],"signature":"00"}"#;
        assert_eq!(
            parse_v2(v1_bytes).unwrap_err(),
            V2Error::LegacyVersionMigrationOnly(1)
        );
        // text-v1 shape has no `version` key at all.
        let text_v1 = br#"{"signed_by":"k","signature_hex":"","issued_at":1,"expires_at":2,"packages":[]}"#;
        assert!(matches!(parse_v2(text_v1).unwrap_err(), V2Error::BadFormat(_)));
    }

    #[test]
    fn parse_v2_rejects_unknown_versions() {
        for bytes in [&br#"{"version":3}"#[..], &br#"{"version":0}"#[..], &br#"{"version":99}"#[..]] {
            assert!(matches!(
                parse_v2(bytes).unwrap_err(),
                V2Error::UnsupportedVersion(_)
            ));
        }
        assert!(parse_v2(br#"{"version":"2"}"#).is_err());
        assert!(parse_v2(br#"{"version":null}"#).is_err());
    }

    #[test]
    fn v2_payload_relabelled_as_v1_is_rejected() {
        // Type confusion: take a valid signed v2 document and change only its
        // version to 1. It must not be accepted at runtime.
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let mut v: serde_json::Value = serde_json::to_value(&doc).unwrap();
        v["version"] = serde_json::json!(1);
        let bytes = serde_json::to_vec(&v).unwrap();
        assert_eq!(parse_v2(&bytes).unwrap_err(), V2Error::LegacyVersionMigrationOnly(1));
        // Same bytes as a typed v2 document fail verification too.
        let mut relabelled = doc.clone();
        relabelled.version = 1;
        assert!(verify_v2(&relabelled, 1_700_000_100, None).is_err());
    }

    #[test]
    fn unsigned_sequence_zero_document_fails_verification() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 0, 1_700_000_000);
        doc.signature_hex = String::new();
        assert_eq!(
            verify_v2(&doc, 1_700_000_100, None).unwrap_err(),
            V2Error::SignatureInvalid
        );
        // Once signed, sequence 0 itself is acceptable on a fresh state.
        sign_doc(&mut doc, &sk);
        assert!(verify_v2(&doc, 1_700_000_100, None).is_ok());
    }

    #[test]
    fn verify_v2_trusted_requires_signer_in_trusted_ring() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let other = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let good = crate::allowlist::Keyring {
            keys: vec![crate::allowlist::KeyEntry { key_id: derive_key_id(&pk), public_key_hex: pk.clone() }],
        };
        assert!(verify_v2_trusted(&doc, &good, 1_700_000_100, None).is_ok());
        let opk = hex::encode(other.verifying_key().to_bytes());
        let bad = crate::allowlist::Keyring {
            keys: vec![crate::allowlist::KeyEntry { key_id: derive_key_id(&opk), public_key_hex: opk }],
        };
        assert!(matches!(
            verify_v2_trusted(&doc, &bad, 1_700_000_100, None).unwrap_err(),
            V2Error::SignerNotTrusted(_)
        ));
    }

    #[test]
    fn downgrade_rejected_after_valid_signature() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 2, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let digest = canonical_digest_hex(&doc).unwrap();
        assert!(matches!(
            verify_v2(&doc, 1_700_000_100, Some((3, &digest))).unwrap_err(),
            V2Error::DowngradeRejected { stored: 3, candidate: 2 }
        ));
    }

    #[test]
    fn key_id_mismatch_rejected() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        // Corrupt the key_id so it no longer matches the pubkey prefix.
        doc.signed_by = "ed25519:0000000000000000".into();
        doc.keyring.keys[0].key_id = "ed25519:0000000000000000".into();
        let err = verify_v2(&doc, 1_700_000_100, None).unwrap_err();
        assert!(matches!(err, V2Error::KeyIdMismatch { .. }));
    }
}

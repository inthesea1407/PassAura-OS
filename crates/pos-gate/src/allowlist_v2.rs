//! Canonical allowlist format v2 (rotation format) with v1 migration.
//!
//! v1 is the single-key format in `allowlist.rs`. v2 adds a signed keyring
//! with per-key validity windows, a monotonic sequence for downgrade
//! rejection, and a `signed_by` field binding the signature to a ring member.
//!
//! This module does not modify `allowlist.rs`. It parses v1 for migration
//! only; new documents must be v2.

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
}

impl fmt::Display for V2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V2Error::Json(m) => write!(f, "v2 json error: {m}"),
            V2Error::UnsupportedVersion(v) => write!(f, "unsupported allowlist version {v}"),
            V2Error::BadFormat(m) => write!(f, "bad allowlist format: {m}"),
            V2Error::SignatureInvalid => write!(f, "signature invalid"),
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
// v1 types (legacy, parse only)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V1Allowlist {
    pub version: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    pub entries: Vec<V1Entry>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V1Entry {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses either v1 or v2 by sniffing `version`. Returns the v2 document,
/// converting v1 in memory. v1 signatures are **not** trusted or re-used;
/// the converted document has an empty `signature_hex` and must be re-signed.
pub fn parse_any(bytes: &[u8]) -> Result<V2Allowlist, V2Error> {
    let probe: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| V2Error::Json(e.to_string()))?;
    let version = probe
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| V2Error::BadFormat("missing version".into()))?;

    match version {
        2 => serde_json::from_slice(bytes).map_err(|e| V2Error::Json(e.to_string())),
        1 => {
            let v1: V1Allowlist =
                serde_json::from_slice(bytes).map_err(|e| V2Error::Json(e.to_string()))?;
            // v1 has no public key in the document. The caller must supply it.
            // For parse-only, we leave public_key_hex empty and the verifier
            // rejects it unless the caller fills it via `attach_v1_pubkey`.
            Ok(convert_v1_to_v2(&v1, ""))
        }
        other => Err(V2Error::UnsupportedVersion(other)),
    }
}

/// Converts v1 to v2. `public_key_hex` is the trusted public key for the v1
/// `key_id`; the caller supplies it from the keyring they already trust.
/// If empty, the result has an empty `public_key_hex` and will fail
/// verification until the caller fills it.
pub fn convert_v1_to_v2(v1: &V1Allowlist, public_key_hex: &str) -> V2Allowlist {
    V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence: 0, // v1 has no sequence; 0 is the floor.
        issued_at: v1.issued_at,
        expires_at: v1.expires_at,
        signed_by: v1.key_id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id: v1.key_id.clone(),
                public_key_hex: public_key_hex.to_string(),
                valid_from: 0,
                valid_until: v1.expires_at,
                retired: false,
            }],
        },
        entries: v1
            .entries
            .iter()
            .map(|e| V2Entry {
                name: e.name.clone(),
                version: e.version.clone(),
                sha256: e.sha256.clone(),
            })
            .collect(),
        // v1 signature is over different canonical bytes; do not carry it.
        signature_hex: String::new(),
    }
}

/// Fills in the v1 public key after `parse_any` for a v1 document.
pub fn attach_v1_pubkey(doc: &mut V2Allowlist, public_key_hex: &str) -> Result<(), V2Error> {
    if doc.version != 2 || doc.keyring.keys.len() != 1 {
        return Err(V2Error::BadFormat("not a converted v1 document".into()));
    }
    let k = &mut doc.keyring.keys[0];
    if !public_key_hex.is_empty() && !is_hex64(public_key_hex) {
        return Err(V2Error::BadFormat("public_key_hex must be 64 hex".into()));
    }
    k.public_key_hex = public_key_hex.to_string();
    Ok(())
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

    // Downgrade / replay check.
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
        // Empty pubkey: only allowed for a freshly converted v1 doc before
        // attach_v1_pubkey. Treat as unverifiable.
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

    Ok(())
}

fn canonical_payload_bytes(doc: &V2Allowlist) -> Result<Vec<u8>, V2Error> {
    let v = canonical_value(doc)?;
    serde_json::to_vec(&v).map_err(|e| V2Error::Json(e.to_string()))
}

fn verify_ed25519(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), V2Error> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_arr: [u8; 32] = pk.try_into().map_err(|_| V2Error::SignatureInvalid)?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| V2Error::SignatureInvalid)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| V2Error::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &signature).map_err(|_| V2Error::SignatureInvalid)
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
    fn v1_converts_and_attaches_pubkey() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let key_id = derive_key_id(&pk_hex);
        let v1 = V1Allowlist {
            version: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            key_id: key_id.clone(),
            entries: vec![V1Entry {
                name: "ripgrep".into(),
                version: Some("14.1.0".into()),
                sha256: "a".repeat(64),
            }],
            signature: "00".repeat(64),
        };
        let mut v2 = convert_v1_to_v2(&v1, "");
        attach_v1_pubkey(&mut v2, &pk_hex).unwrap();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.sequence, 0);
        assert_eq!(v2.keyring.keys.len(), 1);
        assert_eq!(v2.keyring.keys[0].public_key_hex, pk_hex);
        assert!(v2.signature_hex.is_empty());
    }

    #[test]
    fn parse_any_dispatches_v1_and_v2() {
        let sk = SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32]);
        let mut doc = sample_v2(&sk, 1, 1_700_000_000);
        sign_doc(&mut doc, &sk);
        let v2_bytes = serde_json::to_vec(&doc).unwrap();
        assert_eq!(parse_any(&v2_bytes).unwrap().version, 2);

        let v1_bytes = br#"{"version":1,"issued_at":1700000000,"expires_at":1700086400,"key_id":"ed25519:aaaaaaaaaaaaaaaa","entries":[],"signature":"00"}"#;
        let parsed = parse_any(v1_bytes).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.sequence, 0);
    }

    #[test]
    fn parse_any_rejects_unknown_version() {
        let bytes = br#"{"version":3}"#;
        assert!(matches!(
            parse_any(bytes).unwrap_err(),
            V2Error::UnsupportedVersion(3)
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

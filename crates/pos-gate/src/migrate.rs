//! Offline, one-way migration of a legacy text-v1 allowlist to an UNSIGNED v2.
//!
//! Only the text-v1 shape (`allowlist::AllowlistDoc`: signed_by, signature_hex,
//! issued_at, expires_at, packages[name,version]) is supported. Every other
//! shape is rejected, including documents that carry a `version` key: their
//! authenticity is never inferred from structure.
//!
//! Rules:
//! - The v1 signature is verified with the original v1 rules (signed bytes
//!   unchanged) using `verify_strict`, against a key from the TRUSTED keyring
//!   the caller supplies. A key embedded in the document is never used.
//! - v1 entries carry no sha256, but v2 entries need one. The operator
//!   supplies them (`name@version` -> lowercase hex sha256). A missing hash
//!   fails the migration and lists every missing entry. This code checks the
//!   hash FORMAT only; it cannot know whether a hash matches the real
//!   application file.
//! - The result has sequence 0 and an empty signature. It fails `verify_v2`
//!   until it is newly signed (the v1 signature is not carried over: v2 signs
//!   different bytes). Issue/expiry times are copied; the operator may need to
//!   edit times or the key window before signing.

use crate::allowlist::{verify_allowlist, AllowlistDoc, GateError, Keyring};
use crate::allowlist_v2::{derive_key_id, V2Allowlist, V2Entry, V2Key, V2Keyring};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateError {
    /// Not a text-v1 document (wrong shape, has a `version` key, or bad JSON).
    NotTextV1(String),
    /// Legacy signature, key or time check failed.
    Legacy(GateError),
    /// The trusted key's id is not derived from its public key.
    KeyIdMismatch(String),
    /// Operator hash map is invalid.
    BadHashMap(String),
    /// Entries without an operator-supplied sha256 (`name@version`).
    MissingHashes(Vec<String>),
    /// Times do not fit the v2 types.
    TimeOutOfRange,
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTextV1(m) => write!(f, "not a supported text-v1 allowlist: {m}"),
            Self::Legacy(e) => write!(f, "legacy v1 verification failed: {e}"),
            Self::KeyIdMismatch(k) => write!(f, "trusted key id {k} does not match its public key"),
            Self::BadHashMap(m) => write!(f, "invalid sha256 map: {m}"),
            Self::MissingHashes(v) => write!(f, "missing sha256 for: {}", v.join(", ")),
            Self::TimeOutOfRange => write!(f, "issued_at/expires_at out of range"),
        }
    }
}
impl std::error::Error for MigrateError {}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parses the operator map: a JSON object `{"name@version": "<64 lowercase hex>"}`.
pub fn parse_sha256_map(bytes: &[u8]) -> Result<BTreeMap<String, String>, MigrateError> {
    let m: BTreeMap<String, String> =
        serde_json::from_slice(bytes).map_err(|e| MigrateError::BadHashMap(e.to_string()))?;
    for (k, v) in &m {
        if !is_sha256_hex(v) {
            return Err(MigrateError::BadHashMap(format!(
                "value for {k} is not 64 lowercase hex characters"
            )));
        }
    }
    Ok(m)
}

/// Migrates raw text-v1 bytes. `now` is unix seconds (legacy validity check).
pub fn migrate_text_v1(
    bytes: &[u8],
    trusted: &Keyring,
    hashes: &BTreeMap<String, String>,
    now: u64,
) -> Result<V2Allowlist, MigrateError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| MigrateError::NotTextV1(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| MigrateError::NotTextV1("not a JSON object".into()))?;
    for foreign in [
        "version",
        "format",
        "keyring",
        "key_id",
        "entries",
        "signature",
        "sequence",
    ] {
        if obj.contains_key(foreign) {
            return Err(MigrateError::NotTextV1(format!(
                "unexpected field `{foreign}`"
            )));
        }
    }
    let doc = AllowlistDoc::from_json(bytes).map_err(|e| MigrateError::NotTextV1(e.to_string()))?;

    // 1. Original signature over the original signed bytes, strict, trusted key.
    verify_allowlist(trusted, &doc, now).map_err(MigrateError::Legacy)?;

    // 2. Trusted key becomes the v2 ring member. Never a key from the document.
    let key = trusted
        .keys
        .iter()
        .find(|k| k.key_id == doc.signed_by)
        .ok_or_else(|| MigrateError::Legacy(GateError::UnknownKey(doc.signed_by.clone())))?;
    if derive_key_id(&key.public_key_hex) != key.key_id {
        return Err(MigrateError::KeyIdMismatch(key.key_id.clone()));
    }
    let issued_at = i64::try_from(doc.issued_at).map_err(|_| MigrateError::TimeOutOfRange)?;
    let expires_at = i64::try_from(doc.expires_at).map_err(|_| MigrateError::TimeOutOfRange)?;

    // 3. Operator-supplied hashes; fail with the full missing list.
    let mut missing = Vec::new();
    let mut entries = Vec::new();
    for p in &doc.packages {
        let id = format!("{}@{}", p.name, p.version);
        match hashes.get(&id) {
            Some(h) => entries.push(V2Entry {
                name: p.name.clone(),
                version: Some(p.version.clone()),
                sha256: h.clone(),
            }),
            None => missing.push(id),
        }
    }
    if !missing.is_empty() {
        missing.sort();
        missing.dedup();
        return Err(MigrateError::MissingHashes(missing));
    }

    Ok(V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence: 0,
        issued_at,
        expires_at,
        signed_by: key.key_id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id: key.key_id.clone(),
                public_key_hex: key.public_key_hex.clone(),
                valid_from: 0,
                valid_until: expires_at,
                retired: false,
            }],
        },
        entries,
        signature_hex: String::new(),
    })
}

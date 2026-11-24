
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FORMAT_VERSION: u32 = 1;
const MAX_DOCUMENT_ENTRIES: usize = 100_000;
const MAX_KEY_ID_LENGTH: usize = 128;
const MAX_NAME_LENGTH: usize = 4096;
const MAX_PUBLISHER_LENGTH: usize = 4096;
const MAX_SIGNATURE_LENGTH: usize = 256;

/// An allowlisted package.
///
/// sha256 is the lowercase or uppercase hexadecimal representation of
/// exactly 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub name: String,
    pub publisher: String,
    pub sha256: String,
}

/// Signed allowlist document.
///
/// The signature is detached from the canonical signing payload but
/// stored alongside the document for convenient distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistDocument {
    pub version: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub key_id: String,
    pub entries: Vec<AllowlistEntry>,
    pub signature: Option<String>,
}

/// Public key trusted by the device.
///
/// retire_at=None means the key has no scheduled retirement.
/// A key with retire_at is accepted only while now < retire_at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPublicKey {
    pub key_id: String,
    pub public_key_base64: String,
    pub retire_at: Option<u64>,
}

/// A verification error. Avoid including document contents or secrets
/// in error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistError {
    InvalidVersion,
    InvalidTimeRange,
    IssuedInFuture,
    Expired,
    UnknownKey,
    KeyRetired,
    InvalidKey,
    InvalidSignature,
    MissingSignature,
    InvalidEncoding,
    InvalidEntry,
    DuplicateEntry,
    TooManyEntries,
    InvalidKeyId,
    AmbiguousKey,
}

impl std::fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for AllowlistError {}

fn validate_document(doc: &AllowlistDocument) -> Result<(), AllowlistError> {
    if doc.version != FORMAT_VERSION {
        return Err(AllowlistError::InvalidVersion);
    }

    if doc.issued_at >= doc.expires_at {
        return Err(AllowlistError::InvalidTimeRange);
    }

    if doc.key_id.is_empty() || doc.key_id.len() > MAX_KEY_ID_LENGTH {
        return Err(AllowlistError::InvalidKeyId);
    }

    if doc.entries.len() > MAX_DOCUMENT_ENTRIES {
        return Err(AllowlistError::TooManyEntries);
    }

    let mut seen = BTreeSet::new();

    for entry in &doc.entries {
        if entry.name.trim().is_empty()
            || entry.name.len() > MAX_NAME_LENGTH
            || entry.publisher.trim().is_empty()
            || entry.publisher.len() > MAX_PUBLISHER_LENGTH
            || !valid_sha256(&entry.sha256)
        {
            return Err(AllowlistError::InvalidEntry);
        }

        let normalized = (
            entry.name.trim().to_owned(),
            entry.publisher.trim().to_owned(),
            entry.sha256.to_ascii_lowercase(),
        );

        if !seen.insert(normalized) {
            return Err(AllowlistError::DuplicateEntry);
        }
    }

    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Canonical signing payload.
///
/// Format:
/// - domain separator
/// - u32 version (big endian)
/// - u64 issued_at (big endian)
/// - u64 expires_at (big endian)
/// - length-prefixed key_id
/// - u32 entry count
/// - entries sorted lexicographically by (name, publisher, sha256)
/// - each field encoded as u32 byte length + UTF-8 bytes
///
/// The signature field is intentionally excluded.
///
/// This is independent of JSON whitespace, key ordering, or serialization.
pub fn canonical_bytes(
    doc: &AllowlistDocument,
) -> Result<Vec<u8>, AllowlistError> {
    validate_document(doc)?;

    let mut entries = doc.entries.clone();
    entries.sort_by(|a, b| {
        (&a.name, &a.publisher, &a.sha256.to_ascii_lowercase())
            .cmp(&(
                &b.name,
                &b.publisher,
                &b.sha256.to_ascii_lowercase(),
            ))
    });

    let mut out = Vec::new();
    out.extend_from_slice(b"PassAuraOS-Allowlist-Signature-v1\0");

    out.extend_from_slice(&doc.version.to_be_bytes());
    out.extend_from_slice(&doc.issued_at.to_be_bytes());
    out.extend_from_slice(&doc.expires_at.to_be_bytes());

    append_field(&mut out, doc.key_id.as_bytes())?;

    let count = u32::try_from(entries.len())
        .map_err(|_| AllowlistError::TooManyEntries)?;
    out.extend_from_slice(&count.to_be_bytes());

    for entry in entries {
        append_field(&mut out, entry.name.as_bytes())?;
        append_field(&mut out, entry.publisher.as_bytes())?;
        append_field(&mut out, entry.sha256.to_ascii_lowercase().as_bytes())?;
    }

    Ok(out)
}

fn append_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), AllowlistError> {
    let len = u32::try_from(field.len())
        .map_err(|_| AllowlistError::InvalidEncoding)?;

    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Signs the canonical document with the supplied Ed25519 key.
///
/// The caller must ensure doc.key_id identifies the public key
/// corresponding to secret_key in the trusted keyring.
pub fn sign_allowlist(
    secret_key: &SigningKey,
    doc: &mut AllowlistDocument,
) -> Result<(), AllowlistError> {
    doc.signature = None;

    let payload = canonical_bytes(doc)?;
    let signature = secret_key.sign(&payload);

    doc.signature = Some(STANDARD.encode(signature.to_bytes()));
    Ok(())
}

/// Verifies a signed allowlist against the trusted public-key set.
///
/// A key with retire_at is accepted only while now < retire_at.
/// The caller supplies the current Unix timestamp in seconds.
pub fn verify_allowlist(
    public_keys: &[TrustedPublicKey],
    doc: &AllowlistDocument,
    now: u64,
) -> Result<(), AllowlistError> {
    validate_document(doc)?;

    if doc.issued_at > now {
        return Err(AllowlistError::IssuedInFuture);
    }

    if now >= doc.expires_at {
        return Err(AllowlistError::Expired);
    }

    // Two trusted keys with the same id make the keyring ambiguous: fail closed.
    let mut matching = public_keys.iter().filter(|k| k.key_id == doc.key_id);
    let key = matching.next().ok_or(AllowlistError::UnknownKey)?;
    if matching.next().is_some() {
        return Err(AllowlistError::AmbiguousKey);
    }

    if let Some(retire_at) = key.retire_at {
        if now >= retire_at {
            return Err(AllowlistError::KeyRetired);
        }
    }

    if key.key_id.is_empty() || key.key_id.len() > MAX_KEY_ID_LENGTH {
        return Err(AllowlistError::InvalidKeyId);
    }

    let key_bytes = STANDARD
        .decode(&key.public_key_base64)
        .map_err(|_| AllowlistError::InvalidEncoding)?;

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AllowlistError::InvalidKey)?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| AllowlistError::InvalidKey)?;

    let signature_text = doc
        .signature
        .as_ref()
        .ok_or(AllowlistError::MissingSignature)?;

    if signature_text.len() > MAX_SIGNATURE_LENGTH {
        return Err(AllowlistError::InvalidEncoding);
    }

    let signature_bytes = STANDARD
        .decode(signature_text)
        .map_err(|_| AllowlistError::InvalidEncoding)?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AllowlistError::InvalidSignature)?;

    let payload = canonical_bytes(doc)?;

    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| AllowlistError::InvalidSignature)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU8, Ordering};

    static SEED: AtomicU8 = AtomicU8::new(1);

    fn keypair() -> SigningKey {
        SigningKey::from_bytes(&[SEED.fetch_add(1, Ordering::SeqCst); 32])
    }

    fn trusted(key_id: &str, key: &SigningKey, retire_at: Option<u64>) -> TrustedPublicKey {
        TrustedPublicKey {
            key_id: key_id.into(),
            public_key_base64: STANDARD.encode(key.verifying_key().to_bytes()),
            retire_at,
        }
    }

    fn doc(key_id: &str) -> AllowlistDocument {
        AllowlistDocument {
            version: 1,
            issued_at: 100,
            expires_at: 500,
            key_id: key_id.into(),
            entries: vec![
                AllowlistEntry {
                    name: "VaultA".into(),
                    publisher: "PublisherA".into(),
                    sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                },
                AllowlistEntry {
                    name: "VaultB".into(),
                    publisher: "PublisherB".into(),
                    sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                },
            ],
            signature: None,
        }
    }

    #[test]
    fn signing_round_trip() {
        let key = keypair();
        let mut document = doc("key-1");

        sign_allowlist(&key, &mut document).unwrap();

        verify_allowlist(&[trusted("key-1", &key, None)], &document, 200).unwrap();
    }

    #[test]
    fn duplicate_trusted_key_ids_are_ambiguous() {
        let key = keypair();
        let other = keypair();
        let mut document = doc("key-1");
        sign_allowlist(&key, &mut document).unwrap();
        let ring = [trusted("key-1", &key, None), trusted("key-1", &other, None)];
        assert_eq!(verify_allowlist(&ring, &document, 200), Err(AllowlistError::AmbiguousKey));
    }

    #[test]
    fn tampered_entry_rejected() {
        let key = keypair();
        let mut document = doc("key-1");

        sign_allowlist(&key, &mut document).unwrap();
        document.entries[0].name = "ChangedName".into();

        assert_eq!(
            verify_allowlist(&[trusted("key-1", &key, None)], &document, 200),
            Err(AllowlistError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let signing_key = keypair();
        let wrong_key = keypair();
        let mut document = doc("key-1");

        sign_allowlist(&signing_key, &mut document).unwrap();

        assert_eq!(
            verify_allowlist(
                &[trusted("key-1", &wrong_key, None)],
                &document,
                200
            ),
            Err(AllowlistError::InvalidSignature)
        );
    }

    #[test]
    fn expired_document_rejected() {
        let key = keypair();
        let mut document = doc("key-1");

        sign_allowlist(&key, &mut document).unwrap();

        assert_eq!(
            verify_allowlist(&[trusted("key-1", &key, None)], &document, 500),
            Err(AllowlistError::Expired)
        );
    }

    #[test]
    fn future_issued_document_rejected() {
        let key = keypair();
        let mut document = doc("key-1");

        sign_allowlist(&key, &mut document).unwrap();

        assert_eq!(
            verify_allowlist(&[trusted("key-1", &key, None)], &document, 99),
            Err(AllowlistError::IssuedInFuture)
        );
    }

    #[test]
    fn rotation_overlap_accepts_old_and_new_keys() {
        let old_key = keypair();
        let new_key = keypair();

        let mut old_document = doc("old");
        let mut new_document = doc("new");

        sign_allowlist(&old_key, &mut old_document).unwrap();
        sign_allowlist(&new_key, &mut new_document).unwrap();

        let overlap = vec![
            trusted("old", &old_key, Some(300)),
            trusted("new", &new_key, None),
        ];

        verify_allowlist(&overlap, &old_document, 200).unwrap();
        verify_allowlist(&overlap, &new_document, 200).unwrap();

        assert_eq!(
            verify_allowlist(&overlap, &old_document, 300),
            Err(AllowlistError::KeyRetired)
        );

        verify_allowlist(&overlap, &new_document, 300).unwrap();
    }

    #[test]
    fn unknown_key_rejected() {
        let key = keypair();
        let mut document = doc("missing-key");

        sign_allowlist(&key, &mut document).unwrap();

        assert_eq!(
            verify_allowlist(&[], &document, 200),
            Err(AllowlistError::UnknownKey)
        );
    }

    #[test]
    fn malformed_json_rejected() {
        assert!(serde_json::from_str::<AllowlistDocument>("{").is_err());
        assert!(serde_json::from_str::<AllowlistDocument>(
            r#"{"version":"not-a-number"}"#
        )
        .is_err());
    }

    #[test]
    fn signature_is_independent_of_entry_order() {
        let key = keypair();
        let mut first = doc("key-1");
        let mut second = doc("key-1");

        second.entries.reverse();

        assert_eq!(
            canonical_bytes(&first).unwrap(),
            canonical_bytes(&second).unwrap()
        );

        sign_allowlist(&key, &mut first).unwrap();

        verify_allowlist(&[trusted("key-1", &key, None)], &first, 200).unwrap();
    }

    #[test]
    fn duplicate_entries_rejected() {
        let mut document = doc("key-1");
        document.entries.push(document.entries[0].clone());

        assert_eq!(
            canonical_bytes(&document),
            Err(AllowlistError::DuplicateEntry)
        );
    }

    #[test]
    fn expired_key_rejected() {
        let key = keypair();
        let mut document = doc("old");

        sign_allowlist(&key, &mut document).unwrap();

        assert_eq!(
            verify_allowlist(&[trusted("old", &key, Some(200))], &document, 200),
            Err(AllowlistError::KeyRetired)
        );
    }
}

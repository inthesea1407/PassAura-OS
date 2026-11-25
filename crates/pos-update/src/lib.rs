//! Signed update-manifest verification. TUF-inspired, NOT TUF. See
//! `docs/UPDATE_CHANNEL.md`. No security guarantee is claimed.
//!
//! Pure functions only: no file, network, clock or key-holding code. The caller
//! supplies the bytes, the trusted key set, the threshold, `now` and the
//! previously accepted state, and persists the returned state itself.
//!
//! Units: every time value is an unsigned count of whole seconds since the Unix
//! epoch (`u64`). `skew_secs` and `max_validity` are also whole seconds.
//!
//! Envelope (JSON): `{"manifest":{...},"signatures":[{"key_id":..,"sig_hex":..}]}`.
//! Signed bytes: `b"pos-update-manifest-v1\n"` followed by the compact,
//! sorted-key JSON of the `manifest` object only (signatures are not part of it).

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Domain-separation prefix (ends with LF) placed before the canonical manifest JSON.
pub const SIGN_PREFIX: &[u8] = b"pos-update-manifest-v1\n";
/// Value required in `Manifest::format`.
pub const FORMAT: &str = "pos-update-manifest-v1";
/// Maximum accepted envelope size in bytes (1 MiB).
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Default maximum validity window: 90 days, in seconds.
pub const DEFAULT_MAX_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;
/// Maximum number of signature entries in an envelope.
pub const MAX_SIGNATURES: usize = 256;
/// Maximum number of artifacts in a manifest.
pub const MAX_ARTIFACTS: usize = 1024;
/// Maximum channel length in bytes.
pub const MAX_CHANNEL_LEN: usize = 64;
/// Maximum artifact name length in bytes.
pub const MAX_ARTIFACT_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    /// Opaque label. Never parsed or compared; rollback uses `sequence` only.
    pub version: String,
    /// 64 lowercase hex characters.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub channel: String,
    pub sequence: u64,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds. The manifest is invalid when `now >= expires_at`.
    pub expires_at: u64,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub key_id: String,
    /// 128 lowercase hex characters (Ed25519 signature).
    pub sig_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub manifest: Manifest,
    pub signatures: Vec<SignatureEntry>,
}

/// A key the caller trusts. Valid when `valid_from <= now < valid_until` and not retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub retired: bool,
}

/// Cap on `expires_at - issued_at`. The 90-day default is applied unless the
/// caller explicitly chooses `Disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxValidity {
    Secs(u64),
    Disabled,
}

impl Default for MaxValidity {
    fn default() -> Self {
        MaxValidity::Secs(DEFAULT_MAX_VALIDITY_SECS)
    }
}

#[derive(Debug, Clone)]
pub struct VerifyPolicy<'a> {
    pub keys: &'a [TrustedKey],
    /// Number of distinct trusted signers required: `1 <= threshold <= keys.len()`.
    /// A threshold of 1 is allowed but weak: one key compromise forges updates.
    pub threshold: usize,
    /// Caller-supplied current Unix time in seconds. The device clock is untrusted.
    pub now: u64,
    /// Allowed future `issued_at` (seconds). Default 0.
    pub skew_secs: u64,
    pub max_validity: MaxValidity,
    /// The channel this verification is for. Mandatory; a manifest for any other
    /// channel is rejected before signatures are looked at.
    pub expected_channel: &'a str,
}

impl<'a> VerifyPolicy<'a> {
    pub fn new(
        keys: &'a [TrustedKey],
        threshold: usize,
        now: u64,
        expected_channel: &'a str,
    ) -> Self {
        VerifyPolicy {
            expected_channel,
            keys,
            threshold,
            now,
            skew_secs: 0,
            max_validity: MaxValidity::default(),
        }
    }
}

/// State the caller persists after an accepted manifest. State is per channel:
/// keep one per channel and pass only the one for `expected_channel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedState {
    pub channel: String,
    pub sequence: u64,
    /// SHA-256 over the signed bytes (prefix + canonical manifest JSON).
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    pub state: AcceptedState,
    /// True when `prev` had the same sequence and digest (an idempotent re-accept).
    pub idempotent: bool,
}

/// Closed error set. Variants carry no input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    TooLarge,
    Malformed,
    BadFormat,
    BadManifestField,
    TooManySignatures,
    BadPolicyChannel,
    WrongChannel,
    StateChannelMismatch,
    InconsistentTimes,
    IssuedInFuture,
    Expired,
    ValidityTooLong,
    BadKeySet,
    BadThreshold,
    DuplicateSignerId,
    BadSignature,
    ThresholdNotMet,
    Rollback,
    Fork,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UpdateError::TooLarge => "envelope too large",
            UpdateError::Malformed => "malformed envelope",
            UpdateError::BadFormat => "unsupported manifest format",
            UpdateError::BadManifestField => "invalid manifest field",
            UpdateError::TooManySignatures => "too many signature entries",
            UpdateError::BadPolicyChannel => "invalid expected channel",
            UpdateError::WrongChannel => "manifest is for a different channel",
            UpdateError::StateChannelMismatch => "accepted state is for a different channel",
            UpdateError::InconsistentTimes => "inconsistent manifest times",
            UpdateError::IssuedInFuture => "manifest issued in the future",
            UpdateError::Expired => "manifest expired",
            UpdateError::ValidityTooLong => "manifest validity exceeds limit",
            UpdateError::BadKeySet => "invalid trusted key set",
            UpdateError::BadThreshold => "invalid threshold",
            UpdateError::DuplicateSignerId => "duplicate signer id",
            UpdateError::BadSignature => "invalid signature from trusted key",
            UpdateError::ThresholdNotMet => "not enough distinct trusted signers",
            UpdateError::Rollback => "sequence lower than accepted state",
            UpdateError::Fork => "same sequence with different content",
        };
        f.write_str(s)
    }
}

impl std::error::Error for UpdateError {}

fn sort_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, val)| (k, sort_json(val))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(sort_json).collect())
        }
        o => o,
    }
}

/// The exact bytes that are signed: prefix + compact sorted-key JSON of the manifest.
pub fn signed_bytes(m: &Manifest) -> Result<Vec<u8>, UpdateError> {
    let v = serde_json::to_value(m).map_err(|_| UpdateError::Malformed)?;
    let body = serde_json::to_vec(&sort_json(v)).map_err(|_| UpdateError::Malformed)?;
    let mut out = Vec::with_capacity(SIGN_PREFIX.len() + body.len());
    out.extend_from_slice(SIGN_PREFIX);
    out.extend_from_slice(&body);
    Ok(out)
}

/// SHA-256 of the signed bytes.
pub fn manifest_digest(m: &Manifest) -> Result<[u8; 32], UpdateError> {
    Ok(Sha256::digest(signed_bytes(m)?).into())
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 1..=max bytes of ASCII letters, digits, '.', '_', '-'; no leading dot
/// (so neither "." nor "..").
fn is_safe_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn check_manifest(m: &Manifest) -> Result<(), UpdateError> {
    if m.format != FORMAT {
        return Err(UpdateError::BadFormat);
    }
    if !is_safe_name(&m.channel, MAX_CHANNEL_LEN)
        || m.artifacts.is_empty()
        || m.artifacts.len() > MAX_ARTIFACTS
    {
        return Err(UpdateError::BadManifestField);
    }
    let mut names = BTreeSet::new();
    for a in &m.artifacts {
        if !is_safe_name(&a.name, MAX_ARTIFACT_NAME_LEN)
            || !is_lower_hex(&a.sha256, 64)
            || !names.insert(a.name.as_str())
        {
            return Err(UpdateError::BadManifestField);
        }
    }
    if m.issued_at >= m.expires_at {
        return Err(UpdateError::InconsistentTimes);
    }
    Ok(())
}

fn check_policy(p: &VerifyPolicy<'_>) -> Result<(), UpdateError> {
    let mut ids = BTreeSet::new();
    let mut pks = BTreeSet::new();
    for k in p.keys {
        if k.valid_from > k.valid_until
            || k.key_id.is_empty()
            || !ids.insert(k.key_id.as_str())
            || !pks.insert(k.public_key)
        {
            return Err(UpdateError::BadKeySet);
        }
    }
    if p.threshold < 1 || p.threshold > pks.len() {
        return Err(UpdateError::BadThreshold);
    }
    Ok(())
}

fn check_time(m: &Manifest, p: &VerifyPolicy<'_>) -> Result<(), UpdateError> {
    let latest_issue = p.now.checked_add(p.skew_secs).ok_or(UpdateError::IssuedInFuture)?;
    if m.issued_at > latest_issue {
        return Err(UpdateError::IssuedInFuture);
    }
    if p.now >= m.expires_at {
        return Err(UpdateError::Expired);
    }
    if let MaxValidity::Secs(max) = p.max_validity {
        let span = m
            .expires_at
            .checked_sub(m.issued_at)
            .ok_or(UpdateError::InconsistentTimes)?;
        if span > max {
            return Err(UpdateError::ValidityTooLong);
        }
    }
    Ok(())
}

fn verify_sig(pk: &[u8; 32], msg: &[u8], sig_hex: &str) -> Result<(), UpdateError> {
    if !is_lower_hex(sig_hex, 128) {
        return Err(UpdateError::BadSignature);
    }
    let raw = hex::decode(sig_hex).map_err(|_| UpdateError::BadSignature)?;
    let arr: [u8; 64] = raw.as_slice().try_into().map_err(|_| UpdateError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| UpdateError::BadSignature)?;
    vk.verify_strict(msg, &Signature::from_bytes(&arr))
        .map_err(|_| UpdateError::BadSignature)
}

/// Verify an envelope. Order: size, parse, signature count, manifest fields,
/// expected channel, state channel, key set/threshold, time, signatures, then
/// rollback state. Fails closed; nothing is returned on error.
pub fn verify_envelope(
    bytes: &[u8],
    policy: &VerifyPolicy<'_>,
    prev: Option<&AcceptedState>,
) -> Result<Verified, UpdateError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(UpdateError::TooLarge);
    }
    let env: Envelope = serde_json::from_slice(bytes).map_err(|_| UpdateError::Malformed)?;
    if env.signatures.len() > MAX_SIGNATURES {
        return Err(UpdateError::TooManySignatures);
    }
    check_manifest(&env.manifest)?;
    if !is_safe_name(policy.expected_channel, MAX_CHANNEL_LEN) {
        return Err(UpdateError::BadPolicyChannel);
    }
    if env.manifest.channel != policy.expected_channel {
        return Err(UpdateError::WrongChannel);
    }
    if let Some(p) = prev {
        if p.channel != policy.expected_channel {
            return Err(UpdateError::StateChannelMismatch);
        }
    }
    check_policy(policy)?;
    check_time(&env.manifest, policy)?;

    let mut seen = BTreeSet::new();
    for s in &env.signatures {
        if !seen.insert(s.key_id.as_str()) {
            return Err(UpdateError::DuplicateSignerId);
        }
    }
    let msg = signed_bytes(&env.manifest)?;
    let mut good = 0usize;
    for s in &env.signatures {
        let Some(k) = policy.keys.iter().find(|k| k.key_id == s.key_id) else {
            continue; // unknown signer: not counted
        };
        if k.retired || policy.now < k.valid_from || policy.now >= k.valid_until {
            continue; // retired or out of window: not counted
        }
        verify_sig(&k.public_key, &msg, &s.sig_hex)?; // bad sig from trusted key rejects all
        good += 1; // key ids and public keys are unique in the key set
    }
    if good < policy.threshold {
        return Err(UpdateError::ThresholdNotMet);
    }

    let digest: [u8; 32] = Sha256::digest(&msg).into();
    let mut idempotent = false;
    if let Some(p) = prev {
        if env.manifest.sequence < p.sequence {
            return Err(UpdateError::Rollback);
        }
        if env.manifest.sequence == p.sequence {
            if digest != p.digest {
                return Err(UpdateError::Fork);
            }
            idempotent = true;
        }
    }
    Ok(Verified {
        state: AcceptedState {
            channel: env.manifest.channel.clone(),
            sequence: env.manifest.sequence,
            digest,
        },
        manifest: env.manifest,
        idempotent,
    })
}

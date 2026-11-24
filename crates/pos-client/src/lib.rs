//! PassAura OS registry client.
//!
//! This crate communicates with the `register` and `redeem-key` Edge Functions.
//! HTTP is injectable so tests do not perform network I/O.
//!
//! Hardware attestation is NOT performed here.
//! SHA-256 hashing is not hardware identity verification.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

/// SHA-256(salt || opaque_hardware_id), lowercase hexadecimal.
///
/// The caller is responsible for supplying the salt and opaque identifier.
/// The raw identifier must never be sent to the server.
///
/// This does not prove that the input is hardware-backed or unique.
pub fn salted_hardware_id_hash(salt: &[u8], opaque_hardware_id: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(opaque_hardware_id);
    to_lower_hex(&hasher.finalize())
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }

    out
}

/// Validate the exact contract format: 64 lowercase hexadecimal characters.
pub fn validate_hardware_id_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}


// -----------------------------------------------------------------------------
// Contract request/response types
// -----------------------------------------------------------------------------

/// POST `register`.
///
/// `invite_code` may be empty during the seed registration window.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    pub invite_code: String,
    pub hardware_id_hash: String,
}

// Debug output must never carry the invite code, even in logs.
impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("invite_code", &"<redacted>")
            .field("hardware_id_hash", &self.hardware_id_hash)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    pub device_id: String,
}

/// POST `redeem-key`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedeemRequest {
    pub code: String,
    pub device_id: String,
}

// Debug output must never carry the Premium key.
impl std::fmt::Debug for RedeemRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedeemRequest")
            .field("code", &"<redacted>")
            .field("device_id", &self.device_id)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedeemResponse {
    /// RFC3339 timestamp or null.
    pub premium_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
}


// -----------------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClientError {
    #[error("registration closed")]
    RegistrationClosed,

    #[error("invite invalid or already used")]
    InviteInvalidOrUsed,

    #[error("device revoked")]
    DeviceRevoked,

    #[error("device already registered")]
    DeviceAlreadyRegistered,

    #[error("premium key invalid")]
    KeyInvalid,

    #[error("device invalid")]
    DeviceInvalid,

    #[error("rate limited")]
    RateLimited,

    #[error("bad request")]
    BadRequest,

    #[error("HTTP status {0}")]
    HttpStatus(u16),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("invalid HTTPS URL")]
    InvalidUrl,

    #[error("invalid request")]
    InvalidRequest,

    #[error("invalid response JSON")]
    InvalidResponse,

    #[error("cache error: {0}")]
    Cache(String),
}


// -----------------------------------------------------------------------------
// HTTP transport
// -----------------------------------------------------------------------------

/// Injected HTTP transport.
///
/// Implementations must preserve non-2xx status codes and their response bodies.
/// Transport implementations must not retry internally.
pub trait HttpTransport: Send + Sync {
    fn post(
        &self,
        https_url: &str,
        body_json: &str,
    ) -> Result<HttpResponse, ClientError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}


// -----------------------------------------------------------------------------
// Retry policy
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total attempts, including the first attempt.
    pub max_attempts: usize,

    /// Initial retry delay.
    pub base_delay: Duration,

    /// Maximum retry delay.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(3),
        }
    }
}

fn backoff_delay(policy: &RetryPolicy, retry_index: usize) -> Duration {
    let shift = retry_index.min(31) as u32;
    let multiplier = 1u32.checked_shl(shift).unwrap_or(u32::MAX);

    policy
        .base_delay
        .saturating_mul(multiplier)
        .min(policy.max_delay)
}


// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

pub struct PosClient<T: HttpTransport> {
    transport: T,
    register_url: String,
    redeem_url: String,
    retry: RetryPolicy,
}

impl<T: HttpTransport> PosClient<T> {
    /// Construct the client after validating both endpoint URLs.
    pub fn new(
        transport: T,
        register_url: impl Into<String>,
        redeem_url: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let register_url = register_url.into();
        let redeem_url = redeem_url.into();

        validate_https_url(&register_url)?;
        validate_https_url(&redeem_url)?;

        Ok(Self {
            transport,
            register_url,
            redeem_url,
            retry: RetryPolicy::default(),
        })
    }

    /// Configure retries.
    ///
    /// Attempts are clamped to at least one.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self.retry.max_attempts = self.retry.max_attempts.max(1);
        self
    }

    /// Register a device.
    pub fn register(
        &self,
        request: &RegisterRequest,
    ) -> Result<RegisterResponse, ClientError> {
        if !validate_hardware_id_hash(&request.hardware_id_hash) {
            return Err(ClientError::InvalidRequest);
        }

        let response: RegisterResponse = self.send(&self.register_url, request)?;

        if !is_uuid(&response.device_id) {
            return Err(ClientError::InvalidResponse);
        }

        Ok(response)
    }

    /// Redeem a Premium key.
    pub fn redeem(
        &self,
        request: &RedeemRequest,
    ) -> Result<RedeemResponse, ClientError> {
        if request.code.trim().is_empty() || !is_uuid(&request.device_id) {
            return Err(ClientError::InvalidRequest);
        }

        let response: RedeemResponse = self.send(&self.redeem_url, request)?;

        if let Some(ref premium_until) = response.premium_until {
            if !looks_like_rfc3339(premium_until) {
                return Err(ClientError::InvalidResponse);
            }
        }

        Ok(response)
    }

    fn send<R: Serialize, S: DeserializeOwned>(
        &self,
        url: &str,
        request: &R,
    ) -> Result<S, ClientError> {
        let body = serde_json::to_string(request)
            .map_err(|_| ClientError::InvalidRequest)?;

        let attempts = self.retry.max_attempts.max(1);

        for attempt in 0..attempts {
            let response = self.transport.post(url, &body)?;

            if response.status == 200 {
                return serde_json::from_str(&response.body)
                    .map_err(|_| ClientError::InvalidResponse);
            }

            let retryable = response.status == 429
                || (500..=599).contains(&response.status);

            if retryable && attempt + 1 < attempts {
                let delay = backoff_delay(&self.retry, attempt);

                if !delay.is_zero() {
                    thread::sleep(delay);
                }

                continue;
            }

            return Err(map_error(response.status, &response.body));
        }

        Err(ClientError::HttpStatus(500))
    }
}


// -----------------------------------------------------------------------------
// Contract validation
// -----------------------------------------------------------------------------

/// Validate an HTTPS endpoint.
///
/// This is a conservative validator, not a full standards-compliant URL parser.
/// It rejects userinfo, whitespace, fragments, localhost and malformed authority.
pub fn validate_https_url(input: &str) -> Result<(), ClientError> {
    if input.is_empty()
        || input.chars().any(char::is_whitespace)
        || input.contains('#')
    {
        return Err(ClientError::InvalidUrl);
    }

    let rest = input
        .strip_prefix("https://")
        .ok_or(ClientError::InvalidUrl)?;

    let authority = rest.split(['/', '?']).next().unwrap_or("");

    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with(':')
        || authority.ends_with(':')
    {
        return Err(ClientError::InvalidUrl);
    }

    if authority.chars().any(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(c, '.' | '-' | ':' | '[' | ']'))
    }) {
        return Err(ClientError::InvalidUrl);
    }

    // A port, if present, must be 1..=65535. (IPv6 literals are bracketed.)
    let host_port = authority.rsplit_once(':').filter(|(h, _)| !h.ends_with(']') || h.contains(']'));
    if let Some((h, port)) = host_port {
        let is_v6_inner = h.starts_with('[') && !h.ends_with(']');
        if !is_v6_inner {
            match port.parse::<u32>() {
                Ok(n) if (1..=65535).contains(&n) && port.chars().all(|c| c.is_ascii_digit()) => {}
                _ => return Err(ClientError::InvalidUrl),
            }
        }
    }

    if authority == "localhost"
        || authority.ends_with(".localhost")
        || authority == "127.0.0.1"
        || authority == "[::1]"
    {
        return Err(ClientError::InvalidUrl);
    }

    Ok(())
}

/// Lightweight UUID shape check.
///
/// This checks the canonical 8-4-4-4-12 hexadecimal layout.
/// It does not verify UUID version or variant.
pub fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }

    let bytes = value.as_bytes();

    for &index in &[8usize, 13, 18, 23] {
        if bytes[index] != b'-' {
            return false;
        }
    }

    value.bytes().enumerate().all(|(index, byte)| {
        matches!(index, 8 | 13 | 18 | 23)
            || byte.is_ascii_digit()
            || (b'a'..=b'f').contains(&byte)
            || (b'A'..=b'F').contains(&byte)
    })
}

/// Minimal RFC3339 shape validation.
///
/// This validates the structure, not calendar correctness.
fn looks_like_rfc3339(value: &str) -> bool {
    value.len() >= 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && (value.ends_with('Z') || value.contains('+') || value.rfind('-').map_or(false, |i| i > 10))
}


// -----------------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------------

pub fn map_error(status: u16, body: &str) -> ClientError {
    let code = serde_json::from_str::<ErrorResponse>(body)
        .ok()
        .map(|response| response.error);

    match (status, code.as_deref()) {
        (403, Some("REGISTRATION_CLOSED")) => ClientError::RegistrationClosed,
        (403, Some("INVITE_INVALID_OR_USED")) => ClientError::InviteInvalidOrUsed,
        (403, Some("DEVICE_REVOKED")) => ClientError::DeviceRevoked,
        (403, Some("DEVICE_ALREADY_REGISTERED")) => ClientError::DeviceAlreadyRegistered,
        (403, Some("KEY_INVALID")) => ClientError::KeyInvalid,
        (403, Some("DEVICE_INVALID")) => ClientError::DeviceInvalid,
        (429, _) => ClientError::RateLimited,
        (400, _) => ClientError::BadRequest,
        _ => ClientError::HttpStatus(status),
    }
}


// -----------------------------------------------------------------------------
// Local JSON cache
// -----------------------------------------------------------------------------

/// Local client cache.
///
/// Expiry is cache freshness only. It is not proof that membership or Premium
/// remains valid. This cache is plaintext JSON and must be kept in app-private
/// storage by the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCache {
    pub device_id: String,
    pub premium_until: Option<String>,
    /// Unix timestamp at which this cache becomes stale.
    pub expires_at: u64,
}

impl DeviceCache {
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(unix_now())
    }

    pub fn save_json_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| ClientError::Cache(error.to_string()))?;

        // Write to a sibling temp file, then rename, so an interrupted write
        // never leaves a half-written cache.
        let path = path.as_ref();
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let result = fs::write(&tmp, bytes).and_then(|_| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(|error| ClientError::Cache(error.to_string()))
    }

    pub fn load_json_file(
        path: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        let bytes = fs::read(path)
            .map_err(|error| ClientError::Cache(error.to_string()))?;

        serde_json::from_slice(&bytes)
            .map_err(|error| ClientError::Cache(error.to_string()))
    }

    /// Return None when the cache has expired.
    pub fn load_valid_json_file(
        path: impl AsRef<Path>,
        now_unix: u64,
    ) -> Result<Option<Self>, ClientError> {
        let cache = Self::load_json_file(path)?;

        if cache.is_expired_at(now_unix) {
            Ok(None)
        } else {
            Ok(Some(cache))
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}


// -----------------------------------------------------------------------------
// Optional ureq transport
// -----------------------------------------------------------------------------

#[cfg(feature = "ureq")]
pub struct UreqTransport;

#[cfg(feature = "ureq")]
impl HttpTransport for UreqTransport {
    fn post(
        &self,
        https_url: &str,
        body_json: &str,
    ) -> Result<HttpResponse, ClientError> {
        validate_https_url(https_url)?;

        // Finite timeouts so a stalled server cannot hang the app.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirects(0)
            .build();
        let result = agent
            .post(https_url)
            .set("Content-Type", "application/json")
            .send_string(body_json);

        match result {
            Ok(response) => Ok(HttpResponse {
                status: response.status(),
                body: response.into_string().unwrap_or_default(),
            }),

            Err(ureq::Error::Status(status, response)) => {
                Ok(HttpResponse {
                    status,
                    body: response.into_string().unwrap_or_default(),
                })
            }

            Err(ureq::Error::Transport(error)) => {
                Err(ClientError::Transport(error.to_string()))
            }
        }
    }
}


// -----------------------------------------------------------------------------
// Unit tests — fake transport only, no network
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeTransport {
        responses: Arc<Mutex<Vec<HttpResponse>>>,
        calls: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl HttpTransport for FakeTransport {
        fn post(
            &self,
            url: &str,
            body: &str,
        ) -> Result<HttpResponse, ClientError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_owned(), body.to_owned()));

            let mut responses = self.responses.lock().unwrap();

            if responses.is_empty() {
                return Err(ClientError::Transport(
                    "fake response queue exhausted".into(),
                ));
            }

            Ok(responses.remove(0))
        }
    }

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            body: body.to_owned(),
        }
    }

    fn success(body: &str) -> HttpResponse {
        response(200, body)
    }

    fn fake_client(fake: FakeTransport) -> PosClient<FakeTransport> {
        PosClient::new(
            fake,
            "https://example.test/register",
            "https://example.test/redeem-key",
        )
        .unwrap()
        .with_retry_policy(RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        })
    }

    fn valid_register_request() -> RegisterRequest {
        RegisterRequest {
            invite_code: String::new(),
            hardware_id_hash: "a".repeat(64),
        }
    }

    fn valid_redeem_request() -> RedeemRequest {
        RedeemRequest {
            code: "premium-code".into(),
            device_id: "123e4567-e89b-12d3-a456-426614174000".into(),
        }
    }

    #[test]
    fn hash_is_lowercase_64_hex() {
        let value = salted_hardware_id_hash(b"salt", b"opaque-id");

        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|b| {
            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
        }));
    }

    #[test]
    fn hash_changes_when_salt_changes() {
        assert_ne!(
            salted_hardware_id_hash(b"salt-a", b"device"),
            salted_hardware_id_hash(b"salt-b", b"device")
        );
    }

    #[test]
    fn hash_changes_when_input_changes() {
        assert_ne!(
            salted_hardware_id_hash(b"salt", b"device-a"),
            salted_hardware_id_hash(b"salt", b"device-b")
        );
    }

    #[test]
    fn hash_validator_accepts_lowercase_hex() {
        assert!(validate_hardware_id_hash(&"a".repeat(64)));
    }

    #[test]
    fn hash_validator_rejects_wrong_length() {
        assert!(!validate_hardware_id_hash("abc"));
    }

    #[test]
    fn hash_validator_rejects_uppercase() {
        assert!(!validate_hardware_id_hash(&"A".repeat(64)));
    }

    #[test]
    fn hash_validator_rejects_non_hex() {
        assert!(!validate_hardware_id_hash(&"g".repeat(64)));
    }

    #[test]
    fn url_port_must_be_valid() {
        assert!(validate_https_url("https://example.com:443/api").is_ok());
        assert!(validate_https_url("https://example.com:99999999/api").is_err());
        assert!(validate_https_url("https://example.com:0/api").is_err());
        assert!(validate_https_url("https://example.com:80a/api").is_err());
    }

    #[test]
    fn debug_hides_secrets() {
        let r = valid_redeem_request();
        let d = format!("{r:?}");
        assert!(!d.contains(&r.code));
        let g = RegisterRequest { invite_code: "SECRET-INVITE".into(), hardware_id_hash: "h".into() };
        assert!(!format!("{g:?}").contains("SECRET-INVITE"));
    }

    #[test]
    fn https_url_accepted() {
        assert!(validate_https_url("https://example.com/api").is_ok());
    }

    #[test]
    fn http_url_rejected() {
        assert_eq!(
            validate_https_url("http://example.com"),
            Err(ClientError::InvalidUrl)
        );
    }

    #[test]
    fn url_userinfo_rejected() {
        assert_eq!(
            validate_https_url("https://user@example.com"),
            Err(ClientError::InvalidUrl)
        );
    }

    #[test]
    fn url_localhost_rejected() {
        assert_eq!(
            validate_https_url("https://localhost/api"),
            Err(ClientError::InvalidUrl)
        );
    }

    #[test]
    fn register_success() {
        let fake = FakeTransport::new(vec![success(
            r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#,
        )]);

        let client = fake_client(fake);

        let result = client.register(&valid_register_request()).unwrap();

        assert_eq!(
            result.device_id,
            "123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn registration_empty_invite_code_allowed() {
        let fake = FakeTransport::new(vec![success(
            r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#,
        )]);

        let client = fake_client(fake);
        let request = valid_register_request();

        assert!(request.invite_code.is_empty());
        assert!(client.register(&request).is_ok());
    }

    #[test]
    fn register_rejects_invalid_hash_before_transport() {
        let fake = FakeTransport::new(vec![]);
        let client = fake_client(fake.clone());

        let request = RegisterRequest {
            invite_code: String::new(),
            hardware_id_hash: "invalid".into(),
        };

        assert_eq!(client.register(&request), Err(ClientError::InvalidRequest));
        assert_eq!(fake.call_count(), 0);
    }

    #[test]
    fn register_rejects_invalid_device_uuid_response() {
        let fake = FakeTransport::new(vec![success(
            r#"{"device_id":"not-a-uuid"}"#,
        )]);

        let client = fake_client(fake);

        assert_eq!(
            client.register(&valid_register_request()),
            Err(ClientError::InvalidResponse)
        );
    }

    #[test]
    fn redeem_success_null() {
        let fake = FakeTransport::new(vec![success(
            r#"{"premium_until":null}"#,
        )]);

        let client = fake_client(fake);

        assert_eq!(
            client.redeem(&valid_redeem_request()).unwrap().premium_until,
            None
        );
    }

    #[test]
    fn redeem_success_timestamp() {
        let fake = FakeTransport::new(vec![success(
            r#"{"premium_until":"2030-01-01T00:00:00Z"}"#,
        )]);

        let client = fake_client(fake);

        assert_eq!(
            client
                .redeem(&valid_redeem_request())
                .unwrap()
                .premium_until
                .as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    #[test]
    fn redeem_rejects_whitespace_code() {
        let mut req = valid_redeem_request();
        req.code = "   ".to_string();
        let fake = FakeTransport::new(vec![]);
        let c = fake_client(fake);
        assert_eq!(c.redeem(&req), Err(ClientError::InvalidRequest));
    }

    #[test]
    fn backoff_doubles_caps_and_saturates() {
        let p = RetryPolicy {
            max_attempts: 9,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(3),
        };
        assert_eq!(backoff_delay(&p, 0), Duration::from_millis(250));
        assert_eq!(backoff_delay(&p, 1), Duration::from_millis(500));
        assert_eq!(backoff_delay(&p, 3), Duration::from_secs(2));
        assert_eq!(backoff_delay(&p, 4), Duration::from_secs(3));
        assert_eq!(backoff_delay(&p, 500), Duration::from_secs(3));
        let huge = RetryPolicy {
            max_attempts: 9,
            base_delay: Duration::from_secs(u64::MAX / 2),
            max_delay: Duration::from_secs(1),
        };
        assert_eq!(backoff_delay(&huge, 5), Duration::from_secs(1));
    }

    #[test]
    fn redeem_rejects_empty_code() {
        let fake = FakeTransport::new(vec![]);
        let client = fake_client(fake);

        let request = RedeemRequest {
            code: String::new(),
            device_id: "123e4567-e89b-12d3-a456-426614174000".into(),
        };

        assert_eq!(client.redeem(&request), Err(ClientError::InvalidRequest));
    }

    #[test]
    fn map_registration_closed() {
        assert_eq!(
            map_error(403, r#"{"error":"REGISTRATION_CLOSED"}"#),
            ClientError::RegistrationClosed
        );
    }

    #[test]
    fn map_invite_invalid_used() {
        assert_eq!(
            map_error(403, r#"{"error":"INVITE_INVALID_OR_USED"}"#),
            ClientError::InviteInvalidOrUsed
        );
    }

    #[test]
    fn map_device_revoked() {
        assert_eq!(
            map_error(403, r#"{"error":"DEVICE_REVOKED"}"#),
            ClientError::DeviceRevoked
        );
    }

    #[test]
    fn map_device_already_registered() {
        assert_eq!(
            map_error(403, r#"{"error":"DEVICE_ALREADY_REGISTERED"}"#),
            ClientError::DeviceAlreadyRegistered
        );
    }

    #[test]
    fn map_key_invalid() {
        assert_eq!(
            map_error(403, r#"{"error":"KEY_INVALID"}"#),
            ClientError::KeyInvalid
        );
    }

    #[test]
    fn map_device_invalid() {
        assert_eq!(
            map_error(403, r#"{"error":"DEVICE_INVALID"}"#),
            ClientError::DeviceInvalid
        );
    }

    #[test]
    fn map_rate_limited() {
        assert_eq!(map_error(429, "{}"), ClientError::RateLimited);
    }

    #[test]
    fn map_bad_request() {
        assert_eq!(map_error(400, "{}"), ClientError::BadRequest);
    }

    #[test]
    fn map_unknown_status() {
        assert_eq!(map_error(418, "{}"), ClientError::HttpStatus(418));
    }

    #[test]
    fn retry_503_then_success() {
        let fake = FakeTransport::new(vec![
            response(503, "{}"),
            success(r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#),
        ]);

        let client = fake_client(fake.clone());

        assert!(client.register(&valid_register_request()).is_ok());
        assert_eq!(fake.call_count(), 2);
    }

    #[test]
    fn retry_429_then_success() {
        let fake = FakeTransport::new(vec![
            response(429, r#"{"error":"RATE_LIMITED"}"#),
            success(r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#),
        ]);

        let client = fake_client(fake.clone());

        assert!(client.register(&valid_register_request()).is_ok());
        assert_eq!(fake.call_count(), 2);
    }

    #[test]
    fn no_retry_403() {
        let fake = FakeTransport::new(vec![
            response(403, r#"{"error":"REGISTRATION_CLOSED"}"#),
            success(r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#),
        ]);

        let client = fake_client(fake.clone());

        assert_eq!(
            client.register(&valid_register_request()),
            Err(ClientError::RegistrationClosed)
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn no_retry_400() {
        let fake = FakeTransport::new(vec![
            response(400, "{}"),
            success(r#"{"device_id":"123e4567-e89b-12d3-a456-426614174000"}"#),
        ]);

        let client = fake_client(fake.clone());

        assert_eq!(
            client.register(&valid_register_request()),
            Err(ClientError::BadRequest)
        );
        assert_eq!(fake.call_count(), 1);
    }

    #[test]
    fn cache_expiry_boundary() {
        let cache = DeviceCache {
            device_id: "device".into(),
            premium_until: None,
            expires_at: 100,
        };

        assert!(!cache.is_expired_at(99));
        assert!(cache.is_expired_at(100));
    }

    #[test]
    fn cache_json_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "pos-client-cache-{}.json",
            std::process::id()
        ));

        let cache = DeviceCache {
            device_id: "device".into(),
            premium_until: Some("2030-01-01T00:00:00Z".into()),
            expires_at: 1000,
        };

        cache.save_json_file(&path).unwrap();

        assert_eq!(DeviceCache::load_json_file(&path).unwrap(), cache);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_cache_returns_none() {
        let path = std::env::temp_dir().join(format!(
            "pos-client-expired-{}.json",
            std::process::id()
        ));

        let cache = DeviceCache {
            device_id: "device".into(),
            premium_until: None,
            expires_at: 5,
        };

        cache.save_json_file(&path).unwrap();

        assert_eq!(
            DeviceCache::load_valid_json_file(&path, 5).unwrap(),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_success_json() {
        let fake = FakeTransport::new(vec![success("not-json")]);
        let client = fake_client(fake);

        assert_eq!(
            client.register(&valid_register_request()),
            Err(ClientError::InvalidResponse)
        );
    }

    #[test]
    fn constructor_rejects_http_endpoint() {
        let fake = FakeTransport::new(vec![]);

        assert!(PosClient::new(
            fake,
            "http://example.test/register",
            "https://example.test/redeem-key"
        )
        .is_err());
    }
}

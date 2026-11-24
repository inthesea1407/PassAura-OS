//! Device registration with free anti-abuse.
//! One device = one membership. The device id is a hash of a
//! hardware-backed attestation key (supplied by the platform adapter), so
//! it cannot be changed by reinstalling.
//!
//! IMPORTANT: a hash and a `hardware_backed` flag are only claims. The flag
//! must be set by SERVER-SIDE verification of the attestation certificate
//! chain against the vendor roots, bound to a one-time server challenge
//! (see `ChallengeStore`). That chain verification is NOT implemented here;
//! `Attestation` must only be built by that verifier. Even then, attestation
//! shows "a genuine device key", not "one unique person". Rate limits are per attestation
//! root/source and per time window. No paid services involved.

use crate::invite::{InviteBook, InviteError};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    NoAttestation,
    DeviceAlreadyRegistered,
    RateLimited,
    Invite(InviteError),
}

#[derive(Debug, Clone)]
pub struct Attestation {
    /// Hash of the hardware-backed public key (device identity).
    pub device_hash: String,
    /// Whether the attestation chain verified (hardware-backed, not emulator).
    pub hardware_backed: bool,
    /// Coarse source bucket for rate limiting (e.g. network /24 hash).
    pub source_bucket: String,
}

pub const MAX_SEED_PER_BUCKET_PER_DAY: usize = 5;
const DAY: u64 = 86_400;

#[derive(Debug, Default)]
pub struct DeviceRegistry {
    pub book: InviteBook,
    attempts: HashMap<String, Vec<u64>>, // bucket -> successful registration times
    email_verified: HashMap<String, bool>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device as one of the first seed members.
    pub fn register_seed_device(&mut self, a: &Attestation, now: u64) -> Result<usize, RegisterError> {
        if !a.hardware_backed {
            return Err(RegisterError::NoAttestation);
        }
        if let Some(n) = self.book.seed_number(&a.device_hash) {
            return Ok(n); // idempotent retry
        }
        if self.book.is_member(&a.device_hash) {
            return Err(RegisterError::DeviceAlreadyRegistered);
        }
        let times = self.attempts.entry(a.source_bucket.clone()).or_default();
        times.retain(|t| now.saturating_sub(*t) < DAY);
        if times.len() >= MAX_SEED_PER_BUCKET_PER_DAY {
            return Err(RegisterError::RateLimited);
        }
        let n = self.book.register_seed(&a.device_hash).map_err(RegisterError::Invite)?;
        self.attempts.get_mut(&a.source_bucket).unwrap().push(now);
        Ok(n)
    }

    /// Join with an invite code on a device.
    pub fn redeem_on_device(&mut self, code: &str, a: &Attestation) -> Result<(), RegisterError> {
        if !a.hardware_backed {
            return Err(RegisterError::NoAttestation);
        }
        self.book.redeem(code, &a.device_hash).map_err(|e| match e {
            InviteError::AlreadyMember => RegisterError::DeviceAlreadyRegistered,
            e => RegisterError::Invite(e),
        })
    }

    /// Optional free email verification (the owner sends a free link).
    pub fn mark_email_verified(&mut self, device_hash: &str) {
        self.email_verified.insert(device_hash.into(), true);
    }

    pub fn is_email_verified(&self, device_hash: &str) -> bool {
        *self.email_verified.get(device_hash).unwrap_or(&false)
    }
}

/// One-time server challenges. A challenge can be consumed once and only
/// before it expires, which stops replay of an old attestation.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    open: HashMap<String, u64>, // challenge -> expires_at
}

pub const CHALLENGE_TTL: u64 = 300;

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// `challenge` must come from a secure RNG in production.
    pub fn issue(&mut self, challenge: &str, now: u64) {
        self.open.insert(challenge.into(), now + CHALLENGE_TTL);
    }
    pub fn consume(&mut self, challenge: &str, now: u64) -> bool {
        match self.open.remove(challenge) {
            Some(exp) => now < exp,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(d: &str, b: &str, hw: bool) -> Attestation {
        Attestation { device_hash: d.into(), hardware_backed: hw, source_bucket: b.into() }
    }

    #[test]
    fn emulator_or_unattested_rejected() {
        let mut r = DeviceRegistry::new();
        assert_eq!(r.register_seed_device(&att("d1", "b", false), 0), Err(RegisterError::NoAttestation));
    }

    #[test]
    fn one_device_one_membership() {
        let mut r = DeviceRegistry::new();
        assert_eq!(r.register_seed_device(&att("d1", "b", true), 0), Ok(1));
        assert_eq!(r.register_seed_device(&att("d1", "b2", true), 1), Ok(1)); // idempotent
        r.book.issue("d1", "c").unwrap();
        r.redeem_on_device("c", &att("d2", "b", true)).unwrap();
        assert_eq!(r.register_seed_device(&att("d2", "b", true), 2), Err(RegisterError::DeviceAlreadyRegistered));
    }

    #[test]
    fn bucket_rate_limit_resets_after_a_day() {
        let mut r = DeviceRegistry::new();
        for i in 0..MAX_SEED_PER_BUCKET_PER_DAY {
            r.register_seed_device(&att(&format!("d{i}"), "same", true), i as u64).unwrap();
        }
        assert_eq!(r.register_seed_device(&att("x", "same", true), 10), Err(RegisterError::RateLimited));
        assert!(r.register_seed_device(&att("x", "same", true), 2 * DAY).is_ok());
    }

    #[test]
    fn invite_join_on_device_and_second_device_blocked() {
        let mut r = DeviceRegistry::new();
        r.register_seed_device(&att("seed", "b", true), 0).unwrap();
        r.book.issue("seed", "code1").unwrap();
        assert_eq!(r.redeem_on_device("code1", &att("friend", "c", true)), Ok(()));
        r.book.issue("seed", "code2").unwrap();
        assert_eq!(r.redeem_on_device("code2", &att("friend", "c", true)), Err(RegisterError::DeviceAlreadyRegistered));
    }

    #[test]
    fn challenge_is_single_use_and_expires() {
        let mut c = ChallengeStore::new();
        c.issue("n1", 0);
        assert!(c.consume("n1", 10));
        assert!(!c.consume("n1", 11)); // replay
        c.issue("n2", 0);
        assert!(!c.consume("n2", CHALLENGE_TTL)); // expired
        assert!(!c.consume("never-issued", 0));
    }

    #[test]
    fn email_verification_is_optional() {
        let mut r = DeviceRegistry::new();
        r.register_seed_device(&att("d", "b", true), 0).unwrap();
        assert!(!r.is_email_verified("d"));
        r.mark_email_verified("d");
        assert!(r.is_email_verified("d"));
    }
}

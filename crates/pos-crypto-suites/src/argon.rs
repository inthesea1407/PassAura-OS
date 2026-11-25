//! Argon2id parameters with a reader policy by device RAM tier.
//!
//! The numbers below are a RESOURCE POLICY chosen for this project, not a security standard:
//! - absolute floor (any device): m >= 19456 KiB, t >= 2, p >= 1 (OWASP Password Storage Cheat Sheet,
//!   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html);
//! - "default" writer profile: 64 MiB, t=3, p=4 (RFC 9106 second recommended option,
//!   https://www.rfc-editor.org/rfc/rfc9106.html);
//! - ceiling (so an untrusted header cannot exhaust memory): m <= RAM/8 of the READING device's
//!   tier, t <= 10, p <= 8. It is checked BEFORE any key derivation runs;
//! - "high" profile: m = half of that tier's ceiling, t=3, p=4.
//!
//! The parameters are meant to be stored in the container header and re-validated on every read.

use crate::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const FLOOR_M_KIB: u32 = 19_456;
pub const FLOOR_T: u32 = 2;
pub const FLOOR_P: u32 = 1;
pub const MAX_T: u32 = 10;
pub const MAX_P: u32 = 8;
pub const SALT_MIN: usize = 16;
pub const SALT_MAX: usize = 64;

const MIB: u32 = 1024; // KiB per MiB

/// Installed RAM of the device that reads the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Gb2,
    Gb4,
    Gb8,
    Gb16,
    Gb32,
    Gb64,
}

impl Tier {
    pub fn ram_gib(self) -> u32 {
        match self {
            Tier::Gb2 => 2,
            Tier::Gb4 => 4,
            Tier::Gb8 => 8,
            Tier::Gb16 => 16,
            Tier::Gb32 => 32,
            Tier::Gb64 => 64,
        }
    }
    /// Highest memory cost (KiB) this tier accepts: one eighth of its RAM.
    pub fn ceiling_m_kib(self) -> u32 {
        self.ram_gib() * 1024 * MIB / 8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgonParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl ArgonParams {
    /// 64 MiB, t=3, p=4.
    pub const DEFAULT: ArgonParams = ArgonParams { m_kib: 64 * MIB, t: 3, p: 4 };

    /// Half of the tier's ceiling, t=3, p=4.
    pub fn high(tier: Tier) -> ArgonParams {
        ArgonParams { m_kib: tier.ceiling_m_kib() / 2, t: 3, p: 4 }
    }

    /// Floor and ceiling check for a reading device of `reader`. Run before deriving.
    pub fn check(&self, reader: Tier) -> Result<(), CryptoError> {
        if self.m_kib < FLOOR_M_KIB {
            return Err(CryptoError::ParamsOutOfPolicy("memory cost below floor"));
        }
        if self.t < FLOOR_T {
            return Err(CryptoError::ParamsOutOfPolicy("time cost below floor"));
        }
        if self.p < FLOOR_P {
            return Err(CryptoError::ParamsOutOfPolicy("parallelism below floor"));
        }
        if self.m_kib > reader.ceiling_m_kib() {
            return Err(CryptoError::ParamsOutOfPolicy("memory cost above this device tier's ceiling"));
        }
        if self.t > MAX_T {
            return Err(CryptoError::ParamsOutOfPolicy("time cost above ceiling"));
        }
        if self.p > MAX_P {
            return Err(CryptoError::ParamsOutOfPolicy("parallelism above ceiling"));
        }
        Ok(())
    }

    /// Fixed 12-byte encoding for headers: m (KiB), t, p, each a big-endian u32. Always re-validate with `check` after parsing.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.m_kib.to_be_bytes());
        b[4..8].copy_from_slice(&self.t.to_be_bytes());
        b[8..12].copy_from_slice(&self.p.to_be_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<ArgonParams, CryptoError> {
        if b.len() != 12 {
            return Err(CryptoError::BadInput("argon2 parameter block must be 12 bytes"));
        }
        let rd = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Ok(ArgonParams { m_kib: rd(0), t: rd(4), p: rd(8) })
    }
}

/// Derives a 32-byte key from a passphrase. Validates the parameters first.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &ArgonParams,
    reader: Tier,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params.check(reader)?;
    if passphrase.is_empty() {
        return Err(CryptoError::BadInput("empty passphrase"));
    }
    if salt.len() < SALT_MIN || salt.len() > SALT_MAX {
        return Err(CryptoError::BadInput("salt must be 16 to 64 bytes"));
    }
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| CryptoError::Primitive("argon2 params"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(passphrase, salt, &mut *out)
        .map_err(|_| CryptoError::Primitive("argon2 hash"))?;
    Ok(out)
}

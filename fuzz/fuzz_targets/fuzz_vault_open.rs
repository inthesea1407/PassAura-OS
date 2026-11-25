#![no_main]

use libfuzzer_sys::fuzz_target;

use pos_vault_store::{open_min_version, Suite, Tier};

// Arbitrary file bytes must never panic. The passphrase is fixed and the data is random, so a successful
// open would mean a forged file authenticated (a finding). Header, suite and parameter checks reject
// before the KDF, so most inputs are cheap.
fuzz_target!(|data: &[u8]| {
    let Some((sel, file)) = data.split_first() else { return };
    let suite = if sel & 1 == 0 { Suite::V1 } else { Suite::L1 };
    assert!(open_min_version(b"fuzz-passphrase", file, suite, Tier::Gb2, 0).is_err());
});

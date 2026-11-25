#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_update::{verify_envelope, AcceptedState, TrustedKey, VerifyPolicy};

// Arbitrary bytes must never panic. With a fixed key set and no valid signatures, every input must be
// rejected (a forged acceptance would be a finding).
fuzz_target!(|data: &[u8]| {
    let keys = [TrustedKey {
        key_id: "k1".to_string(),
        public_key: [7u8; 32],
        valid_from: 0,
        valid_until: u64::MAX,
        retired: false,
    }];
    let policy = VerifyPolicy::new(&keys, 1, 1_000_000, "stable");
    let prev = AcceptedState { channel: "stable".to_string(), sequence: 5, digest: [1u8; 32] };
    assert!(verify_envelope(data, &policy, None).is_err());
    assert!(verify_envelope(data, &policy, Some(&prev)).is_err());
});

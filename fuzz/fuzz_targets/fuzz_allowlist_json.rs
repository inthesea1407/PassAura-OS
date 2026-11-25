#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_gate::allowlist_v2::{parse_v2, verify_v2_trusted};
use pos_gate::migrate::migrate_text_v1;
use pos_gate::Keyring;
use std::collections::BTreeMap;

const DEFAULT_TEST_KEYRING_JSON: &str = r#"{
  "keys": [
    {
      "key_id": "ed25519:0000000000000000",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}"#;

// Runtime path (v2 only) and the offline text-v1 migration path must never
// panic on arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }

    let Ok(kr) = Keyring::from_json(DEFAULT_TEST_KEYRING_JSON.as_bytes()) else {
        return;
    };
    let now_secs = if data.len() >= 8 {
        u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
    } else {
        1_735_689_600
    };

    if let Ok(doc) = parse_v2(data) {
        let _ = verify_v2_trusted(&doc, &kr, now_secs as i64, None);
    }
    let _ = migrate_text_v1(data, &kr, &BTreeMap::new(), now_secs);
});

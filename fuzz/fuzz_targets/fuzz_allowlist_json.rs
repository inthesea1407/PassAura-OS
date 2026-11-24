#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_gate::{verify_allowlist, AllowlistDoc, Keyring};

const DEFAULT_TEST_KEYRING_JSON: &str = r#"{
  "keys": [
    {
      "key_id": "ed25519:0000000000000000",
      "public_key_hex": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}"#;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }

    let keyring = Keyring::from_json(DEFAULT_TEST_KEYRING_JSON.as_bytes());
    let doc = AllowlistDoc::from_json(data);

    if let (Ok(kr), Ok(allowlist)) = (keyring, doc) {
        let now = if data.len() >= 8 {
            u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])
        } else {
            1_735_689_600
        };
        let _ = verify_allowlist(&kr, &allowlist, now);
    }
});

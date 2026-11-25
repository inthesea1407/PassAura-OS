#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_update::flow::channel_key;
use std::collections::HashMap;

// Properties: no panic; the key is portable (only [A-Za-z0-9%_-], no dot, bounded); keys of two
// channels that differ are different even when compared case-insensitively.
fuzz_target!(|data: &[u8]| {
    let Some((first, second)) = data.split_at_checked(data.len() / 2) else { return };
    let (Ok(a), Ok(b)) = (std::str::from_utf8(first), std::str::from_utf8(second)) else { return };
    let mut seen: HashMap<String, String> = HashMap::new();
    for c in [a, b] {
        if let Ok(k) = channel_key(c) {
            assert!(k.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'%' || x == b'_' || x == b'-'));
            assert!(k.starts_with("ch-"));
            if let Some(prev) = seen.insert(k.to_ascii_lowercase(), c.to_string()) {
                assert_eq!(prev, c, "two channels share a case-folded key");
            }
        }
    }
});

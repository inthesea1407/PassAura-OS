#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_gate::deb_identity::{parse_control, read_identity};
use std::io::Cursor;

// Arbitrary bytes must never panic or hang, and a returned identity must have non-empty name and version.
fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    if let Ok(id) = read_identity(&mut Cursor::new(data)) {
        assert!(!id.package.is_empty() && !id.version.is_empty());
    }
    if let Ok(id) = parse_control(data) {
        assert!(!id.package.is_empty() && !id.version.is_empty());
    }
});

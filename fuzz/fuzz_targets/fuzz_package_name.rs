#![no_main]

use libfuzzer_sys::fuzz_target;
use pos_gate::names::{is_valid_package_name, validate_package_name};

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let candidate = String::from_utf8_lossy(data);
    let res = validate_package_name(&candidate);
    let flag = is_valid_package_name(&candidate);

    assert_eq!(res.is_ok(), flag);

    if flag {
        assert!(!candidate.is_empty());
        assert!(candidate.len() <= 100);
        assert!(!candidate.starts_with('-'));
        assert!(!candidate.contains('/'));
        assert!(!candidate.contains('\\'));
        assert!(!candidate.contains(".."));
    }
});

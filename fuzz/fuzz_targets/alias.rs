//! Alias and code validation agree: every valid alias is a plausible code,
//! and plausible codes never contain path or header metacharacters.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relink_core::code::{is_plausible_code, validate_alias};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if validate_alias(s).is_ok() {
        assert!(is_plausible_code(s));
    }
    if is_plausible_code(s) {
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert!(relink_server::store::parse_change(&format!("1:{s}")) == Some((1, s)));
    }
});

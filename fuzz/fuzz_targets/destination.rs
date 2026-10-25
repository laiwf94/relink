//! Destination URL validation: never panics, output is always an accepted,
//! credential-free http(s) URL within the length limit, and normalising is
//! idempotent.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relink_core::destination::{MAX_URL_LEN, Policy, normalize};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    for policy in [
        Policy::default(),
        Policy {
            allow_ip_literals: true,
            allow_private: false,
        },
        Policy {
            allow_ip_literals: false,
            allow_private: true,
        },
    ] {
        if let Ok(out) = normalize(s, policy) {
            assert!(out.len() <= MAX_URL_LEN);
            assert!(out.starts_with("http://") || out.starts_with("https://"));
            let parsed = url::Url::parse(&out).expect("output parses");
            assert!(parsed.username().is_empty() && parsed.password().is_none());
            assert_eq!(normalize(&out, policy).as_deref(), Ok(out.as_str()));
            assert!(axum_header_safe(&out));
        }
    }
});

/// Stored URLs are sent back in a Location header, so they must be visible ASCII.
fn axum_header_safe(s: &str) -> bool {
    s.bytes().all(|b| (0x21..0x7f).contains(&b))
}

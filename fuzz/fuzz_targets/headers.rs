//! Request header parsers: User-Agent, Referer, country, Cookie, request ID.
//! None may panic, and every output must be bounded.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relink_core::abtest::{Signer, find_cookie};
use relink_server::api::valid_request_id;
use relink_server::trust::TrustedProxies;
use relink_core::classify::{MAX_HOST_LEN, country, device_class, referrer_host};

fuzz_target!(|data: &[u8]| {
    let _ = device_class(Some(data));
    if let Some(host) = referrer_host(Some(data)) {
        assert!(!host.is_empty() && host.len() <= MAX_HOST_LEN);
        assert_eq!(host, host.to_ascii_lowercase());
    }
    if let Some(c) = country(Some(data)) {
        assert!(c.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
    }
    let signer = Signer::new([3; 32]);
    if let Some(value) = find_cookie([data], "rl_abc") {
        // A random cookie must never verify.
        assert_eq!(signer.verify(1, 1, value, 10), None);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if valid_request_id(s) {
            assert!(s.len() <= 64);
        }
        // Proxy lists and forwarded-for chains: never panic, and the client
        // address is the peer or one of the listed hops.
        if let Ok(trusted) = TrustedProxies::parse(s) {
            let peer: std::net::IpAddr = "10.0.0.1".parse().unwrap();
            let ip = trusted.client_ip(peer, Some(s));
            assert!(ip == peer || s.contains(&ip.to_string()) || s.contains(':'));
        }
    }
});

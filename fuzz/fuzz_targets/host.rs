//! Host parsing: the `Host` and `x-forwarded-host` readers, hostname
//! validation for new domains, routing by host, and reading a path on a
//! custom domain. None may panic, and the origin and the edge must read
//! every input to the same domain.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relink_core::code::is_plausible_code;
use relink_core::host::{MAX_HOSTNAME, could_be_domain, custom_host, host_part, is_valid_hostname};
use relink_core::site::{DomainSettings, Target, target};
use relink_core::wire::{KvKey, host_kv_key};
use relink_edge::logic::{EdgeRequest, forwarded_host};
use relink_server::domains::{DomainMap, Route, VerifiedDomain, parse_hostname};

const DEFAULT_HOST: &str = "relink.example";
const VERIFIED: &str = "go.example.com";

fuzz_target!(|data: &[u8]| {
    // The host part is a prefix of the header, without port or final dot,
    // and reading it again changes nothing.
    if let Some(h) = host_part(data) {
        assert!(!h.is_empty() && h.len() <= MAX_HOSTNAME);
        assert!(data.starts_with(h.as_bytes()));
        assert!(!h.ends_with('.'));
        assert_eq!(host_part(h.as_bytes()), Some(h));
        assert!(
            h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        );
    }

    let custom = custom_host(Some(data), DEFAULT_HOST);
    if let Some(h) = custom {
        assert_eq!(Some(h), host_part(data));
        assert!(could_be_domain(h));
        assert!(is_valid_hostname(&h.to_ascii_lowercase()));
        assert!(!h.eq_ignore_ascii_case(DEFAULT_HOST));
    }

    // What the edge forwards routes the origin to the domain the edge chose:
    // the origin reads the first comma-separated entry, trimmed.
    let req = EdgeRequest {
        host: Some(data.to_vec()),
        ..EdgeRequest::default()
    };
    if let Some(fwd) = forwarded_host(&req) {
        let first = fwd.split(',').next().unwrap_or(&fwd).trim();
        assert_eq!(first, fwd);
        assert_eq!(custom_host(Some(first.as_bytes()), DEFAULT_HOST), custom);
    } else {
        assert_eq!(custom, None);
    }

    // The origin's routing agrees with the edge's reading of the host.
    let map = DomainMap::default();
    map.replace(vec![VerifiedDomain {
        hostname: VERIFIED.into(),
        id: 1,
        settings: DomainSettings::default(),
    }]);
    let routed = matches!(map.route(Some(data), DEFAULT_HOST), Route::Domain(_));
    assert_eq!(
        routed,
        custom.is_some_and(|h| h.eq_ignore_ascii_case(VERIFIED))
    );

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    assert_eq!(
        could_be_domain(s),
        is_valid_hostname(&s.to_ascii_lowercase())
    );
    if is_valid_hostname(s) {
        assert!(could_be_domain(s) && !s.bytes().any(|b| b.is_ascii_uppercase()));
    }

    // A hostname a workspace may add is stored in a form every reader
    // accepts unchanged, and adding it again gives the same form.
    if let Ok(h) = parse_hostname(s, DEFAULT_HOST) {
        assert!(is_valid_hostname(&h), "{h:?}");
        assert_ne!(h, DEFAULT_HOST);
        assert_eq!(custom_host(Some(h.as_bytes()), DEFAULT_HOST), Some(&*h));
        assert_eq!(parse_hostname(&h, DEFAULT_HOST).as_deref(), Ok(&*h));
        let key = host_kv_key(&h);
        assert_eq!(KvKey::parse(&key), Some(KvKey::Host(&h)));
    }

    // Any path on a custom domain: a code is always a plausible one, and
    // lowercase on a case-insensitive domain.
    let settings = DomainSettings {
        prefixes: vec!["campaign".into(), "promo".into()],
        case_insensitive: true,
        ..DomainSettings::default()
    };
    for on in [None, Some(&settings)] {
        match target(s, on) {
            Target::Root => assert!(s.is_empty()),
            Target::Code(c) => {
                assert!(is_plausible_code(&c));
                if on.is_some() {
                    assert!(!c.bytes().any(|b| b.is_ascii_uppercase()));
                } else {
                    assert_eq!(&*c, s);
                }
            }
            Target::Miss => {}
            // Association files exist only on custom domains, at exactly
            // their paths.
            Target::AppFile(f) => {
                assert!(on.is_some());
                assert_eq!(relink_core::deeplink::app_file_at(s), Some(f));
            }
        }
    }
});

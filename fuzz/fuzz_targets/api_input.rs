//! API inputs: request bodies, edge click batches, KV link records, cursors
//! and change notifications.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relink_core::wire::ClickBatch;
use relink_server::api::{CreateLink, PatchLink, click_from_wire, decode_cursor, encode_cursor};
use relink_server::store::{link_key, parse_change, split_link_key};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<CreateLink>(data);
    let _ = serde_json::from_slice::<PatchLink>(data);
    // KV records as the edge reads them.
    if let Ok(link) = serde_json::from_slice::<relink_core::model::Link>(data) {
        let again: relink_core::model::Link =
            serde_json::from_str(&serde_json::to_string(&link).unwrap()).unwrap();
        assert_eq!(again, link);
        // A loaded decision list keeps the compiler's promises, so running
        // it never panics and never tests more than the bound.
        let rules = link.rules.compiled();
        let req = relink_core::rules_v2::Request {
            now_ms: 1_794_832_200_000,
            country: Some(*b"US"),
            region: Some(b"CA"),
            user_agent: Some(b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
            accept_language: Some(b"en-US,en;q=0.9"),
            referer: Some(b"https://news.example/"),
            query: Some(b"src=mail&utm_source=ads"),
        };
        let (rule, tested) = rules.evaluate_counted(&req);
        assert!(tested <= relink_core::rules_v2::MAX_CONDITIONS);
        assert!(rule.is_none_or(|r| r < rules.urls().len()));
    }
    if let Ok(batch) = serde_json::from_slice::<ClickBatch>(data) {
        for c in &batch.clicks {
            if let Ok(ev) = click_from_wire(c, c.day) {
                assert!(ev.link_id > 0);
            }
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(id) = decode_cursor(s) {
            assert!(id > 0);
            assert_eq!(encode_cursor(id), s.to_ascii_lowercase());
        }
        if let Some((id, key)) = parse_change(s) {
            assert!(id > 0);
            assert!(s.ends_with(key));
            // A key is a code, or a domain ID and a code, and rebuilds
            // exactly from its parts.
            let (domain, code) = split_link_key(key).expect("parse_change checked the key");
            assert!(relink_core::code::is_plausible_code(code));
            assert!(domain.is_none_or(|d| d > 0));
            assert_eq!(link_key(domain, code), key);
        }
    }
});

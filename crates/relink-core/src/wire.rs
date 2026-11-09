//! JSON shapes that cross between the edge worker and the origin.

use serde::{Deserialize, Serialize};

use crate::code::is_plausible_code;
use crate::host::is_valid_hostname;
use crate::site::DomainSettings;

/// KV key for a link on the default domain. The value is the `model::Link`
/// JSON.
pub fn kv_key(code: &str) -> String {
    format!("{KV_PREFIX}{code}")
}

/// KV key for a link on the custom domain `host` (lowercase, as stored in
/// `domains`): `link:<host>/<code>`. Codes never contain `/` and hostnames
/// never do either, so this cannot collide with a default-domain key or
/// another domain's.
pub fn domain_kv_key(host: &str, code: &str) -> String {
    format!("{KV_PREFIX}{host}/{code}")
}

/// KV key saying `host` is a verified custom domain. The value is an
/// [`EdgeDomain`] JSON. The edge reads it only when a host's link is not in
/// KV, to tell "no such link on this domain" from "not a custom domain".
pub fn host_kv_key(host: &str) -> String {
    format!("{HOST_PREFIX}{host}")
}

pub const KV_PREFIX: &str = "link:";
pub const HOST_PREFIX: &str = "host:";

/// A KV key the origin publishes, parsed. Only canonical keys parse: a
/// plausible code and a lowercase hostname the `domains` table accepts, so
/// each record has exactly one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvKey<'a> {
    /// A link: on the default domain when `host` is `None`.
    Link {
        host: Option<&'a str>,
        code: &'a str,
    },
    /// The record of a verified custom domain.
    Host(&'a str),
}

impl<'a> KvKey<'a> {
    pub fn parse(key: &'a str) -> Option<KvKey<'a>> {
        if let Some(rest) = key.strip_prefix(KV_PREFIX) {
            let (host, code) = match rest.split_once('/') {
                None => (None, rest),
                Some((h, c)) if is_valid_hostname(h) => (Some(h), c),
                Some(_) => return None,
            };
            return is_plausible_code(code).then_some(KvKey::Link { host, code });
        }
        let host = key.strip_prefix(HOST_PREFIX)?;
        is_valid_hostname(host).then_some(KvKey::Host(host))
    }
}

impl std::fmt::Display for KvKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvKey::Link { host: None, code } => write!(f, "{KV_PREFIX}{code}"),
            KvKey::Link {
                host: Some(h),
                code,
            } => write!(f, "{KV_PREFIX}{h}/{code}"),
            KvKey::Host(h) => write!(f, "{HOST_PREFIX}{h}"),
        }
    }
}

/// The value of a [`host_kv_key`]: what the edge knows about a verified
/// custom domain. Unknown fields are ignored, so an origin may publish
/// fields a Worker deployed earlier does not read yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeDomain {
    /// The domain's ID at the origin.
    pub id: i64,
    /// Its root redirect, pages, prefixes and case rule; left out when they
    /// are the defaults.
    #[serde(default, skip_serializing_if = "DomainSettings::is_default")]
    pub settings: DomainSettings,
}

/// Most clicks in one batch sent from the edge.
pub const MAX_BATCH: usize = 1000;

/// One click served at the edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireClick {
    pub link_id: i64,
    /// UTC days since the Unix epoch.
    pub day: i32,
    /// Two-letter country, `XX` when unknown.
    pub country: String,
    /// `desktop`, `mobile`, `tablet`, `bot` or `other`.
    pub device: String,
    pub referrer: Option<String>,
    /// 32 hex characters: `visitor::fingerprint`.
    pub fingerprint: String,
}

/// `POST /v1/edge/clicks` body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickBatch {
    pub clicks: Vec<WireClick>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_round_trips() {
        let b = ClickBatch {
            clicks: vec![WireClick {
                link_id: 1,
                day: 20_000,
                country: "DE".into(),
                device: "mobile".into(),
                referrer: None,
                fingerprint: "00".repeat(16),
            }],
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<ClickBatch>(&json).unwrap(), b);
        assert_eq!(kv_key("abc"), "link:abc");
    }

    #[test]
    fn keys_parse_and_print_canonically() {
        for (key, parsed) in [
            (
                "link:abc",
                KvKey::Link {
                    host: None,
                    code: "abc",
                },
            ),
            (
                "link:go.example.com/abc",
                KvKey::Link {
                    host: Some("go.example.com"),
                    code: "abc",
                },
            ),
            ("host:go.example.com", KvKey::Host("go.example.com")),
        ] {
            assert_eq!(KvKey::parse(key), Some(parsed), "{key}");
            assert_eq!(parsed.to_string(), key);
        }
        assert_eq!(
            domain_kv_key("go.example.com", "abc"),
            "link:go.example.com/abc"
        );
        assert_eq!(host_kv_key("go.example.com"), "host:go.example.com");
        for bad in [
            "",
            "link:",
            "link:ab",
            "link:a/b/c",
            "link:/abc",
            "link:Go.example.com/abc",
            "link:localhost/abc",
            "link:go.example.com/",
            "link:go.example.com/a.b",
            "host:",
            "host:Go.example.com",
            "host:10.0.0.1",
            "other:abc",
        ] {
            assert_eq!(KvKey::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn domain_records_ignore_fields_they_do_not_know() {
        let d: EdgeDomain = serde_json::from_str(r#"{"id":7,"later":"x"}"#).unwrap();
        let plain = EdgeDomain {
            id: 7,
            settings: DomainSettings::default(),
        };
        assert_eq!(d, plain);
        assert_eq!(serde_json::to_string(&d).unwrap(), r#"{"id":7}"#);
        let d = EdgeDomain {
            id: 7,
            settings: DomainSettings {
                case_insensitive: true,
                ..DomainSettings::default()
            },
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, r#"{"id":7,"settings":{"case_insensitive":true}}"#);
        assert_eq!(serde_json::from_str::<EdgeDomain>(&json).unwrap(), d);
    }
}

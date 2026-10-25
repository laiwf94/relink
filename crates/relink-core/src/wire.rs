//! JSON shapes that cross between the edge worker and the origin.

use serde::{Deserialize, Serialize};

/// KV key for a link record. The value is the `model::Link` JSON.
pub fn kv_key(code: &str) -> String {
    format!("{KV_PREFIX}{code}")
}

pub const KV_PREFIX: &str = "link:";

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
}

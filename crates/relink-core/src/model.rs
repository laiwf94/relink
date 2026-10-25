//! The link as the redirect path sees it. The server caches it, and the
//! same JSON is what gets published to the edge, so field names here are a
//! wire format: add fields with defaults, never rename.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One place a link can send visitors, with its share of an A/B split.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Whether a country list is an allow list or a deny list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoMode {
    Allow,
    Deny,
}

impl GeoMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GeoMode::Allow => "allow",
            GeoMode::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<GeoMode> {
        match s {
            "allow" => Some(GeoMode::Allow),
            "deny" => Some(GeoMode::Deny),
            _ => None,
        }
    }
}

/// A country rule, with countries as uppercase two-letter codes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GeoWire", into = "GeoWire")]
pub struct GeoRule {
    pub mode: GeoMode,
    pub countries: Vec<[u8; 2]>,
}

#[derive(Serialize, Deserialize)]
struct GeoWire {
    mode: GeoMode,
    countries: Vec<String>,
}

impl TryFrom<GeoWire> for GeoRule {
    type Error = String;
    fn try_from(w: GeoWire) -> Result<GeoRule, String> {
        let countries = w
            .countries
            .iter()
            .map(|c| <[u8; 2]>::try_from(c.as_bytes()).map_err(|_| format!("bad country {c:?}")))
            .collect::<Result<_, _>>()?;
        Ok(GeoRule {
            mode: w.mode,
            countries,
        })
    }
}

impl From<GeoRule> for GeoWire {
    fn from(g: GeoRule) -> GeoWire {
        GeoWire {
            mode: g.mode,
            countries: g.country_strings(),
        }
    }
}

impl GeoRule {
    /// Whether a visitor from `country` (None when unknown) may follow the link.
    pub fn permits(&self, country: Option<[u8; 2]>) -> bool {
        let listed = country.is_some_and(|c| self.countries.contains(&c));
        match self.mode {
            GeoMode::Allow => listed,
            GeoMode::Deny => !listed,
        }
    }

    pub fn country_strings(&self) -> Vec<String> {
        self.countries
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect()
    }
}

/// Everything needed to answer `GET /{code}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub id: i64,
    pub code: String,
    pub destinations: Vec<Destination>,
    /// Bumped whenever `destinations` change; part of the A/B cookie MAC.
    pub destinations_version: i32,
    pub redirect_status: u16,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub max_clicks: Option<i64>,
    #[serde(default)]
    pub geo: Option<GeoRule>,
    #[serde(default)]
    pub fallback_url: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub health_check: bool,
    /// Per destination: true once health checks failed often enough.
    #[serde(default)]
    pub unhealthy: Vec<bool>,
}

impl Link {
    /// Whether destination `i` should receive traffic.
    pub fn is_healthy(&self, i: usize) -> bool {
        !self.health_check || !self.unhealthy.get(i).copied().unwrap_or(false)
    }

    pub fn weights(&self) -> Vec<u32> {
        self.destinations.iter().map(|d| d.weight).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_rules() {
        let allow = GeoRule {
            mode: GeoMode::Allow,
            countries: vec![*b"US", *b"DE"],
        };
        assert!(allow.permits(Some(*b"US")));
        assert!(!allow.permits(Some(*b"FR")));
        assert!(!allow.permits(None));
        let deny = GeoRule {
            mode: GeoMode::Deny,
            countries: vec![*b"US"],
        };
        assert!(!deny.permits(Some(*b"US")));
        assert!(deny.permits(Some(*b"FR")));
        assert!(deny.permits(None));
        assert_eq!(allow.country_strings(), vec!["US", "DE"]);
        assert_eq!(GeoMode::parse("allow"), Some(GeoMode::Allow));
        assert_eq!(GeoMode::parse("deny"), Some(GeoMode::Deny));
        assert_eq!(GeoMode::parse("x"), None);
        assert_eq!(GeoMode::Deny.as_str(), "deny");
    }

    #[test]
    fn destination_weight_defaults_to_one() {
        let d: Destination = serde_json::from_str(r#"{"url":"https://a.example.com/"}"#).unwrap();
        assert_eq!(d.weight, 1);
        assert!(serde_json::from_str::<Destination>(r#"{"url":"x","extra":1}"#).is_err());
    }

    #[test]
    fn link_json_round_trips_and_tolerates_missing_options() {
        let json = r#"{"id":7,"code":"abc","destinations":[{"url":"https://example.com/","weight":2}],
            "destinations_version":3,"redirect_status":301,"enabled":true,
            "geo":{"mode":"deny","countries":["DE"]}}"#;
        let link: Link = serde_json::from_str(json).unwrap();
        assert_eq!(link.geo.as_ref().unwrap().countries, vec![*b"DE"]);
        assert!(link.expires_at.is_none() && link.unhealthy.is_empty());
        let again: Link = serde_json::from_str(&serde_json::to_string(&link).unwrap()).unwrap();
        assert_eq!(again, link);
        assert!(serde_json::from_str::<Link>(&json.replace("\"DE\"", "\"DEU\"")).is_err());
    }
}

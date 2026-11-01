//! Configuration from environment variables. The full list, with defaults,
//! is in the documentation of the `relink` binary (src/main.rs).

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use axum::http::HeaderName;

use crate::cache;
use crate::clicks::FlushConfig;
use crate::code::{MAX_CODE_LEN, MIN_CODE_LEN};
use crate::destination::Policy;
use crate::ratelimit::Rate;
use crate::trust::TrustedProxies;
use crate::util::hex_decode;

pub const DEFAULT_KV_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Where and how to publish link records for the edge.
#[derive(Clone)]
pub struct KvConfig {
    pub api_base: String,
    pub account_id: String,
    pub namespace_id: String,
    pub api_token: String,
    /// How often the outbox is checked when no change notification arrives.
    pub poll: Duration,
    /// How often KV is compared with the database in full.
    pub reconcile: Duration,
}

impl fmt::Debug for KvConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvConfig")
            .field("api_base", &self.api_base)
            .field("account_id", &self.account_id)
            .field("namespace_id", &self.namespace_id)
            .field("api_token", &"<redacted>")
            .field("poll", &self.poll)
            .field("reconcile", &self.reconcile)
            .finish()
    }
}

/// Health worker settings.
#[derive(Clone, Copy, Debug)]
pub struct HealthConfig {
    pub enabled: bool,
    /// How often each link is checked.
    pub interval: Duration,
    /// Probes in flight at once.
    pub concurrency: usize,
    /// Probes per second to any one host.
    pub per_host_rps: f64,
    pub timeout: Duration,
    /// Consecutive failures before a destination is unhealthy.
    pub failure_threshold: i16,
    /// Links claimed per round.
    pub batch: i64,
}

/// Everything the server needs.
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub public_base_url: String,
    pub code_length: usize,
    pub cookie_key: Option<[u8; 32]>,
    pub cookie_secure: bool,
    pub country_header: Option<HeaderName>,
    pub client_ip_header: Option<HeaderName>,
    /// Peers whose forwarding headers are believed.
    pub trusted_proxies: TrustedProxies,
    pub destination_policy: Policy,
    pub cache: cache::Config,
    pub lookup_concurrency: usize,
    pub click_queue: usize,
    pub flush: FlushConfig,
    pub max_lease: i64,
    pub health: HealthConfig,
    pub api_rate: Rate,
    /// Database lookups per second for API keys not in the auth cache.
    pub auth_lookup_rate: f64,
    /// The same, per client address.
    pub auth_lookup_rate_per_ip: f64,
    pub db_max_connections: u32,
    /// Connections for redirect lookups by code, separate from the main pool.
    pub db_lookup_connections: u32,
    pub db_timeout: Duration,
    pub redirect_max_age: u32,
    /// Shared secret the edge worker uses to post clicks; `None` disables
    /// the endpoint.
    pub edge_token: Option<String>,
    /// Publishing link records to Workers KV; `None` when not configured.
    pub kv: Option<KvConfig>,
    pub shutdown_timeout: Duration,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("addr", &self.addr)
            .field("admin_addr", &self.admin_addr)
            .field("public_base_url", &self.public_base_url)
            .field("code_length", &self.code_length)
            .field("cookie_key", &self.cookie_key.map(|_| "<redacted>"))
            .field("cookie_secure", &self.cookie_secure)
            .field("country_header", &self.country_header)
            .field("client_ip_header", &self.client_ip_header)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("destination_policy", &self.destination_policy)
            .field("cache", &self.cache)
            .field("lookup_concurrency", &self.lookup_concurrency)
            .field("click_queue", &self.click_queue)
            .field("flush", &self.flush)
            .field("max_lease", &self.max_lease)
            .field("health", &self.health)
            .field("api_rate", &self.api_rate)
            .field("auth_lookup_rate", &self.auth_lookup_rate)
            .field("auth_lookup_rate_per_ip", &self.auth_lookup_rate_per_ip)
            .field("db_max_connections", &self.db_max_connections)
            .field("db_lookup_connections", &self.db_lookup_connections)
            .field("db_timeout", &self.db_timeout)
            .field("redirect_max_age", &self.redirect_max_age)
            .field(
                "edge_token",
                &self.edge_token.as_ref().map(|_| "<redacted>"),
            )
            .field("kv", &self.kv)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

struct Vars<'a> {
    get: &'a dyn Fn(&str) -> Option<String>,
}

impl Vars<'_> {
    fn raw(&self, name: &str) -> Option<String> {
        (self.get)(name).filter(|v| !v.trim().is_empty())
    }

    fn parse<T>(&self, name: &str, default: T, min: T, max: T) -> Result<T, String>
    where
        T: FromStr + PartialOrd + fmt::Display + Copy,
    {
        let Some(raw) = self.raw(name) else {
            return Ok(default);
        };
        let v: T = raw
            .trim()
            .parse()
            .map_err(|_| format!("{name}: cannot parse {raw:?}"))?;
        if v < min || v > max {
            return Err(format!("{name}: {v} is outside {min}..={max}"));
        }
        Ok(v)
    }

    fn millis(&self, name: &str, default: u64, min: u64, max: u64) -> Result<Duration, String> {
        self.parse(name, default, min, max)
            .map(Duration::from_millis)
    }

    fn bool(&self, name: &str, default: bool) -> Result<bool, String> {
        match self.raw(name).as_deref().map(str::trim) {
            None => Ok(default),
            Some("1" | "true" | "yes") => Ok(true),
            Some("0" | "false" | "no") => Ok(false),
            Some(other) => Err(format!("{name}: expected true or false, got {other:?}")),
        }
    }

    fn addr(&self, name: &str, default: &str) -> Result<SocketAddr, String> {
        let raw = self.raw(name).unwrap_or_else(|| default.to_owned());
        raw.trim()
            .parse()
            .map_err(|_| format!("{name}: {raw:?} is not an address like 0.0.0.0:8080"))
    }

    fn header(&self, name: &str, default: Option<&str>) -> Result<Option<HeaderName>, String> {
        let raw = match self.raw(name) {
            Some(v) if v.trim() == "-" => return Ok(None),
            Some(v) => v,
            None => match default {
                Some(d) => d.to_owned(),
                None => return Ok(None),
            },
        };
        HeaderName::from_str(raw.trim())
            .map(Some)
            .map_err(|_| format!("{name}: {raw:?} is not a valid header name"))
    }
}

impl Config {
    /// Reads the process environment.
    pub fn from_env() -> Result<Config, String> {
        Config::from_vars(&|k| std::env::var(k).ok())
    }

    /// Reads configuration through `get`, so tests can supply a map.
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, String> {
        let v = Vars { get };
        let database_url = v
            .raw("RELINK_DATABASE_URL")
            .ok_or("RELINK_DATABASE_URL is required (postgres://user:pass@host/db)")?;
        let public_base_url = v
            .raw("RELINK_PUBLIC_BASE_URL")
            .unwrap_or_else(|| "http://localhost:8080".into())
            .trim()
            .trim_end_matches('/')
            .to_owned();
        if !(public_base_url.starts_with("http://") || public_base_url.starts_with("https://")) {
            return Err("RELINK_PUBLIC_BASE_URL must start with http:// or https://".into());
        }
        let cookie_key = match v.raw("RELINK_COOKIE_KEY") {
            None => None,
            Some(hex) => {
                let bytes = hex_decode(hex.trim())
                    .filter(|b| b.len() >= 32)
                    .ok_or("RELINK_COOKIE_KEY must be at least 64 hex characters (32 bytes)")?;
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[..32]);
                Some(key)
            }
        };
        let edge_token = match v.raw("RELINK_EDGE_TOKEN") {
            Some(t) if t.trim().len() >= 32 => Some(t.trim().to_owned()),
            Some(_) => return Err("RELINK_EDGE_TOKEN must be at least 32 characters".into()),
            None => None,
        };
        let kv = match (
            v.raw("RELINK_KV_ACCOUNT_ID"),
            v.raw("RELINK_KV_NAMESPACE_ID"),
            v.raw("RELINK_KV_API_TOKEN"),
        ) {
            (None, None, None) => None,
            (Some(account_id), Some(namespace_id), Some(api_token)) => {
                let api_base = v
                    .raw("RELINK_KV_API_BASE")
                    .unwrap_or_else(|| DEFAULT_KV_API_BASE.into())
                    .trim()
                    .trim_end_matches('/')
                    .to_owned();
                // The API token goes to this host on every request.
                let local = api_base.starts_with("http://127.0.0.1:")
                    || api_base.starts_with("http://localhost:");
                if !api_base.starts_with("https://") && !local {
                    return Err(
                        "RELINK_KV_API_BASE must be https (or http on localhost for tests)".into(),
                    );
                }
                let safe_id = |s: &str| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                };
                if !safe_id(account_id.trim()) || !safe_id(namespace_id.trim()) {
                    return Err(
                        "RELINK_KV_ACCOUNT_ID and RELINK_KV_NAMESPACE_ID must be plain identifiers"
                            .into(),
                    );
                }
                Some(KvConfig {
                    api_base,
                    account_id: account_id.trim().to_owned(),
                    namespace_id: namespace_id.trim().to_owned(),
                    api_token: api_token.trim().to_owned(),
                    poll: Duration::from_millis(v.parse("RELINK_KV_POLL_MS", 1_000, 50, 60_000)?),
                    reconcile: Duration::from_secs(v.parse(
                        "RELINK_KV_RECONCILE_S",
                        3_600,
                        10,
                        86_400,
                    )?),
                })
            }
            _ => {
                return Err("set all of RELINK_KV_ACCOUNT_ID, RELINK_KV_NAMESPACE_ID and RELINK_KV_API_TOKEN, or none".into());
            }
        };
        let ttl = v.millis("RELINK_CACHE_TTL_MS", 30_000, 0, 86_400_000)?;
        let cfg = Config {
            database_url,
            addr: v.addr("RELINK_ADDR", "0.0.0.0:8080")?,
            admin_addr: v.addr("RELINK_ADMIN_ADDR", "127.0.0.1:9090")?,
            public_base_url,
            code_length: v.parse("RELINK_CODE_LENGTH", 7, MIN_CODE_LEN, MAX_CODE_LEN)?,
            cookie_key,
            cookie_secure: v.bool("RELINK_COOKIE_SECURE", true)?,
            country_header: v.header("RELINK_COUNTRY_HEADER", None)?,
            client_ip_header: v.header("RELINK_CLIENT_IP_HEADER", None)?,
            trusted_proxies: TrustedProxies::parse(
                &v.raw("RELINK_TRUSTED_PROXIES").unwrap_or_default(),
            )
            .map_err(|e| format!("RELINK_TRUSTED_PROXIES: {e}"))?,
            destination_policy: Policy {
                allow_ip_literals: v.bool("RELINK_ALLOW_IP_LITERALS", false)?,
                allow_private: v.bool("RELINK_ALLOW_PRIVATE_DESTINATIONS", false)?,
            },
            cache: cache::Config {
                capacity: v.parse("RELINK_CACHE_CAPACITY", 100_000, 0, 50_000_000)?,
                ttl,
                negative_ttl: v.millis("RELINK_CACHE_NEGATIVE_TTL_MS", 10_000, 0, 86_400_000)?,
                stale_while_revalidate: v.millis("RELINK_CACHE_SWR_MS", 300_000, 0, 86_400_000)?,
                stale_if_error: v.millis(
                    "RELINK_CACHE_STALE_IF_ERROR_MS",
                    86_400_000,
                    0,
                    7 * 86_400_000,
                )?,
            },
            lookup_concurrency: v.parse("RELINK_LOOKUP_CONCURRENCY", 32, 1, 10_000)?,
            click_queue: v.parse("RELINK_CLICK_QUEUE", 65_536, 1, 10_000_000)?,
            flush: FlushConfig {
                interval: v.millis("RELINK_CLICK_FLUSH_MS", 1_000, 10, 60_000)?,
                batch: v.parse("RELINK_CLICK_BATCH", 5_000, 1, 1_000_000)?,
                max_backlog: v.parse("RELINK_CLICK_BACKLOG", 200_000, 2, 50_000_000)?,
                max_backoff: Duration::from_secs(30),
            },
            max_lease: v.parse("RELINK_LEASE_MAX", 100, 1, 1_000_000)?,
            health: HealthConfig {
                enabled: v.bool("RELINK_HEALTH_ENABLED", true)?,
                interval: Duration::from_secs(v.parse(
                    "RELINK_HEALTH_INTERVAL_S",
                    300,
                    1,
                    86_400,
                )?),
                concurrency: v.parse("RELINK_HEALTH_CONCURRENCY", 16, 1, 1_000)?,
                per_host_rps: v.parse("RELINK_HEALTH_PER_HOST_RPS", 1.0, 0.01, 1_000.0)?,
                timeout: v.millis("RELINK_HEALTH_TIMEOUT_MS", 5_000, 100, 60_000)?,
                failure_threshold: v.parse("RELINK_HEALTH_FAILURE_THRESHOLD", 2, 1, 100)?,
                batch: v.parse("RELINK_HEALTH_BATCH", 100, 1, 10_000)?,
            },
            api_rate: Rate {
                per_second: v.parse("RELINK_API_RATE", 10.0, 0.01, 100_000.0)?,
                burst: v.parse("RELINK_API_BURST", 20.0, 1.0, 1_000_000.0)?,
            },
            auth_lookup_rate: v.parse("RELINK_AUTH_LOOKUP_RATE", 200.0, 1.0, 1_000_000.0)?,
            auth_lookup_rate_per_ip: v.parse(
                "RELINK_AUTH_LOOKUP_RATE_PER_IP",
                5.0,
                0.01,
                1_000_000.0,
            )?,
            db_max_connections: v.parse("RELINK_DB_MAX_CONNECTIONS", 16, 1, 1_000)?,
            db_lookup_connections: v.parse("RELINK_DB_LOOKUP_CONNECTIONS", 8, 1, 1_000)?,
            db_timeout: v.millis("RELINK_DB_TIMEOUT_MS", 2_000, 50, 60_000)?,
            edge_token,
            kv,
            redirect_max_age: v.parse("RELINK_REDIRECT_MAX_AGE_S", 0, 0, 31_536_000)?,
            shutdown_timeout: Duration::from_secs(v.parse(
                "RELINK_SHUTDOWN_TIMEOUT_S",
                10,
                1,
                300,
            )?),
        };
        if (cfg.country_header.is_some() || cfg.client_ip_header.is_some())
            && cfg.trusted_proxies.is_empty()
        {
            return Err(
                "RELINK_COUNTRY_HEADER and RELINK_CLIENT_IP_HEADER are only read from \
                        RELINK_TRUSTED_PROXIES; set it to your CDN or load balancer addresses"
                    .into(),
            );
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn from(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_vars(&move |k| map.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = from(&[("RELINK_DATABASE_URL", "postgres://x/y")]).unwrap();
        assert_eq!(c.addr.to_string(), "0.0.0.0:8080");
        assert_eq!(c.admin_addr.to_string(), "127.0.0.1:9090");
        assert_eq!(c.code_length, 7);
        assert!(
            c.country_header.is_none(),
            "no header is trusted by default"
        );
        assert!(c.client_ip_header.is_none());
        assert!(c.trusted_proxies.is_empty());
        assert!(c.cookie_secure);
        assert!(c.cookie_key.is_none());
        assert_eq!(c.cache.ttl, Duration::from_secs(30));
        assert!(!c.destination_policy.allow_private);
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("postgres://"), "secrets must not be printed");
    }

    #[test]
    fn overrides() {
        let key = "ab".repeat(32);
        let c = from(&[
            ("RELINK_DATABASE_URL", "postgres://x/y"),
            ("RELINK_ADDR", "127.0.0.1:0"),
            ("RELINK_CODE_LENGTH", "10"),
            ("RELINK_COOKIE_KEY", &key),
            ("RELINK_COOKIE_SECURE", "false"),
            ("RELINK_COUNTRY_HEADER", "cf-ipcountry"),
            ("RELINK_CLIENT_IP_HEADER", "CF-Connecting-IP"),
            ("RELINK_TRUSTED_PROXIES", "10.0.0.0/8, 2001:db8::/32"),
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1"),
            ("RELINK_PUBLIC_BASE_URL", "https://s.example.com/"),
            ("RELINK_HEALTH_PER_HOST_RPS", "0.5"),
        ])
        .unwrap();
        assert_eq!(c.code_length, 10);
        assert_eq!(c.cookie_key, Some([0xab; 32]));
        assert!(!c.cookie_secure);
        assert_eq!(c.country_header.as_ref().unwrap().as_str(), "cf-ipcountry");
        assert!(c.trusted_proxies.contains("10.1.2.3".parse().unwrap()));
        assert_eq!(
            c.client_ip_header.as_ref().unwrap().as_str(),
            "cf-connecting-ip"
        );
        assert!(c.destination_policy.allow_private);
        assert_eq!(c.public_base_url, "https://s.example.com");
        assert_eq!(c.health.per_host_rps, 0.5);
    }

    #[test]
    fn rejects_bad_values() {
        let base = ("RELINK_DATABASE_URL", "postgres://x/y");
        for bad in [
            vec![],
            vec![base, ("RELINK_CODE_LENGTH", "3")],
            vec![base, ("RELINK_CODE_LENGTH", "abc")],
            vec![base, ("RELINK_ADDR", "nope")],
            vec![base, ("RELINK_COOKIE_KEY", "abcd")],
            vec![base, ("RELINK_COOKIE_SECURE", "maybe")],
            vec![base, ("RELINK_COUNTRY_HEADER", "bad header")],
            vec![base, ("RELINK_COUNTRY_HEADER", "cf-ipcountry")],
            vec![base, ("RELINK_TRUSTED_PROXIES", "10.0.0.0/99")],
            vec![base, ("RELINK_PUBLIC_BASE_URL", "ftp://x")],
            vec![base, ("RELINK_DB_TIMEOUT_MS", "1")],
        ] {
            assert!(from(&bad).is_err(), "{bad:?}");
        }
    }
}

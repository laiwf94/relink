//! Configuration from environment variables. The full list, with defaults,
//! is in the documentation of the `relink` binary (src/main.rs).

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use axum::http::HeaderName;

use crate::acme::AcmeConfig;
use crate::cache;
use crate::clicks::FlushConfig;
use crate::code::{MAX_CODE_LEN, MIN_CODE_LEN};
use crate::destination::Policy;
use crate::oidc::OidcConfig;
use crate::ratelimit::Rate;
use crate::tls::TlsConfig;
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
    /// The Cloudflare zone whose custom hostnames (Cloudflare for SaaS)
    /// route verified custom domains to the Worker; `None` leaves custom
    /// hostnames to the operator.
    pub zone_id: Option<String>,
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
            .field("zone_id", &self.zone_id)
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
    /// The host of `public_base_url`, lowercase and without a port: the
    /// default domain, which no workspace can add as a custom one.
    pub default_host: String,
    pub code_length: usize,
    pub cookie_key: Option<[u8; 32]>,
    pub cookie_secure: bool,
    pub country_header: Option<HeaderName>,
    /// Header with the subdivision part of the visitor's ISO 3166-2 region
    /// (`CA` for `US-CA`), read by targeting rules.
    pub region_header: Option<HeaderName>,
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
    /// How often the scheduler looks for due link schedules.
    pub schedule_poll: Duration,
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
    /// OpenID Connect sign-in; `None` when not configured.
    pub oidc: Option<OidcConfig>,
    /// How long a sign-in session lasts.
    pub session_ttl: Duration,
    pub shutdown_timeout: Duration,
    /// Recursive resolvers for domain verification lookups; `None` reads
    /// the system's from /etc/resolv.conf.
    pub dns_servers: Option<Vec<SocketAddr>>,
    /// Bound on each resolver's answer.
    pub dns_timeout: Duration,
    /// Certificates for custom domains from an ACME CA; `None` when not
    /// configured.
    pub acme: Option<AcmeConfig>,
    /// Encrypts certificate and ACME account keys before they are stored;
    /// required with `acme`.
    pub key_encryption_key: Option<[u8; 32]>,
    /// Terminating TLS; `None` when not configured.
    pub tls: Option<TlsConfig>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("addr", &self.addr)
            .field("admin_addr", &self.admin_addr)
            .field("public_base_url", &self.public_base_url)
            .field("default_host", &self.default_host)
            .field("code_length", &self.code_length)
            .field("cookie_key", &self.cookie_key.map(|_| "<redacted>"))
            .field("cookie_secure", &self.cookie_secure)
            .field("country_header", &self.country_header)
            .field("region_header", &self.region_header)
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
            .field("oidc", &self.oidc)
            .field("session_ttl", &self.session_ttl)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("dns_servers", &self.dns_servers)
            .field("dns_timeout", &self.dns_timeout)
            .field("acme", &self.acme)
            .field(
                "key_encryption_key",
                &self.key_encryption_key.map(|_| "<redacted>"),
            )
            .field("tls", &self.tls)
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
        let default_host = url::Url::parse(&public_base_url)
            .ok()
            .and_then(|u| {
                u.host_str()
                    .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            })
            .filter(|h| !h.is_empty())
            .ok_or("RELINK_PUBLIC_BASE_URL must name a host")?;
        let dns_servers = match v.raw("RELINK_DNS_SERVERS") {
            None => None,
            Some(list) => Some(
                list.split(',')
                    .map(|s| {
                        crate::dns::parse_server(s).ok_or_else(|| {
                            format!(
                                "RELINK_DNS_SERVERS: {:?} is not an IP address or ip:port",
                                s.trim()
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
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
                let zone_id = v
                    .raw("RELINK_KV_ZONE_ID")
                    .map(|z| z.trim().to_owned())
                    .filter(|z| !z.is_empty());
                if zone_id.as_deref().is_some_and(|z| !safe_id(z)) {
                    return Err("RELINK_KV_ZONE_ID must be a plain identifier".into());
                }
                Some(KvConfig {
                    api_base,
                    account_id: account_id.trim().to_owned(),
                    namespace_id: namespace_id.trim().to_owned(),
                    api_token: api_token.trim().to_owned(),
                    zone_id,
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
        let oidc = match (v.raw("RELINK_OIDC_ISSUER"), v.raw("RELINK_OIDC_CLIENT_ID")) {
            (None, None) => None,
            (Some(issuer), Some(client_id)) => {
                let oidc = OidcConfig {
                    issuer: issuer.trim().to_owned(),
                    client_id: client_id.trim().to_owned(),
                    client_secret: v
                        .raw("RELINK_OIDC_CLIENT_SECRET")
                        .map(|s| s.trim().to_owned()),
                    redirect_url: v
                        .raw("RELINK_OIDC_REDIRECT_URL")
                        .map(|u| u.trim().to_owned())
                        .unwrap_or_else(|| format!("{public_base_url}/v1/auth/callback")),
                    scopes: v
                        .raw("RELINK_OIDC_SCOPES")
                        .unwrap_or_else(|| "openid email profile".into())
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" "),
                    allowed_domains: v
                        .raw("RELINK_OIDC_ALLOWED_DOMAINS")
                        .unwrap_or_default()
                        .split(',')
                        .map(|d| d.trim().to_ascii_lowercase())
                        .filter(|d| !d.is_empty())
                        .collect(),
                };
                oidc.validate()?;
                Some(oidc)
            }
            _ => {
                return Err(
                    "set both RELINK_OIDC_ISSUER and RELINK_OIDC_CLIENT_ID, or neither".into(),
                );
            }
        };
        let acme = match v.raw("RELINK_ACME_DIRECTORY") {
            None => {
                if v.raw("RELINK_ACME_EMAIL").is_some() {
                    return Err("RELINK_ACME_EMAIL needs RELINK_ACME_DIRECTORY".into());
                }
                None
            }
            Some(directory) => {
                let acme = AcmeConfig {
                    directory_url: directory.trim().to_owned(),
                    email: v.raw("RELINK_ACME_EMAIL").map(|e| e.trim().to_owned()),
                    interval: v.millis("RELINK_ACME_INTERVAL_MS", 60_000, 100, 86_400_000)?,
                    order_timeout: Duration::from_secs(v.parse(
                        "RELINK_ACME_ORDER_TIMEOUT_S",
                        300,
                        5,
                        3_600,
                    )?),
                };
                acme.validate()?;
                Some(acme)
            }
        };
        let key_encryption_key = match v.raw("RELINK_KEY_ENCRYPTION_KEY") {
            None => None,
            Some(hex) => {
                let bytes = hex_decode(hex.trim())
                    .filter(|b| b.len() == 32)
                    .ok_or("RELINK_KEY_ENCRYPTION_KEY must be 64 hex characters (32 bytes)")?;
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Some(key)
            }
        };
        if acme.is_some() && key_encryption_key.is_none() {
            return Err(
                "RELINK_ACME_DIRECTORY needs RELINK_KEY_ENCRYPTION_KEY: certificate \
                        keys are stored encrypted (64 hex characters, e.g. from \
                        `openssl rand -hex 32`)"
                    .into(),
            );
        }
        let tls = match v.raw("RELINK_TLS_ADDR") {
            None => {
                for name in ["RELINK_TLS_CERT_FILE", "RELINK_TLS_KEY_FILE"] {
                    if v.raw(name).is_some() {
                        return Err(format!("{name} needs RELINK_TLS_ADDR"));
                    }
                }
                None
            }
            Some(_) => {
                let file = |name: &str| v.raw(name).map(|p| p.trim().into());
                let tls = TlsConfig {
                    addr: v.addr("RELINK_TLS_ADDR", "0.0.0.0:8443")?,
                    cert_file: file("RELINK_TLS_CERT_FILE"),
                    key_file: file("RELINK_TLS_KEY_FILE"),
                    handshake_timeout: v.millis(
                        "RELINK_TLS_HANDSHAKE_TIMEOUT_MS",
                        10_000,
                        100,
                        120_000,
                    )?,
                };
                if tls.cert_file.is_some() != tls.key_file.is_some() {
                    return Err(
                        "set both RELINK_TLS_CERT_FILE and RELINK_TLS_KEY_FILE, or neither".into(),
                    );
                }
                if tls.cert_file.is_none() && key_encryption_key.is_none() {
                    return Err("RELINK_TLS_ADDR has no certificate to serve: set \
                                RELINK_TLS_CERT_FILE and RELINK_TLS_KEY_FILE, or \
                                RELINK_KEY_ENCRYPTION_KEY to serve custom domains' certificates"
                        .into());
                }
                Some(tls)
            }
        };
        let ttl = v.millis("RELINK_CACHE_TTL_MS", 30_000, 0, 86_400_000)?;
        let cfg = Config {
            database_url,
            addr: v.addr("RELINK_ADDR", "0.0.0.0:8080")?,
            admin_addr: v.addr("RELINK_ADMIN_ADDR", "127.0.0.1:9090")?,
            public_base_url,
            default_host,
            code_length: v.parse("RELINK_CODE_LENGTH", 7, MIN_CODE_LEN, MAX_CODE_LEN)?,
            cookie_key,
            cookie_secure: v.bool("RELINK_COOKIE_SECURE", true)?,
            country_header: v.header("RELINK_COUNTRY_HEADER", None)?,
            region_header: v.header("RELINK_REGION_HEADER", None)?,
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
            schedule_poll: v.millis("RELINK_SCHEDULE_POLL_MS", 1_000, 10, 60_000)?,
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
            oidc,
            session_ttl: Duration::from_secs(v.parse(
                "RELINK_SESSION_TTL_S",
                43_200,
                300,
                30 * 86_400,
            )?),
            redirect_max_age: v.parse("RELINK_REDIRECT_MAX_AGE_S", 0, 0, 31_536_000)?,
            shutdown_timeout: Duration::from_secs(v.parse(
                "RELINK_SHUTDOWN_TIMEOUT_S",
                10,
                1,
                300,
            )?),
            dns_servers,
            dns_timeout: v.millis("RELINK_DNS_TIMEOUT_MS", 2_000, 50, 30_000)?,
            acme,
            key_encryption_key,
            tls,
        };
        if (cfg.country_header.is_some()
            || cfg.region_header.is_some()
            || cfg.client_ip_header.is_some())
            && cfg.trusted_proxies.is_empty()
        {
            return Err(
                "RELINK_COUNTRY_HEADER, RELINK_REGION_HEADER and RELINK_CLIENT_IP_HEADER are \
                 only read from RELINK_TRUSTED_PROXIES; set it to your CDN or load balancer \
                 addresses"
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
        assert!(c.region_header.is_none());
        assert!(c.trusted_proxies.is_empty());
        assert!(c.cookie_secure);
        assert!(c.cookie_key.is_none());
        assert_eq!(c.cache.ttl, Duration::from_secs(30));
        assert!(!c.destination_policy.allow_private);
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("postgres://"), "secrets must not be printed");
        assert!(c.oidc.is_none());
        assert_eq!(c.session_ttl, Duration::from_secs(43_200));
        assert_eq!(c.default_host, "localhost");
        assert_eq!(c.dns_servers, None);
        assert_eq!(c.dns_timeout, Duration::from_secs(2));
        assert_eq!(c.acme, None);
        let c = from(&[
            ("RELINK_DATABASE_URL", "postgres://x/y"),
            ("RELINK_PUBLIC_BASE_URL", "https://Go.Example.com:8443"),
            ("RELINK_DNS_SERVERS", "1.1.1.1, 127.0.0.1:5353"),
        ])
        .unwrap();
        assert_eq!(c.default_host, "go.example.com");
        assert_eq!(
            c.dns_servers,
            Some(vec![
                "1.1.1.1:53".parse().unwrap(),
                "127.0.0.1:5353".parse().unwrap()
            ])
        );
    }

    #[test]
    fn kv_settings() {
        let base = [
            ("RELINK_DATABASE_URL", "postgres://x/y"),
            ("RELINK_KV_ACCOUNT_ID", "acct"),
            ("RELINK_KV_NAMESPACE_ID", "ns"),
            ("RELINK_KV_API_TOKEN", "token"),
        ];
        let kv = from(&base).unwrap().kv.unwrap();
        assert_eq!(kv.zone_id, None);
        assert_eq!(kv.api_base, DEFAULT_KV_API_BASE);
        let with_zone = |zone: &str| {
            let mut vars = base.to_vec();
            vars.push(("RELINK_KV_ZONE_ID", zone));
            from(&vars)
        };
        let kv = with_zone(" zone-1 ").unwrap().kv.unwrap();
        assert_eq!(kv.zone_id.as_deref(), Some("zone-1"));
        assert!(format!("{kv:?}").contains("zone-1"));
        assert!(!format!("{kv:?}").contains("token\""));
        assert_eq!(with_zone("  ").unwrap().kv.unwrap().zone_id, None);
        assert!(
            with_zone("zone/../x")
                .unwrap_err()
                .contains("RELINK_KV_ZONE_ID")
        );
    }

    #[test]
    fn acme_settings() {
        let c = from(&[
            ("RELINK_DATABASE_URL", "postgres://x/y"),
            ("RELINK_ACME_DIRECTORY", " https://acme.example.com/dir "),
            ("RELINK_ACME_EMAIL", "ops@example.com"),
            ("RELINK_ACME_INTERVAL_MS", "500"),
            ("RELINK_KEY_ENCRYPTION_KEY", &"0F".repeat(32)),
        ])
        .unwrap();
        assert_eq!(c.key_encryption_key, Some([0x0f; 32]));
        assert!(!format!("{c:?}").contains("0f0f"));
        assert!(format!("{c:?}").contains("key_encryption_key: Some(\"<redacted>\")"));
        let a = c.acme.unwrap();
        assert_eq!(a.directory_url, "https://acme.example.com/dir");
        assert_eq!(a.email.as_deref(), Some("ops@example.com"));
        assert_eq!(a.interval, Duration::from_millis(500));
        assert_eq!(a.order_timeout, Duration::from_secs(300));
    }

    #[test]
    fn tls_settings() {
        let base = ("RELINK_DATABASE_URL", "postgres://x/y");
        let kek = "ab".repeat(32);
        let c = from(&[base]).unwrap();
        assert_eq!((c.tls, c.key_encryption_key), (None, None));
        // Custom domains' certificates only.
        let c = from(&[
            base,
            ("RELINK_TLS_ADDR", "127.0.0.1:0"),
            ("RELINK_KEY_ENCRYPTION_KEY", &kek),
        ])
        .unwrap();
        let t = c.tls.unwrap();
        assert_eq!(t.addr.to_string(), "127.0.0.1:0");
        assert_eq!((t.cert_file, t.key_file), (None, None));
        assert_eq!(t.handshake_timeout, Duration::from_secs(10));
        // A default certificate only.
        let c = from(&[
            base,
            ("RELINK_TLS_ADDR", "[::]:443"),
            ("RELINK_TLS_CERT_FILE", " /etc/relink/cert.pem "),
            ("RELINK_TLS_KEY_FILE", "/etc/relink/key.pem"),
            ("RELINK_TLS_HANDSHAKE_TIMEOUT_MS", "2500"),
        ])
        .unwrap();
        let t = c.tls.unwrap();
        assert_eq!(t.cert_file, Some("/etc/relink/cert.pem".into()));
        assert_eq!(t.key_file, Some("/etc/relink/key.pem".into()));
        assert_eq!(t.handshake_timeout, Duration::from_millis(2500));
        for bad in [
            // Nothing to serve.
            vec![base, ("RELINK_TLS_ADDR", "0.0.0.0:443")],
            vec![
                base,
                ("RELINK_TLS_ADDR", "nope"),
                ("RELINK_KEY_ENCRYPTION_KEY", &kek),
            ],
            vec![
                base,
                ("RELINK_TLS_ADDR", "0.0.0.0:443"),
                ("RELINK_TLS_CERT_FILE", "/etc/relink/cert.pem"),
            ],
            vec![base, ("RELINK_TLS_CERT_FILE", "/etc/relink/cert.pem")],
            vec![base, ("RELINK_TLS_KEY_FILE", "/etc/relink/key.pem")],
            vec![
                base,
                ("RELINK_TLS_ADDR", "0.0.0.0:443"),
                ("RELINK_KEY_ENCRYPTION_KEY", &kek),
                ("RELINK_TLS_HANDSHAKE_TIMEOUT_MS", "10"),
            ],
            vec![base, ("RELINK_KEY_ENCRYPTION_KEY", "abcd")],
            vec![base, ("RELINK_KEY_ENCRYPTION_KEY", &"ab".repeat(33))],
            // Keys are never stored unencrypted.
            vec![
                base,
                ("RELINK_ACME_DIRECTORY", "https://acme.example.com/dir"),
            ],
        ] {
            assert!(from(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn oidc_settings() {
        let base = ("RELINK_DATABASE_URL", "postgres://x/y");
        let c = from(&[
            base,
            ("RELINK_PUBLIC_BASE_URL", "https://s.example.com/"),
            ("RELINK_OIDC_ISSUER", " https://id.example.com "),
            ("RELINK_OIDC_CLIENT_ID", "relink"),
            ("RELINK_OIDC_CLIENT_SECRET", "hunter2"),
            ("RELINK_OIDC_SCOPES", "openid  email"),
            ("RELINK_OIDC_ALLOWED_DOMAINS", "Example.com, ,example.org"),
            ("RELINK_SESSION_TTL_S", "3600"),
        ])
        .unwrap();
        let o = c.oidc.as_ref().unwrap();
        assert_eq!(o.issuer, "https://id.example.com");
        assert_eq!(o.redirect_url, "https://s.example.com/v1/auth/callback");
        assert_eq!(o.scopes, "openid email");
        assert_eq!(o.allowed_domains, ["example.com", "example.org"]);
        assert_eq!(c.session_ttl, Duration::from_secs(3600));
        assert!(!format!("{c:?}").contains("hunter2"));
        let explicit = from(&[
            base,
            ("RELINK_OIDC_ISSUER", "https://id.example.com"),
            ("RELINK_OIDC_CLIENT_ID", "relink"),
            (
                "RELINK_OIDC_REDIRECT_URL",
                "https://console.example.com/v1/auth/callback",
            ),
        ])
        .unwrap();
        let o = explicit.oidc.unwrap();
        assert_eq!(
            o.redirect_url,
            "https://console.example.com/v1/auth/callback"
        );
        assert_eq!(o.client_secret, None);
        assert_eq!(o.scopes, "openid email profile");
        for bad in [
            vec![base, ("RELINK_OIDC_ISSUER", "https://id.example.com")],
            vec![base, ("RELINK_OIDC_CLIENT_ID", "relink")],
            vec![
                base,
                ("RELINK_OIDC_ISSUER", "http://id.example.com"),
                ("RELINK_OIDC_CLIENT_ID", "relink"),
            ],
            vec![
                base,
                ("RELINK_OIDC_ISSUER", "https://id.example.com"),
                ("RELINK_OIDC_CLIENT_ID", "relink"),
                ("RELINK_OIDC_SCOPES", "email"),
            ],
            vec![base, ("RELINK_SESSION_TTL_S", "10")],
        ] {
            assert!(from(&bad).is_err(), "{bad:?}");
        }
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
            ("RELINK_REGION_HEADER", "CF-Region-Code"),
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
        assert_eq!(c.region_header.as_ref().unwrap().as_str(), "cf-region-code");
        assert!(c.trusted_proxies.contains("10.1.2.3".parse().unwrap()));
        assert_eq!(
            c.client_ip_header.as_ref().unwrap().as_str(),
            "cf-connecting-ip"
        );
        assert!(c.destination_policy.allow_private);
        assert_eq!(c.public_base_url, "https://s.example.com");
        assert_eq!(c.default_host, "s.example.com");
        assert_eq!(c.health.per_host_rps, 0.5);
    }

    #[test]
    fn rejects_bad_values() {
        let base = ("RELINK_DATABASE_URL", "postgres://x/y");
        let hex = "cd".repeat(32);
        let kek = ("RELINK_KEY_ENCRYPTION_KEY", hex.as_str());
        for bad in [
            vec![],
            vec![base, ("RELINK_CODE_LENGTH", "3")],
            vec![base, ("RELINK_CODE_LENGTH", "abc")],
            vec![base, ("RELINK_ADDR", "nope")],
            vec![base, ("RELINK_COOKIE_KEY", "abcd")],
            vec![base, ("RELINK_COOKIE_SECURE", "maybe")],
            vec![base, ("RELINK_COUNTRY_HEADER", "bad header")],
            vec![base, ("RELINK_COUNTRY_HEADER", "cf-ipcountry")],
            vec![base, ("RELINK_REGION_HEADER", "cf-region-code")],
            vec![base, ("RELINK_REGION_HEADER", "bad header")],
            vec![base, ("RELINK_TRUSTED_PROXIES", "10.0.0.0/99")],
            vec![base, ("RELINK_PUBLIC_BASE_URL", "ftp://x")],
            vec![base, ("RELINK_DB_TIMEOUT_MS", "1")],
            vec![base, ("RELINK_DNS_SERVERS", "1.1.1.1,dns.example.com")],
            vec![base, ("RELINK_DNS_TIMEOUT_MS", "10")],
            vec![base, ("RELINK_PUBLIC_BASE_URL", "http://")],
            vec![base, ("RELINK_ACME_EMAIL", "ops@example.com")],
            vec![
                base,
                kek,
                ("RELINK_ACME_DIRECTORY", "http://acme.example.com/dir"),
            ],
            vec![
                base,
                kek,
                ("RELINK_ACME_DIRECTORY", "https://acme.example.com/dir"),
                ("RELINK_ACME_EMAIL", "nobody"),
            ],
            vec![
                base,
                kek,
                ("RELINK_ACME_DIRECTORY", "https://acme.example.com/dir"),
                ("RELINK_ACME_INTERVAL_MS", "10"),
            ],
        ] {
            assert!(from(&bad).is_err(), "{bad:?}");
        }
    }
}

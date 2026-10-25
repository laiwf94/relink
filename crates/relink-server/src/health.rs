//! Background destination health checks.
//!
//! Each round claims links that are due (shared safely between instances
//! with `FOR UPDATE SKIP LOCKED`), probes every destination with bounded
//! concurrency, paced per host, and stores consecutive failure
//! counts. A destination with `failure_threshold` consecutive failures stops
//! receiving traffic; if none are healthy the link's fallback URL is used.
//!
//! Probes are a server-side request to a URL a user chose, so they are the
//! service's SSRF surface. Defences:
//! - the resolver drops every non-public address before connecting, and the
//!   connection uses exactly the addresses it returned (no second lookup an
//!   attacker could rebind);
//! - IP-literal hosts are checked against the same block list;
//! - redirects are never followed, and system proxy settings are ignored;
//! - response bodies are not read.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use url::{Host, Url};

use crate::config::HealthConfig;
use crate::metrics::{DbOp, Metrics, ProbeResult};
use crate::netguard::is_public_ip;
use crate::store::{Db, HealthTarget};
use crate::util::stopped;

/// Returned by the resolver when a name only resolves to blocked addresses.
#[derive(Debug)]
pub struct BlockedHost(pub String);

impl fmt::Display for BlockedHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} resolves only to non-public addresses", self.0)
    }
}

impl StdError for BlockedHost {}

/// DNS resolution that never yields a non-public address (unless allowed).
#[derive(Clone, Copy, Debug)]
pub struct SafeResolver {
    pub allow_private: bool,
}

impl SafeResolver {
    /// Keeps only the addresses a probe may connect to.
    pub fn filter(&self, addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
        addrs
            .filter(|a| self.allow_private || is_public_ip(a.ip()))
            .collect()
    }
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = *self;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = this.filter(found);
            if allowed.is_empty() {
                return Err(Box::new(BlockedHost(host)) as Box<dyn StdError + Send + Sync>);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// Healthy: the server answered with a status that means "this exists".
/// Redirects count as healthy because they are not followed.
pub fn status_is_healthy(status: u16) -> bool {
    status < 400 || matches!(status, 401 | 403 | 405 | 429)
}

/// Upper bound for stored failure counts.
const MAX_FAILURES: i16 = 1000;

/// Failure counts after a round: reset on success, incremented on failure,
/// unchanged when the probe was deferred to a later round.
pub fn next_failures(previous: &[i16], results: &[ProbeResult]) -> Vec<i16> {
    results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let before = previous.get(i).copied().unwrap_or(0);
            match r {
                ProbeResult::Healthy => 0,
                ProbeResult::Unhealthy | ProbeResult::Blocked => (before + 1).min(MAX_FAILURES),
                ProbeResult::RateLimited => before,
            }
        })
        .collect()
}

/// The background worker.
pub struct HealthWorker {
    db: Db,
    client: reqwest::Client,
    cfg: HealthConfig,
    resolver: SafeResolver,
    /// Per host, the earliest time the next probe may start.
    next_probe: Mutex<HashMap<String, Instant>>,
    permits: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}

impl HealthWorker {
    pub fn new(
        db: Db,
        cfg: HealthConfig,
        allow_private: bool,
        metrics: Arc<Metrics>,
    ) -> Result<HealthWorker, reqwest::Error> {
        let resolver = SafeResolver { allow_private };
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(cfg.timeout)
            .connect_timeout(cfg.timeout)
            .pool_max_idle_per_host(0)
            .user_agent("relink-health-check/1.0")
            .build()?;
        Ok(HealthWorker {
            db,
            client,
            cfg,
            resolver,
            next_probe: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(cfg.concurrency)),
            metrics,
        })
    }

    /// Probes one URL.
    pub async fn probe(&self, url: &str) -> ProbeResult {
        probe(&self.client, self.resolver, url).await
    }

    /// One round: claim due links, probe them, store results. Returns the
    /// number of links processed.
    pub async fn round(&self) -> usize {
        let targets = match self
            .db
            .claim_health_targets(self.cfg.interval, self.cfg.batch)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                self.metrics.db_error(DbOp::Health);
                tracing::warn!(error = %e, "could not claim health check targets");
                return 0;
            }
        };
        let mut jobs: JoinSet<(usize, usize, ProbeResult)> = JoinSet::new();
        let now = Instant::now();
        let mut results: Vec<Vec<ProbeResult>> = targets
            .iter()
            .map(|t| vec![ProbeResult::RateLimited; t.destinations.len()])
            .collect();
        for (ti, target) in targets.iter().enumerate() {
            for (di, dest) in target.destinations.iter().enumerate() {
                let host = Url::parse(&dest.url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_default();
                let Some(slot) = self.schedule(&host, now) else {
                    self.metrics.probe(ProbeResult::RateLimited);
                    continue;
                };
                let client = self.client.clone();
                let resolver = self.resolver;
                let url = dest.url.clone();
                let permits = self.permits.clone();
                jobs.spawn(async move {
                    tokio::time::sleep_until(slot.into()).await;
                    let _permit = permits.acquire_owned().await;
                    (ti, di, probe(&client, resolver, &url).await)
                });
            }
        }
        while let Some(done) = jobs.join_next().await {
            match done {
                Ok((ti, di, r)) => {
                    self.metrics.probe(r);
                    results[ti][di] = r;
                }
                Err(e) => tracing::error!(error = %e, "health probe task failed"),
            }
        }
        for (target, res) in targets.iter().zip(&results) {
            self.store(target, res).await;
        }
        targets.len()
    }

    /// When a probe to `host` may run: one per `1 / per_host_rps` seconds,
    /// queued behind earlier probes to the same host. `None` if the queue is
    /// already longer than the check interval; that destination keeps its
    /// previous result and is probed in a later round.
    fn schedule(&self, host: &str, now: Instant) -> Option<Instant> {
        let gap = Duration::from_secs_f64(1.0 / self.cfg.per_host_rps);
        let mut next = self.next_probe.lock().unwrap_or_else(|e| e.into_inner());
        next.retain(|_, t| *t > now);
        let slot = next.get(host).copied().unwrap_or(now).max(now);
        if slot.duration_since(now) > self.cfg.interval {
            return None;
        }
        next.insert(host.to_owned(), slot + gap);
        Some(slot)
    }

    async fn store(&self, target: &HealthTarget, results: &[ProbeResult]) {
        let failures = next_failures(&target.failures, results);
        if failures == target.failures {
            return;
        }
        if let Err(e) = self.db.record_health(target, &failures).await {
            self.metrics.db_error(DbOp::Health);
            tracing::warn!(error = %e, code = %target.code, "could not store health results");
        }
    }

    /// Runs rounds until shutdown. A round that found work is followed
    /// immediately by another; otherwise the worker sleeps.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let idle = (self.cfg.interval / 10).clamp(Duration::from_secs(1), Duration::from_secs(30));
        loop {
            let worked = self.round().await;
            let pause = if worked as i64 >= self.cfg.batch {
                Duration::ZERO
            } else {
                idle
            };
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = stopped(&mut shutdown) => return,
            }
        }
    }
}

async fn probe(client: &reqwest::Client, resolver: SafeResolver, url: &str) -> ProbeResult {
    let Ok(parsed) = Url::parse(url) else {
        return ProbeResult::Unhealthy;
    };
    // IP literals skip DNS, so the block list is applied here instead.
    let literal = match parsed.host() {
        Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        _ => None,
    };
    if let Some(ip) = literal
        && !resolver.allow_private
        && !is_public_ip(ip)
    {
        return ProbeResult::Blocked;
    }
    match client.get(parsed).send().await {
        Ok(resp) if status_is_healthy(resp.status().as_u16()) => ProbeResult::Healthy,
        Ok(_) => ProbeResult::Unhealthy,
        Err(e) => {
            let mut source: Option<&dyn StdError> = Some(&e);
            while let Some(err) = source {
                if err.is::<BlockedHost>() {
                    return ProbeResult::Blocked;
                }
                source = err.source();
            }
            ProbeResult::Unhealthy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses() {
        for s in [200, 204, 301, 302, 304, 401, 403, 405, 429] {
            assert!(status_is_healthy(s), "{s}");
        }
        for s in [400, 404, 410, 500, 502, 503] {
            assert!(!status_is_healthy(s), "{s}");
        }
    }

    #[test]
    fn failure_counting() {
        use ProbeResult::*;
        assert_eq!(
            next_failures(&[0, 3, 5], &[Unhealthy, Healthy, RateLimited]),
            vec![1, 0, 5]
        );
        assert_eq!(next_failures(&[], &[Blocked, Healthy]), vec![1, 0]);
        assert_eq!(
            next_failures(&[MAX_FAILURES], &[Unhealthy]),
            vec![MAX_FAILURES]
        );
    }

    #[test]
    fn resolver_filter() {
        let addrs = || {
            vec![
                "127.0.0.1:0".parse().unwrap(),
                "10.0.0.1:0".parse().unwrap(),
                "8.8.8.8:0".parse().unwrap(),
            ]
            .into_iter()
        };
        let strict = SafeResolver {
            allow_private: false,
        };
        assert_eq!(strict.filter(addrs()), vec!["8.8.8.8:0".parse().unwrap()]);
        let open = SafeResolver {
            allow_private: true,
        };
        assert_eq!(open.filter(addrs()).len(), 3);
        assert!(!BlockedHost("x".into()).to_string().is_empty());
    }

    #[tokio::test]
    async fn resolver_blocks_loopback_names() {
        let strict = SafeResolver {
            allow_private: false,
        };
        let name: Name = "localhost".parse().unwrap();
        let err = match strict.resolve(name).await {
            Err(e) => e,
            Ok(_) => panic!("localhost must not resolve"),
        };
        assert!(err.is::<BlockedHost>());
        let open = SafeResolver {
            allow_private: true,
        };
        let name: Name = "localhost".parse().unwrap();
        assert!(open.resolve(name).await.is_ok());
    }
}

//! Code → link resolution for the redirect path: cache first, then one
//! coalesced database lookup per code, with stale entries served while the
//! database is slow or down.
//!
//! A small circuit breaker keeps an outage from costing every request a
//! timeout: after a failed lookup, for [`BREAKER_COOLDOWN`] expired entries
//! are served stale at once and misses are answered "unavailable" at once.
//! When a lookup is attempted for an expired entry, the request waits at most
//! [`EXPIRED_PATIENCE`] before falling back to the stale entry; the lookup
//! itself carries on in the background.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::cache::{Cache, Freshness, Lookup};
use crate::metrics::{CacheResult, DbOp, Metrics};
use crate::model::Link;
use crate::singleflight::SingleFlight;
use crate::store::{Db, DbError};
use crate::util::BoxFuture;

/// Where links come from on a cache miss. Implemented by [`Db`]; benchmarks
/// and tests use an in-memory map.
pub trait LinkSource: Send + Sync {
    fn load<'a>(&'a self, code: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>>;
}

impl LinkSource for Db {
    fn load<'a>(&'a self, code: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
        Box::pin(async move { Ok(self.link_by_code(code).await?.map(|s| s.link)) })
    }
}

/// The answer for one code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    Found(Arc<Link>),
    NotFound,
    /// Nothing cached and the database could not answer.
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoadError {
    Unavailable,
    Shed,
}

type LoadResult = Result<Option<Arc<Link>>, LoadError>;

/// How long a miss waits for a database lookup slot before giving up.
const SHED_AFTER: Duration = Duration::from_millis(250);

/// After a failed lookup, how long lookups are not attempted on the request path.
pub const BREAKER_COOLDOWN: Duration = Duration::from_secs(1);

/// Longest a request with an expired (but usable) entry waits for a refresh.
pub const EXPIRED_PATIENCE: Duration = Duration::from_millis(100);

/// Open/closed state shared with the lookup tasks.
struct Breaker {
    base: Instant,
    open_until_ms: AtomicU64,
}

impl Breaker {
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }
    fn is_open(&self) -> bool {
        self.now_ms() < self.open_until_ms.load(Ordering::Acquire)
    }
    fn trip(&self) {
        let until = self.now_ms() + BREAKER_COOLDOWN.as_millis() as u64;
        self.open_until_ms.store(until, Ordering::Release);
    }
    fn reset(&self) {
        self.open_until_ms.store(0, Ordering::Release);
    }
}

/// Cache, single flight and lookup concurrency limit around a [`LinkSource`].
pub struct Resolver {
    cache: Arc<Cache<Arc<Link>>>,
    flights: Arc<SingleFlight<String, LoadResult>>,
    source: Arc<dyn LinkSource>,
    permits: Arc<Semaphore>,
    breaker: Arc<Breaker>,
    metrics: Arc<Metrics>,
}

impl Resolver {
    pub fn new(
        cache: Cache<Arc<Link>>,
        source: Arc<dyn LinkSource>,
        max_concurrent_lookups: usize,
        metrics: Arc<Metrics>,
    ) -> Resolver {
        Resolver {
            cache: Arc::new(cache),
            flights: Arc::default(),
            source,
            permits: Arc::new(Semaphore::new(max_concurrent_lookups)),
            breaker: Arc::new(Breaker {
                base: Instant::now(),
                open_until_ms: AtomicU64::new(0),
            }),
            metrics,
        }
    }

    /// Whether recent lookups failed and the request path is skipping them.
    pub fn database_suspect(&self) -> bool {
        self.breaker.is_open()
    }

    pub fn cache(&self) -> &Cache<Arc<Link>> {
        &self.cache
    }

    /// Resolves `code`. Never waits on the database when a fresh or
    /// revalidating entry exists, waits at most [`EXPIRED_PATIENCE`] when an
    /// expired one exists, and does not wait at all while the breaker is open.
    pub async fn resolve(&self, code: &str) -> Resolved {
        let to_resolved = |v: Option<Arc<Link>>| v.map_or(Resolved::NotFound, Resolved::Found);
        match self.cache.get(code, Instant::now()) {
            Lookup::Found(v, Freshness::Fresh) => {
                self.metrics.cache(if v.is_some() {
                    CacheResult::Hit
                } else {
                    CacheResult::NegativeHit
                });
                to_resolved(v)
            }
            Lookup::Found(v, Freshness::Stale) => {
                self.metrics.cache(CacheResult::Stale);
                if !self.breaker.is_open() {
                    self.flights
                        .spawn_if_idle(code.to_owned(), self.loader(code));
                }
                to_resolved(v)
            }
            Lookup::Found(v, Freshness::Expired) => {
                if self.breaker.is_open() {
                    self.metrics.cache(CacheResult::StaleOnError);
                    return to_resolved(v);
                }
                match tokio::time::timeout(EXPIRED_PATIENCE, self.load(code)).await {
                    Ok(Ok(fresh)) => {
                        self.metrics.cache(CacheResult::Miss);
                        to_resolved(fresh)
                    }
                    // Failed, or still running: serve what we have.
                    Ok(Err(_)) | Err(_) => {
                        self.metrics.cache(CacheResult::StaleOnError);
                        to_resolved(v)
                    }
                }
            }
            Lookup::Found(v, Freshness::Suspect) => {
                if self.breaker.is_open() {
                    self.metrics.cache(CacheResult::StaleOnError);
                    return to_resolved(v);
                }
                // No patience limit here: this entry may describe a link that
                // has since been disabled, so only a database failure lets us
                // fall back to it.
                match self.load(code).await {
                    Ok(fresh) => {
                        self.metrics.cache(CacheResult::Miss);
                        to_resolved(fresh)
                    }
                    Err(_) => {
                        self.metrics.cache(CacheResult::StaleOnError);
                        to_resolved(v)
                    }
                }
            }
            Lookup::Miss => {
                self.metrics.cache(CacheResult::Miss);
                if self.breaker.is_open() {
                    return Resolved::Unavailable;
                }
                match self.load(code).await {
                    Ok(v) => to_resolved(v),
                    Err(_) => Resolved::Unavailable,
                }
            }
        }
    }

    async fn load(&self, code: &str) -> LoadResult {
        match self.flights.run(code.to_owned(), self.loader(code)).await {
            Ok((result, leader)) => {
                if !leader {
                    self.metrics.coalesced.inc();
                }
                result
            }
            Err(_) => Err(LoadError::Unavailable),
        }
    }

    /// The work for one coalesced lookup. Owns everything it needs, because
    /// it runs in its own task.
    fn loader(&self, code: &str) -> impl FnOnce() -> BoxFuture<'static, LoadResult> + use<> {
        let cache = self.cache.clone();
        let source = self.source.clone();
        let permits = self.permits.clone();
        let breaker = self.breaker.clone();
        let metrics = self.metrics.clone();
        let code = code.to_owned();
        move || {
            Box::pin(async move {
                let Ok(Ok(_permit)) =
                    tokio::time::timeout(SHED_AFTER, permits.acquire_owned()).await
                else {
                    metrics.lookups_shed.inc();
                    return Err(LoadError::Shed);
                };
                let token = cache.begin_load();
                match source.load(&code).await {
                    Ok(link) => {
                        breaker.reset();
                        let value = link.map(Arc::new);
                        cache.insert(&code, value.clone(), Instant::now(), token);
                        Ok(value)
                    }
                    Err(e) => {
                        breaker.trip();
                        metrics.db_error(DbOp::Lookup);
                        tracing::warn!(error = %e, "link lookup failed");
                        Err(LoadError::Unavailable)
                    }
                }
            })
        }
    }

    /// Drops the cached entry for a changed link.
    pub fn invalidate(&self, code: &str) {
        self.metrics.invalidations.inc();
        self.cache.invalidate(code);
    }
}

#[cfg(test)]
pub mod memory {
    //! An in-memory [`LinkSource`] with failure injection and a call counter.

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct MemorySource {
        pub links: Mutex<HashMap<String, Link>>,
        pub down: AtomicBool,
        pub calls: AtomicUsize,
        pub delay: Mutex<Duration>,
    }

    impl LinkSource for MemorySource {
        fn load<'a>(&'a self, code: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let delay = *self.delay.lock().unwrap();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if self.down.load(Ordering::SeqCst) {
                    return Err(DbError::Unavailable("down".into()));
                }
                Ok(self.links.lock().unwrap().get(code).cloned())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemorySource;
    use super::*;
    use crate::cache::Config;
    use crate::model::Destination;
    use std::sync::atomic::Ordering;

    pub fn link(code: &str) -> Link {
        Link {
            id: 1,
            code: code.into(),
            destinations: vec![Destination {
                url: "https://example.com/".into(),
                weight: 1,
            }],
            destinations_version: 1,
            redirect_status: 302,
            expires_at: None,
            max_clicks: None,
            geo: None,
            fallback_url: None,
            enabled: true,
            health_check: false,
            unhealthy: vec![false],
        }
    }

    fn resolver(source: Arc<MemorySource>, cfg: Config) -> (Resolver, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::default());
        (
            Resolver::new(Cache::new(cfg), source, 4, metrics.clone()),
            metrics,
        )
    }

    fn cfg() -> Config {
        Config {
            capacity: 1000,
            ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(60),
            stale_while_revalidate: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(3600),
        }
    }

    #[tokio::test]
    async fn caches_hits_and_misses() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        let (r, m) = resolver(src.clone(), cfg());
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        assert_eq!(r.resolve("nope").await, Resolved::NotFound);
        assert_eq!(r.resolve("nope").await, Resolved::NotFound);
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
        assert_eq!(m.cache_count(CacheResult::Hit), 1);
        assert_eq!(m.cache_count(CacheResult::NegativeHit), 1);
        assert_eq!(m.cache_count(CacheResult::Miss), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn miss_storm_hits_the_source_once() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("hot".into(), link("hot"));
        *src.delay.lock().unwrap() = Duration::from_millis(50);
        let (r, m) = resolver(src.clone(), cfg());
        let r = Arc::new(r);
        let tasks: Vec<_> = (0..200)
            .map(|_| {
                let r = r.clone();
                tokio::spawn(async move { r.resolve("hot").await })
            })
            .collect();
        for t in tasks {
            assert!(matches!(t.await.unwrap(), Resolved::Found(_)));
        }
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
        assert_eq!(m.coalesced.get(), 199);
    }

    #[tokio::test]
    async fn serves_stale_when_source_is_down() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        let (r, m) = resolver(
            src.clone(),
            Config {
                ttl: Duration::ZERO,
                stale_while_revalidate: Duration::ZERO,
                ..cfg()
            },
        );
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        src.down.store(true, Ordering::SeqCst);
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        assert_eq!(m.cache_count(CacheResult::StaleOnError), 1);
        assert!(r.database_suspect(), "the failure opens the breaker");
        // While open: no lookups at all, stale served, misses refused at once.
        let calls = src.calls.load(Ordering::SeqCst);
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        assert_eq!(r.resolve("other").await, Resolved::Unavailable);
        assert_eq!(src.calls.load(Ordering::SeqCst), calls);
        assert_eq!(m.cache_count(CacheResult::StaleOnError), 2);
        // After the cool-down, lookups resume; a failure re-opens it.
        tokio::time::sleep(BREAKER_COOLDOWN).await;
        assert_eq!(r.resolve("other").await, Resolved::Unavailable);
        assert_eq!(m.db_error_count(DbOp::Lookup), 2);
        // Recovery.
        src.down.store(false, Ordering::SeqCst);
        src.links.lock().unwrap().remove("abc");
        tokio::time::sleep(BREAKER_COOLDOWN).await;
        assert_eq!(r.resolve("abc").await, Resolved::NotFound);
        assert!(!r.database_suspect());
    }

    #[tokio::test]
    async fn slow_refresh_of_expired_entry_serves_stale_after_patience() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        let (r, m) = resolver(
            src.clone(),
            Config {
                ttl: Duration::ZERO,
                stale_while_revalidate: Duration::ZERO,
                ..cfg()
            },
        );
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        *src.delay.lock().unwrap() = Duration::from_millis(300);
        let mut changed = link("abc");
        changed.enabled = false;
        src.links.lock().unwrap().insert("abc".into(), changed);
        let started = Instant::now();
        match r.resolve("abc").await {
            Resolved::Found(l) => assert!(l.enabled, "the old entry, served after the patience"),
            other => panic!("unexpected {other:?}"),
        }
        let waited = started.elapsed();
        assert!(
            waited >= EXPIRED_PATIENCE && waited < Duration::from_millis(250),
            "{waited:?}"
        );
        assert_eq!(m.cache_count(CacheResult::StaleOnError), 1);
        // The refresh finished in the background.
        tokio::time::sleep(Duration::from_millis(300)).await;
        *src.delay.lock().unwrap() = Duration::ZERO;
        let calls = src.calls.load(Ordering::SeqCst);
        match r.resolve("abc").await {
            Resolved::Found(l) => {
                // Expired again (ttl 0) and refreshed quickly this time.
                assert!(!l.enabled);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(src.calls.load(Ordering::SeqCst), calls + 1);
    }

    #[tokio::test]
    async fn stale_entries_refresh_in_background() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        let (r, m) = resolver(
            src.clone(),
            Config {
                ttl: Duration::ZERO,
                ..cfg()
            },
        );
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        src.links.lock().unwrap().remove("abc");
        // Served from cache immediately, refreshed behind the scenes.
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        assert_eq!(m.cache_count(CacheResult::Stale), 1);
        for _ in 0..100 {
            if src.calls.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(r.resolve("abc").await, Resolved::NotFound);
    }

    #[tokio::test]
    async fn invalidate_forces_a_reload() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        let (r, m) = resolver(src.clone(), cfg());
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
        let mut changed = link("abc");
        changed.enabled = false;
        src.links.lock().unwrap().insert("abc".into(), changed);
        r.invalidate("abc");
        match r.resolve("abc").await {
            Resolved::Found(l) => assert!(!l.enabled),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(m.invalidations.get(), 1);
        assert_eq!(r.cache().len(), 1);
    }

    #[tokio::test]
    async fn a_load_that_raced_a_disable_is_not_served_without_asking_again() {
        let src = Arc::new(MemorySource::default());
        src.links.lock().unwrap().insert("abc".into(), link("abc"));
        *src.delay.lock().unwrap() = Duration::from_millis(100);
        let (r, _) = resolver(src.clone(), cfg());
        let r = Arc::new(r);
        // A miss starts loading the enabled link...
        let first = {
            let r = r.clone();
            tokio::spawn(async move { r.resolve("abc").await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        // ...the link is disabled and invalidated while that load runs.
        let mut disabled = link("abc");
        disabled.enabled = false;
        src.links.lock().unwrap().insert("abc".into(), disabled);
        r.invalidate("abc");
        assert!(matches!(first.await.unwrap(), Resolved::Found(_)));
        // The raced result is cached as suspect: the next request reloads,
        // even though that takes longer than the expired-entry patience.
        let started = Instant::now();
        match r.resolve("abc").await {
            Resolved::Found(l) => assert!(!l.enabled),
            other => panic!("unexpected {other:?}"),
        }
        assert!(started.elapsed() >= Duration::from_millis(100));
        // When the database is down, the suspect entry is still better than nothing.
        r.cache().bump_epoch();
        src.down.store(true, Ordering::SeqCst);
        assert!(matches!(r.resolve("abc").await, Resolved::Found(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sheds_when_lookups_are_saturated() {
        let src = Arc::new(MemorySource::default());
        *src.delay.lock().unwrap() = Duration::from_millis(400);
        let metrics = Arc::new(Metrics::default());
        let r = Arc::new(Resolver::new(
            Cache::new(cfg()),
            src.clone(),
            1,
            metrics.clone(),
        ));
        let slow = {
            let r = r.clone();
            tokio::spawn(async move { r.resolve("aaa").await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(r.resolve("bbb").await, Resolved::Unavailable);
        assert_eq!(metrics.lookups_shed.get(), 1);
        assert_eq!(slow.await.unwrap(), Resolved::NotFound);
    }
}

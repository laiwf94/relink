//! Max-click enforcement without a database write per click.
//!
//! Each process reserves blocks of clicks ("leases") from the database with
//! one atomic `UPDATE` and spends them from a local atomic counter. The
//! database never grants more than `max_clicks` in total, and a click is only
//! served after taking a unit from a granted lease, so
//!
//! ```text
//! clicks served  <=  clicks reserved  <=  max_clicks
//! ```
//!
//! holds at all times: the overshoot bound is zero. The cost is undershoot:
//! a process that crashes takes its unspent lease with it. Lease size is
//! `min(max_lease, max(1, remaining / 8))`, so the loss per crashed process is
//! at most an eighth of what was left at its last refill, and near the limit
//! leases shrink to single clicks. Graceful shutdown and invalidation return
//! unspent leases.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::metrics::Metrics;
use crate::util::BoxFuture;

/// The store could not be reached; the caller should fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUnavailable;

/// Where leases come from. Implemented by the Postgres store and, in tests,
/// by an in-memory model.
pub trait LeaseStore: Send + Sync {
    /// Atomically reserves up to `min(max_lease, max(1, remaining / 8))`
    /// clicks for `link_id` and returns how many were granted (0 when the
    /// limit is reached or the link has no limit).
    fn reserve(&self, link_id: i64, max_lease: i64)
    -> BoxFuture<'_, Result<i64, StoreUnavailable>>;
    /// Returns `n` unspent clicks.
    fn release(&self, link_id: i64, n: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>>;
}

/// Whether a click may be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Yes,
    LimitReached,
    /// No local lease and the store could not be reached.
    Unavailable,
}

struct Lease {
    remaining: AtomicI64,
    exhausted_at: Mutex<Option<Instant>>,
    /// After a failed reservation, refills are not retried until then, so an
    /// outage costs one store call per link per [`RETRY_AFTER_FAILURE`]
    /// instead of one queued timeout per click.
    failed_until: Mutex<Option<Instant>>,
    retired: AtomicBool,
    refill: tokio::sync::Mutex<()>,
    /// Milliseconds since the limiter's base instant.
    last_used: AtomicU64,
}

/// How long "the database said the limit is reached" is believed before
/// asking again (in case the limit was raised and the notification missed).
const EXHAUSTED_RECHECK: Duration = Duration::from_secs(30);

/// How long a failed reservation is remembered.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(1);

/// Leases unused for this long are returned to the database by [`ClickLimiter::sweep`].
const IDLE_RETURN: Duration = Duration::from_secs(600);

/// Per-process lease cache.
pub struct ClickLimiter {
    store: Arc<dyn LeaseStore>,
    metrics: Option<Arc<Metrics>>,
    max_lease: i64,
    leases: RwLock<HashMap<i64, Arc<Lease>>>,
    base: Instant,
    closed: AtomicBool,
}

fn try_take(counter: &AtomicI64) -> bool {
    let mut cur = counter.load(Ordering::Acquire);
    while cur > 0 {
        match counter.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
    false
}

impl ClickLimiter {
    pub fn new(store: Arc<dyn LeaseStore>, max_lease: i64) -> Self {
        assert!(max_lease >= 1);
        ClickLimiter {
            store,
            metrics: None,
            max_lease,
            leases: RwLock::new(HashMap::new()),
            base: Instant::now(),
            closed: AtomicBool::new(false),
        }
    }

    /// Counts lease grants in `metrics`.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn millis(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.base).as_millis() as u64
    }

    fn lease(&self, link_id: i64) -> Arc<Lease> {
        if let Some(l) = self
            .leases
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&link_id)
        {
            return l.clone();
        }
        let mut map = self.leases.write().unwrap_or_else(|e| e.into_inner());
        map.entry(link_id)
            .or_insert_with(|| {
                Arc::new(Lease {
                    remaining: AtomicI64::new(0),
                    exhausted_at: Mutex::new(None),
                    failed_until: Mutex::new(None),
                    retired: AtomicBool::new(false),
                    refill: tokio::sync::Mutex::new(()),
                    last_used: AtomicU64::new(self.millis(Instant::now())),
                })
            })
            .clone()
    }

    /// Takes one click for `link_id`, refilling the local lease from the store
    /// when it is empty. Concurrent callers on the same link share one refill.
    pub async fn admit(&self, link_id: i64) -> Admit {
        let lease = self.lease(link_id);
        lease
            .last_used
            .store(self.millis(Instant::now()), Ordering::Relaxed);
        if try_take(&lease.remaining) {
            return Admit::Yes;
        }
        if lease.is_exhausted() {
            return Admit::LimitReached;
        }
        if lease.recently_failed() || self.closed.load(Ordering::Acquire) {
            return Admit::Unavailable;
        }
        let _refilling = lease.refill.lock().await;
        // Another caller may have refilled (or failed) while this one waited.
        if try_take(&lease.remaining) {
            return Admit::Yes;
        }
        if lease.is_exhausted() {
            return Admit::LimitReached;
        }
        if lease.recently_failed() {
            return Admit::Unavailable;
        }
        match self.store.reserve(link_id, self.max_lease).await {
            Ok(0) => {
                *lease.exhausted_at.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now());
                Admit::LimitReached
            }
            Ok(granted) => {
                self.metrics_grant();
                // Keep one for this caller, publish the rest.
                if granted > 1 {
                    lease.remaining.fetch_add(granted - 1, Ordering::SeqCst);
                    // If the lease was retired concurrently, either retire()
                    // swapped out what was just added, or this sees `retired`
                    // and hands it back itself (SeqCst on both sides rules
                    // out both missing each other). Nothing is stranded.
                    if lease.retired.load(Ordering::SeqCst) {
                        let back = lease.remaining.swap(0, Ordering::SeqCst);
                        self.release(link_id, back).await;
                    }
                }
                Admit::Yes
            }
            Err(StoreUnavailable) => {
                *lease.failed_until.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now() + RETRY_AFTER_FAILURE);
                Admit::Unavailable
            }
        }
    }

    /// Forgets the local lease for `link_id` (its limit or destinations
    /// changed) and returns any unspent clicks to the store.
    pub async fn invalidate(&self, link_id: i64) {
        let removed = self
            .leases
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&link_id);
        if let Some(lease) = removed {
            self.retire(link_id, &lease).await;
        }
    }

    async fn retire(&self, link_id: i64, lease: &Lease) {
        lease.retired.store(true, Ordering::SeqCst);
        let unspent = lease.remaining.swap(0, Ordering::SeqCst);
        self.release(link_id, unspent).await;
    }

    async fn release(&self, link_id: i64, n: i64) {
        if n > 0 && self.store.release(link_id, n).await.is_err() {
            // Not an overshoot risk: the clicks stay reserved and unused.
            tracing::warn!(link_id, clicks = n, "could not return unspent clicks");
        }
    }

    fn metrics_grant(&self) {
        if let Some(m) = &self.metrics {
            m.lease_grants.inc();
        }
    }

    /// Clears every "limit reached" mark so the next click asks the store
    /// again. Used when change notifications may have been missed.
    pub fn forget_exhausted(&self) {
        let map = self.leases.read().unwrap_or_else(|e| e.into_inner());
        for lease in map.values() {
            *lease.exhausted_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// Drops leases with nothing left and returns long-idle unspent ones, so
    /// the map only holds links that are actually being clicked.
    pub async fn sweep(&self, now: Instant) {
        let idle: Vec<(i64, Arc<Lease>)> = {
            let mut map = self.leases.write().unwrap_or_else(|e| e.into_inner());
            let mut idle = Vec::new();
            map.retain(|&id, lease| {
                let last = lease.last_used.load(Ordering::Relaxed);
                let quiet = self.millis(now).saturating_sub(last) >= IDLE_RETURN.as_millis() as u64;
                let empty = lease.remaining.load(Ordering::Acquire) == 0 && !lease.is_exhausted();
                // An Arc held only by the map means no admit() is using it.
                let unused = Arc::strong_count(lease) == 1;
                if unused && (empty || quiet) {
                    idle.push((id, lease.clone()));
                    false
                } else {
                    true
                }
            });
            idle
        };
        for (id, lease) in idle {
            self.retire(id, &lease).await;
        }
    }

    /// Stops reserving new leases (shutdown). Clicks already held locally can
    /// still be spent until [`ClickLimiter::release_all`].
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Returns every unspent click to the store (graceful shutdown).
    pub async fn release_all(&self) {
        let all: Vec<(i64, Arc<Lease>)> = self
            .leases
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .collect();
        for (id, lease) in all {
            self.retire(id, &lease).await;
        }
    }

    /// Number of links with a local lease.
    pub fn len(&self) -> usize {
        self.leases.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Unspent clicks held locally for `link_id`.
    pub fn local_remaining(&self, link_id: i64) -> i64 {
        self.leases
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&link_id)
            .map_or(0, |l| l.remaining.load(Ordering::Acquire))
    }
}

impl Lease {
    fn recently_failed(&self) -> bool {
        self.failed_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|t| Instant::now() < t)
    }

    fn is_exhausted(&self) -> bool {
        let mut at = self.exhausted_at.lock().unwrap_or_else(|e| e.into_inner());
        match *at {
            Some(t) if t.elapsed() < EXHAUSTED_RECHECK => true,
            Some(_) => {
                *at = None;
                false
            }
            None => false,
        }
    }
}

/// The lease grant rule shared by the SQL implementation and the test model:
/// `min(max_lease, max(1, remaining / 8), remaining)`.
pub fn grant_size(max_clicks: i64, reserved: i64, max_lease: i64) -> i64 {
    let remaining = (max_clicks - reserved).max(0);
    // The final min() makes this 0 once nothing remains.
    max_lease.min((remaining / 8).max(1)).min(remaining)
}

#[cfg(test)]
pub mod model {
    //! An in-memory [`LeaseStore`] with the same grant rule as Postgres, plus
    //! failure injection.

    use super::*;
    use std::sync::atomic::AtomicU64;

    #[derive(Default)]
    pub struct MemoryStore {
        pub links: Mutex<HashMap<i64, (i64, i64)>>,
        pub fail_every: AtomicU64,
        calls: AtomicU64,
    }

    impl MemoryStore {
        pub fn with_link(id: i64, max: i64) -> Self {
            let s = MemoryStore::default();
            s.links.lock().unwrap().insert(id, (max, 0));
            s
        }
        pub fn reserved(&self, id: i64) -> i64 {
            self.links.lock().unwrap()[&id].1
        }
        fn should_fail(&self) -> bool {
            let every = self.fail_every.load(Ordering::Relaxed);
            let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            every > 0 && n.is_multiple_of(every)
        }
    }

    impl LeaseStore for MemoryStore {
        fn reserve(
            &self,
            link_id: i64,
            max_lease: i64,
        ) -> BoxFuture<'_, Result<i64, StoreUnavailable>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                if self.should_fail() {
                    return Err(StoreUnavailable);
                }
                let mut links = self.links.lock().unwrap();
                let Some((max, reserved)) = links.get_mut(&link_id) else {
                    return Ok(0);
                };
                let g = grant_size(*max, *reserved, max_lease);
                *reserved += g;
                Ok(g)
            })
        }
        fn release(&self, link_id: i64, n: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                if let Some((_, reserved)) = self.links.lock().unwrap().get_mut(&link_id) {
                    *reserved = (*reserved - n).max(0);
                }
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::model::MemoryStore;
    use super::*;

    #[test]
    fn grant_rule() {
        assert_eq!(grant_size(1000, 0, 100), 100);
        assert_eq!(grant_size(1000, 900, 100), 12);
        assert_eq!(grant_size(10, 0, 100), 1);
        assert_eq!(grant_size(10, 9, 100), 1);
        assert_eq!(grant_size(10, 10, 100), 0);
        assert_eq!(grant_size(10, 12, 100), 0);
        assert_eq!(grant_size(5, 0, 1), 1);
    }

    #[tokio::test]
    async fn serves_exactly_the_limit_with_one_instance() {
        let store = Arc::new(MemoryStore::with_link(1, 250));
        let l = ClickLimiter::new(store.clone(), 50);
        let mut yes = 0;
        for _ in 0..400 {
            if l.admit(1).await == Admit::Yes {
                yes += 1;
            }
        }
        assert_eq!(yes, 250);
        assert_eq!(store.reserved(1), 250);
        assert_eq!(l.admit(1).await, Admit::LimitReached);
        assert_eq!(l.len(), 1);
    }

    #[tokio::test]
    async fn store_failure_fails_closed_and_recovers() {
        let store = Arc::new(MemoryStore::with_link(1, 10));
        store.fail_every.store(1, Ordering::Relaxed);
        let l = ClickLimiter::new(store.clone(), 5);
        assert_eq!(l.admit(1).await, Admit::Unavailable);
        store.fail_every.store(0, Ordering::Relaxed);
        // Within the retry window the store is not asked again.
        assert_eq!(l.admit(1).await, Admit::Unavailable);
        assert_eq!(store.reserved(1), 0);
        tokio::time::sleep(RETRY_AFTER_FAILURE).await;
        assert_eq!(l.admit(1).await, Admit::Yes);
    }

    #[tokio::test]
    async fn unknown_link_is_limit_reached() {
        let l = ClickLimiter::new(Arc::new(MemoryStore::default()), 5);
        assert_eq!(l.admit(9).await, Admit::LimitReached);
    }

    #[tokio::test]
    async fn invalidate_and_shutdown_return_unspent_clicks() {
        let store = Arc::new(MemoryStore::with_link(1, 1000));
        store.links.lock().unwrap().insert(2, (1000, 0));
        let l = ClickLimiter::new(store.clone(), 100);
        assert_eq!(l.admit(1).await, Admit::Yes);
        assert_eq!(l.admit(2).await, Admit::Yes);
        assert_eq!(store.reserved(1), 100);
        assert_eq!(l.local_remaining(1), 99);
        l.invalidate(1).await;
        assert_eq!(store.reserved(1), 1);
        assert_eq!(l.local_remaining(1), 0);
        l.invalidate(1).await; // no lease: no-op
        l.release_all().await;
        assert_eq!(store.reserved(2), 1);
        assert!(l.is_empty());
    }

    #[tokio::test]
    async fn a_closed_limiter_reserves_nothing() {
        let store = Arc::new(MemoryStore::with_link(1, 100));
        let l = ClickLimiter::new(store.clone(), 10);
        l.close();
        assert_eq!(l.admit(1).await, Admit::Unavailable);
        assert_eq!(store.reserved(1), 0);
    }

    #[tokio::test]
    async fn exhausted_mark_can_be_cleared() {
        let store = Arc::new(MemoryStore::with_link(1, 1));
        let l = ClickLimiter::new(store.clone(), 10);
        assert_eq!(l.admit(1).await, Admit::Yes);
        assert_eq!(l.admit(1).await, Admit::LimitReached);
        // The limit is raised elsewhere; until the mark is cleared the
        // cached answer stands, afterwards the store is asked again.
        store.links.lock().unwrap().insert(1, (2, 1));
        assert_eq!(l.admit(1).await, Admit::LimitReached);
        l.forget_exhausted();
        assert_eq!(l.admit(1).await, Admit::Yes);
    }

    #[tokio::test]
    async fn sweep_drops_empty_and_returns_idle_leases() {
        let store = Arc::new(MemoryStore::with_link(1, 1000));
        store.links.lock().unwrap().insert(2, (1, 0));
        let l = ClickLimiter::new(store.clone(), 100);
        assert_eq!(l.admit(1).await, Admit::Yes);
        assert_eq!(l.admit(2).await, Admit::Yes); // lease of 1, now empty
        l.sweep(Instant::now()).await;
        assert_eq!(l.len(), 1, "empty lease dropped, live one kept");
        l.sweep(Instant::now() + IDLE_RETURN).await;
        assert!(l.is_empty());
        assert_eq!(store.reserved(1), 1);
    }

    #[test]
    fn exhausted_mark_expires() {
        let lease = Lease {
            remaining: AtomicI64::new(0),
            exhausted_at: Mutex::new(Some(Instant::now() - EXHAUSTED_RECHECK)),
            failed_until: Mutex::new(None),
            retired: AtomicBool::new(false),
            refill: tokio::sync::Mutex::new(()),
            last_used: AtomicU64::new(0),
        };
        assert!(!lease.is_exhausted());
        assert!(lease.exhausted_at.lock().unwrap().is_none());
    }

    mod props {
        //! The max-click bound under random concurrent schedules: several
        //! limiter instances (processes) share one store; tasks interleave at
        //! random yield points; the store fails at random; leases are
        //! invalidated at random.

        use super::super::model::MemoryStore;
        use super::super::*;
        use proptest::prelude::*;

        fn splitmix(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        #[derive(Debug, Default)]
        struct Outcome {
            admitted: i64,
            attempts: i64,
            refused: i64,
        }

        #[allow(clippy::too_many_arguments)]
        async fn run(
            instances: usize,
            tasks: usize,
            attempts: usize,
            max_clicks: i64,
            max_lease: i64,
            fail_every: u64,
            invalidate_every: u64,
            seed: u64,
        ) -> (Outcome, Arc<MemoryStore>, Vec<Arc<ClickLimiter>>) {
            let store = Arc::new(MemoryStore::with_link(1, max_clicks));
            store.fail_every.store(fail_every, Ordering::Relaxed);
            let limiters: Vec<Arc<ClickLimiter>> = (0..instances)
                .map(|_| Arc::new(ClickLimiter::new(store.clone(), max_lease)))
                .collect();
            let mut handles = Vec::new();
            for (i, limiter) in limiters.iter().enumerate() {
                for t in 0..tasks {
                    let limiter = limiter.clone();
                    let mut rng = seed ^ ((i as u64) << 32) ^ t as u64;
                    handles.push(tokio::spawn(async move {
                        let mut out = Outcome::default();
                        for _ in 0..attempts {
                            for _ in 0..splitmix(&mut rng) % 4 {
                                tokio::task::yield_now().await;
                            }
                            if invalidate_every > 0
                                && splitmix(&mut rng).is_multiple_of(invalidate_every)
                            {
                                limiter.invalidate(1).await;
                            }
                            out.attempts += 1;
                            match limiter.admit(1).await {
                                Admit::Yes => out.admitted += 1,
                                Admit::LimitReached => out.refused += 1,
                                Admit::Unavailable => {}
                            }
                        }
                        out
                    }));
                }
            }
            let mut total = Outcome::default();
            for h in handles {
                let o = h.await.unwrap();
                total.admitted += o.admitted;
                total.attempts += o.attempts;
                total.refused += o.refused;
            }
            (total, store, limiters)
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            #[test]
            fn never_more_than_max_clicks(
                instances in 1usize..=4,
                tasks in 1usize..=6,
                attempts in 1usize..=40,
                max_clicks in 1i64..=300,
                max_lease in 1i64..=50,
                fail_every in prop_oneof![Just(0u64), 2u64..=9],
                invalidate_every in prop_oneof![Just(0u64), 5u64..=40],
                seed in any::<u64>(),
            ) {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                let (out, store, limiters) = rt.block_on(run(
                    instances, tasks, attempts, max_clicks, max_lease,
                    fail_every, invalidate_every, seed,
                ));
                // The bound: overshoot is zero.
                prop_assert!(out.admitted <= max_clicks,
                    "admitted {} > max {}", out.admitted, max_clicks);
                // Accounting: every reserved click was served or is still
                // held by some instance; nothing is lost while all live.
                let held: i64 = limiters.iter().map(|l| l.local_remaining(1)).sum();
                prop_assert_eq!(store.reserved(1), out.admitted + held);
                if fail_every == 0 && invalidate_every == 0 {
                    if out.attempts >= max_clicks {
                        prop_assert_eq!(store.reserved(1), max_clicks);
                    } else {
                        prop_assert_eq!(out.admitted, out.attempts);
                    }
                }
                // Shutdown returns everything unspent.
                rt.block_on(async {
                    for l in &limiters {
                        l.release_all().await;
                    }
                });
                prop_assert_eq!(store.reserved(1), out.admitted);
            }
        }
    }
}

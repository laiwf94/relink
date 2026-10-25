//! Request coalescing: concurrent callers asking for the same key share one
//! execution of the work (the "single flight" pattern from Go's
//! `golang.org/x/sync/singleflight`).
//!
//! The work runs in its own task, so a caller that disconnects does not
//! cancel the lookup for everyone else waiting on it.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// Returned when the shared work panicked before producing a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abandoned;

/// Coalesces concurrent work by key.
pub struct SingleFlight<K, V> {
    inflight: Mutex<HashMap<K, watch::Receiver<Option<V>>>>,
}

impl<K, V> Default for SingleFlight<K, V> {
    fn default() -> Self {
        SingleFlight {
            inflight: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, V> SingleFlight<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Runs `work` for `key` unless a run for the same key is already in
    /// flight, in which case this waits for that run's result. Returns the
    /// value and whether this caller started the work.
    pub async fn run<F, Fut>(self: &Arc<Self>, key: K, work: F) -> Result<(V, bool), Abandoned>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V> + Send + 'static,
    {
        let (mut rx, leader) = self.start(key, work);
        loop {
            if let Some(v) = rx.borrow_and_update().clone() {
                return Ok((v, leader));
            }
            rx.changed().await.map_err(|_| Abandoned)?;
        }
    }

    /// Starts `work` for `key` in the background unless a run is already in
    /// flight; never waits. Returns whether a run was started.
    pub fn spawn_if_idle<F, Fut>(self: &Arc<Self>, key: K, work: F) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V> + Send + 'static,
    {
        self.start(key, work).1
    }

    fn start<F, Fut>(self: &Arc<Self>, key: K, work: F) -> (watch::Receiver<Option<V>>, bool)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V> + Send + 'static,
    {
        let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rx) = map.get(&key) {
            return (rx.clone(), false);
        }
        let (tx, rx) = watch::channel(None);
        map.insert(key.clone(), rx.clone());
        let fut = work();
        let this = Arc::clone(self);
        tokio::spawn(async move {
            // Remove the entry even if `fut` panics, so the next caller
            // starts a new run instead of waiting forever.
            let guard = RemoveOnDrop {
                flight: this,
                key: Some(key),
            };
            let value = fut.await;
            let _ = tx.send(Some(value));
            drop(guard);
        });
        (rx, true)
    }

    /// Number of keys with work in flight.
    pub fn in_flight(&self) -> usize {
        self.inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

struct RemoveOnDrop<K: Eq + Hash, V> {
    flight: Arc<SingleFlight<K, V>>,
    key: Option<K>,
}

impl<K: Eq + Hash, V> Drop for RemoveOnDrop<K, V> {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            self.flight
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_share_one_run() {
        let sf: Arc<SingleFlight<String, u64>> = Arc::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..100 {
            let sf = sf.clone();
            let runs = runs.clone();
            handles.push(tokio::spawn(async move {
                sf.run("k".to_string(), || async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    42
                })
                .await
            }));
        }
        let mut leaders = 0;
        for h in handles {
            let (v, leader) = h.await.unwrap().unwrap();
            assert_eq!(v, 42);
            leaders += leader as usize;
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(leaders, 1);
        assert_eq!(sf.in_flight(), 0);
    }

    #[tokio::test]
    async fn different_keys_run_separately_and_later_calls_rerun() {
        let sf: Arc<SingleFlight<u32, u32>> = Arc::default();
        assert_eq!(sf.run(1, || async { 10 }).await, Ok((10, true)));
        assert_eq!(sf.run(2, || async { 20 }).await, Ok((20, true)));
        assert_eq!(sf.run(1, || async { 11 }).await, Ok((11, true)));
    }

    #[tokio::test]
    async fn cancelled_caller_does_not_cancel_the_work() {
        let sf: Arc<SingleFlight<u32, u32>> = Arc::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let r = runs.clone();
        let first = tokio::time::timeout(
            Duration::from_millis(5),
            sf.run(7, move || async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                r.fetch_add(1, Ordering::SeqCst);
                5
            }),
        )
        .await;
        assert!(first.is_err(), "the first caller gave up");
        // A second caller joins the same, still running, flight.
        let (v, leader) = sf.run(7, || async { 99 }).await.unwrap();
        assert_eq!((v, leader), (5, false));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn spawn_if_idle_starts_once_and_never_waits() {
        let sf: Arc<SingleFlight<u32, u32>> = Arc::default();
        let runs = Arc::new(AtomicUsize::new(0));
        for _ in 0..10 {
            let r = runs.clone();
            sf.spawn_if_idle(1, move || async move {
                r.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                1
            });
        }
        assert_eq!(sf.in_flight(), 1);
        // A waiting caller joins the background run.
        assert_eq!(sf.run(1, || async { 2 }).await, Ok((1, false)));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(sf.in_flight(), 0);
    }

    #[tokio::test]
    async fn panicking_work_is_reported_and_cleared() {
        let sf: Arc<SingleFlight<u32, u32>> = Arc::default();
        let res = sf
            .run(1, || async {
                if std::hint::black_box(true) {
                    panic!("boom");
                }
                0
            })
            .await;
        assert_eq!(res, Err(Abandoned));
        assert_eq!(sf.in_flight(), 0);
        assert_eq!(sf.run(1, || async { 3 }).await, Ok((3, true)));
    }
}

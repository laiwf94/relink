//! Click analytics off the redirect path.
//!
//! A redirect hands its click to a bounded channel with `try_send` and moves
//! on; if the channel is full the click is counted as dropped rather than
//! making the visitor wait. One flusher task aggregates clicks in memory by
//! (link, day, country, device, referrer) and writes in chunks of
//! [`FLUSH_CHUNK`] rows, one multi-row upsert per table and chunk.
//!
//! When the database is down the aggregated rows stay in memory (bounded by
//! `max_backlog`) and are retried with exponential backoff, so a short outage
//! loses no clicks and a long one loses only what exceeds the bound, counted
//! in a metric.
//!
//! Client addresses never reach the database. A redirect computes a 16-byte
//! SHA-256 fingerprint of (address, User-Agent) that only lives in memory; the
//! flusher turns it into HMAC(daily salt, link, fingerprint). Salts are random,
//! one per UTC day, and deleted after two days (the scheme used by Plausible
//! Analytics), after which a stored hash cannot be linked to an address.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::{mpsc, watch};

use crate::classify::Device;
use crate::metrics::{DbOp, DropReason, Metrics};
use crate::store::{ClickRow, Db, DbError};
use crate::util::{BoxFuture, now_ms, utc_day};

/// One click, as queued by the redirect path.
#[derive(Clone, Debug)]
pub struct ClickEvent {
    pub link_id: i64,
    /// UTC days since the Unix epoch.
    pub day: i32,
    pub country: [u8; 2],
    pub device: Device,
    pub referrer: Option<Box<str>>,
    /// In-memory only; see the module documentation.
    pub fingerprint: [u8; 16],
}

pub use relink_core::visitor::fingerprint;

/// The stored visitor hash for one link and day.
pub fn visitor_hash(salt: &[u8; 32], link_id: i64, fingerprint: &[u8; 16]) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(&link_id.to_be_bytes());
    mac.update(fingerprint);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    out
}

/// The sending side, held by the redirect path.
#[derive(Clone)]
pub struct ClickQueue {
    tx: mpsc::Sender<ClickEvent>,
    capacity: usize,
    metrics: Arc<Metrics>,
}

impl ClickQueue {
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> (ClickQueue, mpsc::Receiver<ClickEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            ClickQueue {
                tx,
                capacity,
                metrics,
            },
            rx,
        )
    }

    /// Queues a click without waiting. Never blocks the caller.
    pub fn record(&self, event: ClickEvent) {
        match self.tx.try_send(event) {
            Ok(()) => self.metrics.clicks_enqueued.inc(),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.dropped(DropReason::QueueFull, 1)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics.dropped(DropReason::Closed, 1)
            }
        }
    }

    /// Clicks waiting in the channel.
    pub fn depth(&self) -> usize {
        self.capacity - self.tx.capacity()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Where flushed clicks go. Implemented by [`Db`]; tests use a fake.
pub trait ClickSink: Send + Sync {
    /// The salt for `day`, or `None` if that day's salt has been destroyed.
    fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>>;
    fn write<'a>(
        &'a self,
        rows: &'a [(ClickRow, i64)],
        visitors: &'a [(i64, i32, [u8; 16])],
    ) -> BoxFuture<'a, Result<(), DbError>>;
}

impl ClickSink for Db {
    fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
        Box::pin(self.salt_for_day(day, utc_day(now_ms())))
    }
    fn write<'a>(
        &'a self,
        rows: &'a [(ClickRow, i64)],
        visitors: &'a [(i64, i32, [u8; 16])],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(self.flush_clicks(rows, visitors))
    }
}

/// Attempts before a chunk the database keeps refusing is dropped.
pub const MAX_REJECTIONS: u32 = 3;

/// Most count rows and most visitor rows written per transaction.
pub const FLUSH_CHUNK: usize = 5_000;

/// Flusher settings.
#[derive(Clone, Copy, Debug)]
pub struct FlushConfig {
    /// Longest time a click waits in memory before a flush is attempted.
    pub interval: Duration,
    /// Clicks that trigger an early flush.
    pub batch: usize,
    /// Most aggregated rows (counts plus visitor fingerprints) held while the
    /// database is unavailable.
    pub max_backlog: usize,
    /// Longest wait between retries after failed flushes.
    pub max_backoff: Duration,
}

#[derive(Default)]
struct Pending {
    counts: HashMap<ClickRow, i64>,
    visitors: HashSet<(i64, i32, [u8; 16])>,
    events: u64,
}

impl Pending {
    fn size(&self) -> usize {
        self.counts.len() + self.visitors.len()
    }
}

/// Aggregates queued clicks and writes them to the sink.
pub struct Flusher {
    sink: Arc<dyn ClickSink>,
    metrics: Arc<Metrics>,
    cfg: FlushConfig,
    pending: Pending,
    salts: HashMap<i32, [u8; 32]>,
    backoff: Duration,
    next_attempt: Instant,
    /// Consecutive non-transient failures of the current chunk.
    rejections: u32,
}

impl Flusher {
    pub fn new(sink: Arc<dyn ClickSink>, metrics: Arc<Metrics>, cfg: FlushConfig) -> Flusher {
        Flusher {
            sink,
            metrics,
            cfg,
            pending: Pending::default(),
            salts: HashMap::new(),
            backoff: Duration::ZERO,
            next_attempt: Instant::now(),
            rejections: 0,
        }
    }

    /// Aggregated rows waiting to be written.
    pub fn backlog(&self) -> usize {
        self.pending.size()
    }

    fn publish_backlog(&self) {
        self.metrics.backlog.store(
            self.pending.size() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Adds one click to the pending aggregates, or counts it as dropped if
    /// the backlog is full. [`Flusher::run`] calls this for every queued click.
    pub fn absorb(&mut self, ev: ClickEvent) {
        if self.pending.size() + 2 > self.cfg.max_backlog {
            self.metrics.dropped(DropReason::Backlog, 1);
            return;
        }
        let row = ClickRow {
            link_id: ev.link_id,
            day: ev.day,
            country: ev.country,
            device: ev.device.as_str(),
            referrer: ev.referrer,
        };
        *self.pending.counts.entry(row).or_insert(0) += 1;
        self.pending
            .visitors
            .insert((ev.link_id, ev.day, ev.fingerprint));
        self.pending.events += 1;
    }

    /// Tries to write everything pending, in chunks of [`FLUSH_CHUNK`] rows so
    /// that each transaction stays well inside the query timeout even after a
    /// long outage. Chunks that were written are forgotten; on failure the
    /// rest stays pending. Returns true when nothing is left.
    pub async fn flush(&mut self) -> bool {
        if self.pending.counts.is_empty() && self.pending.visitors.is_empty() {
            return true;
        }
        let days: HashSet<i32> = self.pending.visitors.iter().map(|v| v.1).collect();
        for day in days {
            if self.salts.contains_key(&day) {
                continue;
            }
            match self.sink.salt(day).await {
                Ok(Some(salt)) => {
                    self.salts.insert(day, salt);
                }
                Ok(None) => {
                    // The day's salt is gone (a flush delayed past the
                    // retention window). A new salt would count these
                    // visitors a second time, so their unique-visitor data is
                    // dropped; the click counts are still written.
                    let before = self.pending.visitors.len();
                    self.pending.visitors.retain(|v| v.1 != day);
                    let dropped = (before - self.pending.visitors.len()) as u64;
                    self.metrics.late_visitors.add(dropped);
                    tracing::warn!(day, dropped, "visitor hashes for an expired day dropped");
                }
                Err(e) => return self.failed(&e),
            }
        }
        while !(self.pending.counts.is_empty() && self.pending.visitors.is_empty()) {
            let keys: Vec<ClickRow> = self
                .pending
                .counts
                .keys()
                .take(FLUSH_CHUNK)
                .cloned()
                .collect();
            let rows: Vec<(ClickRow, i64)> = keys
                .into_iter()
                .map(|k| {
                    let n = self.pending.counts.remove(&k).unwrap_or(0);
                    (k, n)
                })
                .collect();
            let taken: Vec<(i64, i32, [u8; 16])> = self
                .pending
                .visitors
                .iter()
                .take(FLUSH_CHUNK)
                .copied()
                .collect();
            for v in &taken {
                self.pending.visitors.remove(v);
            }
            let hashed: Vec<(i64, i32, [u8; 16])> = taken
                .iter()
                .map(|&(link, day, fp)| (link, day, visitor_hash(&self.salts[&day], link, &fp)))
                .collect();
            match self.sink.write(&rows, &hashed).await {
                Ok(()) => {
                    self.rejections = 0;
                    let clicks: i64 = rows.iter().map(|(_, n)| n).sum();
                    self.pending.events = self.pending.events.saturating_sub(clicks as u64);
                    self.metrics.clicks_flushed.add(clicks as u64);
                    self.metrics.flushes.inc();
                }
                Err(DbError::Other(e)) if self.rejections + 1 >= MAX_REJECTIONS => {
                    // Refused again for a reason that is not an outage (a bug
                    // or a constraint). Retrying forever would block every
                    // later click, so this chunk is dropped.
                    self.rejections = 0;
                    let clicks: i64 = rows.iter().map(|(_, n)| n).sum();
                    self.pending.events = self.pending.events.saturating_sub(clicks as u64);
                    self.metrics.dropped(DropReason::Rejected, clicks as u64);
                    self.metrics.db_error(DbOp::Flush);
                    tracing::error!(error = %e, clicks, "click batch rejected by the database; dropped");
                }
                Err(e) => {
                    if matches!(e, DbError::Other(_)) {
                        self.rejections += 1;
                    }
                    // Put the chunk back; nothing of it was committed.
                    for (k, n) in rows {
                        *self.pending.counts.entry(k).or_insert(0) += n;
                    }
                    self.pending.visitors.extend(taken);
                    return self.failed(&e);
                }
            }
        }
        self.backoff = Duration::ZERO;
        // Salts older than yesterday are destroyed in the database; forget
        // them here too.
        let today = utc_day(now_ms());
        self.salts.retain(|&d, _| d >= today - 1);
        self.publish_backlog();
        true
    }

    fn failed(&mut self, e: &DbError) -> bool {
        self.metrics.db_error(DbOp::Flush);
        self.backoff = (self.backoff * 2)
            .max(Duration::from_millis(250))
            .min(self.cfg.max_backoff);
        self.next_attempt = Instant::now() + self.backoff;
        tracing::warn!(error = %e, backlog = self.pending.size(), retry_in_ms = self.backoff.as_millis() as u64, "click flush failed");
        false
    }

    /// Runs until `shutdown` carries a deadline (or its sender is gone), then
    /// drains the channel and keeps retrying the final flush until that
    /// deadline.
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<ClickEvent>,
        mut shutdown: watch::Receiver<Option<tokio::time::Instant>>,
    ) {
        let mut buf = Vec::with_capacity(self.cfg.batch);
        let mut tick = tokio::time::interval(self.cfg.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                n = rx.recv_many(&mut buf, self.cfg.batch) => {
                    if n == 0 {
                        break;
                    }
                    for ev in buf.drain(..) {
                        self.absorb(ev);
                    }
                    self.publish_backlog();
                    if self.pending.events as usize >= self.cfg.batch && Instant::now() >= self.next_attempt {
                        self.flush().await;
                    }
                }
                _ = tick.tick() => {
                    if Instant::now() >= self.next_attempt {
                        self.flush().await;
                    }
                }
                _ = shutdown_deadline(&mut shutdown) => break,
            }
        }
        // Every sender gone without a shutdown (only in tests and tools):
        // allow a fixed drain time.
        let deadline = shutdown
            .borrow()
            .map(tokio::time::Instant::into_std)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
        rx.close();
        while let Some(ev) = rx.recv().await {
            self.absorb(ev);
        }
        while !self.flush().await {
            let now = Instant::now();
            if now >= deadline {
                self.metrics
                    .dropped(DropReason::Closed, self.pending.events);
                tracing::error!(
                    lost_clicks = self.pending.events,
                    "database unavailable at shutdown; pending clicks dropped"
                );
                return;
            }
            tokio::time::sleep(self.backoff.min(deadline - now)).await;
        }
        tracing::info!("click queue drained");
    }
}

/// Waits for a shutdown deadline. A dropped sender means "stop now".
async fn shutdown_deadline(
    rx: &mut watch::Receiver<Option<tokio::time::Instant>>,
) -> tokio::time::Instant {
    match rx.wait_for(Option::is_some).await {
        Ok(d) => d.unwrap_or_else(tokio::time::Instant::now),
        Err(_) => tokio::time::Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct FakeSink {
        down: AtomicBool,
        salt_down: AtomicBool,
        rows: Mutex<HashMap<ClickRow, i64>>,
        visitors: Mutex<HashSet<(i64, i32, [u8; 16])>>,
    }

    impl ClickSink for FakeSink {
        fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
            Box::pin(async move {
                if self.salt_down.load(Ordering::SeqCst) {
                    return Err(DbError::Unavailable("down".into()));
                }
                // Days before 0 stand for days whose salt is gone.
                Ok((day >= 0).then_some([day as u8; 32]))
            })
        }
        fn write<'a>(
            &'a self,
            rows: &'a [(ClickRow, i64)],
            visitors: &'a [(i64, i32, [u8; 16])],
        ) -> BoxFuture<'a, Result<(), DbError>> {
            Box::pin(async move {
                if self.down.load(Ordering::SeqCst) {
                    return Err(DbError::Unavailable("down".into()));
                }
                let mut stored = self.rows.lock().unwrap();
                for (k, v) in rows {
                    *stored.entry(k.clone()).or_insert(0) += v;
                }
                self.visitors
                    .lock()
                    .unwrap()
                    .extend(visitors.iter().copied());
                Ok(())
            })
        }
    }

    fn event(link_id: i64, day: i32, visitor: u8) -> ClickEvent {
        ClickEvent {
            link_id,
            day,
            country: *b"DE",
            device: Device::Mobile,
            referrer: Some("example.com".into()),
            fingerprint: [visitor; 16],
        }
    }

    fn cfg() -> FlushConfig {
        FlushConfig {
            interval: Duration::from_millis(10),
            batch: 100,
            max_backlog: 1000,
            max_backoff: Duration::from_millis(40),
        }
    }

    #[test]
    fn visitor_hashes_depend_on_link_and_salt() {
        let fp = fingerprint("203.0.113.1".parse().unwrap(), b"ua");
        let salt = [1u8; 32];
        assert_ne!(visitor_hash(&salt, 1, &fp), visitor_hash(&salt, 2, &fp));
        assert_ne!(
            visitor_hash(&salt, 1, &fp),
            visitor_hash(&[2u8; 32], 1, &fp)
        );
    }

    #[tokio::test]
    async fn aggregates_and_flushes() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        for v in [1, 1, 2] {
            f.absorb(event(7, 100, v));
        }
        f.absorb(event(8, 100, 1));
        assert!(f.flush().await);
        {
            let rows = sink.rows.lock().unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows.values().sum::<i64>(), 4);
        }
        assert_eq!(sink.visitors.lock().unwrap().len(), 3);
        assert_eq!(metrics.clicks_flushed.get(), 4);
        assert_eq!(f.backlog(), 0);
        assert!(f.flush().await, "nothing pending is success");
    }

    #[tokio::test]
    async fn keeps_backlog_while_down_and_bounds_it() {
        let sink = Arc::new(FakeSink::default());
        sink.down.store(true, Ordering::SeqCst);
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(
            sink.clone(),
            metrics.clone(),
            FlushConfig {
                max_backlog: 10,
                ..cfg()
            },
        );
        for v in 0..20 {
            f.absorb(event(1, 100, v));
        }
        // Each event adds one visitor and the first adds one count row.
        assert!(f.backlog() <= 10);
        let kept = metrics.dropped_count(DropReason::Backlog);
        assert!(kept > 0);
        assert!(!f.flush().await);
        assert!(!f.flush().await);
        assert_eq!(metrics.db_error_count(DbOp::Flush), 2);
        sink.down.store(false, Ordering::SeqCst);
        assert!(f.flush().await);
        assert_eq!(
            sink.rows.lock().unwrap().values().sum::<i64>() as u64 + kept,
            20
        );
    }

    #[tokio::test]
    async fn large_backlogs_are_written_in_chunks() {
        #[derive(Default)]
        struct Counting {
            inner: FakeSink,
            writes: std::sync::atomic::AtomicUsize,
            fail_on: std::sync::atomic::AtomicUsize,
        }
        impl ClickSink for Counting {
            fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
                self.inner.salt(day)
            }
            fn write<'a>(
                &'a self,
                rows: &'a [(ClickRow, i64)],
                visitors: &'a [(i64, i32, [u8; 16])],
            ) -> BoxFuture<'a, Result<(), DbError>> {
                assert!(rows.len() <= FLUSH_CHUNK && visitors.len() <= FLUSH_CHUNK);
                let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
                if n == self.fail_on.load(Ordering::SeqCst) {
                    return Box::pin(async { Err(DbError::Unavailable("flaky".into())) });
                }
                self.inner.write(rows, visitors)
            }
        }
        let sink = Arc::new(Counting::default());
        sink.fail_on.store(2, Ordering::SeqCst);
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(
            sink.clone(),
            metrics.clone(),
            FlushConfig {
                max_backlog: 100_000,
                ..cfg()
            },
        );
        // 12,000 distinct links: 12,000 count rows and 12,000 visitors.
        for link in 0..12_000 {
            f.absorb(event(link, 1, 7));
        }
        assert!(!f.flush().await, "the second chunk fails");
        assert_eq!(metrics.clicks_flushed.get(), FLUSH_CHUNK as u64);
        assert!(f.flush().await);
        assert_eq!(metrics.clicks_flushed.get(), 12_000);
        assert_eq!(
            sink.inner.rows.lock().unwrap().values().sum::<i64>(),
            12_000
        );
        assert_eq!(sink.inner.visitors.lock().unwrap().len(), 12_000);
        assert_eq!(f.backlog(), 0);
    }

    #[tokio::test]
    async fn non_transient_failures_drop_the_chunk_instead_of_blocking() {
        struct Refusing;
        impl ClickSink for Refusing {
            fn salt(&self, _: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
                Box::pin(async { Ok(Some([0; 32])) })
            }
            fn write<'a>(
                &'a self,
                _: &'a [(ClickRow, i64)],
                _: &'a [(i64, i32, [u8; 16])],
            ) -> BoxFuture<'a, Result<(), DbError>> {
                Box::pin(async { Err(DbError::Other("check constraint".into())) })
            }
        }
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(Arc::new(Refusing), metrics.clone(), cfg());
        f.absorb(event(1, 1, 1));
        f.absorb(event(1, 1, 2));
        for _ in 1..MAX_REJECTIONS {
            assert!(!f.flush().await, "retried a few times first");
        }
        assert!(
            f.flush().await,
            "then dropped, so nothing blocks later clicks"
        );
        assert_eq!(metrics.dropped_count(DropReason::Rejected), 2);
        assert_eq!(f.backlog(), 0);
    }

    #[tokio::test]
    async fn visitors_for_a_day_without_salt_are_dropped_but_clicks_kept() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        f.absorb(event(1, -3, 1));
        f.absorb(event(1, -3, 2));
        f.absorb(event(1, 5, 1));
        assert!(f.flush().await);
        assert_eq!(sink.rows.lock().unwrap().values().sum::<i64>(), 3);
        assert_eq!(sink.visitors.lock().unwrap().len(), 1);
        assert_eq!(metrics.late_visitors.get(), 2);
    }

    #[tokio::test]
    async fn salt_failure_keeps_pending() {
        let sink = Arc::new(FakeSink::default());
        sink.salt_down.store(true, Ordering::SeqCst);
        let mut f = Flusher::new(sink.clone(), Arc::new(Metrics::default()), cfg());
        f.absorb(event(1, 5, 1));
        assert!(!f.flush().await);
        sink.salt_down.store(false, Ordering::SeqCst);
        assert!(f.flush().await);
        assert_eq!(sink.visitors.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn queue_drops_when_full_and_after_close() {
        let metrics = Arc::new(Metrics::default());
        let (q, mut rx) = ClickQueue::new(2, metrics.clone());
        for _ in 0..3 {
            q.record(event(1, 1, 1));
        }
        assert_eq!(q.depth(), 2);
        assert_eq!(q.capacity(), 2);
        assert_eq!(metrics.clicks_enqueued.get(), 2);
        assert_eq!(metrics.dropped_count(DropReason::QueueFull), 1);
        rx.close();
        q.record(event(1, 1, 1));
        assert_eq!(metrics.dropped_count(DropReason::Closed), 1);
    }

    #[tokio::test]
    async fn run_flushes_on_interval_and_drains_on_shutdown() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let (q, rx) = ClickQueue::new(1000, metrics.clone());
        let (stop_tx, stop_rx) = watch::channel(None);
        let f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        let task = tokio::spawn(f.run(rx, stop_rx));
        q.record(event(1, 1, 1));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sink.rows.lock().unwrap().values().sum::<i64>(), 1);
        // A full batch flushes immediately.
        for i in 0..250 {
            q.record(event(1, 1, (i % 200) as u8));
        }
        q.record(event(2, 1, 1));
        stop_tx
            .send(Some(tokio::time::Instant::now() + Duration::from_secs(1)))
            .unwrap();
        task.await.unwrap();
        assert_eq!(sink.rows.lock().unwrap().values().sum::<i64>(), 252);
    }

    #[tokio::test]
    async fn run_gives_up_at_the_drain_deadline() {
        let sink = Arc::new(FakeSink::default());
        sink.down.store(true, Ordering::SeqCst);
        let metrics = Arc::new(Metrics::default());
        let (q, rx) = ClickQueue::new(10, metrics.clone());
        q.record(event(1, 1, 1));
        let (stop_tx, stop_rx) = watch::channel(None);
        let f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        let task = tokio::spawn(f.run(rx, stop_rx));
        tokio::time::sleep(Duration::from_millis(20)).await;
        stop_tx
            .send(Some(
                tokio::time::Instant::now() + Duration::from_millis(100),
            ))
            .unwrap();
        task.await.unwrap();
        assert_eq!(metrics.dropped_count(DropReason::Closed), 1);
    }

    #[tokio::test]
    async fn run_stops_when_all_senders_are_gone() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let (q, rx) = ClickQueue::new(10, metrics.clone());
        let (_stop_tx, stop_rx) = watch::channel(None);
        let f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        q.record(event(1, 1, 1));
        drop(q);
        f.run(rx, stop_rx).await;
        assert_eq!(sink.rows.lock().unwrap().values().sum::<i64>(), 1);
    }
}

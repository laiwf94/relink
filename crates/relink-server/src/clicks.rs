//! Click analytics off the redirect path.
//!
//! A redirect hands its click to a bounded channel with `try_send` and moves
//! on; if the channel is full the click is counted as dropped rather than
//! making the visitor wait. One flusher task aggregates clicks in memory by
//! (link, hour, country, device, referrer), keeps the raw events, and writes
//! them as batches of at most [`FLUSH_CHUNK`] rows of each kind.
//!
//! One batch feeds every rollup at once, in one transaction: the daily and
//! hourly counts, the quota meter, the visitor hashes, the hourly and daily
//! visitor sketches and the raw events (docs/DESIGN.md, "Rollups"). Each
//! batch carries a random key that the transaction records first. A batch
//! that failed is kept whole and retried with the same key, so when only the
//! acknowledgement of a commit was lost the retry finds its key and writes
//! nothing: replaying a batch never counts its clicks twice.
//!
//! When the database is down the aggregated rows stay in memory (bounded by
//! `max_backlog`) and are retried with exponential backoff, so a short outage
//! loses no clicks and a long one loses only what exceeds the bound, counted
//! in a metric. Raw events take one entry per click, so they have their own
//! bound, `max_events`; past it a click still reaches every rollup and only
//! its raw event is dropped.
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
use crate::store::{Applied, ClickRow, Db, DbError, FlushBatch, HourRow, StoredEvent};
use crate::util::{BoxFuture, now_ms, utc_day};
use relink_core::hll::Hll;

/// Milliseconds in an hour.
const HOUR_MS: i64 = 3_600_000;

/// One click, as queued by the redirect path.
#[derive(Clone, Debug)]
pub struct ClickEvent {
    pub link_id: i64,
    /// When the click happened, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    pub country: [u8; 2],
    pub device: Device,
    pub referrer: Option<Box<str>>,
    /// In-memory only; see the module documentation.
    pub fingerprint: [u8; 16],
}

impl ClickEvent {
    /// UTC days since the Unix epoch.
    pub fn day(&self) -> i32 {
        utc_day(self.at_ms)
    }

    /// UTC hours since the Unix epoch.
    pub fn hour(&self) -> i32 {
        self.at_ms.div_euclid(HOUR_MS) as i32
    }
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

/// The hash a visitor sketch is fed for one day: HMAC(daily salt,
/// fingerprint), the same for every link, so sketches of different links
/// merge into the visitors of all of them. Its input is 19 bytes against the
/// 24 of [`visitor_hash`], so the two can never be computed from the same
/// message.
pub fn sketch_hash(salt: &[u8; 32], fingerprint: &[u8; 16]) -> u64 {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(b"hll");
    mac.update(fingerprint);
    let tag = mac.finalize().into_bytes();
    u64::from_be_bytes(tag[..8].try_into().expect("8 bytes"))
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
    /// Writes one batch atomically; see [`Db::write_batch`].
    fn write<'a>(&'a self, batch: &'a FlushBatch) -> BoxFuture<'a, Result<Applied, DbError>>;
}

impl ClickSink for Db {
    fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
        Box::pin(self.salt_for_day(day, utc_day(now_ms())))
    }
    fn write<'a>(&'a self, batch: &'a FlushBatch) -> BoxFuture<'a, Result<Applied, DbError>> {
        Box::pin(self.write_batch(batch))
    }
}

/// Attempts before a batch the database keeps refusing is dropped.
pub const MAX_REJECTIONS: u32 = 3;

/// Most rows of each kind (counts, visitors, events) written per
/// transaction.
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
    /// Most raw events held while the database is unavailable.
    pub max_events: usize,
    /// Longest wait between retries after failed flushes.
    pub max_backoff: Duration,
}

#[derive(Default)]
struct Pending {
    counts: HashMap<HourRow, i64>,
    /// (link, hour, fingerprint).
    visitors: HashSet<(i64, i32, [u8; 16])>,
    events: Vec<ClickEvent>,
    /// Clicks counted in `counts`.
    clicks: u64,
}

impl Pending {
    fn size(&self) -> usize {
        self.counts.len() + self.visitors.len()
    }

    fn is_empty(&self) -> bool {
        self.counts.is_empty() && self.visitors.is_empty() && self.events.is_empty()
    }
}

/// Aggregates queued clicks and writes them to the sink.
pub struct Flusher {
    sink: Arc<dyn ClickSink>,
    metrics: Arc<Metrics>,
    cfg: FlushConfig,
    pending: Pending,
    /// A batch that failed, retried whole with the same key before anything
    /// else is written.
    retry: Option<FlushBatch>,
    salts: HashMap<i32, [u8; 32]>,
    backoff: Duration,
    next_attempt: Instant,
    /// Consecutive non-transient failures of the current batch.
    rejections: u32,
}

impl Flusher {
    pub fn new(sink: Arc<dyn ClickSink>, metrics: Arc<Metrics>, cfg: FlushConfig) -> Flusher {
        Flusher {
            sink,
            metrics,
            cfg,
            pending: Pending::default(),
            retry: None,
            salts: HashMap::new(),
            backoff: Duration::ZERO,
            next_attempt: Instant::now(),
            rejections: 0,
        }
    }

    /// Aggregated rows waiting to be written, including a batch waiting to
    /// be retried.
    pub fn backlog(&self) -> usize {
        self.pending.size() + self.retry.as_ref().map_or(0, FlushBatch::size)
    }

    /// Raw events waiting to be written.
    pub fn event_backlog(&self) -> usize {
        self.pending.events.len() + self.retry.as_ref().map_or(0, |b| b.events.len())
    }

    /// Clicks waiting to be written.
    fn clicks_pending(&self) -> u64 {
        self.pending.clicks + self.retry.as_ref().map_or(0, |b| b.clicks() as u64)
    }

    fn publish_backlog(&self) {
        self.metrics
            .backlog
            .store(self.backlog() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Adds one click to the pending aggregates, or counts it as dropped if
    /// the backlog is full. [`Flusher::run`] calls this for every queued click.
    pub fn absorb(&mut self, ev: ClickEvent) {
        if self.backlog() + 2 > self.cfg.max_backlog {
            self.metrics.dropped(DropReason::Backlog, 1);
            return;
        }
        let row = HourRow {
            link_id: ev.link_id,
            hour: ev.hour(),
            country: ev.country,
            device: ev.device.as_str(),
            referrer: ev.referrer.clone(),
        };
        *self.pending.counts.entry(row).or_insert(0) += 1;
        self.pending
            .visitors
            .insert((ev.link_id, ev.hour(), ev.fingerprint));
        self.pending.clicks += 1;
        if self.event_backlog() < self.cfg.max_events {
            self.pending.events.push(ev);
        } else {
            self.metrics.events_dropped.inc();
        }
    }

    /// Tries to write everything pending, in batches of at most
    /// [`FLUSH_CHUNK`] rows of each kind so that each transaction stays well
    /// inside the query timeout even after a long outage. Batches that were
    /// written are forgotten; a failed one is kept whole for the next
    /// attempt. Returns true when nothing is left.
    pub async fn flush(&mut self) -> bool {
        if let Some(batch) = self.retry.take()
            && !self.send(batch).await
        {
            return false;
        }
        if self.pending.is_empty() {
            return self.finished();
        }
        let days: HashSet<i32> = self
            .pending
            .visitors
            .iter()
            .map(|v| v.1.div_euclid(24))
            .chain(self.pending.events.iter().map(ClickEvent::day))
            .collect();
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
                    // dropped; the click counts are still written, and the
                    // raw events without a visitor hash.
                    let before = self.pending.visitors.len();
                    self.pending.visitors.retain(|v| v.1.div_euclid(24) != day);
                    let dropped = (before - self.pending.visitors.len()) as u64;
                    self.metrics.late_visitors.add(dropped);
                    tracing::warn!(day, dropped, "visitor hashes for an expired day dropped");
                }
                Err(e) => return self.failed(&e),
            }
        }
        while !self.pending.is_empty() {
            let batch = self.next_batch();
            if !self.send(batch).await {
                return false;
            }
        }
        self.finished()
    }

    fn finished(&mut self) -> bool {
        self.backoff = Duration::ZERO;
        // Salts older than yesterday are destroyed in the database; forget
        // them here too.
        let today = utc_day(now_ms());
        self.salts.retain(|&d, _| d >= today - 1);
        self.publish_backlog();
        true
    }

    /// Takes the next batch out of the pending aggregates. Every visitor's
    /// day has a salt in `self.salts` (days without one were removed).
    fn next_batch(&mut self) -> FlushBatch {
        let mut id = [0u8; 16];
        crate::util::secure_random(&mut id);
        let keys: Vec<HourRow> = self
            .pending
            .counts
            .keys()
            .take(FLUSH_CHUNK)
            .cloned()
            .collect();
        let hourly: Vec<(HourRow, i64)> = keys
            .into_iter()
            .map(|k| {
                let n = self.pending.counts.remove(&k).unwrap_or(0);
                (k, n)
            })
            .collect();
        let mut daily: HashMap<ClickRow, i64> = HashMap::with_capacity(hourly.len());
        for (row, n) in &hourly {
            *daily.entry(row.daily()).or_insert(0) += n;
        }
        let clicks: i64 = hourly.iter().map(|(_, n)| n).sum();
        self.pending.clicks = self.pending.clicks.saturating_sub(clicks as u64);

        let taken: Vec<(i64, i32, [u8; 16])> = self
            .pending
            .visitors
            .iter()
            .take(FLUSH_CHUNK)
            .copied()
            .collect();
        let mut visitors: HashSet<(i64, i32, [u8; 16])> = HashSet::with_capacity(taken.len());
        let mut hour_sketches: HashMap<(i64, i32), Hll> = HashMap::new();
        let mut day_sketches: HashMap<(i64, i32), Hll> = HashMap::new();
        for v in &taken {
            self.pending.visitors.remove(v);
            let (link, hour, fp) = *v;
            let day = hour.div_euclid(24);
            let salt = &self.salts[&day];
            visitors.insert((link, day, visitor_hash(salt, link, &fp)));
            let h = sketch_hash(salt, &fp);
            hour_sketches
                .entry((link, hour))
                .or_default()
                .insert_hash(h);
            day_sketches.entry((link, day)).or_default().insert_hash(h);
        }

        let n = self.pending.events.len().min(FLUSH_CHUNK);
        let events: Vec<StoredEvent> = self
            .pending
            .events
            .drain(..n)
            .map(|ev| StoredEvent {
                at_ms: ev.at_ms,
                link_id: ev.link_id,
                country: ev.country,
                device: ev.device.as_str(),
                visitor: self
                    .salts
                    .get(&ev.day())
                    .map(|salt| visitor_hash(salt, ev.link_id, &ev.fingerprint)),
                referrer: ev.referrer,
            })
            .collect();
        FlushBatch {
            id,
            daily: daily.into_iter().collect(),
            hourly,
            visitors: visitors.into_iter().collect(),
            events,
            hour_sketches: hour_sketches
                .into_iter()
                .map(|((l, h), s)| (l, h, s))
                .collect(),
            day_sketches: day_sketches
                .into_iter()
                .map(|((l, d), s)| (l, d, s))
                .collect(),
        }
    }

    /// Writes one batch. Returns false, keeping the batch for a retry, when
    /// it failed and should be tried again.
    async fn send(&mut self, batch: FlushBatch) -> bool {
        let clicks = batch.clicks().max(0) as u64;
        match self.sink.write(&batch).await {
            Ok(applied) => {
                self.rejections = 0;
                if applied == Applied::Replayed {
                    // An earlier attempt committed; its clicks are stored,
                    // and counted here because that attempt reported an
                    // error.
                    self.metrics.batches_replayed.inc();
                }
                self.metrics.clicks_flushed.add(clicks);
                self.metrics.flushes.inc();
                true
            }
            Err(DbError::Other(e)) if self.rejections + 1 >= MAX_REJECTIONS => {
                // Refused again for a reason that is not an outage (a bug
                // or a constraint). Retrying forever would block every
                // later click, so this batch is dropped.
                self.rejections = 0;
                self.metrics.dropped(DropReason::Rejected, clicks);
                self.metrics.db_error(DbOp::Flush);
                tracing::error!(error = %e, clicks, "click batch rejected by the database; dropped");
                true
            }
            Err(e) => {
                if matches!(e, DbError::Other(_)) {
                    self.rejections += 1;
                }
                self.retry = Some(batch);
                self.failed(&e)
            }
        }
    }

    fn failed(&mut self, e: &DbError) -> bool {
        self.metrics.db_error(DbOp::Flush);
        self.backoff = (self.backoff * 2)
            .max(Duration::from_millis(250))
            .min(self.cfg.max_backoff);
        self.next_attempt = Instant::now() + self.backoff;
        self.publish_backlog();
        tracing::warn!(error = %e, backlog = self.backlog(), retry_in_ms = self.backoff.as_millis() as u64, "click flush failed");
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
                    if self.pending.clicks as usize >= self.cfg.batch && Instant::now() >= self.next_attempt {
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
                let lost = self.clicks_pending();
                self.metrics.dropped(DropReason::Closed, lost);
                tracing::error!(
                    lost_clicks = lost,
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Applies batches the way [`Db::write_batch`] does: once per key.
    #[derive(Default)]
    struct FakeSink {
        down: AtomicBool,
        salt_down: AtomicBool,
        /// Commit the next batch, then report an error as if the
        /// acknowledgement was lost.
        lose_ack: AtomicBool,
        attempts: Mutex<Vec<[u8; 16]>>,
        seen: Mutex<HashSet<[u8; 16]>>,
        rows: Mutex<HashMap<ClickRow, i64>>,
        hourly: Mutex<HashMap<HourRow, i64>>,
        visitors: Mutex<HashSet<(i64, i32, [u8; 16])>>,
        events: Mutex<Vec<StoredEvent>>,
        hour_sketches: Mutex<HashMap<(i64, i32), Hll>>,
        day_sketches: Mutex<HashMap<(i64, i32), Hll>>,
    }

    impl FakeSink {
        fn clicks(&self) -> i64 {
            self.rows.lock().unwrap().values().sum()
        }
        fn hourly_clicks(&self) -> i64 {
            self.hourly.lock().unwrap().values().sum()
        }
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
        fn write<'a>(&'a self, batch: &'a FlushBatch) -> BoxFuture<'a, Result<Applied, DbError>> {
            Box::pin(async move {
                self.attempts.lock().unwrap().push(batch.id);
                if self.down.load(Ordering::SeqCst) {
                    return Err(DbError::Unavailable("down".into()));
                }
                if !self.seen.lock().unwrap().insert(batch.id) {
                    return Ok(Applied::Replayed);
                }
                let mut stored = self.rows.lock().unwrap();
                for (k, v) in &batch.daily {
                    *stored.entry(k.clone()).or_insert(0) += v;
                }
                let mut hourly = self.hourly.lock().unwrap();
                for (k, v) in &batch.hourly {
                    *hourly.entry(k.clone()).or_insert(0) += v;
                }
                self.visitors
                    .lock()
                    .unwrap()
                    .extend(batch.visitors.iter().copied());
                self.events
                    .lock()
                    .unwrap()
                    .extend(batch.events.iter().cloned());
                for (l, h, sk) in &batch.hour_sketches {
                    self.hour_sketches
                        .lock()
                        .unwrap()
                        .entry((*l, *h))
                        .or_default()
                        .merge(sk);
                }
                for (l, d, sk) in &batch.day_sketches {
                    self.day_sketches
                        .lock()
                        .unwrap()
                        .entry((*l, *d))
                        .or_default()
                        .merge(sk);
                }
                if self.lose_ack.swap(false, Ordering::SeqCst) {
                    return Err(DbError::Unavailable("connection reset".into()));
                }
                Ok(Applied::Written)
            })
        }
    }

    /// A click on `link` in UTC hour `hour` from visitor `visitor`.
    fn at(link_id: i64, hour: i32, visitor: u8) -> ClickEvent {
        ClickEvent {
            link_id,
            at_ms: i64::from(hour) * HOUR_MS + 1_234,
            country: *b"DE",
            device: Device::Mobile,
            referrer: Some("example.com".into()),
            fingerprint: [visitor; 16],
        }
    }

    /// A click on `link` on UTC day `day` (in its first hour).
    fn event(link_id: i64, day: i32, visitor: u8) -> ClickEvent {
        at(link_id, day * 24, visitor)
    }

    fn cfg() -> FlushConfig {
        FlushConfig {
            interval: Duration::from_millis(10),
            batch: 100,
            max_backlog: 1000,
            max_events: 1000,
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
        // The sketch hash is the same for every link, but not every day.
        assert_ne!(sketch_hash(&salt, &fp), sketch_hash(&[2u8; 32], &fp));
        assert_ne!(sketch_hash(&salt, &fp), sketch_hash(&salt, &[0; 16]));
    }

    #[test]
    fn events_know_their_hour_and_day() {
        let ev = ClickEvent {
            at_ms: 86_400_000 + 2 * HOUR_MS + 5,
            ..at(1, 0, 1)
        };
        assert_eq!((ev.day(), ev.hour()), (1, 26));
        let before_epoch = ClickEvent { at_ms: -1, ..ev };
        assert_eq!((before_epoch.day(), before_epoch.hour()), (-1, -1));
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
        assert_eq!(f.event_backlog(), 4);
        assert!(f.flush().await);
        {
            let rows = sink.rows.lock().unwrap();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows.values().sum::<i64>(), 4);
        }
        assert_eq!(sink.visitors.lock().unwrap().len(), 3);
        assert_eq!(sink.events.lock().unwrap().len(), 4);
        assert_eq!(metrics.clicks_flushed.get(), 4);
        assert_eq!(f.backlog(), 0);
        assert_eq!(f.event_backlog(), 0);
        assert!(f.flush().await, "nothing pending is success");
        assert_eq!(sink.attempts.lock().unwrap().len(), 1);
    }

    /// Hourly rows keep the hour; the daily rows of the same batch add the
    /// hours of a day up; raw events keep the exact time.
    #[tokio::test]
    async fn hourly_and_daily_rollups_agree() {
        let sink = Arc::new(FakeSink::default());
        let mut f = Flusher::new(sink.clone(), Arc::new(Metrics::default()), cfg());
        // Day 10 is hours 240 to 263.
        for (hour, n) in [(240, 3), (241, 2), (263, 1), (264, 4)] {
            for v in 0..n {
                f.absorb(at(1, hour, v));
            }
        }
        assert!(f.flush().await);
        let hourly = sink.hourly.lock().unwrap();
        let by_hour = |h: i32| -> i64 {
            hourly
                .iter()
                .filter(|(k, _)| k.hour == h)
                .map(|(_, n)| n)
                .sum()
        };
        assert_eq!(
            [by_hour(240), by_hour(241), by_hour(263), by_hour(264)],
            [3, 2, 1, 4]
        );
        let rows = sink.rows.lock().unwrap();
        let by_day = |d: i32| -> i64 {
            rows.iter()
                .filter(|(k, _)| k.day == d)
                .map(|(_, n)| n)
                .sum()
        };
        assert_eq!((by_day(10), by_day(11)), (6, 4));
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 10);
        assert!(events.iter().all(|e| e.at_ms % HOUR_MS == 1_234));
        assert!(events.iter().all(|e| e.visitor.is_some()));
    }

    /// Visitor sketches per hour and per day estimate the distinct visitors,
    /// and sketches of two links merge into the visitors of both.
    #[tokio::test]
    async fn sketches_count_visitors_per_hour_day_and_across_links() {
        let sink = Arc::new(FakeSink::default());
        let mut f = Flusher::new(
            sink.clone(),
            Arc::new(Metrics::default()),
            FlushConfig {
                max_backlog: 10_000,
                max_events: 10_000,
                ..cfg()
            },
        );
        // Link 1: visitors 0..100 in hour 240 and 50..150 in hour 241.
        // Link 2: visitors 100..200 in hour 241.
        for v in 0..100u8 {
            f.absorb(at(1, 240, v));
            f.absorb(at(1, 241, v + 50));
            f.absorb(at(2, 241, v + 100));
        }
        assert!(f.flush().await);
        let hours = sink.hour_sketches.lock().unwrap();
        let days = sink.day_sketches.lock().unwrap();
        assert_eq!(hours[&(1, 240)].count(), 100);
        assert_eq!(hours[&(1, 241)].count(), 100);
        assert_eq!(days[&(1, 10)].count(), 150);
        assert_eq!(days[&(2, 10)].count(), 100);
        let mut both = days[&(1, 10)].clone();
        both.merge(&days[&(2, 10)]);
        assert_eq!(both.count(), 200, "visitors 100..150 clicked both links");
        // The day sketch is the merge of the day's hour sketches.
        let mut merged = hours[&(1, 240)].clone();
        merged.merge(&hours[&(1, 241)]);
        assert_eq!(merged, days[&(1, 10)]);
    }

    /// A batch whose commit succeeded but whose acknowledgement was lost is
    /// retried whole, with the same key, and found already applied: no click
    /// is counted twice, and nothing else is written before it.
    #[tokio::test]
    async fn a_replayed_batch_is_not_counted_twice() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(sink.clone(), metrics.clone(), cfg());
        for v in 0..5 {
            f.absorb(at(1, 240, v));
        }
        sink.lose_ack.store(true, Ordering::SeqCst);
        assert!(!f.flush().await, "the error is all the flusher sees");
        assert_eq!(f.backlog(), 6, "the batch is kept for a retry");
        assert_eq!(f.event_backlog(), 5);
        f.absorb(at(1, 240, 9));
        assert!(f.flush().await);
        let attempts = sink.attempts.lock().unwrap().clone();
        assert_eq!(attempts.len(), 3, "retry, then the new click");
        assert_eq!(attempts[0], attempts[1], "the retry has the same key");
        assert_ne!(attempts[1], attempts[2]);
        assert_eq!(sink.clicks(), 6);
        assert_eq!(sink.hourly_clicks(), 6);
        assert_eq!(sink.events.lock().unwrap().len(), 6);
        assert_eq!(metrics.batches_replayed.get(), 1);
        assert_eq!(metrics.clicks_flushed.get(), 6);
        assert_eq!(f.backlog(), 0);
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
        assert!(f.backlog() <= 10, "a batch kept for retry still counts");
        assert!(!f.flush().await);
        assert_eq!(metrics.db_error_count(DbOp::Flush), 2);
        f.absorb(event(1, 100, 99));
        assert_eq!(metrics.dropped_count(DropReason::Backlog), kept + 1);
        sink.down.store(false, Ordering::SeqCst);
        assert!(f.flush().await);
        assert_eq!(sink.clicks() as u64 + kept, 20);
    }

    /// Past the event bound a click still reaches every rollup; only its raw
    /// event is dropped, and counted.
    #[tokio::test]
    async fn raw_events_have_their_own_bound() {
        let sink = Arc::new(FakeSink::default());
        let metrics = Arc::new(Metrics::default());
        let mut f = Flusher::new(
            sink.clone(),
            metrics.clone(),
            FlushConfig {
                max_events: 3,
                ..cfg()
            },
        );
        for v in 0..5 {
            f.absorb(at(1, 240, v));
        }
        assert_eq!(f.event_backlog(), 3);
        assert_eq!(metrics.events_dropped.get(), 2);
        assert_eq!(metrics.dropped_count(DropReason::Backlog), 0);
        assert!(f.flush().await);
        assert_eq!(sink.clicks(), 5);
        assert_eq!(sink.visitors.lock().unwrap().len(), 5);
        assert_eq!(sink.events.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn large_backlogs_are_written_in_chunks() {
        #[derive(Default)]
        struct Counting {
            inner: FakeSink,
            writes: AtomicUsize,
            fail_on: AtomicUsize,
        }
        impl ClickSink for Counting {
            fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
                self.inner.salt(day)
            }
            fn write<'a>(
                &'a self,
                batch: &'a FlushBatch,
            ) -> BoxFuture<'a, Result<Applied, DbError>> {
                assert!(batch.hourly.len() <= FLUSH_CHUNK);
                assert!(batch.daily.len() <= FLUSH_CHUNK);
                assert!(batch.visitors.len() <= FLUSH_CHUNK);
                assert!(batch.events.len() <= FLUSH_CHUNK);
                let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
                if n == self.fail_on.load(Ordering::SeqCst) {
                    return Box::pin(async { Err(DbError::Unavailable("flaky".into())) });
                }
                self.inner.write(batch)
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
                max_events: 100_000,
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
        assert_eq!(sink.inner.clicks(), 12_000);
        assert_eq!(sink.inner.hourly_clicks(), 12_000);
        assert_eq!(sink.inner.visitors.lock().unwrap().len(), 12_000);
        assert_eq!(sink.inner.events.lock().unwrap().len(), 12_000);
        assert_eq!(sink.inner.day_sketches.lock().unwrap().len(), 12_000);
        assert_eq!(f.backlog(), 0);
    }

    #[tokio::test]
    async fn non_transient_failures_drop_the_chunk_instead_of_blocking() {
        struct Refusing;
        impl ClickSink for Refusing {
            fn salt(&self, _: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
                Box::pin(async { Ok(Some([0; 32])) })
            }
            fn write<'a>(&'a self, _: &'a FlushBatch) -> BoxFuture<'a, Result<Applied, DbError>> {
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
        assert_eq!(f.event_backlog(), 0);
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
        assert_eq!(sink.clicks(), 3);
        assert_eq!(sink.visitors.lock().unwrap().len(), 1);
        assert_eq!(metrics.late_visitors.get(), 2);
        assert_eq!(sink.day_sketches.lock().unwrap().len(), 1);
        // Their raw events are kept, without a visitor hash.
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events.iter().filter(|e| e.visitor.is_none()).count(), 2);
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

    /// A kept batch is retried before the salts for newer clicks are
    /// fetched, and a salt failure after it leaves the newer clicks pending.
    #[tokio::test]
    async fn retry_goes_first_then_a_salt_failure_keeps_the_rest() {
        let sink = Arc::new(FakeSink::default());
        let mut f = Flusher::new(sink.clone(), Arc::new(Metrics::default()), cfg());
        f.absorb(event(1, 5, 1));
        sink.down.store(true, Ordering::SeqCst);
        assert!(!f.flush().await);
        sink.down.store(false, Ordering::SeqCst);
        sink.salt_down.store(true, Ordering::SeqCst);
        f.absorb(event(1, 6, 1));
        assert!(!f.flush().await);
        assert_eq!(sink.clicks(), 1, "the kept batch was written");
        sink.salt_down.store(false, Ordering::SeqCst);
        assert!(f.flush().await);
        assert_eq!(sink.clicks(), 2);
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
        assert_eq!(sink.clicks(), 1);
        // A full batch flushes immediately.
        for i in 0..250 {
            q.record(event(1, 1, (i % 200) as u8));
        }
        q.record(event(2, 1, 1));
        stop_tx
            .send(Some(tokio::time::Instant::now() + Duration::from_secs(1)))
            .unwrap();
        task.await.unwrap();
        assert_eq!(sink.clicks(), 252);
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
        assert_eq!(sink.clicks(), 1);
    }
}

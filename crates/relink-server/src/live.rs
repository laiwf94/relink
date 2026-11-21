//! Live clicks: `GET /v1/links/{code}/live`, a server-sent events stream
//! that pushes each click on one link as it happens.
//!
//! **Fan-out.** The [`LiveHub`] keeps one broadcast channel per workspace
//! that has a stream open, and a map from each watched link to its
//! workspace. A click is offered to the hub before it is queued for the
//! flusher (src/clicks.rs): when no link is watched that costs one atomic
//! load; otherwise one read lock and a map lookup, and a click on a watched
//! link is sent once to its workspace's channel, where each stream keeps the
//! clicks on its own link. Nothing on the redirect path ever waits for a
//! stream.
//!
//! **Backpressure.** A workspace's channel is a ring of `buffer` clicks. A
//! stream reads from it only as fast as its connection takes bytes, so a
//! slow reader falls behind instead of slowing anyone else; once it is more
//! than a ring behind, the oldest clicks are overwritten and the stream gets
//! a `lag` event saying how many it missed, then carries on from the oldest
//! click still held. Streams are capped per workspace and per instance, and
//! each ends after `max_age` so a revoked key or session does not keep one
//! open; `EventSource` reconnects by itself.
//!
//! **Across instances.** A click reaches whichever instance the load
//! balancer picked, and the stream may be on another. Every instance with a
//! stream open announces its watched links on the `relink_live` channel
//! (`pg_notify`) when a link is first watched and every `announce`
//! interval; every instance remembers the links watched elsewhere for three
//! intervals. A click on a link watched elsewhere is put on a bounded relay
//! queue (dropped and counted when full, never waited for), and the relay
//! task sends what is queued in notifications of at most
//! [`MAX_PAYLOAD`] bytes. Receiving instances hand the clicks to their own
//! streams; an instance ignores its own notifications.
//!
//! A live click carries what the rollups keep: the time, country, device
//! class and referrer host. Never the visitor's address or fingerprint.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::body::{Body, Bytes};
use chrono::{DateTime, SecondsFormat};
use tokio::sync::{Notify, broadcast, mpsc, watch};
use tokio::time::Instant;

use crate::classify::{self, Device};
use crate::clicks::ClickEvent;
use crate::metrics::Metrics;
use crate::store::{Db, DbError};
use crate::util::{BoxFuture, secure_random, stopped};

/// The notification channel live clicks and watch announcements travel on.
pub const LIVE_CHANNEL: &str = "relink_live";

/// Largest notification payload sent. Postgres refuses payloads of 8000
/// bytes or more.
pub const MAX_PAYLOAD: usize = 7_900;

/// Settings for live streams (`RELINK_LIVE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveConfig {
    /// Open streams allowed per workspace on one instance.
    pub max_per_workspace: usize,
    /// Open streams allowed on one instance.
    pub max_streams: usize,
    /// Clicks a workspace's channel holds for streams that fall behind.
    pub buffer: usize,
    /// Clicks waiting to be relayed to other instances.
    pub relay_queue: usize,
    /// How often watched links are announced to other instances.
    pub announce: Duration,
    /// Comment sent on an idle stream so proxies keep it open.
    pub keep_alive: Duration,
    /// How long one stream may stay open.
    pub max_age: Duration,
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            max_per_workspace: 50,
            max_streams: 10_000,
            buffer: 256,
            relay_queue: 4_096,
            announce: Duration::from_secs(10),
            keep_alive: Duration::from_secs(15),
            max_age: Duration::from_secs(3_600),
        }
    }
}

/// One click as a stream sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveClick {
    pub link_id: i64,
    pub at_ms: i64,
    pub country: [u8; 2],
    pub device: Device,
    pub referrer: Option<Box<str>>,
}

impl From<&ClickEvent> for LiveClick {
    fn from(ev: &ClickEvent) -> Self {
        LiveClick {
            link_id: ev.link_id,
            at_ms: ev.at_ms,
            country: ev.country,
            device: ev.device,
            referrer: ev.referrer.clone(),
        }
    }
}

/// Why a stream was not opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The workspace has `max_per_workspace` streams open here.
    Workspace,
    /// This instance has `max_streams` streams open.
    Instance,
    /// The server is shutting down.
    Closed,
}

struct Topic {
    tx: broadcast::Sender<Arc<LiveClick>>,
    streams: usize,
}

struct Watched {
    workspace: i64,
    streams: usize,
}

#[derive(Default)]
struct Inner {
    topics: HashMap<i64, Topic>,
    links: HashMap<i64, Watched>,
    /// Links watched on other instances, until when.
    remote: HashMap<i64, Instant>,
    streams: usize,
    closed: bool,
}

/// Live click fan-out for one instance; see the module documentation.
pub struct LiveHub {
    cfg: LiveConfig,
    inner: RwLock<Inner>,
    /// Links watched here plus links watched elsewhere: zero means a click
    /// needs no further look.
    watched: AtomicUsize,
    relay: mpsc::Sender<LiveClick>,
    relay_rx: std::sync::Mutex<Option<mpsc::Receiver<LiveClick>>>,
    /// Poked when a link is first watched here, to announce it at once.
    announce_now: Notify,
    instance: u64,
    stop: watch::Sender<bool>,
    metrics: Arc<Metrics>,
}

impl LiveHub {
    pub fn new(cfg: LiveConfig, metrics: Arc<Metrics>) -> LiveHub {
        let (relay, relay_rx) = mpsc::channel(cfg.relay_queue.max(1));
        let mut id = [0u8; 8];
        secure_random(&mut id);
        LiveHub {
            cfg,
            inner: RwLock::new(Inner::default()),
            watched: AtomicUsize::new(0),
            relay,
            relay_rx: std::sync::Mutex::new(Some(relay_rx)),
            announce_now: Notify::new(),
            instance: u64::from_be_bytes(id),
            stop: watch::channel(false).0,
            metrics,
        }
    }

    pub fn config(&self) -> &LiveConfig {
        &self.cfg
    }

    /// Open streams on this instance.
    pub fn streams(&self) -> usize {
        self.read().streams
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    fn recount(&self, inner: &Inner) {
        self.watched
            .store(inner.links.len() + inner.remote.len(), Ordering::Release);
    }

    /// Offers a click taken on this instance: to the streams here watching
    /// its link, and to the relay when another instance watches it.
    pub fn publish(&self, ev: &ClickEvent) {
        if self.watched.load(Ordering::Acquire) == 0 {
            return;
        }
        let (local, remote) = {
            let inner = self.read();
            let local = inner
                .links
                .get(&ev.link_id)
                .and_then(|w| inner.topics.get(&w.workspace))
                .map(|t| t.tx.clone());
            let remote = inner
                .remote
                .get(&ev.link_id)
                .is_some_and(|until| *until > Instant::now());
            (local, remote)
        };
        if local.is_none() && !remote {
            return;
        }
        let click = LiveClick::from(ev);
        if remote {
            match self.relay.try_send(click.clone()) {
                Ok(()) => {}
                Err(_) => self.metrics.live_relay_dropped.inc(),
            }
        }
        if let Some(tx) = local {
            let _ = tx.send(Arc::new(click));
        }
    }

    /// Hands clicks relayed by another instance to the streams here.
    fn deliver(&self, clicks: Vec<LiveClick>) {
        let inner = self.read();
        for click in clicks {
            if let Some(t) = inner
                .links
                .get(&click.link_id)
                .and_then(|w| inner.topics.get(&w.workspace))
            {
                let _ = t.tx.send(Arc::new(click));
            }
        }
    }

    /// Opens a stream on `link_id` in `workspace`.
    pub fn subscribe(self: &Arc<Self>, workspace: i64, link_id: i64) -> Result<Stream, Refused> {
        let mut inner = self.write();
        if inner.closed {
            return Err(Refused::Closed);
        }
        if inner.streams >= self.cfg.max_streams {
            return Err(Refused::Instance);
        }
        let buffer = self.cfg.buffer.max(1);
        let topic = inner.topics.entry(workspace).or_insert_with(|| Topic {
            tx: broadcast::channel(buffer).0,
            streams: 0,
        });
        if topic.streams >= self.cfg.max_per_workspace {
            return Err(Refused::Workspace);
        }
        topic.streams += 1;
        let rx = topic.tx.subscribe();
        inner.streams += 1;
        let watched = inner.links.entry(link_id).or_insert(Watched {
            workspace,
            streams: 0,
        });
        watched.streams += 1;
        let first = watched.streams == 1;
        self.recount(&inner);
        drop(inner);
        if first {
            self.announce_now.notify_one();
        }
        Ok(Stream {
            hub: self.clone(),
            rx,
            workspace,
            link_id,
            stop: self.stop.subscribe(),
        })
    }

    fn unsubscribe(&self, workspace: i64, link_id: i64) {
        let mut inner = self.write();
        inner.streams -= 1;
        if let Some(t) = inner.topics.get_mut(&workspace) {
            t.streams -= 1;
            if t.streams == 0 {
                inner.topics.remove(&workspace);
            }
        }
        if let Some(w) = inner.links.get_mut(&link_id) {
            w.streams -= 1;
            if w.streams == 0 {
                inner.links.remove(&link_id);
            }
        }
        self.recount(&inner);
    }

    /// Ends every open stream and refuses new ones (shutdown).
    pub fn close(&self) {
        self.write().closed = true;
        let _ = self.stop.send(true);
    }

    /// Links watched on this instance, sorted.
    fn local_links(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self.read().links.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Applies one notification from the live channel.
    pub fn receive(&self, payload: &str) {
        match decode(payload) {
            Some(Message::Watch { instance, links }) if instance != self.instance => {
                let until = Instant::now() + self.cfg.announce * 3;
                let mut inner = self.write();
                for id in links {
                    inner.remote.insert(id, until);
                }
                self.recount(&inner);
            }
            Some(Message::Clicks { instance, clicks }) if instance != self.instance => {
                self.metrics.live_received.add(clicks.len() as u64);
                self.deliver(clicks);
            }
            Some(_) => {}
            None => tracing::debug!("ignoring a malformed live notification"),
        }
    }

    /// Forgets links whose last announcement is three intervals old.
    fn expire_remote(&self, now: Instant) {
        let mut inner = self.write();
        let before = inner.remote.len();
        inner.remote.retain(|_, until| *until > now);
        if inner.remote.len() != before {
            self.recount(&inner);
        }
    }

    /// The relay: announces watched links and sends clicks on links watched
    /// elsewhere, until `stop`. Runs once per hub.
    pub async fn run_relay(
        self: Arc<Self>,
        sink: Arc<dyn LiveSink>,
        mut stop: watch::Receiver<bool>,
    ) {
        let Some(mut rx) = self
            .relay_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        let mut tick = tokio::time::interval(self.cfg.announce);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                Some(first) = rx.recv() => {
                    let mut clicks = vec![first];
                    while let Ok(c) = rx.try_recv() {
                        clicks.push(c);
                    }
                    let n = clicks.len() as u64;
                    let mut sent = 0;
                    for payload in encode_clicks(self.instance, &clicks) {
                        let lines = payload.lines().count() as u64 - 1;
                        match sink.notify(payload).await {
                            Ok(()) => sent += lines,
                            Err(e) => tracing::debug!(error = %e, "could not relay live clicks"),
                        }
                    }
                    self.metrics.live_relayed.add(sent);
                    self.metrics.live_relay_dropped.add(n - sent);
                }
                _ = tick.tick() => self.announce(&*sink).await,
                _ = self.announce_now.notified() => self.announce(&*sink).await,
                _ = stopped(&mut stop) => return,
            }
        }
    }

    async fn announce(&self, sink: &dyn LiveSink) {
        self.expire_remote(Instant::now());
        for payload in encode_watch(self.instance, &self.local_links()) {
            if let Err(e) = sink.notify(payload).await {
                tracing::debug!(error = %e, "could not announce watched links");
            }
        }
    }
}

/// Where the relay sends notifications. Implemented by [`Db`]; tests use a
/// fake.
pub trait LiveSink: Send + Sync {
    fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), DbError>>;
}

impl LiveSink for Db {
    fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            self.timed(
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(LIVE_CHANNEL)
                    .bind(payload)
                    .execute(self.pool()),
            )
            .await
            .map(|_| ())
        })
    }
}

/// An open stream. Dropping it closes it.
pub struct Stream {
    hub: Arc<LiveHub>,
    rx: broadcast::Receiver<Arc<LiveClick>>,
    workspace: i64,
    link_id: i64,
    stop: watch::Receiver<bool>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.hub.unsubscribe(self.workspace, self.link_id);
    }
}

/// What one stream shows; see [`Stream::into_body`].
pub struct View {
    /// The link's code, echoed in every click.
    pub code: String,
    pub include_bots: bool,
}

/// Most clicks written in one chunk when several are waiting.
const MAX_BATCH: usize = 64;

impl Stream {
    /// The next chunk to write, or `None` when the stream ends.
    async fn next_chunk(&mut self, view: &View, deadline: Instant) -> Option<Bytes> {
        let keep_alive = self.hub.cfg.keep_alive;
        let idle_until = Instant::now() + keep_alive;
        loop {
            let mut out = String::new();
            tokio::select! {
                biased;
                _ = stopped(&mut self.stop) => return None,
                _ = tokio::time::sleep_until(deadline) => return None,
                r = self.rx.recv() => {
                    match r {
                        Ok(click) => self.push(&mut out, view, &click),
                        Err(broadcast::error::RecvError::Lagged(n)) => self.lagged(&mut out, n),
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                    // Whatever else is waiting goes out in the same chunk.
                    for _ in 1..MAX_BATCH {
                        match self.rx.try_recv() {
                            Ok(click) => self.push(&mut out, view, &click),
                            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                                self.lagged(&mut out, n);
                            }
                            Err(_) => break,
                        }
                    }
                }
                _ = tokio::time::sleep_until(idle_until) => out.push_str(": keep-alive\n\n"),
            }
            if !out.is_empty() {
                return Some(Bytes::from(out));
            }
        }
    }

    fn push(&self, out: &mut String, view: &View, click: &LiveClick) {
        if click.link_id != self.link_id || (!view.include_bots && click.device == Device::Bot) {
            return;
        }
        self.hub.metrics.live_sent.inc();
        write_click(out, &view.code, click);
    }

    fn lagged(&self, out: &mut String, missed: u64) {
        // The count covers the whole workspace's channel, so it is an upper
        // bound on this link's missed clicks.
        self.hub.metrics.live_lagged.add(missed);
        let _ = write!(out, "event: lag\ndata: {{\"missed\":{missed}}}\n\n");
    }

    /// The response body: a `retry` hint and an `open` event, then a
    /// `click` event per click, `lag` when clicks were missed and a comment
    /// when idle, until the stream's age limit or shutdown.
    pub fn into_body(self, view: View) -> Body {
        let deadline = Instant::now() + self.hub.cfg.max_age;
        let mut head = String::from("retry: 2000\n\nevent: open\ndata: ");
        head.push_str(&serde_json::json!({ "code": view.code }).to_string());
        head.push_str("\n\n");
        let first = futures_util::stream::once(async move { Ok(Bytes::from(head)) });
        let rest =
            futures_util::stream::unfold((self, view), move |(mut stream, view)| async move {
                let chunk = stream.next_chunk(&view, deadline).await?;
                Some((Ok::<_, Infallible>(chunk), (stream, view)))
            });
        Body::from_stream(futures_util::StreamExt::chain(first, rest))
    }
}

/// Appends one `click` event.
pub fn write_click(out: &mut String, code: &str, c: &LiveClick) {
    let at = DateTime::from_timestamp_millis(c.at_ms)
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_default();
    let data = serde_json::json!({
        "code": code,
        "at": at,
        "country": std::str::from_utf8(&c.country).unwrap_or("XX"),
        "device": c.device.as_str(),
        "referrer": c.referrer.as_deref(),
        "bot": c.device == Device::Bot,
    });
    let _ = write!(out, "event: click\ndata: {data}\n\n");
}

/// A notification on [`LIVE_CHANNEL`].
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// `w <instance>` then one watched link id per line.
    Watch { instance: u64, links: Vec<i64> },
    /// `c <instance>` then `<link> <at_ms> <country> <device> <referrer|->`
    /// per line.
    Clicks {
        instance: u64,
        clicks: Vec<LiveClick>,
    },
}

/// Splits `lines` after a header into payloads under [`MAX_PAYLOAD`].
fn pack(header: &str, lines: impl Iterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::from(header);
    for line in lines {
        if cur.len() + 1 + line.len() > MAX_PAYLOAD && cur.len() > header.len() {
            out.push(std::mem::replace(&mut cur, String::from(header)));
        }
        cur.push('\n');
        cur.push_str(&line);
    }
    if cur.len() > header.len() {
        out.push(cur);
    }
    out
}

/// Watch announcements for `links` (none when it is empty).
pub fn encode_watch(instance: u64, links: &[i64]) -> Vec<String> {
    pack(
        &format!("w {instance:016x}"),
        links.iter().map(|id| id.to_string()),
    )
}

/// Click notifications for `clicks`, in order.
pub fn encode_clicks(instance: u64, clicks: &[LiveClick]) -> Vec<String> {
    pack(
        &format!("c {instance:016x}"),
        clicks.iter().map(|c| {
            format!(
                "{} {} {} {} {}",
                c.link_id,
                c.at_ms,
                std::str::from_utf8(&c.country).unwrap_or("XX"),
                c.device.as_str(),
                c.referrer.as_deref().unwrap_or("-"),
            )
        }),
    )
}

/// Parses a notification, checking every field as strictly as a click from
/// the edge: anyone who can connect to the database can send one.
pub fn decode(payload: &str) -> Option<Message> {
    let mut lines = payload.split('\n');
    let header = lines.next()?;
    let (kind, instance) = header.split_once(' ')?;
    if instance.len() != 16 {
        return None;
    }
    let instance = u64::from_str_radix(instance, 16).ok()?;
    match kind {
        "w" => {
            let links = lines
                .map(|l| l.parse::<i64>().ok().filter(|id| *id > 0))
                .collect::<Option<Vec<_>>>()?;
            Some(Message::Watch { instance, links })
        }
        "c" => {
            let clicks = lines.map(decode_click).collect::<Option<Vec<_>>>()?;
            Some(Message::Clicks { instance, clicks })
        }
        _ => None,
    }
}

fn decode_click(line: &str) -> Option<LiveClick> {
    let mut f = line.split(' ');
    let link_id = f.next()?.parse::<i64>().ok().filter(|id| *id > 0)?;
    let at_ms = f.next()?.parse::<i64>().ok()?;
    DateTime::from_timestamp_millis(at_ms)?;
    let country: [u8; 2] = match f.next()?.as_bytes() {
        b"XX" => *b"XX",
        c => classify::country(Some(c)).filter(|parsed| parsed == c)?,
    };
    let device = Device::parse(f.next()?)?;
    let referrer = match f.next()? {
        "-" => None,
        r => {
            let parsed = classify::referrer_host(Some(format!("https://{r}/").as_bytes()))?;
            if parsed != r {
                return None;
            }
            Some(parsed.into_boxed_str())
        }
    };
    if f.next().is_some() {
        return None;
    }
    Some(LiveClick {
        link_id,
        at_ms,
        country,
        device,
        referrer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::sync::Mutex;

    fn hub(cfg: LiveConfig) -> Arc<LiveHub> {
        Arc::new(LiveHub::new(cfg, Arc::new(Metrics::default())))
    }

    fn click(link_id: i64, device: Device) -> ClickEvent {
        ClickEvent {
            link_id,
            at_ms: 1_795_000_000_123,
            country: *b"NZ",
            device,
            referrer: Some("news.example.org".into()),
            fingerprint: [7; 16],
        }
    }

    fn view(include_bots: bool) -> View {
        View {
            code: "abc".into(),
            include_bots,
        }
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(3_600)
    }

    async fn chunk(s: &mut Stream, v: &View) -> String {
        let b = tokio::time::timeout(Duration::from_secs(5), s.next_chunk(v, far()))
            .await
            .expect("a chunk in time")
            .expect("the stream is open");
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[derive(Default)]
    struct FakeSink(Mutex<Vec<String>>, AtomicUsize);

    impl LiveSink for FakeSink {
        fn notify(&self, payload: String) -> BoxFuture<'_, Result<(), DbError>> {
            Box::pin(async move {
                if self.1.load(Ordering::Relaxed) > 0 {
                    self.1.fetch_sub(1, Ordering::Relaxed);
                    return Err(DbError::Unavailable("down".into()));
                }
                self.0.lock().unwrap().push(payload);
                Ok(())
            })
        }
    }

    #[test]
    fn notifications_round_trip() {
        let clicks = vec![
            LiveClick::from(&click(5, Device::Mobile)),
            LiveClick {
                referrer: None,
                country: *b"XX",
                ..LiveClick::from(&click(9, Device::Bot))
            },
        ];
        let p = encode_clicks(0xabc, &clicks);
        assert_eq!(p.len(), 1);
        assert_eq!(
            p[0],
            "c 0000000000000abc\n5 1795000000123 NZ mobile news.example.org\n9 1795000000123 XX bot -"
        );
        assert_eq!(
            decode(&p[0]),
            Some(Message::Clicks {
                instance: 0xabc,
                clicks
            })
        );
        let w = encode_watch(u64::MAX, &[1, 22, 333]);
        assert_eq!(w, ["w ffffffffffffffff\n1\n22\n333"]);
        assert_eq!(
            decode(&w[0]),
            Some(Message::Watch {
                instance: u64::MAX,
                links: vec![1, 22, 333]
            })
        );
        assert!(encode_watch(1, &[]).is_empty());
        assert!(encode_clicks(1, &[]).is_empty());
    }

    #[test]
    fn large_batches_split_under_the_payload_limit() {
        let clicks: Vec<LiveClick> = (1..=2_000)
            .map(|i| LiveClick::from(&click(i, Device::Desktop)))
            .collect();
        let payloads = encode_clicks(42, &clicks);
        assert!(payloads.len() > 1);
        let mut back = Vec::new();
        for p in &payloads {
            assert!(p.len() <= MAX_PAYLOAD, "{} bytes", p.len());
            match decode(p) {
                Some(Message::Clicks {
                    instance: 42,
                    clicks,
                }) => back.extend(clicks),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(back, clicks);
        let ids: Vec<i64> = (1..=5_000).collect();
        let w = encode_watch(1, &ids);
        assert!(w.len() > 1 && w.iter().all(|p| p.len() <= MAX_PAYLOAD));
    }

    #[test]
    fn malformed_notifications_are_refused() {
        for bad in [
            "",
            "c",
            "c 12",
            "x 0000000000000001\n1",
            "c 000000000000000g\n1 0 NZ mobile -",
            "w 0000000000000001\n0",
            "w 0000000000000001\n-4",
            "w 0000000000000001\nseven",
            "c 0000000000000001\n1 0 nz mobile -",
            "c 0000000000000001\n1 0 NZ phone -",
            "c 0000000000000001\n1 0 NZ mobile News.Example.org",
            "c 0000000000000001\n1 0 NZ mobile -  ",
            "c 0000000000000001\n1 0 NZ mobile - extra",
            "c 0000000000000001\n1 soon NZ mobile -",
            "c 0000000000000001\n1 99999999999999999 NZ mobile -",
            "c 0000000000000001\n1 0 NZ mobile",
            "c 0000000000000001\n0 0 NZ mobile -",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn clicks_reach_streams_on_their_link_only() {
        let h = hub(LiveConfig::default());
        h.publish(&click(1, Device::Mobile)); // nobody watching: a no-op
        let mut a = h.subscribe(10, 1).unwrap();
        let mut b = h.subscribe(10, 2).unwrap();
        let mut bots = h.subscribe(10, 1).unwrap();
        assert_eq!(h.streams(), 3);
        h.publish(&click(2, Device::Desktop));
        h.publish(&click(1, Device::Bot));
        h.publish(&click(1, Device::Mobile));
        h.publish(&click(3, Device::Mobile)); // unwatched
        let got = chunk(&mut a, &view(false)).await;
        assert_eq!(got.matches("event: click").count(), 1, "{got}");
        assert!(got.contains(
            r#"data: {"at":"2026-11-18T11:06:40.123Z","bot":false,"code":"abc","country":"NZ","device":"mobile","referrer":"news.example.org"}"#
        ), "{got}");
        let got = chunk(&mut bots, &view(true)).await;
        assert_eq!(got.matches("event: click").count(), 2, "{got}");
        assert!(got.contains(r#""bot":true"#), "{got}");
        let got = chunk(&mut b, &view(false)).await;
        assert_eq!(got.matches("event: click").count(), 1);
        assert!(got.contains(r#""device":"desktop""#));
        assert_eq!(h.metrics.live_sent.get(), 4);
        drop((a, b, bots));
        assert_eq!(h.streams(), 0);
        assert_eq!(h.watched.load(Ordering::Acquire), 0);
        assert!(h.read().topics.is_empty() && h.read().links.is_empty());
    }

    #[tokio::test]
    async fn a_slow_stream_is_told_what_it_missed() {
        let h = hub(LiveConfig {
            buffer: 4,
            ..LiveConfig::default()
        });
        let mut s = h.subscribe(1, 1).unwrap();
        for _ in 0..10 {
            h.publish(&click(1, Device::Mobile));
        }
        let got = chunk(&mut s, &view(false)).await;
        assert!(
            got.starts_with("event: lag\ndata: {\"missed\":6}\n\n"),
            "{got}"
        );
        assert_eq!(got.matches("event: click").count(), 4, "{got}");
        assert_eq!(h.metrics.live_lagged.get(), 6);
    }

    #[tokio::test]
    async fn streams_are_capped_per_workspace_and_instance() {
        let h = hub(LiveConfig {
            max_per_workspace: 2,
            max_streams: 3,
            ..LiveConfig::default()
        });
        let a1 = h.subscribe(1, 1).unwrap();
        let _a2 = h.subscribe(1, 2).unwrap();
        assert_eq!(h.subscribe(1, 3).err(), Some(Refused::Workspace));
        let _b1 = h.subscribe(2, 4).unwrap();
        assert_eq!(h.subscribe(3, 5).err(), Some(Refused::Instance));
        drop(a1);
        let _a3 = h.subscribe(1, 3).unwrap();
        // A refused workspace with no streams leaves nothing behind.
        assert!(!h.read().topics.contains_key(&3));
    }

    #[tokio::test]
    async fn close_ends_streams_and_refuses_new_ones() {
        let h = hub(LiveConfig::default());
        let s = h.subscribe(1, 1).unwrap();
        let mut body = s.into_body(view(false)).into_data_stream();
        let head = body.next().await.unwrap().unwrap();
        assert_eq!(
            &head[..],
            b"retry: 2000\n\nevent: open\ndata: {\"code\":\"abc\"}\n\n"
        );
        h.publish(&click(1, Device::Tablet));
        let next = body.next().await.unwrap().unwrap();
        assert!(std::str::from_utf8(&next).unwrap().contains("\"tablet\""));
        h.close();
        assert!(body.next().await.is_none());
        drop(body);
        assert_eq!(h.streams(), 0);
        assert_eq!(h.subscribe(1, 1).err(), Some(Refused::Closed));
    }

    #[tokio::test]
    async fn idle_streams_get_keep_alives_and_end_at_their_age_limit() {
        let h = hub(LiveConfig {
            keep_alive: Duration::from_millis(300),
            max_age: Duration::from_millis(800),
            ..LiveConfig::default()
        });
        let mut body = h
            .subscribe(1, 1)
            .unwrap()
            .into_body(view(false))
            .into_data_stream();
        body.next().await.unwrap().unwrap();
        let start = Instant::now();
        // Clicks on other links in the workspace do not delay keep-alives.
        let _other = h.subscribe(1, 2).unwrap();
        let h2 = h.clone();
        let noise = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                h2.publish(&click(2, Device::Mobile));
            }
        });
        assert_eq!(
            &body.next().await.unwrap().unwrap()[..],
            b": keep-alive\n\n"
        );
        let first = start.elapsed();
        assert!(
            first >= Duration::from_millis(300) && first < Duration::from_millis(600),
            "{first:?}"
        );
        assert_eq!(
            &body.next().await.unwrap().unwrap()[..],
            b": keep-alive\n\n"
        );
        assert!(body.next().await.is_none());
        assert!(start.elapsed() >= Duration::from_millis(800));
        noise.await.unwrap();
    }

    #[tokio::test]
    async fn clicks_cross_instances_through_the_relay() {
        let cfg = LiveConfig {
            announce: Duration::from_millis(100),
            relay_queue: 2,
            ..LiveConfig::default()
        };
        let origin = hub(cfg);
        let watcher = hub(cfg);
        let sink = Arc::new(FakeSink::default());
        let (stop_tx, stop) = watch::channel(false);
        let relay = tokio::spawn(origin.clone().run_relay(sink.clone(), stop));
        // Not watched anywhere yet: nothing is relayed.
        origin.publish(&click(7, Device::Mobile));
        let mut s = watcher.subscribe(3, 7).unwrap();
        let announced = encode_watch(watcher.instance, &watcher.local_links());
        assert_eq!(announced.len(), 1);
        // The origin ignores its own announcements, and takes the watcher's.
        origin.receive(&encode_watch(origin.instance, &[8])[0]);
        origin.receive("w nonsense");
        origin.receive(&announced[0]);
        assert!(origin.read().remote.contains_key(&7));
        assert!(!origin.read().remote.contains_key(&8));
        origin.publish(&click(7, Device::Mobile));
        origin.publish(&click(9, Device::Mobile)); // watched nowhere
        let deadline = Instant::now() + Duration::from_secs(5);
        let payload = loop {
            let found = sink
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|p| p.starts_with('c'))
                .cloned();
            if let Some(p) = found {
                break p;
            }
            assert!(Instant::now() < deadline, "nothing relayed");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(payload.lines().count(), 2, "{payload}");
        watcher.receive(&payload);
        // Its own relayed clicks are not delivered twice.
        origin.receive(&payload);
        let got = chunk(&mut s, &view(false)).await;
        assert_eq!(got.matches("event: click").count(), 1, "{got}");
        assert_eq!(watcher.metrics.live_received.get(), 1);
        assert_eq!(origin.metrics.live_relayed.get(), 1);
        // A full relay queue drops instead of waiting.
        for _ in 0..1_000 {
            origin.publish(&click(7, Device::Mobile));
        }
        assert!(origin.metrics.live_relay_dropped.get() > 0);
        // A failed notification is counted as dropped.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = origin.metrics.live_relay_dropped.get();
        sink.1.store(1, Ordering::Relaxed);
        origin.publish(&click(7, Device::Mobile));
        let deadline = Instant::now() + Duration::from_secs(5);
        while origin.metrics.live_relay_dropped.get() == before {
            assert!(Instant::now() < deadline, "failure not counted");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        stop_tx.send(true).unwrap();
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn watched_links_are_announced_and_remote_ones_expire() {
        let cfg = LiveConfig {
            announce: Duration::from_millis(100),
            ..LiveConfig::default()
        };
        let h = hub(cfg);
        let sink = Arc::new(FakeSink::default());
        let (stop_tx, stop) = watch::channel(false);
        let relay = tokio::spawn(h.clone().run_relay(sink.clone(), stop));
        let other = encode_watch(1, &[50])[0].clone();
        h.receive(&other);
        assert_eq!(h.watched.load(Ordering::Acquire), 1);
        let _s = h.subscribe(1, 4).unwrap();
        let expected = format!("w {:016x}\n4", h.instance);
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == expected)
            .count()
            < 2
        {
            assert!(Instant::now() < deadline, "not announced twice");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Link 50 was announced once, three intervals ago at least.
        let deadline = Instant::now() + Duration::from_secs(5);
        while h.read().remote.contains_key(&50) {
            assert!(Instant::now() < deadline, "remote watch never expired");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(h.watched.load(Ordering::Acquire), 1);
        stop_tx.send(true).unwrap();
        relay.await.unwrap();
        // The relay runs once per hub.
        let (_tx, stop) = watch::channel(false);
        h.clone().run_relay(sink, stop).await;
    }
}

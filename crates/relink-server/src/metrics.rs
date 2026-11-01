//! Prometheus metrics in the text exposition format, without a client library.
//!
//! Counters and histogram buckets are plain atomics, so recording on the
//! redirect path is a handful of relaxed increments.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// A monotonically increasing counter.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// Latency histogram with fixed bucket bounds in seconds.
pub struct Histogram {
    bounds: &'static [f64],
    buckets: Box<[AtomicU64]>,
    sum_nanos: AtomicU64,
    count: AtomicU64,
}

/// Bounds from 10 µs to 2.5 s: the redirect path lives in the first few,
/// database-backed misses in the middle.
pub const LATENCY_BOUNDS: &[f64] = &[
    0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
    0.1, 0.25, 0.5, 1.0, 2.5,
];

impl Histogram {
    pub fn new(bounds: &'static [f64]) -> Self {
        Histogram {
            bounds,
            buckets: (0..bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        if let Some(i) = self.bounds.iter().position(|&b| secs <= b) {
            self.buckets[i].fetch_add(1, Relaxed);
        }
        self.sum_nanos
            .fetch_add(d.as_nanos().min(u64::MAX as u128) as u64, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Relaxed)
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
        let mut cumulative = 0;
        for (bound, bucket) in self.bounds.iter().zip(self.buckets.iter()) {
            cumulative += bucket.load(Relaxed);
            let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {cumulative}");
        }
        let count = self.count.load(Relaxed);
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {count}");
        let sum = self.sum_nanos.load(Relaxed) as f64 / 1e9;
        let _ = writeln!(out, "{name}_sum {sum}\n{name}_count {count}");
    }
}

/// How a redirect request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Redirect,
    Fallback,
    NotFound,
    Gone,
    GeoBlocked,
    Unavailable,
}

impl Outcome {
    const ALL: [Outcome; 6] = [
        Outcome::Redirect,
        Outcome::Fallback,
        Outcome::NotFound,
        Outcome::Gone,
        Outcome::GeoBlocked,
        Outcome::Unavailable,
    ];
    fn label(self) -> &'static str {
        match self {
            Outcome::Redirect => "redirect",
            Outcome::Fallback => "fallback",
            Outcome::NotFound => "not_found",
            Outcome::Gone => "gone",
            Outcome::GeoBlocked => "geo_blocked",
            Outcome::Unavailable => "unavailable",
        }
    }
}

/// What the in-process cache answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheResult {
    /// Fresh entry.
    Hit,
    /// Fresh negative entry: the code is known not to exist.
    NegativeHit,
    /// Served a stale entry while refreshing it in the background.
    Stale,
    /// Served a stale entry because the database could not be reached.
    StaleOnError,
    /// Nothing usable; the request waited for the database.
    Miss,
}

impl CacheResult {
    const ALL: [CacheResult; 5] = [
        CacheResult::Hit,
        CacheResult::NegativeHit,
        CacheResult::Stale,
        CacheResult::StaleOnError,
        CacheResult::Miss,
    ];
    fn label(self) -> &'static str {
        match self {
            CacheResult::Hit => "hit",
            CacheResult::NegativeHit => "negative_hit",
            CacheResult::Stale => "stale",
            CacheResult::StaleOnError => "stale_on_error",
            CacheResult::Miss => "miss",
        }
    }
}

/// Which database operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbOp {
    Lookup,
    Lease,
    Flush,
    Api,
    Health,
    Listen,
    Maintenance,
    Kv,
}

impl DbOp {
    const ALL: [DbOp; 8] = [
        DbOp::Lookup,
        DbOp::Lease,
        DbOp::Flush,
        DbOp::Api,
        DbOp::Health,
        DbOp::Listen,
        DbOp::Maintenance,
        DbOp::Kv,
    ];
    fn label(self) -> &'static str {
        match self {
            DbOp::Lookup => "lookup",
            DbOp::Lease => "lease",
            DbOp::Flush => "flush",
            DbOp::Api => "api",
            DbOp::Health => "health",
            DbOp::Listen => "listen",
            DbOp::Maintenance => "maintenance",
            DbOp::Kv => "kv",
        }
    }
}

/// Why a click was not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The in-memory queue was full.
    QueueFull,
    /// The flusher's backlog was full because the database was unavailable.
    Backlog,
    /// The process was shutting down.
    Closed,
    /// The database refused the batch for a non-transient reason.
    Rejected,
}

impl DropReason {
    const ALL: [DropReason; 4] = [
        DropReason::QueueFull,
        DropReason::Backlog,
        DropReason::Closed,
        DropReason::Rejected,
    ];
    fn label(self) -> &'static str {
        match self {
            DropReason::QueueFull => "queue_full",
            DropReason::Backlog => "backlog",
            DropReason::Closed => "closed",
            DropReason::Rejected => "rejected",
        }
    }
}

/// Result of one destination health probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Healthy,
    Unhealthy,
    Blocked,
    RateLimited,
}

impl ProbeResult {
    const ALL: [ProbeResult; 4] = [
        ProbeResult::Healthy,
        ProbeResult::Unhealthy,
        ProbeResult::Blocked,
        ProbeResult::RateLimited,
    ];
    fn label(self) -> &'static str {
        match self {
            ProbeResult::Healthy => "healthy",
            ProbeResult::Unhealthy => "unhealthy",
            ProbeResult::Blocked => "blocked",
            ProbeResult::RateLimited => "rate_limited",
        }
    }
}

/// Point-in-time values sampled when /metrics is scraped.
pub struct Gauges {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub backlog_keys: usize,
    pub cache_entries: usize,
    pub leases: usize,
    pub db_pool_size: u32,
    pub db_pool_idle: usize,
}

/// Every metric the service exports.
pub struct Metrics {
    pub redirect_latency: Histogram,
    pub api_latency: Histogram,
    outcomes: [Counter; 6],
    cache: [Counter; 5],
    db_errors: [Counter; 8],
    drops: [Counter; 4],
    probes: [Counter; 4],
    pub coalesced: Counter,
    pub lookups_shed: Counter,
    pub clicks_enqueued: Counter,
    pub clicks_flushed: Counter,
    pub flushes: Counter,
    pub lease_grants: Counter,
    pub api_requests: Counter,
    pub api_errors: Counter,
    pub rate_limited: Counter,
    /// Requests refused because the key lacks the scope or its owner's role
    /// does not grant it.
    pub permission_denied: Counter,
    pub invalidations: Counter,
    pub kv_writes: Counter,
    pub kv_deletes: Counter,
    pub kv_errors: Counter,
    pub kv_reconciled: Counter,
    pub edge_clicks: Counter,
    /// Visitor hashes dropped because their day's salt was already destroyed.
    pub late_visitors: Counter,
    /// Gauge: aggregated click rows held by the flusher.
    pub backlog: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            redirect_latency: Histogram::new(LATENCY_BOUNDS),
            api_latency: Histogram::new(LATENCY_BOUNDS),
            outcomes: Default::default(),
            cache: Default::default(),
            db_errors: Default::default(),
            drops: Default::default(),
            probes: Default::default(),
            coalesced: Counter::default(),
            lookups_shed: Counter::default(),
            clicks_enqueued: Counter::default(),
            clicks_flushed: Counter::default(),
            flushes: Counter::default(),
            lease_grants: Counter::default(),
            api_requests: Counter::default(),
            api_errors: Counter::default(),
            rate_limited: Counter::default(),
            permission_denied: Counter::default(),
            invalidations: Counter::default(),
            kv_writes: Counter::default(),
            kv_deletes: Counter::default(),
            kv_errors: Counter::default(),
            kv_reconciled: Counter::default(),
            edge_clicks: Counter::default(),
            late_visitors: Counter::default(),
            backlog: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn outcome(&self, o: Outcome) {
        self.outcomes[o as usize].inc();
    }
    pub fn outcome_count(&self, o: Outcome) -> u64 {
        self.outcomes[o as usize].get()
    }
    pub fn cache(&self, r: CacheResult) {
        self.cache[r as usize].inc();
    }
    pub fn cache_count(&self, r: CacheResult) -> u64 {
        self.cache[r as usize].get()
    }
    pub fn db_error(&self, op: DbOp) {
        self.db_errors[op as usize].inc();
    }
    pub fn db_error_count(&self, op: DbOp) -> u64 {
        self.db_errors[op as usize].get()
    }
    pub fn dropped(&self, reason: DropReason, n: u64) {
        self.drops[reason as usize].add(n);
    }
    pub fn dropped_count(&self, reason: DropReason) -> u64 {
        self.drops[reason as usize].get()
    }
    pub fn probe(&self, r: ProbeResult) {
        self.probes[r as usize].inc();
    }
    pub fn probe_count(&self, r: ProbeResult) -> u64 {
        self.probes[r as usize].get()
    }

    /// Renders all metrics in the Prometheus text format (version 0.0.4).
    pub fn render(&self, g: &Gauges) -> String {
        let mut out = String::with_capacity(8192);
        self.redirect_latency.render(
            &mut out,
            "relink_redirect_duration_seconds",
            "Time to answer a redirect request, from routing to response.",
        );
        self.api_latency.render(
            &mut out,
            "relink_api_duration_seconds",
            "Time to answer a management API request.",
        );
        family(
            &mut out,
            "relink_redirects_total",
            "Redirect requests by outcome.",
            "outcome",
            Outcome::ALL
                .iter()
                .map(|o| (o.label(), self.outcome_count(*o))),
        );
        family(
            &mut out,
            "relink_cache_requests_total",
            "Link cache lookups by result.",
            "result",
            CacheResult::ALL
                .iter()
                .map(|r| (r.label(), self.cache_count(*r))),
        );
        family(
            &mut out,
            "relink_db_errors_total",
            "Failed database operations.",
            "op",
            DbOp::ALL
                .iter()
                .map(|o| (o.label(), self.db_error_count(*o))),
        );
        family(
            &mut out,
            "relink_clicks_dropped_total",
            "Clicks not recorded, by reason.",
            "reason",
            DropReason::ALL
                .iter()
                .map(|r| (r.label(), self.dropped_count(*r))),
        );
        family(
            &mut out,
            "relink_health_probes_total",
            "Destination health probes by result.",
            "result",
            ProbeResult::ALL
                .iter()
                .map(|r| (r.label(), self.probe_count(*r))),
        );
        let counters: [(&str, &str, u64); 18] = [
            (
                "relink_kv_writes_total",
                "Link records written to Workers KV.",
                self.kv_writes.get(),
            ),
            (
                "relink_kv_deletes_total",
                "Link records deleted from Workers KV.",
                self.kv_deletes.get(),
            ),
            (
                "relink_kv_errors_total",
                "Failed KV sync or reconciliation calls (retried).",
                self.kv_errors.get(),
            ),
            (
                "relink_kv_reconciled_total",
                "Links queued for KV sync because KV and the database disagreed.",
                self.kv_reconciled.get(),
            ),
            (
                "relink_edge_clicks_total",
                "Clicks reported by the edge worker.",
                self.edge_clicks.get(),
            ),
            (
                "relink_visitors_dropped_total",
                "Visitor hashes dropped because their day's salt had already been destroyed.",
                self.late_visitors.get(),
            ),
            (
                "relink_lookups_coalesced_total",
                "Cache misses that waited for another request's database lookup.",
                self.coalesced.get(),
            ),
            (
                "relink_lookups_shed_total",
                "Cache misses refused because too many lookups were in flight.",
                self.lookups_shed.get(),
            ),
            (
                "relink_clicks_enqueued_total",
                "Clicks accepted into the in-memory queue.",
                self.clicks_enqueued.get(),
            ),
            (
                "relink_clicks_flushed_total",
                "Clicks written to the database.",
                self.clicks_flushed.get(),
            ),
            (
                "relink_click_flushes_total",
                "Successful batch writes of click aggregates.",
                self.flushes.get(),
            ),
            (
                "relink_click_lease_grants_total",
                "Click leases granted by the database for max-click links.",
                self.lease_grants.get(),
            ),
            (
                "relink_api_requests_total",
                "Management API requests.",
                self.api_requests.get(),
            ),
            (
                "relink_api_errors_total",
                "Management API requests answered with an error.",
                self.api_errors.get(),
            ),
            (
                "relink_api_rate_limited_total",
                "Management API requests refused by the per-key rate limit.",
                self.rate_limited.get(),
            ),
            (
                "relink_api_permission_denied_total",
                "Management API requests refused for a missing scope or role right.",
                self.permission_denied.get(),
            ),
            (
                "relink_cache_invalidations_total",
                "Link cache entries invalidated by change notifications.",
                self.invalidations.get(),
            ),
            (
                "relink_redirect_requests_total",
                "Redirect requests answered.",
                self.redirect_latency.count(),
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        }
        let gauges: [(&str, &str, u64); 7] = [
            (
                "relink_click_queue_depth",
                "Clicks waiting in the in-memory queue.",
                g.queue_depth as u64,
            ),
            (
                "relink_click_queue_capacity",
                "Capacity of the in-memory click queue.",
                g.queue_capacity as u64,
            ),
            (
                "relink_click_backlog_keys",
                "Aggregated click rows waiting to be written after a failed flush.",
                g.backlog_keys as u64,
            ),
            (
                "relink_cache_entries",
                "Entries in the link cache, including negative entries.",
                g.cache_entries as u64,
            ),
            (
                "relink_click_leases",
                "Max-click links with a local lease.",
                g.leases as u64,
            ),
            (
                "relink_db_pool_connections",
                "Open database connections.",
                g.db_pool_size as u64,
            ),
            (
                "relink_db_pool_idle_connections",
                "Idle database connections.",
                g.db_pool_idle as u64,
            ),
        ];
        for (name, help, value) in gauges {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
        out
    }
}

fn family<'a>(
    out: &mut String,
    name: &str,
    help: &str,
    label: &str,
    values: impl Iterator<Item = (&'a str, u64)>,
) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
    for (value, n) in values {
        let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {n}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauges() -> Gauges {
        Gauges {
            queue_depth: 3,
            queue_capacity: 10,
            backlog_keys: 0,
            cache_entries: 7,
            leases: 1,
            db_pool_size: 2,
            db_pool_idle: 1,
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let h = Histogram::new(&[0.001, 0.01]);
        h.observe(Duration::from_micros(500));
        h.observe(Duration::from_millis(5));
        h.observe(Duration::from_secs(1));
        let mut out = String::new();
        h.render(&mut out, "x", "help");
        assert!(out.contains("x_bucket{le=\"0.001\"} 1\n"));
        assert!(out.contains("x_bucket{le=\"0.01\"} 2\n"));
        assert!(out.contains("x_bucket{le=\"+Inf\"} 3\n"));
        assert!(out.contains("x_count 3\n"));
        assert!(out.contains("x_sum 1.0055"));
    }

    #[test]
    fn renders_every_family() {
        let m = Metrics::default();
        m.outcome(Outcome::Redirect);
        m.outcome(Outcome::Redirect);
        m.cache(CacheResult::StaleOnError);
        m.db_error(DbOp::Flush);
        m.dropped(DropReason::QueueFull, 5);
        m.probe(ProbeResult::Blocked);
        m.redirect_latency.observe(Duration::from_micros(20));
        let text = m.render(&gauges());
        for needle in [
            "relink_redirects_total{outcome=\"redirect\"} 2",
            "relink_cache_requests_total{result=\"stale_on_error\"} 1",
            "relink_db_errors_total{op=\"flush\"} 1",
            "relink_clicks_dropped_total{reason=\"queue_full\"} 5",
            "relink_health_probes_total{result=\"blocked\"} 1",
            "relink_click_queue_depth 3",
            "relink_cache_entries 7",
            "relink_redirect_requests_total 1",
            "# TYPE relink_redirect_duration_seconds histogram",
        ] {
            assert!(text.contains(needle), "missing {needle}");
        }
        // Every non-comment line is "name{labels} value" or "name value".
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit(' ').next().unwrap();
            assert!(value.parse::<f64>().is_ok(), "bad line {line}");
        }
    }
}

//! Hourly and daily rollups fed from the click stream (migration 0021):
//! every table one flush writes agrees with the others, a batch replayed
//! after a lost acknowledgement changes nothing, concurrent flushers merge
//! their visitor sketches without losing any, deleted links are skipped,
//! retention deletes old hourly rows, and tenants see only their own rows.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use relink_server::classify::Device;
use relink_server::clicks::{ClickEvent, ClickSink, FlushConfig, Flusher, sketch_hash};
use relink_server::hll::Hll;
use relink_server::metrics::Metrics;
use relink_server::server::{migrate_with_retry, open_db};
use relink_server::store::{
    Applied, ClickRow, Db, DbError, FlushBatch, HourRow, StoredEvent, day_to_date,
};
use relink_server::util::{BoxFuture, now_ms};
use sqlx::Row;

use common::{TestDb, admin_url, config, insert_link, new_link_for};

const HOUR_MS: i64 = 3_600_000;

/// Five standard errors of a dense sketch (1.04 / sqrt(16384) = 0.81%).
/// The RMS error itself is tested in relink-core/tests/hll.rs.
const MAX_ERROR: f64 = 0.041;

async fn fresh() -> Option<(TestDb, Db)> {
    let admin = admin_url()?;
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, &[])).unwrap();
    migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    Some((db, store))
}

fn cfg() -> FlushConfig {
    FlushConfig {
        interval: Duration::from_millis(50),
        batch: 1000,
        max_backlog: 1_000_000,
        max_events: 1_000_000,
        max_backoff: Duration::from_millis(100),
    }
}

/// The current UTC hour, in hours since the epoch.
fn this_hour() -> i32 {
    (now_ms() / HOUR_MS) as i32
}

fn click(link_id: i64, hour: i32, country: &[u8; 2], visitor: u32) -> ClickEvent {
    let mut fingerprint = [0u8; 16];
    fingerprint[..4].copy_from_slice(&visitor.to_be_bytes());
    ClickEvent {
        link_id,
        at_ms: i64::from(hour) * HOUR_MS + i64::from(visitor % 3_600) * 1_000,
        country: *country,
        device: Device::Desktop,
        referrer: visitor.is_multiple_of(2).then(|| "news.example.org".into()),
        fingerprint,
    }
}

fn hour_time(hour: i32) -> DateTime<Utc> {
    DateTime::from_timestamp(i64::from(hour) * 3_600, 0).unwrap()
}

async fn scalar(store: &Db, sql: &'static str, link: i64) -> i64 {
    sqlx::query_scalar(sql)
        .bind(link)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

async fn hourly_clicks(store: &Db, link: i64) -> i64 {
    scalar(
        store,
        "SELECT COALESCE(sum(clicks), 0)::bigint FROM click_hourly WHERE link_id = $1",
        link,
    )
    .await
}

async fn daily_clicks(store: &Db, link: i64) -> i64 {
    scalar(
        store,
        "SELECT COALESCE(sum(clicks), 0)::bigint FROM click_daily WHERE link_id = $1",
        link,
    )
    .await
}

async fn event_count(store: &Db, link: i64) -> i64 {
    scalar(
        store,
        "SELECT count(*) FROM click_events WHERE link_id = $1",
        link,
    )
    .await
}

/// The stored sketch of one link and hour.
async fn hour_sketch(store: &Db, link: i64, hour: i32) -> Option<Hll> {
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT sketch FROM visitor_sketch_hourly WHERE link_id = $1 AND hour = $2",
    )
    .bind(link)
    .bind(hour_time(hour))
    .fetch_optional(store.pool())
    .await
    .unwrap();
    bytes.map(|b| Hll::from_bytes(&b).unwrap())
}

/// The stored daily sketches of one link, merged.
async fn day_sketches(store: &Db, link: i64) -> Hll {
    let rows: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT sketch FROM visitor_sketch_daily WHERE link_id = $1")
            .bind(link)
            .fetch_all(store.pool())
            .await
            .unwrap();
    let mut all = Hll::new();
    for b in rows {
        all.merge(&Hll::from_bytes(&b).unwrap());
    }
    all
}

/// One flush writes every rollup, and they agree: hourly rows add up to the
/// daily rows and to the raw events, per dimension; events carry the link's
/// workspace; sketches count the distinct visitors per hour, per day, and
/// across links.
#[tokio::test]
async fn one_flush_feeds_every_rollup_consistently() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let a = insert_link(&store, &new_link_for("alice", "roll-a"), 7)
        .await
        .unwrap();
    let b = insert_link(&store, &new_link_for("alice", "roll-b"), 7)
        .await
        .unwrap();
    let h = this_hour();
    let metrics = Arc::new(Metrics::default());
    let mut f = Flusher::new(Arc::new(store.clone()), metrics.clone(), cfg());
    // Link a: visitors 0..3000 in hour h (DE) and 2000..4000 in hour h + 1
    // (NZ). Link b: visitors 3500..4500 in hour h + 1. Every visitor
    // clicks twice.
    for _ in 0..2 {
        for v in 0..3_000 {
            f.absorb(click(a.id, h, b"DE", v));
        }
        for v in 2_000..4_000 {
            f.absorb(click(a.id, h + 1, b"NZ", v));
        }
        for v in 3_500..4_500 {
            f.absorb(click(b.id, h + 1, b"NZ", v));
        }
    }
    assert!(f.flush().await);
    assert_eq!(metrics.clicks_flushed.get(), 12_000);
    assert!(metrics.flushes.get() >= 3, "written in several batches");

    assert_eq!(hourly_clicks(&store, a.id).await, 10_000);
    assert_eq!(daily_clicks(&store, a.id).await, 10_000);
    assert_eq!(event_count(&store, a.id).await, 10_000);
    assert_eq!(hourly_clicks(&store, b.id).await, 2_000);

    // Per hour and dimension, hourly rows equal the raw events.
    let hourly: Vec<(DateTime<Utc>, String, String, i64)> = sqlx::query(
        "SELECT hour, country, referrer_host, clicks FROM click_hourly WHERE link_id = $1 ORDER BY 1, 2, 3",
    )
    .bind(a.id)
    .fetch_all(store.pool())
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect();
    let from_events: Vec<(DateTime<Utc>, String, String, i64)> = sqlx::query(
        "SELECT date_trunc('hour', at), country, referrer_host, count(*) FROM click_events
          WHERE link_id = $1 GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
    )
    .bind(a.id)
    .fetch_all(store.pool())
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect();
    assert_eq!(hourly, from_events);
    assert_eq!(
        hourly
            .iter()
            .map(|r| (r.0, r.1.as_str(), r.2.as_str()))
            .collect::<Vec<_>>(),
        [
            (hour_time(h), "DE", "(direct)"),
            (hour_time(h), "DE", "news.example.org"),
            (hour_time(h + 1), "NZ", "(direct)"),
            (hour_time(h + 1), "NZ", "news.example.org"),
        ]
    );
    // The hourly rows and events carry the link's workspace, and the events
    // a visitor hash.
    let (ws_rows, with_visitor): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM click_hourly WHERE workspace_id = $2),
                (SELECT count(*) FROM click_events WHERE workspace_id = $2 AND visitor IS NOT NULL)",
    )
    .bind(a.id)
    .bind(a.workspace_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!((ws_rows, with_visitor), (6, 12_000));

    // Sketches against the exact distinct visitors. Salts are random, so
    // the estimates differ between runs: sparse sketches (up to 3,072
    // visitors) are within 0.1%, dense ones within five standard errors.
    let close = |sketch: &Hll, exact: f64| {
        let e = sketch.estimate();
        let bound = if sketch.is_sparse() { 0.001 } else { MAX_ERROR };
        assert!((e - exact).abs() / exact < bound, "{e} vs {exact}");
    };
    close(&hour_sketch(&store, a.id, h).await.unwrap(), 3_000.0);
    close(&hour_sketch(&store, a.id, h + 1).await.unwrap(), 2_000.0);
    let days_a = day_sketches(&store, a.id).await;
    let days_b = day_sketches(&store, b.id).await;
    let same_day = h.div_euclid(24) == (h + 1).div_euclid(24);
    if same_day {
        // One salt for both hours: visitors 2000..3000 count once.
        close(&days_a, 4_000.0);
        let mut both = days_a.clone();
        both.merge(&days_b);
        // b's visitors 3500..4000 also clicked a; 4000..4500 are new.
        close(&both, 4_500.0);
        // The day's sketch is the merge of its hours.
        let mut hours = hour_sketch(&store, a.id, h).await.unwrap();
        hours.merge(&hour_sketch(&store, a.id, h + 1).await.unwrap());
        assert_eq!(hours, days_a);
    } else {
        // Hour h + 1 starts a new day with a new salt: returning visitors
        // count again on it.
        close(&days_a, 5_000.0);
    }
    let visitors: i64 = scalar(
        &store,
        "SELECT count(*) FROM visitor_daily WHERE link_id = $1",
        a.id,
    )
    .await;
    assert_eq!(visitors, if same_day { 4_000 } else { 5_000 });
}

/// Writes batches to the database, and the first `lose` of them commit but
/// report an error, as when the connection drops after COMMIT was sent.
struct LosingAcks {
    db: Db,
    lose: AtomicBool,
}

impl ClickSink for LosingAcks {
    fn salt(&self, day: i32) -> BoxFuture<'_, Result<Option<[u8; 32]>, DbError>> {
        ClickSink::salt(&self.db, day)
    }
    fn write<'a>(&'a self, batch: &'a FlushBatch) -> BoxFuture<'a, Result<Applied, DbError>> {
        Box::pin(async move {
            let applied = self.db.write_batch(batch).await?;
            if self.lose.swap(false, Ordering::SeqCst) {
                return Err(DbError::Unavailable("connection reset after commit".into()));
            }
            Ok(applied)
        })
    }
}

/// A batch whose commit reached the database but whose acknowledgement did
/// not is retried with its key and changes nothing the second time: no
/// count, quota, event or sketch is applied twice.
#[tokio::test]
async fn a_batch_replayed_after_a_lost_commit_changes_nothing() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = insert_link(&store, &new_link_for("alice", "replay"), 7)
        .await
        .unwrap();
    let h = this_hour();
    let sink = Arc::new(LosingAcks {
        db: store.clone(),
        lose: AtomicBool::new(true),
    });
    let metrics = Arc::new(Metrics::default());
    let mut f = Flusher::new(sink, metrics.clone(), cfg());
    for v in 0..500 {
        f.absorb(click(link.id, h, b"DE", v));
    }
    assert!(!f.flush().await, "the flusher only saw an error");
    assert_eq!(
        hourly_clicks(&store, link.id).await,
        500,
        "but it committed"
    );
    let sketch_before = hour_sketch(&store, link.id, h).await.unwrap();
    assert!(f.flush().await);
    assert_eq!(metrics.batches_replayed.get(), 1);
    assert_eq!(metrics.clicks_flushed.get(), 500);
    assert_eq!(hourly_clicks(&store, link.id).await, 500);
    assert_eq!(daily_clicks(&store, link.id).await, 500);
    assert_eq!(event_count(&store, link.id).await, 500);
    assert_eq!(
        hour_sketch(&store, link.id, h).await.unwrap(),
        sketch_before
    );
    let usage: i64 = scalar(
        &store,
        "SELECT clicks FROM workspace_usage WHERE workspace_id = $1",
        link.workspace_id,
    )
    .await;
    assert_eq!(usage, 500);
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM click_batches")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(keys, 1);
}

/// The same batch written directly twice: the second write reports a
/// replay. A batch naming a link deleted meanwhile is written without it.
#[tokio::test]
async fn write_batch_is_idempotent_and_skips_deleted_links() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = insert_link(&store, &new_link_for("alice", "direct"), 7)
        .await
        .unwrap();
    let gone = insert_link(&store, &new_link_for("alice", "gone"), 7)
        .await
        .unwrap();
    sqlx::query("DELETE FROM links WHERE id = $1")
        .bind(gone.id)
        .execute(store.pool())
        .await
        .unwrap();
    let h = this_hour();
    let day = h.div_euclid(24);
    let row = |link_id| HourRow {
        link_id,
        hour: h,
        country: *b"FR",
        device: "mobile",
        referrer: None,
    };
    let mut sketch = Hll::new();
    for v in 0..10u32 {
        sketch.insert_hash(sketch_hash(&[1; 32], &[v as u8; 16]));
    }
    let event = |link_id| StoredEvent {
        at_ms: i64::from(h) * HOUR_MS + 5,
        link_id,
        country: *b"FR",
        device: "mobile",
        referrer: None,
        visitor: None,
    };
    let batch = FlushBatch {
        id: [42; 16],
        daily: vec![(row(link.id).daily(), 3), (row(gone.id).daily(), 4)],
        hourly: vec![(row(link.id), 3), (row(gone.id), 4)],
        visitors: vec![(link.id, day, [1; 16]), (gone.id, day, [2; 16])],
        events: vec![event(link.id), event(gone.id)],
        hour_sketches: vec![(link.id, h, sketch.clone()), (gone.id, h, sketch.clone())],
        day_sketches: vec![
            (link.id, day, sketch.clone()),
            (gone.id, day, sketch.clone()),
        ],
    };
    assert_eq!(batch.clicks(), 7);
    assert_eq!(store.write_batch(&batch).await.unwrap(), Applied::Written);
    assert_eq!(store.write_batch(&batch).await.unwrap(), Applied::Replayed);
    assert_eq!(hourly_clicks(&store, link.id).await, 3);
    assert_eq!(daily_clicks(&store, link.id).await, 3);
    assert_eq!(event_count(&store, link.id).await, 1);
    assert_eq!(hour_sketch(&store, link.id, h).await.unwrap().count(), 10);
    assert_eq!(day_sketches(&store, link.id).await.count(), 10);
    for table in [
        "click_hourly",
        "click_daily",
        "click_events",
        "visitor_daily",
        "visitor_sketch_hourly",
        "visitor_sketch_daily",
    ] {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE link_id = $1"
        )))
        .bind(gone.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    // A daily-only batch from the shorthand still counts and still uses a
    // key of its own.
    store
        .flush_clicks(
            &[(
                ClickRow {
                    link_id: link.id,
                    day,
                    country: *b"FR",
                    device: "mobile",
                    referrer: None,
                },
                2,
            )],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(daily_clicks(&store, link.id).await, 5);
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM click_batches")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(keys, 2);
}

/// Eight flushers merge sketches into the same link and hours at once.
/// Each row is created once and locked in key order, so no flusher
/// overwrites another's visitors and none deadlocks.
#[tokio::test]
async fn concurrent_sketch_merges_lose_no_visitors() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let links = [
        insert_link(&store, &new_link_for("alice", "conc-a"), 7)
            .await
            .unwrap()
            .id,
        insert_link(&store, &new_link_for("alice", "conc-b"), 7)
            .await
            .unwrap()
            .id,
    ];
    let h = this_hour();
    let day = h.div_euclid(24);
    let salt = [9u8; 32];
    let mut tasks = Vec::new();
    for worker in 0..8u32 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..5u32 {
                let mut sketch = Hll::new();
                for v in 0..200u32 {
                    let id = (worker * 5 + round) * 200 + v;
                    let mut fp = [0u8; 16];
                    fp[..4].copy_from_slice(&id.to_be_bytes());
                    sketch.insert_hash(sketch_hash(&salt, &fp));
                }
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&worker.to_be_bytes());
                id[4..8].copy_from_slice(&round.to_be_bytes());
                // Half the workers list the keys in the opposite order.
                let mut keys = [(links[0], h), (links[1], h), (links[0], h + 1)];
                if worker % 2 == 1 {
                    keys.reverse();
                }
                let batch = FlushBatch {
                    id,
                    hour_sketches: keys
                        .iter()
                        .map(|&(l, hr)| (l, hr, sketch.clone()))
                        .collect(),
                    day_sketches: vec![(links[1], day), (links[0], day)]
                        .into_iter()
                        .map(|(l, d)| (l, d, sketch.clone()))
                        .collect(),
                    ..FlushBatch::default()
                };
                store.write_batch(&batch).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    // 8 workers x 5 rounds x 200 distinct visitors. Every stored sketch is
    // exactly the sketch of all of them: none was overwritten.
    let mut expected = Hll::new();
    for id in 0..8_000u32 {
        let mut fp = [0u8; 16];
        fp[..4].copy_from_slice(&id.to_be_bytes());
        expected.insert_hash(sketch_hash(&salt, &fp));
    }
    for (link, hour) in [(links[0], h), (links[1], h), (links[0], h + 1)] {
        assert_eq!(hour_sketch(&store, link, hour).await.unwrap(), expected);
    }
    for link in links {
        assert_eq!(day_sketches(&store, link).await, expected);
    }
    let e = expected.estimate();
    assert!((e - 8_000.0).abs() / 8_000.0 < MAX_ERROR, "{e}");
}

/// Retention deletes hourly rows and sketches older than the setting, and
/// replay keys older than a week, in bounded steps; daily rows stay.
#[tokio::test]
async fn retention_deletes_old_hourly_rows_and_keys() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = insert_link(&store, &new_link_for("alice", "old-hours"), 7)
        .await
        .unwrap();
    let now = now_ms();
    let h = (now / HOUR_MS) as i32;
    // Hours 0, 10, 20 and 40 days ago.
    let ages = [0, 10 * 24, 20 * 24, 40 * 24];
    let mut batch = FlushBatch {
        id: [1; 16],
        ..FlushBatch::default()
    };
    for (i, age) in ages.iter().enumerate() {
        let hour = h - age;
        let row = HourRow {
            link_id: link.id,
            hour,
            country: *b"DE",
            device: "desktop",
            referrer: None,
        };
        batch.daily.push((row.daily(), 1));
        batch.hourly.push((row, 1));
        let mut sketch = Hll::new();
        sketch.insert_hash(i as u64 + 1);
        batch.hour_sketches.push((link.id, hour, sketch));
    }
    store.write_batch(&batch).await.unwrap();
    // Keys from now and from eight days ago.
    sqlx::query("INSERT INTO click_batches (id, at) VALUES ($1, now() - interval '8 days')")
        .bind(vec![2u8; 16])
        .execute(store.pool())
        .await
        .unwrap();

    let hours = |store: Db| async move {
        let rows: Vec<DateTime<Utc>> =
            sqlx::query_scalar("SELECT hour FROM click_hourly ORDER BY hour DESC")
                .fetch_all(store.pool())
                .await
                .unwrap();
        let sketches: i64 = sqlx::query_scalar("SELECT count(*) FROM visitor_sketch_hourly")
            .fetch_one(store.pool())
            .await
            .unwrap();
        (rows, sketches)
    };
    // A limit of one row per table per call: three calls for two old hours
    // and one old key, then nothing.
    assert_eq!(store.maintain_rollups(now, 15, 1).await.unwrap(), 3);
    assert_eq!(store.maintain_rollups(now, 15, 1).await.unwrap(), 2);
    assert_eq!(store.maintain_rollups(now, 15, 1).await.unwrap(), 0);
    let (rows, sketches) = hours(store.clone()).await;
    assert_eq!(rows, vec![hour_time(h), hour_time(h - 240)]);
    assert_eq!(sketches, 2);
    let keys: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM click_batches")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(keys, vec![vec![1u8; 16]]);
    assert_eq!(daily_clicks(&store, link.id).await, 4, "daily rows stay");
    // A shorter retention takes the next hour too.
    assert_eq!(store.maintain_rollups(now, 5, 100).await.unwrap(), 2);
    assert_eq!(hours(store.clone()).await, (vec![hour_time(h)], 1));
}

/// Tenants read their own workspace's hourly rows and sketches and nothing
/// else, cannot write them, and cannot read replay keys at all.
#[tokio::test]
async fn tenants_see_only_their_own_rollups() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let a = insert_link(&store, &new_link_for("alice", "tenant-a"), 7)
        .await
        .unwrap();
    let b = insert_link(&store, &new_link_for("bob", "tenant-b"), 7)
        .await
        .unwrap();
    assert_ne!(a.workspace_id, b.workspace_id);
    let mut f = Flusher::new(Arc::new(store.clone()), Arc::new(Metrics::default()), cfg());
    let h = this_hour();
    for v in 0..3 {
        f.absorb(click(a.id, h, b"DE", v));
    }
    for v in 0..5 {
        f.absorb(click(b.id, h, b"US", v));
    }
    assert!(f.flush().await);

    let mut tx = store.begin_tenant(a.workspace_id).await.unwrap();
    let mut seen = HashMap::new();
    for table in [
        "click_hourly",
        "visitor_sketch_hourly",
        "visitor_sketch_daily",
    ] {
        let links: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT DISTINCT link_id FROM {table}"
        )))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        seen.insert(table, links);
    }
    let clicks: i64 = sqlx::query_scalar("SELECT sum(clicks)::bigint FROM click_hourly")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    for (table, links) in &seen {
        assert_eq!(links, &vec![a.id], "{table}");
    }
    assert_eq!(clicks, 3);

    for sql in [
        "SELECT count(*) FROM click_batches",
        "UPDATE click_hourly SET clicks = 1",
        "DELETE FROM visitor_sketch_daily",
    ] {
        let mut tx = store.begin_tenant(a.workspace_id).await.unwrap();
        let err = sqlx::query(sql).execute(&mut *tx).await.unwrap_err();
        let code = err
            .as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.into_owned());
        assert_eq!(code.as_deref(), Some("42501"), "{sql}: {err}");
    }
}

/// The schema refuses what the flusher never writes: hours that are not on
/// the hour, empty or oversized sketches, zero counts, and keys of the
/// wrong length.
#[tokio::test]
async fn the_schema_refuses_malformed_rollups() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = insert_link(&store, &new_link_for("alice", "schema"), 7)
        .await
        .unwrap();
    let hour = hour_time(this_hour());
    let day: NaiveDate = day_to_date(this_hour().div_euclid(24));
    let refused = |what: &str, r: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| {
        let err = r.unwrap_err();
        let code = err
            .as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.into_owned());
        assert_eq!(code.as_deref(), Some("23514"), "{what}: {err}");
    };
    for (what, minute, country, clicks) in [
        ("an hour off the hour", 1, "DE", 1i64),
        ("zero clicks", 0, "DE", 0),
        ("a long country", 0, "DEU", 1),
    ] {
        let r = sqlx::query(
            "INSERT INTO click_hourly VALUES ($1, $2, $3 + make_interval(mins => $4), $5, 'mobile', '(direct)', $6)",
        )
        .bind(link.id)
        .bind(link.workspace_id)
        .bind(hour)
        .bind(minute)
        .bind(country)
        .bind(clicks)
        .execute(store.pool())
        .await;
        refused(what, r);
    }
    let r = sqlx::query("INSERT INTO visitor_sketch_hourly VALUES ($1, $2, '')")
        .bind(link.id)
        .bind(hour)
        .execute(store.pool())
        .await;
    refused("an empty sketch", r);
    let r = sqlx::query("INSERT INTO visitor_sketch_daily VALUES ($1, $2, $3)")
        .bind(link.id)
        .bind(day)
        .bind(vec![0u8; 16_385])
        .execute(store.pool())
        .await;
    refused("an oversized sketch", r);
    let r = sqlx::query("INSERT INTO click_batches (id) VALUES ($1)")
        .bind(vec![1u8, 2])
        .execute(store.pool())
        .await;
    refused("a short batch key", r);
    let ok = Hll::new().to_bytes();
    sqlx::query("INSERT INTO visitor_sketch_daily VALUES ($1, $2, $3)")
        .bind(link.id)
        .bind(day)
        .bind(ok)
        .execute(store.pool())
        .await
        .unwrap();
}

//! Postgres-level behaviour: lease grants under concurrency, visitor-hash
//! retention, health-check claiming and guarded updates.

mod common;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use relink_server::classify::Device;
use relink_server::clicks::{ClickEvent, FLUSH_CHUNK, FlushConfig, Flusher};
use relink_server::metrics::Metrics;
use relink_server::util::{now_ms, utc_day};

use common::{TestDb, admin_url, config};
use relink_server::limiter::grant_size;
use relink_server::model::Destination;
use relink_server::server::{migrate_with_retry, open_db};
use relink_server::store::{ClickRow, Db, DbError, HealthTarget, NewLink};

async fn fresh() -> Option<(TestDb, Db)> {
    let admin = admin_url()?;
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, &[])).unwrap();
    migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    Some((db, store))
}

fn new_link(alias: Option<&str>, max_clicks: Option<i64>) -> NewLink {
    NewLink {
        owner: "alice".into(),
        alias: alias.map(str::to_owned),
        destinations: vec![Destination {
            url: "https://example.com/".into(),
            weight: 1,
        }],
        redirect_status: 302,
        expires_at: None,
        max_clicks,
        geo: None,
        fallback_url: None,
        enabled: true,
        health_check: true,
    }
}

#[tokio::test]
async fn lease_grants_follow_the_rule_and_never_exceed_the_limit() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = common::insert_link(&store, &new_link(None, Some(1000)), 7)
        .await
        .unwrap();
    // Sequential grants match the reference rule exactly.
    let mut reserved = 0;
    for _ in 0..5 {
        let g = store.reserve_clicks(link.id, 100).await.unwrap();
        assert_eq!(g, grant_size(1000, reserved, 100));
        reserved += g;
    }
    // Concurrent grants from many tasks: total is capped at max_clicks.
    let store = Arc::new(store);
    let tasks: Vec<_> = (0..64)
        .map(|_| {
            let s = store.clone();
            let id = link.id;
            tokio::spawn(async move {
                let mut got = 0;
                loop {
                    match s.reserve_clicks(id, 100).await.unwrap() {
                        0 => return got,
                        g => got += g,
                    }
                }
            })
        })
        .collect();
    let mut total = reserved;
    for t in tasks {
        total += t.await.unwrap();
    }
    assert_eq!(total, 1000);
    assert_eq!(store.clicks_reserved(link.id).await.unwrap(), 1000);
    store.release_clicks(link.id, 10).await.unwrap();
    assert_eq!(store.reserve_clicks(link.id, 100).await.unwrap(), 1);
    // A link without a limit grants nothing.
    let unlimited = common::insert_link(&store, &new_link(None, None), 7)
        .await
        .unwrap();
    assert_eq!(store.reserve_clicks(unlimited.id, 100).await.unwrap(), 0);
}

#[tokio::test]
async fn aliases_conflict_and_codes_are_unique() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    common::insert_link(&store, &new_link(Some("taken"), None), 7)
        .await
        .unwrap();
    assert_eq!(
        common::insert_link(&store, &new_link(Some("taken"), None), 7).await,
        Err(DbError::Conflict)
    );
    let mut codes = HashSet::new();
    for _ in 0..200 {
        let l = common::insert_link(&store, &new_link(None, None), 4)
            .await
            .unwrap();
        assert!(codes.insert(l.code.clone()));
    }
    // Codes are global, but another workspace cannot see the link.
    let bob = store.personal_workspace("bob").await.unwrap();
    assert_eq!(
        store.tenant(bob).link("taken").await,
        Err(DbError::NotFound)
    );
    assert!(store.link_by_code("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn visitor_hashes_roll_up_and_salts_are_destroyed() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = common::insert_link(&store, &new_link(None, None), 7)
        .await
        .unwrap();
    let today = relink_server::util::utc_day(relink_server::util::now_ms());
    let salt_today = store.salt_for_day(today, today).await.unwrap();
    assert!(salt_today.is_some());
    assert_eq!(
        store.salt_for_day(today, today).await.unwrap(),
        salt_today,
        "stable per day"
    );
    let old_day = today - 3;
    // Created back when that day was current.
    store.salt_for_day(old_day, old_day).await.unwrap();
    // A day that never had a salt does not get one now.
    assert_eq!(store.salt_for_day(old_day - 1, today).await.unwrap(), None);
    let row = |day| ClickRow {
        link_id: link.id,
        day,
        country: *b"DE",
        device: "mobile",
        referrer: None,
    };
    store
        .flush_clicks(
            &[(row(old_day), 3), (row(today), 2)],
            &[
                (link.id, old_day, [1; 16]),
                (link.id, old_day, [2; 16]),
                (link.id, today, [1; 16]),
            ],
        )
        .await
        .unwrap();
    // A referrer that looks like the "no referrer" marker is a different row,
    // and duplicate keys within one batch are merged, not an error.
    let direct_looking = ClickRow {
        referrer: Some("direct".into()),
        ..row(today)
    };
    store
        .flush_clicks(&[(direct_looking.clone(), 1), (direct_looking, 1)], &[])
        .await
        .unwrap();
    // Re-flushing the same visitor is idempotent; counts add up.
    store
        .flush_clicks(&[(row(today), 1)], &[(link.id, today, [1; 16])])
        .await
        .unwrap();
    store.maintain_visitors(today).await.unwrap();
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM visitor_daily")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(live, 1, "only today's hash remains");
    let salts: Vec<chrono::NaiveDate> =
        sqlx::query_scalar("SELECT day FROM visitor_salts ORDER BY day")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(salts, vec![relink_server::store::day_to_date(today)]);
    assert_eq!(
        store.salt_for_day(old_day, today).await.unwrap(),
        None,
        "a destroyed salt is never recreated"
    );
    let from = relink_server::store::day_to_date(old_day);
    let to = relink_server::store::day_to_date(today);
    let alice = store.tenant(link.workspace_id);
    let stats = alice.stats(&link.code, from, to).await.unwrap();
    assert_eq!(stats.total_clicks, 8);
    assert_eq!(stats.days.len(), 2);
    assert_eq!(stats.days[0].unique_visitors, 2, "rolled up");
    assert_eq!(stats.days[1].unique_visitors, 1);
    assert_eq!(stats.referrers[0].value, "(direct)");
    // Clicks for a deleted link are skipped, not an error.
    alice.delete_link(&link.code).await.unwrap();
    store
        .flush_clicks(&[(row(today), 1)], &[(link.id, today, [9; 16])])
        .await
        .unwrap();
}

#[tokio::test]
async fn health_targets_are_claimed_once_and_updates_are_guarded() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    for _ in 0..10 {
        common::insert_link(&store, &new_link(None, None), 7)
            .await
            .unwrap();
    }
    let interval = std::time::Duration::from_secs(60);
    let (a, b) = tokio::join!(
        store.claim_health_targets(interval, 6),
        store.claim_health_targets(interval, 6)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.len() + b.len(), 10);
    let ids: HashSet<i64> = a.iter().chain(&b).map(|t| t.id).collect();
    assert_eq!(ids.len(), 10, "no link claimed twice");
    assert!(
        store
            .claim_health_targets(interval, 6)
            .await
            .unwrap()
            .is_empty()
    );

    let target: HealthTarget = a[0].clone();
    assert!(store.record_health(&target, &[1]).await.unwrap());
    // Destinations changed after the claim: the stale result is dropped.
    let code = target.code.clone();
    let alice = store.tenant(store.personal_workspace("alice").await.unwrap());
    alice
        .update_link(
            &code,
            &relink_server::store::LinkPatch {
                destinations: Some(vec![Destination {
                    url: "https://example.org/".into(),
                    weight: 1,
                }]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!store.record_health(&target, &[5]).await.unwrap());
    let link = alice.link(&code).await.unwrap();
    assert_eq!(
        link.unhealthy,
        vec![false],
        "failures were reset by the change"
    );
}

#[tokio::test]
async fn api_keys_hash_lookup_and_revocation() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let key = relink_server::auth::generate_key();
    let hash = relink_server::auth::hash_key(&key);
    let id = store.insert_api_key("alice", "ci", &hash).await.unwrap();
    let found = store.api_key_by_hash(&hash).await.unwrap().unwrap();
    assert_eq!(
        (found.id, found.owner.as_str(), found.hash.as_slice()),
        (id, "alice", &hash[..])
    );
    assert_eq!(
        found.workspace_id,
        store.personal_workspace("alice").await.unwrap()
    );
    assert!(store.revoke_api_key(id).await.unwrap());
    assert!(store.api_key_by_hash(&hash).await.unwrap().is_none());
    // The owner format is enforced by the database too.
    assert!(matches!(
        store.insert_api_key("Not Valid", "", &[0; 32]).await,
        Err(DbError::Other(_))
    ));
}

#[tokio::test]
async fn malformed_rows_are_errors_not_panics() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = common::insert_link(&store, &new_link(Some("bad-weight"), None), 7)
        .await
        .unwrap();
    // The schema refuses an empty destination list outright.
    let empty = sqlx::query("UPDATE links SET destinations = '[]' WHERE id = $1")
        .bind(link.id)
        .execute(store.pool())
        .await;
    assert!(empty.is_err());
    // A zero weight gets past the schema but is refused when read.
    sqlx::query(r#"UPDATE links SET destinations = '[{"url":"https://example.com/","weight":0}]' WHERE id = $1"#)
        .bind(link.id)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.link_by_code("bad-weight").await,
        Err(DbError::Other(_))
    ));
}

fn click(link_id: i64, day: i32, referrer: Option<&str>, fingerprint: [u8; 16]) -> ClickEvent {
    ClickEvent {
        link_id,
        day,
        country: *b"DE",
        device: Device::Mobile,
        referrer: referrer.map(Into::into),
        fingerprint,
    }
}

fn flush_cfg() -> FlushConfig {
    FlushConfig {
        interval: Duration::from_millis(50),
        batch: 1000,
        max_backlog: 1_000_000,
        max_backoff: Duration::from_secs(1),
    }
}

async fn sum_clicks(store: &Db, link_id: i64) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(clicks), 0)::bigint FROM click_daily WHERE link_id = $1",
    )
    .bind(link_id)
    .fetch_one(store.pool())
    .await
    .unwrap()
}

/// A large backlog (100,000 count rows and 100,000 visitors, as after a long
/// outage) is written in chunks that each fit the 2 s query timeout.
#[tokio::test]
async fn a_large_backlog_flushes_in_chunks() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, &[("RELINK_DB_TIMEOUT_MS", "2000")])).unwrap();
    migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    let link = common::insert_link(&store, &new_link(None, None), 7)
        .await
        .unwrap();
    let today = utc_day(now_ms());
    let metrics = Arc::new(Metrics::default());
    let mut f = Flusher::new(Arc::new(store.clone()), metrics.clone(), flush_cfg());
    for i in 0..100_000u32 {
        let mut fp = [0u8; 16];
        fp[..4].copy_from_slice(&i.to_be_bytes());
        let referrer = format!("r{i}.example.org");
        f.absorb(click(link.id, today, Some(&referrer), fp));
    }
    assert_eq!(f.backlog(), 200_000);
    let started = std::time::Instant::now();
    assert!(f.flush().await, "the backlog must drain");
    assert_eq!(f.backlog(), 0);
    assert!(
        metrics.flushes.get() >= 20,
        "written in chunks of {FLUSH_CHUNK}"
    );
    assert_eq!(sum_clicks(&store, link.id).await, 100_000);
    let visitors: i64 = sqlx::query_scalar("SELECT count(*) FROM visitor_daily WHERE link_id = $1")
        .bind(link.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(visitors, 100_000);
    eprintln!("flushed 100k+100k rows in {:?}", started.elapsed());
}

/// Clicks whose day's salt is already gone keep their counts but lose their
/// visitor hashes, and no salt is recreated for that day. A referrer host
/// spelled like the "no referrer" marker and a missing referrer in the same
/// batch do not collide.
#[tokio::test]
async fn late_clicks_and_lookalike_referrers_against_postgres() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = common::insert_link(&store, &new_link(None, None), 7)
        .await
        .unwrap();
    let today = utc_day(now_ms());
    let metrics = Arc::new(Metrics::default());
    let mut f = Flusher::new(Arc::new(store.clone()), metrics.clone(), flush_cfg());
    f.absorb(click(link.id, today - 3, None, [1; 16]));
    f.absorb(click(link.id, today - 3, None, [2; 16]));
    f.absorb(click(link.id, today, None, [3; 16]));
    f.absorb(click(link.id, today, Some("direct"), [4; 16]));
    assert!(f.flush().await);
    assert_eq!(sum_clicks(&store, link.id).await, 4);
    assert_eq!(metrics.late_visitors.get(), 2);
    let salt_days: Vec<chrono::NaiveDate> = sqlx::query_scalar("SELECT day FROM visitor_salts")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(salt_days, vec![relink_server::store::day_to_date(today)]);
    let referrers: Vec<String> = sqlx::query_scalar(
        "SELECT referrer_host FROM click_daily WHERE link_id = $1 AND day = $2 ORDER BY 1",
    )
    .bind(link.id)
    .bind(relink_server::store::day_to_date(today))
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(referrers, vec!["(direct)", "direct"]);
}

/// A click flush holds a key-share lock on every link it counts (the foreign
/// key from click_daily). Health claims and lease reservations must not skip
/// or queue behind it, or the busiest links are the ones never checked.
#[tokio::test]
async fn claims_and_leases_are_not_blocked_by_a_click_flush() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let link = common::insert_link(&store, &new_link(None, Some(100)), 7)
        .await
        .unwrap();
    let today = utc_day(now_ms());
    let mut flush = store.pool().begin().await.unwrap();
    sqlx::query(
        "INSERT INTO click_daily (link_id, day, country, device, referrer_host, clicks)
         VALUES ($1, $2, 'DE', 'mobile', '(direct)', 1)",
    )
    .bind(link.id)
    .bind(relink_server::store::day_to_date(today))
    .execute(&mut *flush)
    .await
    .unwrap();
    let claimed = store
        .claim_health_targets(Duration::from_secs(60), 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "a link being counted is still claimed");
    // Blocked behind the flush, this would hit the statement timeout and
    // fail; a wall-clock limit here would only measure how slow the build is.
    let granted = store.reserve_clicks(link.id, 10).await;
    assert!(
        matches!(granted, Ok(n) if n > 0),
        "a reservation does not wait for the flush: {granted:?}"
    );
    flush.commit().await.unwrap();
}

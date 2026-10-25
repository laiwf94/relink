//! Failure injection: the database disappears (all connections cut, new ones
//! refused) and comes back. Redirects keep working from memory, writes fail
//! cleanly with 503, clicks are buffered and written after recovery.

mod common;

use std::time::{Duration, Instant};

use common::{Harness, admin_url, eventually, metric};
use reqwest::Method;
use serde_json::json;

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redirects_survive_a_database_outage() {
    let mut h = harness!(
        ("RELINK_DB_TIMEOUT_MS", "1000"),
        ("RELINK_CACHE_TTL_MS", "200"),
        ("RELINK_CACHE_SWR_MS", "0"),
        ("RELINK_CACHE_STALE_IF_ERROR_MS", "3600000")
    );
    let warm = h.create(json!({"url": "https://example.com/warm"})).await;
    let warm = warm["code"].as_str().unwrap().to_owned();
    let cold = h.create(json!({"url": "https://example.com/cold"})).await;
    let cold = cold["code"].as_str().unwrap().to_owned();
    assert_eq!(h.visit(&warm, &[]).await.status(), 302);

    h.proxy.cut();
    // Past the TTL: the entry is expired, the refresh fails, the stale
    // entry is served.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..5 {
        let r = h.visit(&warm, &[]).await;
        assert_eq!(r.status(), 302);
        assert_eq!(r.headers()["location"], "https://example.com/warm");
    }
    // Not cached: nothing to serve.
    let r = h.visit(&cold, &[]).await;
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "5");

    // Writes fail fast and cleanly.
    let started = Instant::now();
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.com/"})),
        )
        .await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["error"]["code"], "unavailable");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "took {:?}",
        started.elapsed()
    );
    let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(status, 503);
    let (status, _) = h
        .api(
            Method::GET,
            "/v1/links",
            &relink_server::auth::generate_key(),
            None,
        )
        .await;
    assert_eq!(status, 503, "an unknown key cannot be checked either");

    // Still ready: cached redirects are being served.
    let ready: serde_json::Value = serde_json::from_str(
        &h.http
            .get(format!("{}/readyz", h.base))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ready, json!({"status": "ready", "database": "down"}));

    let m = h.metrics().await;
    assert!(metric(&m, "relink_cache_requests_total{result=\"stale_on_error\"}") >= 5.0);
    assert!(metric(&m, "relink_db_errors_total{op=\"lookup\"}") >= 1.0);
    assert!(metric(&m, "relink_redirects_total{outcome=\"unavailable\"}") >= 1.0);

    // Recovery: clicks taken during the outage reach the database, writes
    // work again and the change feed reconnects.
    h.proxy.restore();
    let app = h.app().clone();
    let path = format!("/v1/links/{warm}/stats");
    let flushed = eventually(Duration::from_secs(15), || async {
        let (status, s) = h.api(Method::GET, &path, &h.alice, None).await;
        status == 200 && s["total_clicks"] == 6
    })
    .await;
    assert!(flushed, "outage clicks were not written after recovery");
    // Within one breaker cool-down of the last failure, uncached codes work again.
    assert!(
        eventually(relink_server::resolver::BREAKER_COOLDOWN * 3, || async {
            h.visit(&cold, &[]).await.status() == 302
        })
        .await
    );
    h.create(json!({"url": "https://example.com/after"})).await;
    assert!(
        eventually(Duration::from_secs(10), || async {
            app.change_feed.load(std::sync::atomic::Ordering::Acquire)
        })
        .await
    );
    h.shutdown().await;
}

#[tokio::test]
async fn max_clicks_fail_closed_when_the_lease_runs_out() {
    let mut h = harness!(("RELINK_LEASE_MAX", "5"), ("RELINK_DB_TIMEOUT_MS", "1000"));
    let l = h
        .create(json!({"url": "https://example.com/", "max_clicks": 1000}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    assert_eq!(h.visit(&code, &[]).await.status(), 302); // takes a lease of 5
    h.proxy.cut();
    for _ in 0..4 {
        assert_eq!(
            h.visit(&code, &[]).await.status(),
            302,
            "spends the local lease"
        );
    }
    assert_eq!(
        h.visit(&code, &[]).await.status(),
        503,
        "no lease, no database: refuse"
    );
    h.proxy.restore();
    assert!(
        eventually(Duration::from_secs(10), || async {
            h.visit(&code, &[]).await.status() == 302
        })
        .await
    );
    h.shutdown().await;
}

#[tokio::test]
async fn shutdown_flushes_queued_clicks() {
    let mut h = harness!(("RELINK_CLICK_FLUSH_MS", "60000"));
    let l = h.create(json!({"url": "https://example.com/"})).await;
    let code = l["code"].as_str().unwrap().to_owned();
    for _ in 0..25 {
        assert_eq!(h.visit(&code, &[]).await.status(), 302);
    }
    let store = h.store.clone();
    h.shutdown().await;
    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(clicks), 0)::bigint FROM click_daily c JOIN links l ON l.id = c.link_id WHERE l.code = $1",
    )
    .bind(&code)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(total, 25);
}

#[tokio::test]
async fn startup_waits_for_the_database_then_gives_up() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let proxy = common::ChaosProxy::start(common::pg_addr(&admin)).await;
    proxy.cut();
    let cfg = common::config(&db.url_via(proxy.addr), &[]);
    let store = relink_server::server::open_db(&cfg).unwrap();
    let started = Instant::now();
    let err = relink_server::server::migrate_with_retry(&store, Duration::from_millis(800))
        .await
        .unwrap_err();
    assert!(err.contains("migrations failed"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // And succeeds once the database is reachable.
    proxy.restore();
    relink_server::server::migrate_with_retry(&store, Duration::from_secs(5))
        .await
        .unwrap();
}

/// With the database gone at shutdown, every phase (drain, click flush,
/// lease return) shares one deadline, so shutdown takes about
/// RELINK_SHUTDOWN_TIMEOUT_S rather than a multiple of it.
#[tokio::test]
async fn shutdown_with_the_database_down_respects_one_deadline() {
    let mut h = harness!(
        ("RELINK_SHUTDOWN_TIMEOUT_S", "2"),
        ("RELINK_DB_TIMEOUT_MS", "500"),
        ("RELINK_LEASE_MAX", "50")
    );
    let l = h
        .create(json!({"url": "https://example.com/", "max_clicks": 1000}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    assert_eq!(h.visit(&code, &[]).await.status(), 302);
    h.proxy.cut();
    assert_eq!(
        h.visit(&code, &[]).await.status(),
        302,
        "spends the local lease"
    );
    let app = h.app().clone();
    let started = Instant::now();
    h.shutdown().await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(2_900),
        "shutdown took {took:?}"
    );
    assert!(
        app.metrics
            .dropped_count(relink_server::metrics::DropReason::Closed)
            >= 1,
        "clicks that could not be written are counted, not silently lost"
    );
}

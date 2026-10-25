//! Destination health checks against real local HTTP servers, including the
//! SSRF defences.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use common::{Harness, admin_url, eventually};
use relink_server::config::HealthConfig;
use relink_server::health::HealthWorker;
use relink_server::metrics::{Metrics, ProbeResult};
use reqwest::Method;
use serde_json::json;

/// A destination server whose status code can be changed at runtime.
async fn destination(status: Arc<AtomicU16>) -> SocketAddr {
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let s = status.load(Ordering::SeqCst);
                async move { StatusCode::from_u16(s).unwrap() }
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                "late"
            }),
        )
        .route(
            "/to-metadata",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "http://169.254.169.254/latest/meta-data/")],
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn health_cfg() -> HealthConfig {
    HealthConfig {
        enabled: true,
        interval: Duration::from_secs(1),
        concurrency: 4,
        per_host_rps: 1000.0,
        timeout: Duration::from_millis(300),
        failure_threshold: 2,
        batch: 100,
    }
}

async fn due_again(h: &Harness) {
    sqlx::query("UPDATE links SET health_checked_at = NULL")
        .execute(h.store.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn unhealthy_destinations_fail_over_and_recover() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1"),
            ("RELINK_HEALTH_FAILURE_THRESHOLD", "2"),
        ],
    )
    .await;
    let status = Arc::new(AtomicU16::new(200));
    let dest = destination(status.clone()).await;
    let l = h
        .create(
            json!({"url": format!("http://{dest}/"), "health_check": true,
                       "fallback_url": "https://example.com/fallback"}),
        )
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    let metrics = Arc::new(Metrics::default());
    let worker = HealthWorker::new(h.store.clone(), health_cfg(), true, metrics.clone()).unwrap();

    assert_eq!(worker.round().await, 1);
    assert_eq!(worker.round().await, 0, "not due again within the interval");
    assert_eq!(
        h.visit(&code, &[]).await.headers()["location"],
        format!("http://{dest}/").as_str()
    );

    status.store(503, Ordering::SeqCst);
    due_again(&h).await;
    worker.round().await;
    // One failure is below the threshold.
    assert_eq!(
        h.visit(&code, &[]).await.headers()["location"],
        format!("http://{dest}/").as_str()
    );
    due_again(&h).await;
    worker.round().await;
    let failed_over = eventually(Duration::from_secs(5), || async {
        h.visit(&code, &[]).await.headers()["location"] == "https://example.com/fallback"
    })
    .await;
    assert!(
        failed_over,
        "the change notification should switch traffic to the fallback"
    );
    let (_, view) = h
        .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(view["destinations"][0]["healthy"], false);

    status.store(200, Ordering::SeqCst);
    due_again(&h).await;
    worker.round().await;
    let recovered = eventually(Duration::from_secs(5), || async {
        h.visit(&code, &[]).await.headers()["location"] == format!("http://{dest}/").as_str()
    })
    .await;
    assert!(recovered);
    assert!(metrics.probe_count(ProbeResult::Unhealthy) >= 2);
    assert!(metrics.probe_count(ProbeResult::Healthy) >= 2);
    h.shutdown().await;
}

#[tokio::test]
async fn ab_traffic_avoids_the_unhealthy_variant() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1"),
            ("RELINK_HEALTH_FAILURE_THRESHOLD", "1"),
        ],
    )
    .await;
    let good = destination(Arc::new(AtomicU16::new(204))).await;
    let bad = destination(Arc::new(AtomicU16::new(404))).await;
    let l = h
        // Different host names: probes are rate limited per host.
        .create(json!({"destinations": [{"url": format!("http://{good}/")},
                                        {"url": format!("http://localhost:{}/", bad.port())}],
                       "health_check": true}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    let worker = HealthWorker::new(
        h.store.clone(),
        health_cfg(),
        true,
        Arc::new(Metrics::default()),
    )
    .unwrap();
    worker.round().await;
    let only_good = eventually(Duration::from_secs(5), || async {
        let mut all = true;
        for _ in 0..20 {
            all &= h.visit(&code, &[]).await.headers()["location"]
                == format!("http://{good}/").as_str();
        }
        all
    })
    .await;
    assert!(only_good);
    h.shutdown().await;
}

#[tokio::test]
async fn probes_refuse_private_addresses_and_do_not_follow_redirects() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(&admin, &[("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1")]).await;
    let ok = destination(Arc::new(AtomicU16::new(200))).await;
    let metrics = Arc::new(Metrics::default());
    let strict = HealthWorker::new(h.store.clone(), health_cfg(), false, metrics.clone()).unwrap();
    for url in [
        format!("http://{ok}/"),
        format!("http://localhost:{}/", ok.port()),
        "http://[::1]/".to_owned(),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "http://10.0.0.1/".to_owned(),
    ] {
        assert_eq!(strict.probe(&url).await, ProbeResult::Blocked, "{url}");
    }
    let open = HealthWorker::new(h.store.clone(), health_cfg(), true, metrics).unwrap();
    assert_eq!(
        open.probe(&format!("http://{ok}/")).await,
        ProbeResult::Healthy
    );
    // A redirect to the metadata service is reported, never followed.
    assert_eq!(
        open.probe(&format!("http://{ok}/to-metadata")).await,
        ProbeResult::Healthy
    );
    assert_eq!(
        open.probe(&format!("http://{ok}/slow")).await,
        ProbeResult::Unhealthy
    );
    assert_eq!(
        open.probe("http://127.0.0.1:1/").await,
        ProbeResult::Unhealthy
    );
    assert_eq!(open.probe("not a url").await, ProbeResult::Unhealthy);

    // A stored private destination (allowed when it was created) counts as
    // failing under the strict worker.
    let l = h
        .create(json!({"url": format!("http://{ok}/"), "health_check": true}))
        .await;
    strict.round().await;
    let failures: Vec<i16> =
        sqlx::query_scalar("SELECT health_failures FROM links WHERE code = $1")
            .bind(l["code"].as_str().unwrap())
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(failures, vec![1]);
    h.shutdown().await;
}

#[tokio::test]
async fn probes_to_one_host_are_paced() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(&admin, &[("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1")]).await;
    let dest = destination(Arc::new(AtomicU16::new(200))).await;
    for i in 0..3 {
        h.create(json!({"url": format!("http://{dest}/?n={i}"), "health_check": true}))
            .await;
    }
    let metrics = Arc::new(Metrics::default());
    let cfg = HealthConfig {
        per_host_rps: 0.01,
        ..health_cfg()
    };
    let worker = HealthWorker::new(h.store.clone(), cfg, true, metrics.clone()).unwrap();
    assert_eq!(worker.round().await, 3);
    assert_eq!(metrics.probe_count(ProbeResult::Healthy), 1);
    assert_eq!(
        metrics.probe_count(ProbeResult::RateLimited),
        2,
        "a queue longer than the interval waits for a later round"
    );

    // At 10 per second the same three destinations are all probed, spaced
    // 100 ms apart.
    sqlx::query("UPDATE links SET health_checked_at = NULL")
        .execute(h.store.pool())
        .await
        .unwrap();
    let metrics = Arc::new(Metrics::default());
    let cfg = HealthConfig {
        per_host_rps: 10.0,
        ..health_cfg()
    };
    let worker = HealthWorker::new(h.store.clone(), cfg, true, metrics.clone()).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(worker.round().await, 3);
    assert_eq!(metrics.probe_count(ProbeResult::Healthy), 3);
    assert_eq!(metrics.probe_count(ProbeResult::RateLimited), 0);
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "{:?}",
        started.elapsed()
    );
    h.shutdown().await;
}

#[tokio::test]
async fn worker_runs_in_the_server_and_stops_on_shutdown() {
    let Some(admin) = admin_url() else { return };
    let status = Arc::new(AtomicU16::new(500));
    let dest = destination(status).await;
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "1"),
            ("RELINK_HEALTH_ENABLED", "true"),
            ("RELINK_HEALTH_INTERVAL_S", "1"),
            ("RELINK_HEALTH_FAILURE_THRESHOLD", "1"),
            ("RELINK_HEALTH_TIMEOUT_MS", "500"),
        ],
    )
    .await;
    let l = h
        .create(json!({"url": format!("http://{dest}/"), "health_check": true}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    let marked = eventually(Duration::from_secs(10), || async {
        let (_, v) = h
            .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
            .await;
        v["destinations"][0]["healthy"] == false
    })
    .await;
    assert!(
        marked,
        "the background worker should mark the destination unhealthy"
    );
    h.shutdown().await;
}

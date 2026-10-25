//! Publishing link records to KV, against a local fake of the Cloudflare KV
//! REST API (no account, no network).

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, put};
use common::{Harness, admin_url, config, eventually};
use relink_server::config::KvConfig;
use relink_server::kvsync::{CloudflareKv, KvSync};
use relink_server::metrics::Metrics;
use relink_server::model::Link;
use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::Notify;

const TOKEN: &str = "kv-api-token-for-tests";

#[derive(Default)]
struct FakeKv {
    values: Mutex<BTreeMap<String, String>>,
    down: AtomicBool,
    unauthorized: AtomicUsize,
}

type Shared = Arc<FakeKv>;

fn authorized(kv: &FakeKv, headers: &HeaderMap, account: &str, ns: &str) -> Result<(), StatusCode> {
    if kv.down.load(Ordering::SeqCst) {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let ok = headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"))
        && account == "acct1"
        && ns == "ns1";
    if !ok {
        kv.unauthorized.fetch_add(1, Ordering::SeqCst);
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn put_value(
    State(kv): State<Shared>,
    Path((account, ns, key)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    if let Err(s) = authorized(&kv, &headers, &account, &ns) {
        return s;
    }
    kv.values.lock().unwrap().insert(key, body);
    StatusCode::OK
}

async fn delete_value(
    State(kv): State<Shared>,
    Path((account, ns, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> StatusCode {
    if let Err(s) = authorized(&kv, &headers, &account, &ns) {
        return s;
    }
    match kv.values.lock().unwrap().remove(&key) {
        Some(_) => StatusCode::OK,
        None => StatusCode::NOT_FOUND,
    }
}

async fn list_keys(
    State(kv): State<Shared>,
    Path((account, ns)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    authorized(&kv, &headers, &account, &ns)?;
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let cursor = q.get("cursor").cloned();
    // Two keys per page, so the client's cursor handling is exercised.
    let values = kv.values.lock().unwrap();
    let keys: Vec<String> = values
        .keys()
        .filter(|k| k.starts_with(&prefix) && cursor.as_ref().is_none_or(|c| k > &c))
        .take(2)
        .cloned()
        .collect();
    let next = if keys.len() == 2 {
        keys[1].clone()
    } else {
        String::new()
    };
    let body = json!({
        "success": true,
        "result": keys.iter().map(|k| json!({"name": k})).collect::<Vec<_>>(),
        "result_info": {"cursor": next}
    });
    Ok(axum::response::IntoResponse::into_response(
        body.to_string(),
    ))
}

async fn fake_kv() -> (SocketAddr, Shared) {
    let kv: Shared = Arc::default();
    let app = Router::new()
        .route(
            "/client/v4/accounts/{account}/storage/kv/namespaces/{ns}/values/{key}",
            put(put_value).delete(delete_value),
        )
        .route(
            "/client/v4/accounts/{account}/storage/kv/namespaces/{ns}/keys",
            get(list_keys),
        )
        .with_state(kv.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, kv)
}

fn record(kv: &FakeKv, code: &str) -> Option<Link> {
    kv.values
        .lock()
        .unwrap()
        .get(&format!("link:{code}"))
        .map(|v| serde_json::from_str(v).unwrap())
}

#[tokio::test]
async fn changes_reach_kv_and_failures_are_retried() {
    let Some(admin) = admin_url() else { return };
    let (addr, kv) = fake_kv().await;
    let base = format!("http://{addr}/client/v4");
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_KV_ACCOUNT_ID", "acct1"),
            ("RELINK_KV_NAMESPACE_ID", "ns1"),
            ("RELINK_KV_API_TOKEN", TOKEN),
            ("RELINK_KV_API_BASE", &base),
            ("RELINK_KV_POLL_MS", "50"),
        ],
    )
    .await;
    let l = h
        .create(json!({"url": "https://example.com/one", "alias": "edge-one"}))
        .await;
    assert_eq!(l["code"], "edge-one");
    assert!(
        eventually(Duration::from_secs(5), || async {
            record(&kv, "edge-one").is_some()
        })
        .await,
        "create must publish the record"
    );
    let published = record(&kv, "edge-one").unwrap();
    assert_eq!(published.destinations[0].url, "https://example.com/one");
    assert!(published.enabled);

    // Disable while KV is failing: nothing is lost, the write lands later.
    kv.down.store(true, Ordering::SeqCst);
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/links/edge-one",
            &h.alice,
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(record(&kv, "edge-one").unwrap().enabled, "KV is down");
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM kv_outbox")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(pending, 1);
    kv.down.store(false, Ordering::SeqCst);
    // The first retry backs off for a second or two.
    assert!(
        eventually(Duration::from_secs(10), || async {
            record(&kv, "edge-one").is_some_and(|l| !l.enabled)
        })
        .await,
        "the retry must publish the disable"
    );

    let (status, _) = h
        .api(Method::DELETE, "/v1/links/edge-one", &h.alice, None)
        .await;
    assert_eq!(status, 204);
    assert!(
        eventually(Duration::from_secs(5), || async {
            record(&kv, "edge-one").is_none()
        })
        .await,
        "delete must remove the record"
    );
    assert!(
        eventually(Duration::from_secs(5), || async {
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kv_outbox")
                .fetch_one(h.store.pool())
                .await
                .unwrap();
            n == 0
        })
        .await
    );
    assert_eq!(kv.unauthorized.load(Ordering::SeqCst), 0);
    let m = h.metrics().await;
    assert!(m.contains("relink_kv_writes_total 2"), "{m}");
    assert!(m.contains("relink_kv_deletes_total 1"));
    h.shutdown().await;
}

#[tokio::test]
async fn reconciliation_repairs_drift() {
    let Some(admin) = admin_url() else { return };
    let (addr, kv) = fake_kv().await;
    let db = common::TestDb::create(&admin).await;
    let cfg = config(
        &db.url,
        &[
            ("RELINK_KV_ACCOUNT_ID", "acct1"),
            ("RELINK_KV_NAMESPACE_ID", "ns1"),
            ("RELINK_KV_API_TOKEN", TOKEN),
            ("RELINK_KV_API_BASE", &format!("http://{addr}/client/v4")),
        ],
    );
    let store = relink_server::server::open_db(&cfg).unwrap();
    relink_server::server::migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    for alias in ["keep-a", "keep-b", "keep-c", "missing-d"] {
        store
            .insert_link(
                &relink_server::store::NewLink {
                    owner: "alice".into(),
                    alias: Some(alias.into()),
                    destinations: vec![relink_server::model::Destination {
                        url: "https://example.com/".into(),
                        weight: 1,
                    }],
                    redirect_status: 302,
                    expires_at: None,
                    max_clicks: None,
                    geo: None,
                    fallback_url: None,
                    enabled: true,
                    health_check: false,
                },
                7,
            )
            .await
            .unwrap();
    }
    let kv_cfg: KvConfig = cfg.kv.clone().unwrap();
    let metrics = Arc::new(Metrics::default());
    let sync = KvSync::new(
        store.clone(),
        Arc::new(CloudflareKv::new(&kv_cfg).unwrap()),
        metrics.clone(),
        Duration::from_millis(50),
        Duration::from_secs(60),
        Arc::new(Notify::new()),
    );
    assert_eq!(sync.round().await, 4);
    // Someone deletes a key by hand and leaves a stray one behind.
    kv.values.lock().unwrap().remove("link:missing-d");
    kv.values
        .lock()
        .unwrap()
        .insert("link:stray".into(), "{}".into());
    assert_eq!(sync.reconcile_once().await.unwrap(), 2);
    assert_eq!(sync.round().await, 2);
    let keys: Vec<String> = kv.values.lock().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "link:keep-a",
            "link:keep-b",
            "link:keep-c",
            "link:missing-d"
        ]
    );
    assert_eq!(
        sync.reconcile_once().await.unwrap(),
        0,
        "nothing left to repair"
    );
    let raw: Value = serde_json::from_str(&kv.values.lock().unwrap()["link:keep-a"]).unwrap();
    assert_eq!(raw["code"], "keep-a");
    assert!(raw.get("owner").is_none(), "owners stay in the database");
}

#![allow(dead_code)]

//! A local fake of the Cloudflare KV REST API and of a zone's custom
//! hostnames API (no account, no network), for the KV sync tests and the
//! week 2 end-to-end test.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, put};
use serde_json::{Value, json};

pub const TOKEN: &str = "kv-api-token-for-tests";

/// Account `acct1`, namespace `ns1` and zone `zone1`, all behind the
/// bearer token [`TOKEN`]; switches make each API fail.
#[derive(Default)]
pub struct FakeKv {
    pub values: Mutex<BTreeMap<String, String>>,
    pub down: AtomicBool,
    pub unauthorized: AtomicUsize,
    /// Custom hostnames of zone `zone1`, by ID.
    pub hostnames: Mutex<BTreeMap<String, String>>,
    pub next_hostname: AtomicUsize,
    pub hostnames_down: AtomicBool,
}

pub type Shared = Arc<FakeKv>;

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

fn zone_authorized(kv: &FakeKv, headers: &HeaderMap, zone: &str) -> Result<(), StatusCode> {
    if kv.hostnames_down.load(Ordering::SeqCst) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    authorized(kv, headers, "acct1", "ns1")?;
    if zone != "zone1" {
        kv.unauthorized.fetch_add(1, Ordering::SeqCst);
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// Lists custom hostnames, filtered by a substring of `hostname` (looser
/// than equality, as the client must expect), two per page.
async fn list_hostnames(
    State(kv): State<Shared>,
    Path(zone): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    zone_authorized(&kv, &headers, &zone)?;
    let per_page: usize = q.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(50);
    assert_eq!(per_page, 50, "the client asks for full pages");
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let all: Vec<(String, String)> = kv
        .hostnames
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, h)| q.get("hostname").is_none_or(|f| h.contains(f.as_str())))
        .map(|(id, h)| (id.clone(), h.clone()))
        .collect();
    // Pages of two, so paging is exercised; the client must not stop at a
    // short page count alone.
    let pages = all.len().div_ceil(2).max(1);
    let result: Vec<Value> = all
        .iter()
        .skip((page - 1) * 2)
        .take(2)
        .map(|(id, h)| json!({"id": id, "hostname": h, "ssl": {"status": "pending_validation"}}))
        .collect();
    let body = json!({"success": true, "result": result,
                      "result_info": {"page": page, "per_page": 2, "total_pages": pages}});
    Ok(axum::response::IntoResponse::into_response(
        body.to_string(),
    ))
}

async fn create_hostname(
    State(kv): State<Shared>,
    Path(zone): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Result<axum::response::Response, StatusCode> {
    zone_authorized(&kv, &headers, &zone)?;
    let body: Value = serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    assert_eq!(body["ssl"]["method"], "http");
    let host = body["hostname"].as_str().unwrap().to_owned();
    let mut all = kv.hostnames.lock().unwrap();
    if all.values().any(|h| *h == host) {
        return Err(StatusCode::CONFLICT);
    }
    let id = format!("ch-{}", kv.next_hostname.fetch_add(1, Ordering::SeqCst));
    all.insert(id.clone(), host.clone());
    let body = json!({"success": true, "result": {"id": id, "hostname": host}});
    Ok(axum::response::IntoResponse::into_response(
        body.to_string(),
    ))
}

async fn delete_hostname(
    State(kv): State<Shared>,
    Path((zone, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> StatusCode {
    if let Err(s) = zone_authorized(&kv, &headers, &zone) {
        return s;
    }
    match kv.hostnames.lock().unwrap().remove(&id) {
        Some(_) => StatusCode::OK,
        None => StatusCode::NOT_FOUND,
    }
}

impl FakeKv {
    pub fn hostnames(&self) -> Vec<String> {
        let mut v: Vec<String> = self.hostnames.lock().unwrap().values().cloned().collect();
        v.sort();
        v
    }

    pub fn keys(&self) -> Vec<String> {
        self.values.lock().unwrap().keys().cloned().collect()
    }
}

/// Starts the fake on a local port: its `/client/v4` base and its state.
pub async fn fake_kv() -> (SocketAddr, Shared) {
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
        .route(
            "/client/v4/zones/{zone}/custom_hostnames",
            get(list_hostnames).post(create_hostname),
        )
        .route(
            "/client/v4/zones/{zone}/custom_hostnames/{id}",
            axum::routing::delete(delete_hostname),
        )
        .with_state(kv.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, kv)
}

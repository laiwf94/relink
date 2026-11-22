//! Webhooks end to end: endpoints registered through the API, events from
//! link changes, expiries and health checks, signed deliveries to a local
//! receiver, retries with backoff, the delivery log and manual retries,
//! workspace isolation, and two instances sharing the work.

mod common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use common::{Harness, admin_url, eventually, metric};
use relink_server::auth::{Scopes, generate_key, hash_key};
use relink_server::store::NewApiKey;
use relink_server::webhooks::{self, Claimed, verify};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::net::TcpListener;

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "true"),
            ("RELINK_WEBHOOK_POLL_MS", "20"),
            ("RELINK_WEBHOOK_RETRY_BASE_MS", "50"),
            ("RELINK_WEBHOOK_RETRY_MAX_MS", "200"),
            ("RELINK_WEBHOOK_TIMEOUT_MS", "2000"),
            $($extra),*
        ]).await
    }};
}

/// One request the receiver got.
#[derive(Clone, Debug)]
struct Received {
    headers: HashMap<String, String>,
    body: Bytes,
}

impl Received {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("no {name} header"))
    }
}

#[derive(Default)]
struct ReceiverState {
    got: Mutex<Vec<Received>>,
    /// Statuses to answer with, in order; 200 once they run out.
    script: Mutex<VecDeque<u16>>,
    /// Answer every request with this instead, when set.
    always: Mutex<Option<u16>>,
}

/// A webhook endpoint on loopback that records every request.
struct Receiver {
    url: String,
    state: Arc<ReceiverState>,
}

impl Receiver {
    async fn start() -> Receiver {
        let state = Arc::new(ReceiverState::default());
        let app = axum::Router::new()
            .route("/hook", post(receive))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Receiver {
            url: format!("http://{addr}/hook"),
            state,
        }
    }

    fn script(&self, statuses: &[u16]) {
        self.state.script.lock().unwrap().extend(statuses);
    }

    fn always(&self, status: Option<u16>) {
        *self.state.always.lock().unwrap() = status;
    }

    fn got(&self) -> Vec<Received> {
        self.state.got.lock().unwrap().clone()
    }

    /// Requests for `event`, in arrival order.
    fn of(&self, event: &str) -> Vec<Received> {
        self.got()
            .into_iter()
            .filter(|r| r.headers.get("relink-event").map(String::as_str) == Some(event))
            .collect()
    }

    async fn wait_for(&self, event: &str, n: usize) -> Vec<Received> {
        assert!(
            eventually(Duration::from_secs(10), || async {
                self.of(event).len() >= n
            })
            .await,
            "expected {n} {event} requests, got {:?}",
            self.of(event).len()
        );
        self.of(event)
    }
}

async fn receive(
    State(state): State<Arc<ReceiverState>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let headers = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    state.got.lock().unwrap().push(Received { headers, body });
    let status = match *state.always.lock().unwrap() {
        Some(s) => s,
        None => state.script.lock().unwrap().pop_front().unwrap_or(200),
    };
    (StatusCode::from_u16(status).unwrap(), "thanks")
}

async fn create_webhook(h: &Harness, key: &str, url: &str, events: &[&str]) -> Value {
    let (status, hook) = h
        .api(
            Method::POST,
            "/v1/webhooks",
            key,
            Some(json!({"url": url, "events": events, "description": "test endpoint"})),
        )
        .await;
    assert_eq!(status, 201, "{hook}");
    hook
}

/// Checks a request's signature with the endpoint's secret.
fn assert_signed(r: &Received, secret: &str) {
    let now = chrono::Utc::now().timestamp();
    verify(
        secret,
        r.header("relink-signature"),
        &r.body,
        now,
        Duration::from_secs(300),
    )
    .unwrap_or_else(|e| panic!("bad signature {e:?}: {:?}", r.headers));
}

#[tokio::test]
async fn link_events_are_signed_retried_and_logged() {
    let mut h = harness!();
    let rx = Receiver::start().await;
    let hook = create_webhook(
        &h,
        &h.alice,
        &rx.url,
        &["link.created", "link.updated", "link.updated"],
    )
    .await;
    let secret = hook["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("whsec_"));
    assert_eq!(hook["events"], json!(["link.created", "link.updated"]));
    assert_eq!(hook["enabled"], true);
    assert_eq!(hook["created_by"], "alice");
    let id = hook["id"].as_i64().unwrap();

    // The secret is shown once.
    let (status, got) = h
        .api(Method::GET, &format!("/v1/webhooks/{id}"), &h.alice, None)
        .await;
    assert_eq!(status, 200);
    assert!(got.get("secret").is_none(), "{got}");
    let (_, list) = h.api(Method::GET, "/v1/webhooks", &h.alice, None).await;
    assert_eq!(list["webhooks"].as_array().unwrap().len(), 1);
    assert!(list["webhooks"][0].get("secret").is_none());

    // The first try fails; the retry, after the backoff, gets through.
    rx.script(&[500]);
    let link = h
        .create(json!({"alias": "spring", "url": "https://example.com/a"}))
        .await;
    let tries = rx.wait_for("link.created", 2).await;
    for r in &tries {
        assert_signed(r, &secret);
        assert_eq!(r.header("content-type"), "application/json");
        assert!(r.header("user-agent").starts_with("relink-webhooks/"));
    }
    // A retry is the same event, byte for byte.
    assert_eq!(tries[0].body, tries[1].body);
    assert_eq!(
        tries[0].header("relink-event-id"),
        tries[1].header("relink-event-id")
    );
    let event = tries[1].json();
    assert_eq!(event["type"], "link.created");
    assert_eq!(event["id"], tries[1].header("relink-event-id"));
    assert!(event["id"].as_str().unwrap().starts_with("evt_"));
    assert_eq!(event["data"]["link"]["code"], "spring");
    assert_eq!(event["data"]["link"]["short_url"], link["short_url"]);
    assert_eq!(
        event["data"]["link"]["destinations"][0]["url"],
        "https://example.com/a"
    );
    let workspace = h.store.personal_workspace("alice").await.unwrap();
    assert_eq!(event["workspace_id"], workspace);

    // An update says what changed and what it was.
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/links/spring",
            &h.alice,
            Some(json!({"url": "https://example.com/b", "redirect_type": 301})),
        )
        .await;
    assert_eq!(status, 200);
    let updated = rx.wait_for("link.updated", 1).await;
    let data = &updated[0].json()["data"];
    assert_eq!(data["changed"], json!(["destinations", "redirect_type"]));
    assert_eq!(
        data["previous"]["destinations"][0]["url"],
        "https://example.com/a"
    );
    assert_eq!(data["previous"]["redirect_type"], 302);
    assert_eq!(data["link"]["redirect_type"], 301);
    // A patch that changes nothing sends nothing, and a rollback is an
    // update like any other.
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/links/spring",
            &h.alice,
            Some(json!({"redirect_type": 301})),
        )
        .await;
    assert_eq!(status, 200);
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links/spring/rollback",
            &h.alice,
            Some(json!({"version": 1})),
        )
        .await;
    assert_eq!(status, 200);
    let updated = rx.wait_for("link.updated", 2).await;
    assert_eq!(updated.len(), 2);
    assert_eq!(updated[1].json()["data"]["link"]["redirect_type"], 302);

    // The delivery log, newest first.
    let (status, log) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{log}");
    let deliveries = log["deliveries"].as_array().unwrap();
    assert_eq!(deliveries.len(), 3);
    assert_eq!(deliveries[2]["event"], "link.created");
    assert_eq!(deliveries[2]["state"], "delivered");
    assert_eq!(deliveries[2]["attempts"], 2);
    assert_eq!(deliveries[2]["last_status"], 200);
    assert_eq!(deliveries[2]["next_attempt_at"], Value::Null);
    assert!(deliveries[2]["delivered_at"].is_string());
    assert_eq!(log["next_cursor"], Value::Null);
    // Paged.
    let (_, page) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries?limit=2"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(page["deliveries"].as_array().unwrap().len(), 2);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let (_, rest) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries?limit=2&cursor={cursor}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(rest["deliveries"][0]["event"], "link.created");
    let (_, only) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries?state=failed"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(only["deliveries"], json!([]));

    // One delivery, with the payload sent and both tries.
    let delivery = deliveries[2]["id"].as_i64().unwrap();
    let (status, detail) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries/{delivery}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["payload"], event);
    let tries = detail["attempt_log"].as_array().unwrap();
    assert_eq!(tries.len(), 2);
    assert_eq!(tries[0]["attempt"], 1);
    assert_eq!(tries[0]["status"], 500);
    assert_eq!(tries[0]["response"], "thanks");
    assert_eq!(tries[1]["status"], 200);
    assert_eq!(tries[1]["error"], Value::Null);
    assert_eq!(
        rx.of("link.created")[0].header("relink-delivery"),
        delivery.to_string()
    );

    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_webhook_deliveries_total"), 3.0);
    assert_eq!(metric(&m, "relink_webhook_retries_total"), 1.0);
    assert_eq!(metric(&m, "relink_webhook_failures_total"), 0.0);

    // Bad requests.
    for (query, what) in [
        ("?state=lost", "state"),
        ("?limit=0", "limit"),
        ("?cursor=zz", "cursor"),
    ] {
        let (status, err) = h
            .api(
                Method::GET,
                &format!("/v1/webhooks/{id}/deliveries{query}"),
                &h.alice,
                None,
            )
            .await;
        assert_eq!(status, 400, "{query}");
        assert!(
            err["error"]["message"].as_str().unwrap().contains(what),
            "{err}"
        );
    }
    let (status, _) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries/999999"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 404);
    h.shutdown().await;
}

#[tokio::test]
async fn deliveries_fail_after_the_last_try_and_can_be_retried() {
    let mut h = harness!(("RELINK_WEBHOOK_MAX_ATTEMPTS", "3"));
    let rx = Receiver::start().await;
    let hook = create_webhook(&h, &h.alice, &rx.url, &["link.created"]).await;
    let id = hook["id"].as_i64().unwrap();
    rx.always(Some(503));
    h.create(json!({"url": "https://example.com/"})).await;
    rx.wait_for("link.created", 3).await;
    let failed = format!("/v1/webhooks/{id}/deliveries?state=failed");
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, log) = h.api(Method::GET, &failed, &h.alice, None).await;
            log["deliveries"].as_array().unwrap().len() == 1
        })
        .await
    );
    let (_, log) = h.api(Method::GET, &failed, &h.alice, None).await;
    let d = &log["deliveries"][0];
    assert_eq!(d["attempts"], 3);
    assert_eq!(d["last_status"], 503);
    assert_eq!(d["last_error"], "the endpoint answered 503");
    let delivery = d["id"].as_i64().unwrap();
    // No fourth try on its own.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(rx.of("link.created").len(), 3);
    assert_eq!(
        metric(&h.metrics().await, "relink_webhook_failures_total"),
        1.0
    );

    // A manual retry gets one more try, which now succeeds.
    rx.always(None);
    let retry = format!("/v1/webhooks/{id}/deliveries/{delivery}/retry");
    let (status, body) = h.api(Method::POST, &retry, &h.alice, None).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["state"], "pending");
    rx.wait_for("link.created", 4).await;
    let detail_path = format!("/v1/webhooks/{id}/deliveries/{delivery}");
    assert!(
        eventually(Duration::from_secs(5), || async {
            h.api(Method::GET, &detail_path, &h.alice, None).await.1["state"] == "delivered"
        })
        .await
    );
    let (_, detail) = h.api(Method::GET, &detail_path, &h.alice, None).await;
    assert_eq!(detail["attempts"], 4);
    assert_eq!(detail["attempt_log"].as_array().unwrap().len(), 4);
    // A delivered one is not sent again.
    let (status, _) = h.api(Method::POST, &retry, &h.alice, None).await;
    assert_eq!(status, 409);

    // A connection that fails is logged with why.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_url = format!("http://{}/hook", dead.local_addr().unwrap());
    drop(dead);
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            Some(json!({"url": dead_url})),
        )
        .await;
    assert_eq!(status, 200);
    h.create(json!({"url": "https://example.com/"})).await;
    let pending = format!("/v1/webhooks/{id}/deliveries?state=pending");
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, log) = h.api(Method::GET, &pending, &h.alice, None).await;
            log["deliveries"][0]["attempts"].as_i64().unwrap_or(0) >= 1
        })
        .await
    );
    let (_, log) = h.api(Method::GET, &pending, &h.alice, None).await;
    let d = &log["deliveries"][0];
    assert_eq!(d["last_status"], Value::Null);
    assert!(d["last_error"].as_str().unwrap().len() > 5, "{d}");
    let stuck = d["id"].as_i64().unwrap();

    // Disabling the endpoint fails what is pending, and it cannot be
    // retried until the endpoint is enabled again.
    let (status, off) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            Some(json!({"enabled": false, "url": rx.url})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(off["enabled"], false);
    let (_, detail) = h
        .api(
            Method::GET,
            &format!("/v1/webhooks/{id}/deliveries/{stuck}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(detail["state"], "failed");
    assert_eq!(detail["last_error"], "the endpoint was disabled");
    let retry = format!("/v1/webhooks/{id}/deliveries/{stuck}/retry");
    let (status, err) = h.api(Method::POST, &retry, &h.alice, None).await;
    assert_eq!(status, 409, "{err}");
    // A disabled endpoint gets no new events either.
    let before = rx.got().len();
    h.create(json!({"url": "https://example.com/"})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rx.got().len(), before);
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(status, 200);
    let (status, _) = h.api(Method::POST, &retry, &h.alice, None).await;
    assert_eq!(status, 202);
    assert!(eventually(Duration::from_secs(5), || async { rx.got().len() > before }).await);
    h.shutdown().await;
}

#[tokio::test]
async fn expiries_and_health_changes_are_announced_once() {
    let mut h = harness!();
    let rx = Receiver::start().await;
    let hook = create_webhook(&h, &h.alice, &rx.url, &["link.expired", "health.changed"]).await;
    let secret = hook["secret"].as_str().unwrap().to_owned();

    let soon = (chrono::Utc::now() + chrono::Duration::milliseconds(600)).to_rfc3339();
    h.create(json!({"alias": "flash", "url": "https://example.com/", "expires_at": soon}))
        .await;
    let expired = rx.wait_for("link.expired", 1).await;
    assert_signed(&expired[0], &secret);
    let event = expired[0].json();
    assert_eq!(event["data"]["link"]["code"], "flash");
    // Once per expiry.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rx.of("link.expired").len(), 1);
    // A new expiry is announced in its turn.
    let later = (chrono::Utc::now() + chrono::Duration::milliseconds(400)).to_rfc3339();
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/links/flash",
            &h.alice,
            Some(json!({"expires_at": later})),
        )
        .await;
    assert_eq!(status, 200);
    rx.wait_for("link.expired", 2).await;
    assert!(metric(&h.metrics().await, "relink_webhook_expiries_total") >= 2.0);
    // Nothing else was subscribed to.
    assert!(rx.of("link.created").is_empty() && rx.of("link.updated").is_empty());

    // Health: the second failure crosses the threshold (2) and flips the
    // destination; a third changes nothing; a success flips it back.
    h.create(json!({"alias": "probed", "health_check": true,
                     "destinations": [{"url": "https://example.com/a"},
                                      {"url": "https://example.com/b"}]}))
        .await;
    let claim = || h.store.claim_health_targets(Duration::ZERO, 10);
    let target = claim()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.code == "probed")
        .unwrap();
    assert!(h.store.record_health(&target, &[1, 0]).await.unwrap());
    let target = claim()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.code == "probed")
        .unwrap();
    assert!(h.store.record_health(&target, &[2, 0]).await.unwrap());
    let health = rx.wait_for("health.changed", 1).await;
    let data = &health[0].json()["data"];
    assert_eq!(
        data["destinations"],
        json!([{"index": 0, "url": "https://example.com/a", "healthy": false}])
    );
    assert_eq!(data["link"]["destinations"][0]["healthy"], false);
    assert_eq!(data["link"]["destinations"][1]["healthy"], true);
    let target = claim()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.code == "probed")
        .unwrap();
    assert!(h.store.record_health(&target, &[3, 0]).await.unwrap());
    let target = claim()
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.code == "probed")
        .unwrap();
    assert!(h.store.record_health(&target, &[0, 0]).await.unwrap());
    let health = rx.wait_for("health.changed", 2).await;
    assert_eq!(health.len(), 2);
    assert_eq!(health[1].json()["data"]["destinations"][0]["healthy"], true);
    h.shutdown().await;
}

#[tokio::test]
async fn webhooks_belong_to_their_workspace_and_its_admins() {
    let mut h = harness!();
    let rx = Receiver::start().await;
    let hook = create_webhook(&h, &h.alice, &rx.url, &["link.created"]).await;
    let id = hook["id"].as_i64().unwrap();

    // Bob's workspace cannot see Alice's endpoint, and his links do not
    // reach it.
    for (method, path) in [
        (Method::GET, format!("/v1/webhooks/{id}")),
        (Method::DELETE, format!("/v1/webhooks/{id}")),
        (Method::GET, format!("/v1/webhooks/{id}/deliveries")),
        (
            Method::POST,
            format!("/v1/webhooks/{id}/deliveries/1/retry"),
        ),
        (Method::GET, format!("/v1/webhooks/{id}/deliveries/1")),
    ] {
        let (status, _) = h.api(method.clone(), &path, &h.bob, None).await;
        assert_eq!(status, 404, "{method} {path}");
    }
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.bob,
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, 404);
    let (_, list) = h.api(Method::GET, "/v1/webhooks", &h.bob, None).await;
    assert_eq!(list["webhooks"], json!([]));
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.com/bob"})),
        )
        .await;
    assert_eq!(status, 201);
    h.create(json!({"url": "https://example.com/alice"})).await;
    let got = rx.wait_for("link.created", 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rx.got().len(), 1);
    assert_eq!(
        got[0].json()["data"]["link"]["destinations"][0]["url"],
        "https://example.com/alice"
    );

    // An editor in Alice's workspace may change links but not webhooks.
    let workspace = h.store.personal_workspace("alice").await.unwrap();
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, member, role) VALUES ($1, 'carol', 'editor')",
    )
    .bind(workspace)
    .execute(h.store.pool())
    .await
    .unwrap();
    let carol = generate_key();
    h.store
        .create_api_key(&NewApiKey {
            owner: "carol",
            name: "test",
            hash: hash_key(&carol),
            workspace_id: Some(workspace),
            scopes: Scopes::ALL,
            lifetime: None,
        })
        .await
        .unwrap();
    for (method, path) in [
        (Method::GET, "/v1/webhooks".to_owned()),
        (Method::GET, format!("/v1/webhooks/{id}")),
        (Method::DELETE, format!("/v1/webhooks/{id}")),
    ] {
        let (status, err) = h.api(method, &path, &carol, None).await;
        assert_eq!(status, 403, "{path}: {err}");
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap()
                .contains("admin or owner")
        );
    }

    // Validation.
    for (body, what) in [
        (
            json!({"url": "ftp://example.com/", "events": ["link.created"]}),
            "url",
        ),
        (json!({"url": rx.url, "events": []}), "at least one"),
        (
            json!({"url": rx.url, "events": ["link.clicked"]}),
            "unknown event",
        ),
        (
            json!({"url": rx.url, "events": ["link.created"], "description": "x".repeat(201)}),
            "description",
        ),
        (
            json!({"url": rx.url, "events": ["link.created"], "secret": "mine"}),
            "secret",
        ),
    ] {
        let (status, err) = h
            .api(Method::POST, "/v1/webhooks", &h.alice, Some(body.clone()))
            .await;
        assert_eq!(status, 400, "{body}: {err}");
        assert!(
            err["error"]["message"].as_str().unwrap().contains(what),
            "{body}: {err}"
        );
    }
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            Some(json!({"events": ["nope"]})),
        )
        .await;
    assert_eq!(status, 400);
    let (status, _) = h.api(Method::GET, "/v1/webhooks/abc", &h.alice, None).await;
    assert_eq!(status, 400);

    // At most fifty per workspace.
    for _ in 1..webhooks::MAX_WEBHOOKS {
        create_webhook(&h, &h.alice, &rx.url, &["link.created"]).await;
    }
    let (status, err) = h
        .api(
            Method::POST,
            "/v1/webhooks",
            &h.alice,
            Some(json!({"url": rx.url, "events": ["link.created"]})),
        )
        .await;
    assert_eq!(status, 409, "{err}");

    // Rotating the secret shows the new one once; the next delivery is
    // signed with it.
    let (status, rotated) = h
        .api(
            Method::PATCH,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            Some(json!({"rotate_secret": true, "description": "rotated"})),
        )
        .await;
    assert_eq!(status, 200);
    let secret = rotated["secret"].as_str().unwrap().to_owned();
    assert_ne!(secret, hook["secret"].as_str().unwrap());
    assert_eq!(rotated["description"], "rotated");
    // Leave only the first endpoint, so one request arrives.
    let (_, list) = h.api(Method::GET, "/v1/webhooks", &h.alice, None).await;
    for w in list["webhooks"].as_array().unwrap() {
        if w["id"] != id {
            let (status, _) = h
                .api(
                    Method::DELETE,
                    &format!("/v1/webhooks/{}", w["id"]),
                    &h.alice,
                    None,
                )
                .await;
            assert_eq!(status, 204);
        }
    }
    h.create(json!({"url": "https://example.com/rotated"}))
        .await;
    let got = rx.wait_for("link.created", 2).await;
    assert_signed(&got[1], &secret);

    // Every change to an endpoint is audited, without its secret.
    let actions: Vec<(String, Option<Value>)> = sqlx::query_as(
        "SELECT action, after FROM audit_log WHERE workspace_id = $1 \
         AND action LIKE 'webhook.%' ORDER BY seq",
    )
    .bind(workspace)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    let count = |a: &str| actions.iter().filter(|(x, _)| x == a).count();
    assert_eq!(count("webhook.create"), 50);
    assert_eq!(count("webhook.update"), 1);
    assert_eq!(count("webhook.delete"), 49);
    let update = &actions
        .iter()
        .find(|(a, _)| a == "webhook.update")
        .unwrap()
        .1;
    assert_eq!(update.as_ref().unwrap()["secret_rotated"], true);
    assert!(!actions.iter().any(|(_, after)| {
        after
            .as_ref()
            .is_some_and(|v| v.to_string().contains("whsec_"))
    }));

    // Deleting an endpoint takes its log with it.
    let (status, _) = h
        .api(
            Method::DELETE,
            &format!("/v1/webhooks/{id}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 204);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn two_instances_share_deliveries_without_sending_twice() {
    let mut h = harness!();
    let second = h
        .second_instance(&[
            ("RELINK_ALLOW_PRIVATE_DESTINATIONS", "true"),
            ("RELINK_WEBHOOK_POLL_MS", "20"),
            ("RELINK_WEBHOOK_CONCURRENCY", "2"),
        ])
        .await;
    let rx = Receiver::start().await;
    create_webhook(&h, &h.alice, &rx.url, &["link.created"]).await;
    const N: usize = 40;
    for i in 0..N {
        h.create(json!({"alias": format!("bulk{i}"), "url": "https://example.com/"}))
            .await;
    }
    let got = rx.wait_for("link.created", N).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ids: HashSet<String> = got
        .iter()
        .map(|r| r.header("relink-event-id").to_owned())
        .collect();
    assert_eq!(ids.len(), N);
    assert_eq!(rx.got().len(), N, "no event was delivered twice");
    let both = metric(&h.metrics().await, "relink_webhook_deliveries_total")
        + metric(
            &h.http
                .get(format!("http://{}/metrics", second.admin_addr))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "relink_webhook_deliveries_total",
        );
    assert_eq!(both, N as f64);
    second.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn finished_deliveries_are_purged_after_the_retention() {
    let mut h = harness!(("RELINK_WEBHOOKS_ENABLED", "false"));
    let rx = Receiver::start().await;
    let hook = create_webhook(&h, &h.alice, &rx.url, &["link.created"]).await;
    for _ in 0..3 {
        h.create(json!({"url": "https://example.com/"})).await;
    }
    // Nothing is sent from an instance with the worker turned off.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.got().is_empty());
    let pool = h.store.pool();
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY id")
            .bind(hook["id"].as_i64().unwrap())
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(ids.len(), 3);
    sqlx::query(
        "UPDATE webhook_deliveries SET created_at = now() - interval '31 days', \
         state = CASE WHEN id = $1 THEN 'delivered' WHEN id = $2 THEN 'failed' ELSE 'pending' END, \
         delivered_at = CASE WHEN id = $1 THEN now() END",
    )
    .bind(ids[0])
    .bind(ids[1])
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(h.store.purge_deliveries(30, 100).await.unwrap(), 2);
    let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM webhook_deliveries")
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(left, vec![ids[2]], "a pending delivery is never purged");
    assert_eq!(h.store.purge_deliveries(30, 100).await.unwrap(), 0);
    h.shutdown().await;
}

#[tokio::test]
async fn deliveries_never_reach_private_addresses_unless_allowed() {
    let strict = relink_server::health::SafeResolver {
        allow_private: false,
    };
    let client = reqwest::Client::builder()
        .dns_resolver(strict)
        .no_proxy()
        .build()
        .unwrap();
    let claimed = |url: &str| Claimed {
        id: 1,
        event_id: webhooks::generate_event_id(),
        event: "link.created".into(),
        body: "{}".into(),
        attempts: 0,
        url: url.into(),
        secret: webhooks::generate_secret(),
    };
    let rx = Receiver::start().await;
    let out = webhooks::deliver(&client, strict, &claimed(&rx.url), 0).await;
    assert_eq!(out.status, None);
    assert!(out.error.unwrap().contains("not public"));
    let by_name = rx.url.replace("127.0.0.1", "localhost");
    let out = webhooks::deliver(&client, strict, &claimed(&by_name), 0).await;
    assert_eq!(out.status, None);
    assert!(
        out.error.as_deref().unwrap().contains("non-public"),
        "{out:?}"
    );
    let out = webhooks::deliver(&client, strict, &claimed("not a url"), 0).await;
    assert!(out.error.unwrap().contains("not valid"));
    assert!(rx.got().is_empty());

    // Allowed (development), the same request arrives.
    let open = relink_server::health::SafeResolver {
        allow_private: true,
    };
    let client = reqwest::Client::builder()
        .dns_resolver(open)
        .no_proxy()
        .build()
        .unwrap();
    let out = webhooks::deliver(&client, open, &claimed(&by_name), 0).await;
    assert_eq!(out.status, Some(200), "{out:?}");
    assert!(out.succeeded());
    assert_eq!(out.response.as_deref(), Some("thanks"));
    assert_eq!(rx.got().len(), 1);
}

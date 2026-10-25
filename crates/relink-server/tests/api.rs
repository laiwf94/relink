//! Management API end to end, over real HTTP against a real Postgres.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::{Harness, admin_url, eventually, metric};
use reqwest::Method;
use serde_json::{Value, json};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

#[tokio::test]
async fn create_get_list_update_delete() {
    let mut h = harness!();
    let link = h
        .create(json!({"url": "https://Example.com/Landing?x=1"}))
        .await;
    let code = link["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 7);
    assert_eq!(link["short_url"], format!("http://localhost:8080/{code}"));
    assert_eq!(
        link["destinations"][0]["url"],
        "https://example.com/Landing?x=1"
    );
    assert_eq!(link["destinations"][0]["healthy"], Value::Null);
    assert_eq!(link["redirect_type"], 302);
    assert_eq!(link["enabled"], true);

    let (status, got) = h
        .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(got["code"], code.as_str());

    let (status, patched) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(
                json!({"url": "https://example.org/new", "redirect_type": 301,
                        "max_clicks": 10, "health_check": true}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["destinations"][0]["url"], "https://example.org/new");
    assert_eq!(patched["destinations"][0]["healthy"], true);
    assert_eq!(patched["redirect_type"], 301);
    assert_eq!(patched["max_clicks"], 10);

    // null clears an optional field; absent leaves it.
    let (status, cleared) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"max_clicks": null})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(cleared["max_clicks"], Value::Null);
    assert_eq!(cleared["redirect_type"], 301);

    let (status, body) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (400, Some("invalid_argument"))
    );

    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    let (status, body) = h
        .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (404, Some("not_found"))
    );
    assert_eq!(h.visit(&code, &[]).await.status(), 404);
    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 404);
    h.shutdown().await;
}

#[tokio::test]
async fn aliases_are_validated_and_unique() {
    let mut h = harness!();
    let link = h
        .create(json!({"url": "https://example.com/", "alias": "Summer-Sale"}))
        .await;
    assert_eq!(link["code"], "Summer-Sale");
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.com/", "alias": "Summer-Sale"})),
        )
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (409, Some("already_exists"))
    );
    // Case matters: a different alias.
    h.create(json!({"url": "https://example.com/", "alias": "summer-sale"}))
        .await;
    h.shutdown().await;
}

#[tokio::test]
async fn invalid_inputs_are_rejected_with_stable_codes() {
    let mut h = harness!();
    let cases: Vec<(Value, &str)> = vec![
        (json!({}), "url or destinations is required"),
        (
            json!({"url": "https://a.example.com/", "destinations": [{"url": "https://b.example.com/"}]}),
            "not both",
        ),
        (json!({"url": "ftp://example.com/"}), "http or https"),
        (json!({"url": "javascript:alert(1)"}), "http or https"),
        (
            json!({"url": "https://u:p@example.com/"}),
            "user name or password",
        ),
        (json!({"url": "http://localhost/"}), "not a public"),
        (
            json!({"url": "http://169.254.169.254/latest"}),
            "IP address",
        ),
        (
            json!({"url": "https://example.com/", "alias": "metrics"}),
            "reserved",
        ),
        (
            json!({"url": "https://example.com/", "alias": "a b"}),
            "alias",
        ),
        (
            json!({"url": "https://example.com/", "alias": "ab"}),
            "3 to 64",
        ),
        (
            json!({"url": "https://example.com/", "redirect_type": 303}),
            "redirect_type",
        ),
        (
            json!({"url": "https://example.com/", "max_clicks": 0}),
            "max_clicks",
        ),
        (
            json!({"url": "https://example.com/", "max_clicks": -1}),
            "max_clicks",
        ),
        (
            json!({"url": "https://example.com/", "expires_at": "2000-01-01T00:00:00Z"}),
            "future",
        ),
        (
            json!({"url": "https://example.com/", "expires_at": "tomorrow"}),
            "invalid JSON",
        ),
        (
            json!({"url": "https://example.com/", "geo": {"mode": "allow", "countries": []}}),
            "geo.countries",
        ),
        (
            json!({"url": "https://example.com/", "geo": {"mode": "allow", "countries": ["USA"]}}),
            "two-letter",
        ),
        (
            json!({"url": "https://example.com/", "geo": {"mode": "maybe", "countries": ["US"]}}),
            "invalid JSON",
        ),
        (json!({"destinations": []}), "1 to 10"),
        (
            json!({"destinations": [{"url": "https://example.com/", "weight": 0}]}),
            "weight",
        ),
        (
            json!({"destinations": [{"url": "https://example.com/", "weight": 1001}]}),
            "weight",
        ),
        (
            json!({"destinations": (0..11).map(|i| json!({"url": format!("https://e{i}.example.com/")})).collect::<Vec<_>>()}),
            "1 to 10",
        ),
        (
            json!({"url": "https://example.com/", "fallback_url": "file:///etc/passwd"}),
            "fallback_url",
        ),
        (
            json!({"url": "https://example.com/", "surprise": true}),
            "unknown field",
        ),
        (json!({"url": 5}), "invalid JSON"),
        (json!({"url": "https://example.com/".repeat(200)}), "2048"),
    ];
    for (body, needle) in cases {
        let (status, resp) = h
            .api(Method::POST, "/v1/links", &h.alice, Some(body.clone()))
            .await;
        assert_eq!(status, 400, "{body} -> {resp}");
        assert_eq!(resp["error"]["code"], "invalid_argument");
        let msg = resp["error"]["message"].as_str().unwrap();
        assert!(msg.contains(needle), "{body}: {msg:?} lacks {needle:?}");
        assert!(!resp["error"]["request_id"].as_str().unwrap().is_empty());
    }

    // Malformed bodies, content types and sizes.
    let raw = |body: &'static str, ct: &'static str| {
        h.http
            .post(format!("{}/v1/links", h.base))
            .bearer_auth(&h.alice)
            .header("content-type", ct)
            .body(body)
    };
    let r = raw(
        r#"{"url":"https://example.com/"} trailing"#,
        "application/json",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), 400);
    let r = raw(
        r#"{"url":"https://example.com/","url":"https://x.example.com/"}"#,
        "application/json",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "duplicate keys are refused");
    let r = raw(r#"{"url":"https://example.com/"}"#, "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 415);
    let r: Value = r.json_value().await;
    assert_eq!(r["error"]["code"], "unsupported_media_type");
    let big = format!(r#"{{"url":"https://example.com/{}"}}"#, "a".repeat(70_000));
    let r = h
        .http
        .post(format!("{}/v1/links", h.base))
        .bearer_auth(&h.alice)
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    assert_eq!(r.json_value().await["error"]["code"], "payload_too_large");
    h.shutdown().await;
}

#[tokio::test]
async fn authentication_and_owner_scoping() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();

    let r = h
        .http
        .get(format!("{}/v1/links", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    assert_eq!(r.json_value().await["error"]["code"], "unauthenticated");
    for bad in ["rlk_short", &format!("rlk_{}", "0".repeat(64)), "Basic abc"] {
        let (status, _) = h.api(Method::GET, "/v1/links", bad, None).await;
        assert_eq!(status, 401, "{bad}");
    }

    // A revoked key is refused.
    let key = relink_server::auth::generate_key();
    let id = h
        .store
        .insert_api_key("carol", "", &relink_server::auth::hash_key(&key))
        .await
        .unwrap();
    assert!(h.store.revoke_api_key(id).await.unwrap());
    assert!(!h.store.revoke_api_key(id).await.unwrap());
    let (status, _) = h.api(Method::GET, "/v1/links", &key, None).await;
    assert_eq!(status, 401);

    // Bob cannot see or touch alice's link, and cannot tell it exists.
    for (method, path, body) in [
        (Method::GET, format!("/v1/links/{code}"), None),
        (
            Method::PATCH,
            format!("/v1/links/{code}"),
            Some(json!({"enabled": false})),
        ),
        (Method::DELETE, format!("/v1/links/{code}"), None),
        (Method::GET, format!("/v1/links/{code}/stats"), None),
    ] {
        let (status, body) = h.api(method.clone(), &path, &h.bob, body).await;
        assert_eq!(status, 404, "{method} {path}: {body}");
    }
    let (_, list) = h.api(Method::GET, "/v1/links", &h.bob, None).await;
    assert_eq!(list["links"].as_array().unwrap().len(), 0);
    assert_eq!(h.visit(code, &[]).await.status(), 302, "untouched");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn made_up_keys_cannot_flood_the_database() {
    let mut h = harness!(
        ("RELINK_AUTH_LOOKUP_RATE", "5"),
        ("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000")
    );
    // Authenticate alice once so her key is cached.
    let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(status, 200);
    // 40 connections x 10 requests (more simultaneous connects would only
    // test the OS accept backlog).
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let http = h.http.clone();
        let url = format!("{}/v1/links", h.base);
        tasks.push(tokio::spawn(async move {
            let mut statuses = Vec::new();
            for _ in 0..10 {
                let key = relink_server::auth::generate_key();
                let r = http.get(&url).bearer_auth(key).send().await.unwrap();
                statuses.push(r.status().as_u16());
            }
            statuses
        }));
    }
    let mut refused = 0;
    let mut throttled = 0;
    for t in tasks {
        for status in t.await.unwrap() {
            match status {
                401 => refused += 1,
                429 => throttled += 1,
                // Lookups that queued past the query timeout (slow builds).
                503 => {}
                s => panic!("unexpected {s}"),
            }
        }
    }
    assert!(throttled > 0, "uncached lookups must be throttled");
    assert!(refused > 0, "some lookups still run and are refused");
    // A cached key is unaffected.
    let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(status, 200);
    h.shutdown().await;
}

#[tokio::test]
async fn key_guessing_is_limited_per_client_address() {
    let mut h = harness!(
        ("RELINK_CLIENT_IP_HEADER", "x-forwarded-for"),
        // Effectively no refill during the test, however slow the build.
        ("RELINK_AUTH_LOOKUP_RATE_PER_IP", "0.01")
    );
    let attempt = |ip: &'static str, key: String| {
        let http = h.http.clone();
        let url = format!("{}/v1/links", h.base);
        async move {
            http.get(url)
                .bearer_auth(key)
                .header("x-forwarded-for", ip)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    // One lookup, then throttled: this address is guessing.
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(attempt("198.51.100.1", relink_server::auth::generate_key()).await);
    }
    assert_eq!(statuses, [401, 429, 429, 429, 429]);
    // A repeated unknown key is answered from the negative cache, without
    // touching the budget.
    let key = relink_server::auth::generate_key();
    assert_eq!(attempt("198.51.100.2", key.clone()).await, 401);
    for _ in 0..5 {
        assert_eq!(attempt("198.51.100.2", key.clone()).await, 401);
    }
    // Another address and a valid, cached key are unaffected.
    assert_eq!(
        attempt("198.51.100.3", relink_server::auth::generate_key()).await,
        401
    );
    let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(status, 200);
    h.shutdown().await;
}

const EDGE_TOKEN: &str = "edge-token-for-tests-0123456789abcdef";

#[tokio::test]
async fn edge_clicks_endpoint() {
    let mut h = harness!(("RELINK_EDGE_TOKEN", EDGE_TOKEN));
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap().to_owned();
    let id: i64 = sqlx::query_scalar("SELECT id FROM links WHERE code = $1")
        .bind(&code)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let today = relink_server::util::utc_day(relink_server::util::now_ms());
    let click = |fp: &str| {
        json!({"link_id": id, "day": today, "country": "DE", "device": "mobile",
               "referrer": "news.example.org", "fingerprint": fp})
    };
    let post = |token: &str, body: Value| {
        let req = h
            .http
            .post(format!("{}/v1/edge/clicks", h.base))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(body.to_string());
        async move {
            let r = req.send().await.unwrap();
            (r.status().as_u16(), r.json_value().await)
        }
    };
    let good = json!({"clicks": [click(&"aa".repeat(16)), click(&"bb".repeat(16))]});
    assert_eq!(post("wrong-token", good.clone()).await.0, 401);
    assert_eq!(
        post(&h.alice, good.clone()).await.0,
        401,
        "API keys do not work here"
    );
    let (status, body) = post(EDGE_TOKEN, json!({"clicks": [click("zz")]})).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (400, Some("invalid_argument"))
    );
    let too_many: Vec<Value> = (0..1001).map(|_| click(&"aa".repeat(16))).collect();
    assert_eq!(post(EDGE_TOKEN, json!({"clicks": too_many})).await.0, 400);
    let (status, body) = post(EDGE_TOKEN, good).await;
    assert_eq!((status, body["accepted"].as_i64()), (202, Some(2)));
    let path = format!("/v1/links/{code}/stats");
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, s) = h.api(Method::GET, &path, &h.alice, None).await;
            s["total_clicks"] == 2 && s["days"][0]["unique_visitors"] == 2
        })
        .await
    );
    h.shutdown().await;

    // Without a token configured the endpoint does not exist.
    let mut h = harness!();
    let r = h
        .http
        .post(format!("{}/v1/edge/clicks", h.base))
        .bearer_auth(EDGE_TOKEN)
        .header("content-type", "application/json")
        .body(r#"{"clicks":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    h.shutdown().await;
}

#[tokio::test]
async fn cursor_pagination_is_complete_and_stable() {
    let mut h = harness!();
    let mut created = BTreeSet::new();
    for i in 0..7 {
        let l = h
            .create(json!({"url": format!("https://example.com/{i}")}))
            .await;
        created.insert(l["code"].as_str().unwrap().to_owned());
    }
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/links?limit=3&cursor={c}"),
            None => "/v1/links?limit=3".to_owned(),
        };
        let (status, page) = h.api(Method::GET, &path, &h.alice, None).await;
        assert_eq!(status, 200);
        pages += 1;
        for l in page["links"].as_array().unwrap() {
            seen.push(l["code"].as_str().unwrap().to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 7, "no duplicates or gaps");
    assert_eq!(seen.iter().cloned().collect::<BTreeSet<_>>(), created);
    // Newest first.
    let (_, first) = h
        .api(Method::GET, "/v1/links?limit=1", &h.alice, None)
        .await;
    assert_eq!(
        first["links"][0]["destinations"][0]["url"],
        "https://example.com/6"
    );

    for bad in [
        "/v1/links?limit=0",
        "/v1/links?limit=101",
        "/v1/links?limit=x",
        "/v1/links?cursor=zzzz",
        "/v1/links?page=2",
    ] {
        let (status, body) = h.api(Method::GET, bad, &h.alice, None).await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn request_ids_errors_and_unknown_routes() {
    let mut h = harness!();
    let r = h
        .http
        .get(format!("{}/v1/links/nope", h.base))
        .bearer_auth(&h.alice)
        .header("x-request-id", "trace-123")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["x-request-id"], "trace-123");
    assert_eq!(r.json_value().await["error"]["request_id"], "trace-123");

    let r = h
        .http
        .get(format!("{}/healthz", h.base))
        .header("x-request-id", "bad id with spaces")
        .send()
        .await
        .unwrap();
    let id = r.headers()["x-request-id"].to_str().unwrap().to_owned();
    assert_eq!(id.len(), 16);

    let r = h
        .http
        .put(format!("{}/v1/links", h.base))
        .bearer_auth(&h.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    assert_eq!(r.json_value().await["error"]["code"], "method_not_allowed");

    let r = h
        .http
        .get(format!("{}/v1/unknown", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.json_value().await["error"]["code"], "not_found");
    let r = h
        .http
        .get(format!("{}/a/b/c", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    h.shutdown().await;
}

#[tokio::test]
async fn per_key_rate_limit() {
    // Slow refill, so test timing cannot add a token.
    let mut h = harness!(("RELINK_API_RATE", "0.01"), ("RELINK_API_BURST", "2"));
    for _ in 0..2 {
        let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
        assert_eq!(status, 200);
    }
    let r = h
        .http
        .get(format!("{}/v1/links", h.base))
        .bearer_auth(&h.alice)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    let retry: u64 = r.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=100).contains(&retry), "retry-after {retry}");
    assert_eq!(r.json_value().await["error"]["code"], "resource_exhausted");
    // Another key has its own bucket.
    let (status, _) = h.api(Method::GET, "/v1/links", &h.bob, None).await;
    assert_eq!(status, 200);
    assert!(metric(&h.metrics().await, "relink_api_rate_limited_total") >= 1.0);
    h.shutdown().await;
}

#[tokio::test]
async fn openapi_matches_the_router_and_responses() {
    let mut h = harness!(("RELINK_EDGE_TOKEN", EDGE_TOKEN));
    let doc: Value = h
        .http
        .get(format!("{}/openapi.json", h.base))
        .send()
        .await
        .unwrap()
        .json_value()
        .await;
    assert_eq!(doc["openapi"], "3.1.0");
    let mut documented = BTreeSet::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in ["get", "post", "patch", "delete", "put"] {
            if item.get(method).is_some() {
                documented.insert((method.to_owned(), path.clone()));
            }
        }
    }
    let routes: BTreeSet<(String, String)> = relink_server::api::ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    assert_eq!(
        documented, routes,
        "OpenAPI paths and the route table differ"
    );

    // Every documented route is served (wrong methods would be 405, unknown
    // paths 404 with a JSON body).
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    // Deletion last, so the other routes still find the link.
    let mut ordered: Vec<&(String, String)> = routes.iter().collect();
    ordered.sort_by_key(|(m, _)| m == "delete");
    for (method, path) in ordered {
        let url = format!("{}{}", h.base, path.replace("{code}", code));
        let m = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
        let edge = path.starts_with("/v1/edge/");
        let key = if edge { EDGE_TOKEN } else { h.alice.as_str() };
        let mut req = h.http.request(m, url).bearer_auth(key);
        if method == "post" || method == "patch" {
            let body = if edge {
                r#"{"clicks":[]}"#
            } else {
                r#"{"enabled":true,"url":"https://example.com/"}"#
            };
            req = req.header("content-type", "application/json").body(body);
        }
        let status = req.send().await.unwrap().status().as_u16();
        assert!(
            matches!(status, 200 | 201 | 202 | 204 | 302),
            "{method} {path} returned {status}"
        );
    }

    // Response bodies carry exactly the documented required fields.
    let schema_keys = |name: &str| -> BTreeSet<String> {
        doc["components"]["schemas"][name]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let keys: BTreeSet<String> = link.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, schema_keys("Link"));
    let (_, stats) = h
        .api(
            Method::GET,
            &format!("/v1/links/{}/stats", link["code"].as_str().unwrap()),
            &h.alice,
            None,
        )
        .await;
    let keys: BTreeSet<String> = stats.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, schema_keys("Stats"));
    let (_, list) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    let keys: BTreeSet<String> = list.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, schema_keys("LinkList"));
    let (_, err) = h.api(Method::GET, "/v1/links/nope", &h.alice, None).await;
    let keys: BTreeSet<String> = err["error"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        doc["components"]["schemas"]["Error"]["properties"]["error"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    );
    h.shutdown().await;
}

#[tokio::test]
async fn stats_aggregate_clicks_by_dimension() {
    let mut h = harness!(("RELINK_CLIENT_IP_HEADER", "x-client-ip"));
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    let chrome_mac =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15";
    let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148";
    let visits: &[(&str, &str, &str, &str)] = &[
        (
            "de",
            chrome_mac,
            "https://news.example.org/a",
            "203.0.113.1",
        ),
        (
            "DE",
            chrome_mac,
            "https://news.example.org/b",
            "203.0.113.1",
        ),
        ("US", iphone, "", "203.0.113.2"),
        ("??", iphone, "https://Social.Example.net/", "203.0.113.3"),
    ];
    for (country, ua, referer, ip) in visits {
        let mut headers = vec![
            ("cf-ipcountry", *country),
            ("user-agent", *ua),
            ("x-client-ip", *ip),
        ];
        if !referer.is_empty() {
            headers.push(("referer", referer));
        }
        assert_eq!(h.visit(code, &headers).await.status(), 302);
    }
    let path = format!("/v1/links/{code}/stats");
    let ok = eventually(Duration::from_secs(5), || async {
        let (_, s) = h.api(Method::GET, &path, &h.alice, None).await;
        s["total_clicks"] == 4
    })
    .await;
    assert!(ok, "clicks were not flushed");
    let (_, s) = h.api(Method::GET, &path, &h.alice, None).await;
    assert_eq!(s["days"].as_array().unwrap().len(), 1);
    assert_eq!(s["days"][0]["clicks"], 4);
    assert_eq!(s["days"][0]["unique_visitors"], 3, "{s}");
    assert_eq!(s["countries"][0], json!({"value": "DE", "clicks": 2}));
    let values = |k: &str| -> BTreeSet<String> {
        s[k].as_array()
            .unwrap()
            .iter()
            .map(|b| b["value"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        values("countries"),
        ["DE", "US", "XX"].map(String::from).into()
    );
    assert_eq!(
        values("devices"),
        ["desktop", "mobile"].map(String::from).into()
    );
    assert_eq!(
        values("referrers"),
        ["news.example.org", "(direct)", "social.example.net"]
            .map(String::from)
            .into()
    );
    // Bad ranges.
    for q in [
        "?from=2030-01-02&to=2030-01-01",
        "?from=2020-01-01&to=2022-01-01",
        "?from=nope",
        "?x=1",
    ] {
        let (status, _) = h
            .api(Method::GET, &format!("{path}{q}"), &h.alice, None)
            .await;
        assert_eq!(status, 400, "{q}");
    }
    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_clicks_flushed_total"), 4.0);
    assert_eq!(
        metric(&m, "relink_redirects_total{outcome=\"redirect\"}"),
        4.0
    );
    h.shutdown().await;
}

#[tokio::test]
async fn probes_and_metrics() {
    let mut h = harness!();
    let r = h
        .http
        .get(format!("{}/healthz", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let ready = eventually(Duration::from_secs(5), || async {
        let r: Value = h
            .http
            .get(format!("{}/readyz", h.admin))
            .send()
            .await
            .unwrap()
            .json_value()
            .await;
        r == json!({"status": "ready", "database": "up"})
    })
    .await;
    assert!(ready);
    let r = h
        .http
        .get(format!("{}/metrics", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "metrics are only on the admin listener");
    let m = h.metrics().await;
    assert!(m.contains("# TYPE relink_redirect_duration_seconds histogram"));
    let r = h
        .http
        .get(format!("{}/nope", h.admin))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    h.shutdown().await;
}

/// `resp.json()` needs reqwest's json feature; parse by hand instead.
trait JsonValue {
    async fn json_value(self) -> Value;
}

impl JsonValue for reqwest::Response {
    async fn json_value(self) -> Value {
        serde_json::from_str(&self.text().await.unwrap()).unwrap()
    }
}

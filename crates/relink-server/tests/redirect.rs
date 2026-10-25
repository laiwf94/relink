//! The redirect path end to end: link options, caching, cross-instance
//! invalidation and max-click enforcement under concurrency.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Harness, admin_url, client, eventually, metric};
use reqwest::Method;
use serde_json::json;

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

#[tokio::test]
async fn redirect_statuses_and_headers() {
    let mut h = harness!();
    for status in [301, 302, 307, 308] {
        let l = h
            .create(json!({"url": "https://example.com/x?y=1", "redirect_type": status}))
            .await;
        let r = h.visit(l["code"].as_str().unwrap(), &[]).await;
        assert_eq!(r.status().as_u16(), status);
        assert_eq!(location(&r), "https://example.com/x?y=1");
        assert_eq!(r.headers()["cache-control"], "private, max-age=0");
        assert!(r.headers().get("set-cookie").is_none());
    }
    // Garbage codes never reach the cache or database.
    for path in ["ab", "has.dot", "%00abc", &"a".repeat(65)] {
        assert_eq!(h.visit(path, &[]).await.status(), 404, "{path}");
    }
    assert_eq!(h.visit("unknown-code", &[]).await.status(), 404);
    h.shutdown().await;
}

#[tokio::test]
async fn disabled_and_expired_links() {
    let mut h = harness!();
    let l = h
        .create(json!({"url": "https://example.com/", "enabled": false}))
        .await;
    let code = l["code"].as_str().unwrap();
    assert_eq!(h.visit(code, &[]).await.status(), 404);
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"enabled": true})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        h.visit(code, &[]).await.status(),
        302,
        "re-enabled immediately"
    );

    let soon = (chrono::Utc::now() + chrono::Duration::milliseconds(1500)).to_rfc3339();
    let l = h
        .create(json!({"url": "https://example.com/", "expires_at": soon}))
        .await;
    let code = l["code"].as_str().unwrap();
    let r = h.visit(code, &[]).await;
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["cache-control"], "no-store");
    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert_eq!(
        h.visit(code, &[]).await.status(),
        410,
        "expiry is checked per request, even from cache"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn geo_rules_and_fallback() {
    let mut h = harness!();
    let allow = h
        .create(json!({"url": "https://example.com/us", "geo": {"mode": "allow", "countries": ["us", "CA"]},
                       "fallback_url": "https://example.com/elsewhere"}))
        .await;
    let code = allow["code"].as_str().unwrap();
    let r = h.visit(code, &[("cf-ipcountry", "US")]).await;
    assert_eq!(
        (r.status().as_u16(), location(&r).as_str()),
        (302, "https://example.com/us")
    );
    let r = h.visit(code, &[("cf-ipcountry", "DE")]).await;
    assert_eq!(
        (r.status().as_u16(), location(&r).as_str()),
        (302, "https://example.com/elsewhere")
    );
    let r = h.visit(code, &[]).await;
    assert_eq!(
        location(&r),
        "https://example.com/elsewhere",
        "unknown country is not allowed"
    );

    let deny = h
        .create(
            json!({"url": "https://example.com/", "geo": {"mode": "deny", "countries": ["DE"]}}),
        )
        .await;
    let code = deny["code"].as_str().unwrap();
    assert_eq!(h.visit(code, &[("cf-ipcountry", "de")]).await.status(), 451);
    assert_eq!(h.visit(code, &[("cf-ipcountry", "FR")]).await.status(), 302);
    assert_eq!(h.visit(code, &[]).await.status(), 302);
    let m = h.metrics().await;
    assert_eq!(
        metric(&m, "relink_redirects_total{outcome=\"geo_blocked\"}"),
        3.0
    );
    h.shutdown().await;
}

#[tokio::test]
async fn forwarding_headers_from_untrusted_peers_are_ignored() {
    // Loopback is not a trusted proxy here, so a client sending CF-IPCountry
    // directly cannot pass the geo rule.
    let mut h = harness!(("RELINK_TRUSTED_PROXIES", "192.0.2.1"));
    let allow = h
        .create(
            json!({"url": "https://example.com/us", "geo": {"mode": "allow", "countries": ["US"]}}),
        )
        .await;
    let code = allow["code"].as_str().unwrap();
    assert_eq!(h.visit(code, &[("cf-ipcountry", "US")]).await.status(), 451);
    h.shutdown().await;
}

#[tokio::test]
async fn ab_split_is_weighted_and_sticky() {
    let mut h = harness!();
    let l = h
        .create(json!({"destinations": [
            {"url": "https://a.example.com/", "weight": 3},
            {"url": "https://b.example.com/", "weight": 1}
        ]}))
        .await;
    let code = l["code"].as_str().unwrap();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut cookie_for: HashMap<String, String> = HashMap::new();
    for _ in 0..400 {
        let r = h.visit(code, &[]).await;
        assert_eq!(r.status(), 302);
        assert_eq!(r.headers()["cache-control"], "no-store");
        let set = r.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert!(set.contains(&format!("Path=/{code}")));
        assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax"));
        let dest = location(&r);
        cookie_for
            .entry(dest.clone())
            .or_insert_with(|| set.split(';').next().unwrap().to_owned());
        *counts.entry(dest).or_default() += 1;
    }
    let a = counts["https://a.example.com/"] as f64;
    // Expected 300 of 400; binomial sd ~8.7, allow 5 sd.
    assert!((a - 300.0).abs() < 45.0, "a got {a}");

    // A visitor with a cookie keeps their variant, and gets no new cookie.
    for (dest, cookie) in &cookie_for {
        for _ in 0..20 {
            let r = h.visit(code, &[("cookie", cookie)]).await;
            assert_eq!(&location(&r), dest);
            assert!(r.headers().get("set-cookie").is_none());
        }
    }
    // A forged cookie is ignored and replaced.
    let r = h
        .visit(
            code,
            &[("cookie", &format!("rl_{code}=1.{}", "0".repeat(32)))],
        )
        .await;
    assert!(r.headers().get("set-cookie").is_some());

    // Changing destinations invalidates old assignments.
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"destinations": [
                {"url": "https://a.example.com/", "weight": 1},
                {"url": "https://c.example.com/", "weight": 1}
            ]})),
        )
        .await;
    assert_eq!(status, 200);
    let cookie = &cookie_for["https://a.example.com/"];
    let r = h.visit(code, &[("cookie", cookie)]).await;
    assert!(
        r.headers().get("set-cookie").is_some(),
        "old cookie must not verify"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn negative_cache_is_cleared_when_the_code_is_created() {
    let mut h = harness!(("RELINK_CACHE_NEGATIVE_TTL_MS", "600000"));
    assert_eq!(h.visit("fresh-alias", &[]).await.status(), 404);
    assert_eq!(h.visit("fresh-alias", &[]).await.status(), 404);
    let m = h.metrics().await;
    assert_eq!(
        metric(&m, "relink_cache_requests_total{result=\"negative_hit\"}"),
        1.0
    );
    h.create(json!({"url": "https://example.com/", "alias": "fresh-alias"}))
        .await;
    assert_eq!(h.visit("fresh-alias", &[]).await.status(), 302);
    h.shutdown().await;
}

#[tokio::test]
async fn changes_propagate_to_other_instances() {
    let mut h = harness!(("RELINK_CACHE_TTL_MS", "600000"));
    let other = h
        .second_instance(&[("RELINK_CACHE_TTL_MS", "600000")])
        .await;
    let other_base = format!("http://{}", other.addr);
    let http = client();
    let visit_other = |code: String| {
        let http = http.clone();
        let url = format!("{other_base}/{code}");
        async move { http.get(url).send().await.unwrap() }
    };
    let l = h.create(json!({"url": "https://example.com/one"})).await;
    let code = l["code"].as_str().unwrap().to_owned();
    let r = visit_other(code.clone()).await;
    assert_eq!(location(&r), "https://example.com/one");

    // Updated on instance 1, cached for 10 minutes on instance 2.
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"url": "https://example.com/two"})),
        )
        .await;
    assert_eq!(status, 200);
    let ok = eventually(Duration::from_secs(5), || {
        let v = visit_other(code.clone());
        async move { location(&v.await) == "https://example.com/two" }
    })
    .await;
    assert!(ok, "the update did not reach the other instance");

    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    let ok = eventually(Duration::from_secs(5), || {
        let v = visit_other(code.clone());
        async move { v.await.status() == 404 }
    })
    .await;
    assert!(ok, "the delete did not reach the other instance");
    assert!(other.app.metrics.invalidations.get() >= 2);
    other.shutdown().await;
    h.shutdown().await;
}

/// Three instances serve one max-clicks link concurrently. The number of
/// redirects served must equal max_clicks exactly: never more (the bound),
/// and here never fewer, because every instance stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn max_clicks_is_exact_across_instances() {
    let mut h = harness!(("RELINK_LEASE_MAX", "20"));
    let b = h.second_instance(&[("RELINK_LEASE_MAX", "20")]).await;
    let c = h.second_instance(&[("RELINK_LEASE_MAX", "20")]).await;
    let l = h
        .create(json!({"url": "https://example.com/", "max_clicks": 500}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    let bases = Arc::new(vec![
        h.base.clone(),
        format!("http://{}", b.addr),
        format!("http://{}", c.addr),
    ]);
    let served = Arc::new(AtomicUsize::new(0));
    let gone = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for t in 0..48 {
        let (bases, served, gone, code) =
            (bases.clone(), served.clone(), gone.clone(), code.clone());
        tasks.push(tokio::spawn(async move {
            let http = client();
            for i in 0..20 {
                let base = &bases[(t + i) % bases.len()];
                let r = http.get(format!("{base}/{code}")).send().await.unwrap();
                match r.status().as_u16() {
                    302 => served.fetch_add(1, Ordering::SeqCst),
                    410 => gone.fetch_add(1, Ordering::SeqCst),
                    s => panic!("unexpected status {s}"),
                };
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(
        served.load(Ordering::SeqCst) + gone.load(Ordering::SeqCst),
        960
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        500,
        "served must equal max_clicks"
    );
    let id = h.app().resolver.cache().len();
    assert!(id > 0);
    b.shutdown().await;
    c.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn unused_leases_are_returned_on_update_and_shutdown() {
    let mut h = harness!(("RELINK_LEASE_MAX", "50"));
    let l = h
        .create(json!({"url": "https://example.com/", "max_clicks": 1000}))
        .await;
    let code = l["code"].as_str().unwrap().to_owned();
    assert_eq!(h.visit(&code, &[]).await.status(), 302);
    let id: i64 = sqlx::query_scalar("SELECT id FROM links WHERE code = $1")
        .bind(&code)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(h.store.clicks_reserved(id).await.unwrap(), 50);
    // Raising the limit drops the local lease and hands back the unused 49.
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"max_clicks": 2000})),
        )
        .await;
    assert_eq!(status, 200);
    // Returned by this request or by the change notification, whichever
    // reaches the lease first.
    assert!(
        eventually(Duration::from_secs(5), || async {
            h.store.clicks_reserved(id).await.unwrap() == 1
        })
        .await
    );
    assert_eq!(h.visit(&code, &[]).await.status(), 302);
    assert_eq!(h.store.clicks_reserved(id).await.unwrap(), 51);
    let store = h.store.clone();
    h.shutdown().await;
    assert_eq!(
        store.clicks_reserved(id).await.unwrap(),
        2,
        "shutdown returns the unspent lease"
    );
}

#[tokio::test]
async fn limit_reached_is_gone() {
    let mut h = harness!();
    let l = h
        .create(json!({"url": "https://example.com/", "max_clicks": 3}))
        .await;
    let code = l["code"].as_str().unwrap();
    for _ in 0..3 {
        let r = h.visit(code, &[]).await;
        assert_eq!(r.status(), 302);
        assert_eq!(r.headers()["cache-control"], "no-store");
    }
    for _ in 0..3 {
        assert_eq!(h.visit(code, &[]).await.status(), 410);
    }
    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_redirects_total{outcome=\"gone\"}"), 3.0);
    h.shutdown().await;
}

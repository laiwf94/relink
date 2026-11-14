//! Link version history, rollback and scheduled changes, end to end: what
//! each change records, rollbacks restoring every setting, pruning, tenancy,
//! the scheduler applying each change exactly once across instances and
//! through a database outage, and the migration that starts the history of
//! existing links.

mod common;

use std::borrow::Cow;
use std::time::Duration;

use chrono::{DateTime, Utc};
use common::{Harness, TestDb, admin_url, eventually, metric};
use relink_server::schedule::LinkSpec;
use relink_server::store::MIGRATOR;
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

fn in_secs(secs: i64) -> String {
    (Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

async fn versions(h: &Harness, code: &str) -> Vec<Value> {
    let (status, body) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/versions?limit=100"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    body["versions"].as_array().unwrap().clone()
}

async fn patch(h: &Harness, code: &str, body: Value) -> Value {
    let (status, link) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(body),
        )
        .await;
    assert_eq!(status, 200, "{link}");
    link
}

async fn schedule(h: &Harness, code: &str, body: Value) -> (u16, Value) {
    h.api(
        Method::POST,
        &format!("/v1/links/{code}/schedules"),
        &h.alice,
        Some(body),
    )
    .await
}

/// A pool straight to the test database, not through the chaos proxy.
async fn direct(h: &Harness) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&h.db.url)
        .await
        .unwrap()
}

/// The settings of a link as the API shows it, in a version's shape.
fn settings_of(link: &Value) -> Value {
    json!({
        "destinations": link["destinations"].as_array().unwrap().iter()
            .map(|d| json!({"url": d["url"], "weight": d["weight"]}))
            .collect::<Vec<_>>(),
        "redirect_type": link["redirect_type"],
        "expires_at": link["expires_at"],
        "max_clicks": link["max_clicks"],
        "geo": link["geo"],
        "fallback_url": link["fallback_url"],
        "enabled": link["enabled"],
        "health_check": link["health_check"],
        "rules": link["rules"],
        "app": link["app"],
    })
}

/// Timestamps compared as instants, whatever their spelling.
fn same_instant(a: &Value, b: &Value) -> bool {
    match (a.as_str(), b.as_str()) {
        (Some(a), Some(b)) => {
            DateTime::parse_from_rfc3339(a).unwrap() == DateTime::parse_from_rfc3339(b).unwrap()
        }
        _ => a == b,
    }
}

fn assert_settings(version: &Value, link: &Value) {
    let mut got = version["settings"].clone();
    let mut want = settings_of(link);
    assert!(
        same_instant(&got["expires_at"], &want["expires_at"]),
        "{got} vs {want}"
    );
    got["expires_at"] = Value::Null;
    want["expires_at"] = Value::Null;
    assert_eq!(got, want);
}

#[tokio::test]
async fn every_change_is_a_version_and_no_ops_are_not() {
    let mut h = harness!();
    let link = h
        .create(json!({
            "url": "https://example.com/a",
            "redirect_type": 307,
            "expires_at": in_secs(86_400),
            "max_clicks": 1000,
            "geo": {"mode": "deny", "countries": ["de", "FR"]},
            "fallback_url": "https://example.com/elsewhere",
            "rules": [{"if": {"language": ["de"]}, "url": "https://example.com/de"}],
            "app": {"ios": {"store_url": "https://apps.apple.com/app/id1"}},
        }))
        .await;
    let code = link["code"].as_str().unwrap();
    assert_eq!(link["version"], 1);
    let v = versions(&h, code).await;
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["version"], 1);
    assert_eq!(v[0]["source"], "create");
    assert_eq!(v[0]["member"], "alice");
    assert!(
        v[0]["via"].as_str().unwrap().starts_with("key:"),
        "{}",
        v[0]
    );
    assert_eq!(v[0]["restored_from"], Value::Null);
    assert_eq!(v[0]["schedule_id"], Value::Null);
    assert_settings(&v[0], &link);

    let changed = patch(&h, code, json!({"url": "https://example.com/b"})).await;
    assert_eq!(changed["version"], 2);
    // Setting what is already set records nothing.
    let same = patch(
        &h,
        code,
        json!({"url": "https://example.com/b", "max_clicks": 1000}),
    )
    .await;
    assert_eq!(same["version"], 2);
    let disabled = patch(&h, code, json!({"enabled": false, "geo": null})).await;
    assert_eq!(disabled["version"], 3);

    let v = versions(&h, code).await;
    let numbers: Vec<i64> = v.iter().map(|v| v["version"].as_i64().unwrap()).collect();
    assert_eq!(numbers, vec![3, 2, 1]);
    assert!(v[..2].iter().all(|v| v["source"] == "update"));
    assert_settings(&v[0], &disabled);
    assert_settings(&v[1], &changed);
    // The settings parse as the server's own type.
    let spec: LinkSpec = serde_json::from_value(v[2]["settings"].clone()).unwrap();
    assert_eq!(spec.redirect_type, 307);
    assert_eq!(spec.geo.unwrap().countries, vec![*b"DE", *b"FR"]);

    // Pages, newest first.
    let (status, page) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/versions?limit=2"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(page["versions"].as_array().unwrap().len(), 2);
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, rest) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/versions?limit=2&cursor={cursor}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(rest["versions"][0]["version"], 1);
    assert_eq!(rest["next_cursor"], Value::Null);
    for bad in ["limit=0", "limit=101", "cursor=zz", "other=1"] {
        let (status, body) = h
            .api(
                Method::GET,
                &format!("/v1/links/{code}/versions?{bad}"),
                &h.alice,
                None,
            )
            .await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn rollback_restores_every_setting_as_a_new_version() {
    let mut h = harness!();
    let original = h
        .create(json!({
            "destinations": [{"url": "https://example.com/a", "weight": 3},
                             {"url": "https://example.com/b", "weight": 1}],
            "fallback_url": "https://example.com/elsewhere",
            "geo": {"mode": "allow", "countries": ["NL"]},
            "max_clicks": 50,
        }))
        .await;
    let code = original["code"].as_str().unwrap();
    patch(
        &h,
        code,
        json!({
            "url": "https://example.com/new",
            "redirect_type": 301,
            "geo": null,
            "fallback_url": null,
            "max_clicks": null,
            "expires_at": in_secs(3600),
            "rules": [{"if": {"language": ["fr"]}, "url": "https://example.com/fr"}],
            "app": {"android": {"package": "com.example.app", "url": "myapp://x"}},
        }),
    )
    .await;
    let r = h.visit(code, &[("cf-ipcountry", "US")]).await;
    assert_eq!(r.status(), 301);
    assert_eq!(location(&r), "https://example.com/new");

    let (status, restored) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 1})),
        )
        .await;
    assert_eq!(status, 200, "{restored}");
    assert_eq!(restored["version"], 3);
    assert_eq!(settings_of(&restored), settings_of(&original));
    let v = versions(&h, code).await;
    assert_eq!(v[0]["source"], "rollback");
    assert_eq!(v[0]["restored_from"], 1);
    assert_eq!(v[0]["settings"], v[2]["settings"]);
    // The redirect follows at once: the geo rule is back, and so are the
    // destinations.
    let r = h.visit(code, &[("cf-ipcountry", "US")]).await;
    assert_eq!(r.status(), 302);
    assert_eq!(location(&r), "https://example.com/elsewhere");
    let r = h.visit(code, &[("cf-ipcountry", "NL")]).await;
    assert!(location(&r).starts_with("https://example.com/"));
    assert_ne!(location(&r), "https://example.com/new");

    // Back to what it already is: nothing to record.
    let (status, again) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 3})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(again["version"], 3);
    // Forward again to version 2.
    let (_, forward) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 2})),
        )
        .await;
    assert_eq!(forward["version"], 4);
    assert_eq!(
        location(&h.visit(code, &[]).await),
        "https://example.com/new"
    );

    let (status, body) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 99})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no version 99"),
        "{body}"
    );
    for bad in [
        json!({"version": 0}),
        json!({"version": -1}),
        json!({}),
        json!({"version": 1, "url": "https://example.com/"}),
    ] {
        let (status, body) = h
            .api(
                Method::POST,
                &format!("/v1/links/{code}/rollback"),
                &h.alice,
                Some(bad.clone()),
            )
            .await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links/nosuchlink/rollback",
            &h.alice,
            Some(json!({"version": 1})),
        )
        .await;
    assert_eq!(status, 404);

    // Audited as a rollback, with the state before and after.
    let ws: i64 = h.store.personal_workspace("alice").await.unwrap();
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE workspace_id = $1 ORDER BY seq")
            .bind(ws)
            .fetch_all(h.store.pool())
            .await
            .unwrap();
    assert_eq!(
        actions.iter().filter(|a| *a == "link.rollback").count(),
        3,
        "{actions:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn history_keeps_the_newest_hundred_versions() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/0"})).await;
    let code = link["code"].as_str().unwrap();
    for i in 1..=104 {
        patch(&h, code, json!({"url": format!("https://example.com/{i}")})).await;
    }
    let v = versions(&h, code).await;
    assert_eq!(v.len(), 100);
    assert_eq!(v[0]["version"], 105);
    assert_eq!(v[99]["version"], 6);
    let (status, _) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 5})),
        )
        .await;
    assert_eq!(status, 404);
    let (status, rolled) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 6})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(rolled["destinations"][0]["url"], "https://example.com/5");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM link_versions")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(count, 100);
    h.shutdown().await;
}

#[tokio::test]
async fn another_workspace_sees_no_history_or_schedules() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    let (status, _) = schedule(&h, code, json!({"run_at": in_secs(3600), "enabled": false})).await;
    assert_eq!(status, 201);
    let paths = [
        (Method::GET, format!("/v1/links/{code}/versions"), None),
        (
            Method::POST,
            format!("/v1/links/{code}/rollback"),
            Some(json!({"version": 1})),
        ),
        (Method::GET, format!("/v1/links/{code}/schedules"), None),
        (
            Method::POST,
            format!("/v1/links/{code}/schedules"),
            Some(json!({"run_at": in_secs(3600), "enabled": false})),
        ),
        (
            Method::DELETE,
            format!("/v1/links/{code}/schedules/1"),
            None,
        ),
    ];
    for (method, path, body) in paths {
        let (status, body) = h.api(method.clone(), &path, &h.bob, body).await;
        assert_eq!(status, 404, "{method} {path}: {body}");
    }
    // Row-level security, not only the queries: a tenant transaction for
    // bob's workspace reads none of alice's rows.
    let bob_ws = h.store.personal_workspace("bob").await.unwrap();
    let mut tx = h.store.begin_tenant(bob_ws).await.unwrap();
    for table in ["link_versions", "link_schedules"] {
        let n: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    drop(tx);
    h.shutdown().await;
}

#[tokio::test]
async fn schedules_are_validated_and_bounded() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    let ten_years = (Utc::now() + chrono::Duration::days(3651)).to_rfc3339();
    let bad = [
        json!({"run_at": in_secs(-1), "url": "https://example.com/x"}),
        json!({"run_at": ten_years, "url": "https://example.com/x"}),
        json!({"run_at": in_secs(60)}),
        json!({"url": "https://example.com/x"}),
        json!({"run_at": "tomorrow", "url": "https://example.com/x"}),
        json!({"run_at": in_secs(60), "url": "https://example.com/x",
               "destinations": [{"url": "https://example.com/y"}]}),
        json!({"run_at": in_secs(60), "url": "ftp://example.com/x"}),
        json!({"run_at": in_secs(60), "destinations": []}),
        json!({"run_at": in_secs(60), "destinations": [{"url": "https://example.com/y", "weight": 0}]}),
        json!({"run_at": in_secs(60), "max_clicks": 5}),
    ];
    for body in bad {
        let (status, resp) = schedule(&h, code, body.clone()).await;
        assert_eq!(status, 400, "{body}: {resp}");
    }
    // Destinations are stored normalised.
    let (status, s) = schedule(
        &h,
        code,
        json!({"run_at": in_secs(3600), "url": "HTTPS://Example.COM/x"}),
    )
    .await;
    assert_eq!(status, 201, "{s}");
    assert_eq!(
        s["change"],
        json!({"destinations": [{"url": "https://example.com/x", "weight": 1}]})
    );
    assert_eq!(s["state"], "pending");
    assert_eq!(s["member"], "alice");
    for i in 1..20 {
        let (status, _) = schedule(
            &h,
            code,
            json!({"run_at": in_secs(3600 + i), "enabled": i % 2 == 0}),
        )
        .await;
        assert_eq!(status, 201);
    }
    let (status, body) =
        schedule(&h, code, json!({"run_at": in_secs(7200), "enabled": true})).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "failed_precondition");

    // Listing pages newest first.
    let (_, page) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/schedules?limit=15"),
            &h.alice,
            None,
        )
        .await;
    let first = page["schedules"].as_array().unwrap();
    assert_eq!(first.len(), 15);
    assert!(
        first
            .windows(2)
            .all(|w| w[0]["id"].as_i64() > w[1]["id"].as_i64())
    );
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, rest) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/schedules?limit=15&cursor={cursor}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(rest["schedules"].as_array().unwrap().len(), 5);
    assert_eq!(rest["next_cursor"], Value::Null);

    // Cancelling frees a slot; a finished schedule cannot be cancelled.
    let id = s["id"].as_i64().unwrap();
    let path = format!("/v1/links/{code}/schedules/{id}");
    let (status, cancelled) = h.api(Method::DELETE, &path, &h.alice, None).await;
    assert_eq!(status, 200, "{cancelled}");
    assert_eq!(cancelled["state"], "canceled");
    assert!(cancelled["finished_at"].is_string());
    let (status, body) = h.api(Method::DELETE, &path, &h.alice, None).await;
    assert_eq!(status, 409, "{body}");
    for missing in ["999999", "0", "-1", "abc", "99999999999999999999"] {
        let (status, _) = h
            .api(
                Method::DELETE,
                &format!("/v1/links/{code}/schedules/{missing}"),
                &h.alice,
                None,
            )
            .await;
        assert_eq!(status, 404, "{missing}");
    }
    let (status, _) = schedule(&h, code, json!({"run_at": in_secs(7200), "enabled": true})).await;
    assert_eq!(status, 201);
    h.shutdown().await;
}

#[tokio::test]
async fn a_scheduled_swap_is_applied_on_time_and_cancelled_ones_are_not() {
    let mut h = harness!(("RELINK_SCHEDULE_POLL_MS", "50"));
    let link = h.create(json!({"url": "https://example.com/before"})).await;
    let code = link["code"].as_str().unwrap();
    // Cached now, so the swap must invalidate it.
    assert_eq!(
        location(&h.visit(code, &[]).await),
        "https://example.com/before"
    );
    let (status, swap) = schedule(
        &h,
        code,
        json!({"run_at": in_secs(1), "destinations": [{"url": "https://example.com/after", "weight": 2}]}),
    )
    .await;
    assert_eq!(status, 201, "{swap}");
    let (_, off) = schedule(&h, code, json!({"run_at": in_secs(1), "enabled": false})).await;
    let off_id = off["id"].as_i64().unwrap();
    let (status, _) = h
        .api(
            Method::DELETE,
            &format!("/v1/links/{code}/schedules/{off_id}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        location(&h.visit(code, &[]).await),
        "https://example.com/before"
    );

    assert!(
        eventually(Duration::from_secs(10), || async {
            let r = h.visit(code, &[]).await;
            r.status() == 302 && location(&r) == "https://example.com/after"
        })
        .await,
        "the scheduled swap was not applied"
    );
    let (_, list) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/schedules"),
            &h.alice,
            None,
        )
        .await;
    let list = list["schedules"].as_array().unwrap();
    let applied = list.iter().find(|s| s["id"] == swap["id"]).unwrap();
    assert_eq!(applied["state"], "applied");
    assert_eq!(applied["applied_version"], 2);
    assert!(applied["finished_at"].is_string());
    let cancelled = list.iter().find(|s| s["id"] == off_id).unwrap();
    assert_eq!(cancelled["state"], "canceled");
    assert_eq!(cancelled["applied_version"], Value::Null);

    let (_, now) = h
        .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(now["enabled"], true);
    assert_eq!(now["version"], 2);
    assert_eq!(now["destinations"][0]["weight"], 2);
    let v = versions(&h, code).await;
    assert_eq!(v[0]["source"], "schedule");
    assert_eq!(v[0]["schedule_id"], swap["id"]);
    assert_eq!(v[0]["member"], Value::Null);
    assert_eq!(v[0]["via"], "system");
    assert!(metric(&h.metrics().await, "relink_schedules_applied_total") >= 1.0);
    // A scheduled change can itself be rolled back.
    let (status, back) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": 1})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(back["destinations"][0]["url"], "https://example.com/before");
    h.shutdown().await;
}

#[tokio::test]
async fn two_instances_apply_each_schedule_exactly_once() {
    let mut h = harness!(("RELINK_SCHEDULE_POLL_MS", "10"));
    let other = h
        .second_instance(&[("RELINK_SCHEDULE_POLL_MS", "10")])
        .await;
    let mut codes = Vec::new();
    for i in 0..10 {
        let link = h
            .create(json!({"url": format!("https://example.com/{i}")}))
            .await;
        let code = link["code"].as_str().unwrap().to_owned();
        for step in 0..2 {
            let (status, body) = schedule(
                &h,
                &code,
                json!({"run_at": in_secs(2), "url": format!("https://example.com/{i}/{step}")}),
            )
            .await;
            assert_eq!(status, 201, "{body}");
        }
        codes.push(code);
    }
    let pool = direct(&h).await;
    assert!(
        eventually(Duration::from_secs(15), || async {
            let pending: i64 =
                sqlx::query_scalar("SELECT count(*) FROM link_schedules WHERE state <> 'applied'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            pending == 0
        })
        .await,
        "not every schedule was applied"
    );
    let applies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'schedule.apply'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(applies, 20);
    let scheduled: i64 =
        sqlx::query_scalar("SELECT count(*) FROM link_versions WHERE source = 'schedule'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scheduled, 20);
    // Each link went through both of its changes, in order: the second
    // schedule, with the higher ID, came last.
    for (i, code) in codes.iter().enumerate() {
        let (_, link) = h
            .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
            .await;
        assert_eq!(link["version"], 3, "{link}");
        assert_eq!(
            link["destinations"][0]["url"],
            format!("https://example.com/{i}/1")
        );
    }
    let applied_here = metric(&h.metrics().await, "relink_schedules_applied_total");
    let applied_there = other.app.metrics.schedules_applied.get() as f64;
    assert_eq!(applied_here + applied_there, 20.0);
    other.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn a_schedule_due_during_an_outage_is_applied_when_the_database_returns() {
    let mut h = harness!(
        ("RELINK_SCHEDULE_POLL_MS", "50"),
        ("RELINK_DB_TIMEOUT_MS", "500")
    );
    let link = h.create(json!({"url": "https://example.com/before"})).await;
    let code = link["code"].as_str().unwrap();
    let (status, s) = schedule(
        &h,
        code,
        json!({"run_at": in_secs(1), "url": "https://example.com/after"}),
    )
    .await;
    assert_eq!(status, 201);
    h.proxy.cut();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let pool = direct(&h).await;
    let state: String = sqlx::query_scalar("SELECT state FROM link_schedules WHERE id = $1")
        .bind(s["id"].as_i64().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "pending");
    assert!(
        metric(
            &h.metrics().await,
            "relink_db_errors_total{op=\"schedule\"}"
        ) >= 1.0
    );
    h.proxy.restore();
    assert!(
        eventually(Duration::from_secs(15), || async {
            let r = h.visit(code, &[]).await;
            r.status() == 302 && location(&r) == "https://example.com/after"
        })
        .await,
        "the schedule was not applied after the outage"
    );
    let row = sqlx::query("SELECT state, applied_version FROM link_schedules WHERE id = $1")
        .bind(s["id"].as_i64().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "applied");
    assert_eq!(row.get::<Option<i32>, _>("applied_version"), Some(2));
    h.shutdown().await;
}

#[tokio::test]
async fn an_unreadable_change_is_marked_failed_not_retried() {
    let mut h = harness!(("RELINK_SCHEDULE_POLL_MS", "50"));
    let link = h.create(json!({"url": "https://example.com/before"})).await;
    let code = link["code"].as_str().unwrap();
    let (_, s) = schedule(&h, code, json!({"run_at": in_secs(3600), "enabled": false})).await;
    let id = s["id"].as_i64().unwrap();
    // A row edited by hand into a shape the server does not write.
    let pool = direct(&h).await;
    sqlx::query(
        "UPDATE link_schedules SET change = '{\"colour\": \"blue\"}', run_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || async {
            let state: String =
                sqlx::query_scalar("SELECT state FROM link_schedules WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            state == "failed"
        })
        .await
    );
    let (_, list) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/schedules"),
            &h.alice,
            None,
        )
        .await;
    let s = &list["schedules"][0];
    assert!(
        s["error"].as_str().unwrap().contains("unreadable change"),
        "{s}"
    );
    let (_, now) = h
        .api(Method::GET, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(now["enabled"], true);
    assert_eq!(now["version"], 1);
    h.shutdown().await;
}

#[tokio::test]
async fn deleting_a_link_deletes_its_history_and_schedules() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    patch(&h, code, json!({"url": "https://example.com/2"})).await;
    schedule(&h, code, json!({"run_at": in_secs(3600), "enabled": false})).await;
    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    for table in ["link_versions", "link_schedules"] {
        let n: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(h.store.pool())
                .await
                .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn the_migration_starts_the_history_of_existing_links() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin).await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url)
        .await
        .unwrap();
    // Every migration before version history.
    let before = sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 18)
                .cloned()
                .collect(),
        ),
        ignore_missing: MIGRATOR.ignore_missing,
        locking: MIGRATOR.locking,
        no_tx: MIGRATOR.no_tx,
        table_name: MIGRATOR.table_name.clone(),
        create_schemas: MIGRATOR.create_schemas.clone(),
    };
    before.run(&pool).await.unwrap();
    // In a session whose time zone is not UTC, to show the snapshot is not
    // written in the session's.
    sqlx::raw_sql(
        "SET TIME ZONE 'Asia/Kolkata';
         INSERT INTO workspaces (name, personal_owner) VALUES ('old', 'old');
         INSERT INTO links (code, owner, workspace_id, destinations, redirect_status, expires_at,
                            max_clicks, geo_mode, geo_countries, fallback_url, enabled, rules, app)
         SELECT 'legacy1', 'old', id,
                '[{\"url\": \"https://example.com/a\", \"weight\": 2}]', 308,
                '2030-05-06 07:08:09.5+00', 7, 'deny', '{DE}', 'https://example.com/f', false,
                '[{\"if\": {\"language\": [\"de\"]}, \"url\": \"https://example.com/de\"}]',
                '{\"ios\": {\"store_url\": \"https://apps.apple.com/app/id1\"}}'
           FROM workspaces WHERE personal_owner = 'old';
         INSERT INTO links (code, owner, workspace_id, destinations)
         SELECT 'legacy2', 'old', id, '[{\"url\": \"https://example.com/b\", \"weight\": 1}]'
           FROM workspaces WHERE personal_owner = 'old';",
    )
    .execute(&pool)
    .await
    .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let rows = sqlx::query(
        "SELECT l.code, l.version AS current, v.version, v.source, v.via, v.member, v.spec \
         FROM links l JOIN link_versions v ON v.link_id = l.id ORDER BY l.code",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    for r in &rows {
        assert_eq!(r.get::<i32, _>("current"), 1);
        assert_eq!(r.get::<i32, _>("version"), 1);
        assert_eq!(r.get::<String, _>("source"), "migration");
        assert_eq!(r.get::<String, _>("via"), "system");
        assert_eq!(r.get::<Option<String>, _>("member"), None);
    }
    let spec: LinkSpec = serde_json::from_value(rows[0].get::<Value, _>("spec")).unwrap();
    assert_eq!(spec.destinations[0].url, "https://example.com/a");
    assert_eq!(spec.destinations[0].weight, 2);
    assert_eq!(spec.redirect_type, 308);
    assert_eq!(
        spec.expires_at.unwrap(),
        "2030-05-06T07:08:09.5Z".parse::<DateTime<Utc>>().unwrap()
    );
    assert_eq!(spec.max_clicks, Some(7));
    assert_eq!(spec.geo.as_ref().unwrap().countries, vec![*b"DE"]);
    assert_eq!(spec.fallback_url.as_deref(), Some("https://example.com/f"));
    assert!(!spec.enabled);
    assert_eq!(spec.rules.rules().len(), 1);
    assert!(spec.app.as_ref().unwrap().ios.is_some());
    let plain: LinkSpec = serde_json::from_value(rows[1].get::<Value, _>("spec")).unwrap();
    assert_eq!(plain.redirect_type, 302);
    assert!(plain.geo.is_none() && plain.expires_at.is_none() && plain.app.is_none());
    assert!(plain.enabled && plain.rules.rules().is_empty());

    // The same settings give the same snapshot in any time zone, so a
    // later change that sets nothing new is recognised as no change.
    for zone in ["UTC", "America/Los_Angeles", "Pacific/Chatham"] {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("SET TIME ZONE '{zone}'")))
            .execute(&mut *conn)
            .await
            .unwrap();
        let same: bool = sqlx::query_scalar(
            "SELECT bool_and(v.spec = relink_link_spec(l)) FROM links l \
             JOIN link_versions v ON v.link_id = l.id",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert!(same, "{zone}");
    }
    pool.close().await;
}

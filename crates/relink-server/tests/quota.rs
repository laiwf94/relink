//! Plans and quotas against Postgres and over HTTP: link limits are exact
//! under concurrent creation, clicks are metered per workspace and month
//! from the click pipeline and cap link creation, redirects are never
//! refused, the usage endpoint reports both, and tenants can neither move
//! themselves to another plan nor read another workspace's usage.

mod common;

use std::time::Duration;

use chrono::{Datelike, NaiveDate, Utc};
use common::{Harness, admin_url, eventually};
use relink_server::audit::Actor;
use relink_server::auth::{Scope, Scopes, generate_key, hash_key};
use relink_server::quota::{PlanChange, PlanError, month_start, next_month};
use relink_server::store::{ClickRow, Db, NewApiKey};
use relink_server::util::{now_ms, utc_day};
use reqwest::Method;
use serde_json::{Value, json};

macro_rules! harness {
    () => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[]).await
    }};
}

async fn workspace_of(store: &Db, owner: &str) -> i64 {
    store.personal_workspace(owner).await.unwrap()
}

async fn put_on_plan(store: &Db, ws: i64, name: &str, change: PlanChange) {
    store.set_plan(name, change).await.unwrap();
    store.assign_plan(ws, name, &Actor::cli()).await.unwrap();
}

fn limits(links: Option<i64>, clicks: Option<i64>) -> PlanChange {
    PlanChange {
        max_links: Some(links),
        monthly_clicks: Some(clicks),
    }
}

/// `relink_quota_exceeded_total{limit="..."}`.
fn quota_metric(text: &str, limit: &str) -> f64 {
    let prefix = format!("relink_quota_exceeded_total{{limit=\"{limit}\"}} ");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("no {prefix}"))
}

async fn usage(h: &Harness, key: &str) -> Value {
    let (status, body) = h.api(Method::GET, "/v1/usage", key, None).await;
    assert_eq!(status, 200, "{body}");
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_link_limit_is_exact_under_concurrent_creation() {
    let mut h = harness!();
    let ws = workspace_of(&h.store, "alice").await;
    put_on_plan(&h.store, ws, "small", limits(Some(5), None)).await;
    for _ in 0..2 {
        h.create(json!({"url": "https://example.com/"})).await;
    }

    // 20 requests race for the last 3 slots.
    let mut tasks = Vec::new();
    for i in 0..20 {
        let http = h.http.clone();
        let url = format!("{}/v1/links", h.base);
        let key = h.alice.clone();
        tasks.push(tokio::spawn(async move {
            let r = http
                .post(url)
                .bearer_auth(key)
                .header("content-type", "application/json")
                .body(json!({"url": format!("https://example.com/{i}")}).to_string())
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            let text = r.text().await.unwrap();
            (status, serde_json::from_str::<Value>(&text).unwrap())
        }));
    }
    let mut created = 0;
    let mut refused = 0;
    for t in tasks {
        let (status, body) = t.await.unwrap();
        match status {
            201 => created += 1,
            403 => {
                assert_eq!(body["error"]["code"], "quota_exceeded", "{body}");
                let msg = body["error"]["message"].as_str().unwrap();
                assert!(msg.contains("5 links"), "{msg}");
                refused += 1;
            }
            other => panic!("unexpected {other}: {body}"),
        }
    }
    assert_eq!((created, refused), (3, 17));
    let u = usage(&h, &h.alice).await;
    assert_eq!(u["plan"], "small");
    assert_eq!(u["links"], json!({"used": 5, "limit": 5}));
    assert_eq!(quota_metric(&h.metrics().await, "links"), 17.0);
    assert_eq!(quota_metric(&h.metrics().await, "monthly_clicks"), 0.0);

    // Deleting a link frees its slot.
    let (_, list) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    let code = list["links"][0]["code"].as_str().unwrap().to_owned();
    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    h.create(json!({"url": "https://example.com/again"})).await;

    // A lower limit keeps every existing link readable, changeable and
    // redirecting; only new ones are refused.
    h.store
        .set_plan("small", limits(Some(1), None))
        .await
        .unwrap();
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.com/"})),
        )
        .await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("quota_exceeded"))
    );
    let (_, list) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(list["links"].as_array().unwrap().len(), 5);
    let code = list["links"][0]["code"].as_str().unwrap().to_owned();
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"url": "https://example.com/changed"})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(h.visit(&code, &[]).await.status(), 302);

    // Another workspace is on its own plan.
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.com/"})),
        )
        .await;
    assert_eq!(status, 201);
    h.shutdown().await;
}

#[tokio::test]
async fn clicks_are_metered_per_month_and_cap_link_creation() {
    let mut h = harness!();
    let ws = workspace_of(&h.store, "alice").await;
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap().to_owned();
    for _ in 0..7 {
        assert_eq!(h.visit(&code, &[]).await.status(), 302);
    }
    assert!(
        eventually(Duration::from_secs(10), || async {
            usage(&h, &h.alice).await["clicks"]["used"] == 7
        })
        .await,
        "the meter did not reach 7: {}",
        usage(&h, &h.alice).await
    );
    let today = Utc::now().date_naive();
    let u = usage(&h, &h.alice).await;
    assert_eq!(u["workspace_id"], ws);
    assert_eq!(u["plan"], "unlimited");
    assert_eq!(u["clicks"]["limit"], Value::Null);
    assert_eq!(u["links"], json!({"used": 1, "limit": null}));
    assert_eq!(u["period_start"], month_start(today).to_string());
    assert_eq!(u["period_end"], next_month(month_start(today)).to_string());

    // At the month's allowance, creating links is refused until the
    // next month, but the link keeps redirecting and counting.
    put_on_plan(&h.store, ws, "metered", limits(None, Some(7))).await;
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.com/"})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "quota_exceeded");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains(&format!("again on {}", next_month(month_start(today)))),
        "{msg}"
    );
    assert_eq!(h.visit(&code, &[]).await.status(), 302);
    assert!(
        eventually(Duration::from_secs(10), || async {
            usage(&h, &h.alice).await["clicks"]["used"] == 8
        })
        .await
    );
    assert_eq!(quota_metric(&h.metrics().await, "monthly_clicks"), 1.0);
    h.store
        .set_plan(
            "metered",
            PlanChange {
                monthly_clicks: Some(Some(9)),
                ..PlanChange::default()
            },
        )
        .await
        .unwrap();
    h.create(json!({"url": "https://example.com/"})).await;

    // The meter follows the click's own day, not the flush time: a late
    // batch for the last day of the previous month lands in that month.
    let link_id: i64 = sqlx::query_scalar("SELECT id FROM links WHERE code = $1")
        .bind(&code)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let this_month = month_start(today);
    let last_day_before = this_month.pred_opt().unwrap();
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    let day = (last_day_before - epoch).num_days() as i32;
    let row = |n: &'static str| ClickRow {
        link_id,
        day,
        country: *b"DE",
        device: n,
        referrer: None,
    };
    h.store
        .flush_clicks(&[(row("desktop"), 4), (row("mobile"), 2)], &[])
        .await
        .unwrap();
    let months: Vec<(NaiveDate, i64)> = sqlx::query_as(
        "SELECT month, clicks FROM workspace_usage WHERE workspace_id = $1 ORDER BY month",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(
        months,
        vec![(month_start(last_day_before), 6), (this_month, 8)]
    );
    assert_eq!(month_start(last_day_before).day(), 1);

    // The meter and the statistics agree, month by month.
    let per_month: Vec<(NaiveDate, i64)> = sqlx::query_as(
        "SELECT day - (extract(day FROM day)::int - 1), sum(clicks)::bigint FROM click_daily \
          GROUP BY 1 ORDER BY 1",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(per_month, months);

    // Clicks for a link deleted before the flush are counted nowhere.
    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    let today_day = utc_day(now_ms());
    h.store
        .flush_clicks(
            &[(
                ClickRow {
                    day: today_day,
                    ..row("desktop")
                },
                5,
            )],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(usage(&h, &h.alice).await["clicks"]["used"], 8);
    h.shutdown().await;
}

#[tokio::test]
async fn usage_needs_stats_read_and_stays_in_its_workspace() {
    let mut h = harness!();
    let alice_ws = workspace_of(&h.store, "alice").await;
    let bob_ws = workspace_of(&h.store, "bob").await;
    let make = |scopes: Scopes| {
        let store = h.store.clone();
        async move {
            let key = generate_key();
            store
                .create_api_key(&NewApiKey {
                    owner: "alice",
                    name: "scoped",
                    hash: hash_key(&key),
                    workspace_id: None,
                    scopes,
                    lifetime: None,
                })
                .await
                .unwrap();
            key
        }
    };
    let stats_only = make(Scope::StatsRead.into()).await;
    let links_only = make(Scopes::from(Scope::LinksRead) | Scope::LinksWrite).await;
    assert_eq!(usage(&h, &stats_only).await["workspace_id"], alice_ws);
    let (status, body) = h.api(Method::GET, "/v1/usage", &links_only, None).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"]["code"], "permission_denied");
    assert_eq!(usage(&h, &h.bob).await["workspace_id"], bob_ws);
    // Naming another workspace is refused, as on every route.
    let r = h
        .http
        .get(format!("{}/v1/usage", h.base))
        .bearer_auth(&h.alice)
        .header("relink-workspace", bob_ws.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let (status, _) = h.api(Method::GET, "/v1/usage", "rlk_nope", None).await;
    assert_eq!(status, 401);
    h.shutdown().await;
}

#[tokio::test]
async fn tenants_cannot_move_plans_or_read_other_usage() {
    let mut h = harness!();
    let alice_ws = workspace_of(&h.store, "alice").await;
    let bob_ws = workspace_of(&h.store, "bob").await;
    h.store
        .set_plan("free", limits(Some(10), Some(100)))
        .await
        .unwrap();
    h.store
        .assign_plan(alice_ws, "free", &Actor::cli())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workspace_usage (workspace_id, month, clicks) VALUES ($1, '2026-01-01', 3), ($2, '2026-01-01', 4)",
    )
    .bind(alice_ws)
    .bind(bob_ws)
    .execute(h.store.pool())
    .await
    .unwrap();

    let mut tx = h.store.begin_tenant(alice_ws).await.unwrap();
    let err = sqlx::query("UPDATE workspaces SET plan = 'unlimited'")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("42501"),
        "{err}"
    );
    drop(tx);
    let mut tx = h.store.begin_tenant(alice_ws).await.unwrap();
    let renamed = sqlx::query("UPDATE workspaces SET name = 'renamed'")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(renamed.rows_affected(), 1);
    let rows: Vec<(i64, i64)> = sqlx::query_as("SELECT workspace_id, clicks FROM workspace_usage")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(rows, vec![(alice_ws, 3)]);
    for write in [
        "INSERT INTO workspace_usage (workspace_id, month, clicks) VALUES (relink_current_workspace(), '2026-02-01', 1)",
        "UPDATE workspace_usage SET clicks = 0",
        "UPDATE plans SET max_links = NULL",
    ] {
        let mut tx = h.store.begin_tenant(alice_ws).await.unwrap();
        let err = sqlx::query(write).execute(&mut *tx).await.unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("42501"),
            "{write}: {err}"
        );
    }
    tx.rollback().await.unwrap();
    h.shutdown().await;
}

#[tokio::test]
async fn plans_are_defined_assigned_and_audited() {
    let mut h = harness!();
    let ws = workspace_of(&h.store, "alice").await;
    let plans = h.store.plans().await.unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].name, "unlimited");
    assert_eq!(plans[0].limits.max_links, None);

    // A new plan starts without limits; a change touches only what it names.
    let p = h
        .store
        .set_plan(
            "team",
            PlanChange {
                max_links: Some(Some(50)),
                ..PlanChange::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (p.limits.max_links, p.limits.monthly_clicks),
        (Some(50), None)
    );
    let p = h
        .store
        .set_plan(
            "team",
            PlanChange {
                monthly_clicks: Some(Some(1000)),
                ..PlanChange::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (p.limits.max_links, p.limits.monthly_clicks),
        (Some(50), Some(1000))
    );
    let p = h
        .store
        .set_plan("team", PlanChange::default())
        .await
        .unwrap();
    assert_eq!(p.limits.max_links, Some(50));
    assert!(
        h.store
            .set_plan("Team!", PlanChange::default())
            .await
            .is_err()
    );

    assert_eq!(
        h.store.assign_plan(ws, "nope", &Actor::cli()).await,
        Err(PlanError::NoSuchPlan("nope".into()))
    );
    assert_eq!(
        h.store.assign_plan(999_999, "team", &Actor::cli()).await,
        Err(PlanError::NoSuchWorkspace(999_999))
    );
    let (old, new) = h
        .store
        .assign_plan(ws, "team", &Actor::cli())
        .await
        .unwrap();
    assert_eq!(
        (old.name.as_str(), new.name.as_str()),
        ("unlimited", "team")
    );

    let (actor, via, target, before, after): (Option<String>, String, String, Value, Value) =
        sqlx::query_as(
            "SELECT actor, via, target, before, after FROM audit_log \
              WHERE workspace_id = $1 AND action = 'workspace.plan'",
        )
        .bind(ws)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(actor, None);
    assert_eq!(via, "cli");
    assert_eq!(target, format!("workspace:{ws}"));
    assert_eq!(
        before,
        json!({"plan": "unlimited", "max_links": null, "monthly_clicks": null})
    );
    assert_eq!(
        after,
        json!({"plan": "team", "max_links": 50, "monthly_clicks": 1000})
    );
    h.store.verify_audit(Some(ws), &[]).await.unwrap();

    // A plan in use cannot be deleted.
    let err = sqlx::query("DELETE FROM plans WHERE name = 'team'")
        .execute(h.store.pool())
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let names: Vec<String> = h
        .store
        .plans()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert_eq!(names, ["team", "unlimited"]);
    h.shutdown().await;
}

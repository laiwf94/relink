//! Conversion tracking end to end (docs/DESIGN.md, "Conversions"): click
//! ids on redirects at the origin and as the edge mints them, postbacks
//! attributed to the click, destination and variant, duplicates, scopes,
//! workspaces, the attribution window, and stats per destination.

mod common;

use std::collections::BTreeMap;

use chrono::{Duration as ChronoDuration, Utc};
use common::{Harness, admin_url, metric};
use relink_core::abtest::Signer;
use relink_core::conversion::{self, ClickId, Target};
use relink_core::rules::{Decision, Settings, Visit, evaluate};
use relink_server::auth::{Scope, Scopes, generate_key, hash_key};
use relink_server::store::NewApiKey;
use reqwest::Method;
use serde_json::{Value, json};

macro_rules! harness {
    () => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[]).await
    }};
}

/// The key the harness signs with (`RELINK_COOKIE_KEY`).
const KEY: [u8; 32] = [0x5a; 32];

const A: &str = "https://shop.example.com/a";
const B: &str = "https://shop.example.com/b?ref=x";

async fn key_with(h: &Harness, owner: &str, scopes: Scopes) -> String {
    let key = generate_key();
    h.store
        .create_api_key(&NewApiKey {
            owner,
            name: "conversions",
            hash: hash_key(&key),
            workspace_id: None,
            scopes,
            lifetime: None,
        })
        .await
        .unwrap();
    key
}

/// Follows `code` once and returns where it went and its click id.
async fn click(h: &Harness, code: &str, headers: &[(&str, &str)]) -> (String, String) {
    let r = h.visit(code, headers).await;
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let to = r.headers()["location"].to_str().unwrap().to_owned();
    let id = conversion::find(&to)
        .unwrap_or_else(|| panic!("no click id in {to}"))
        .to_owned();
    (to, id)
}

async fn post(h: &Harness, key: &str, body: Value) -> (u16, Value) {
    h.api(Method::POST, "/v1/conversions", key, Some(body))
        .await
}

#[tokio::test]
async fn conversions_are_attributed_to_click_destination_and_variant() {
    let mut h = harness!();
    let poster = key_with(&h, "alice", Scope::ConversionsWrite.into()).await;
    let link = h
        .create(json!({
            "destinations": [{"url": A, "weight": 1}, {"url": B, "weight": 1}],
            "conversion_window_days": 7,
        }))
        .await;
    assert_eq!(link["conversion_window_days"], 7);
    let code = link["code"].as_str().unwrap().to_owned();

    // Every click carries its own id, which names the variant it was sent
    // to: 40 new visitors split over both.
    let signer = Signer::new(KEY);
    let mut ids = BTreeMap::new();
    for _ in 0..40 {
        let (to, id) = click(&h, &code, &[]).await;
        let c = ClickId::decode(&signer, &id).unwrap();
        let variant = match to.split_once("rl_cid=").unwrap().0 {
            "https://shop.example.com/a?" => 0,
            "https://shop.example.com/b?ref=x&" => 1,
            other => panic!("unexpected location {other}"),
        };
        assert_eq!(c.target, Target::Destination(variant));
        assert_eq!(c.link_id, link_id(&h, &code).await);
        assert!((c.at_ms() - Utc::now().timestamp_millis()).abs() < 5_000);
        assert!(ids.insert(id, variant).is_none(), "ids are unique");
    }
    assert_eq!(
        ids.values()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    let pick = |v: u8| {
        ids.iter()
            .filter(|&(_, &w)| w == v)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };
    let (on_a, on_b) = (pick(0), pick(1));

    // A signup and a purchase from a click on B.
    let (status, signup) = post(&h, &poster, json!({"click_id": on_b[0], "event": "signup"})).await;
    assert_eq!(status, 201, "{signup}");
    assert_eq!(signup["link"], code.as_str());
    assert_eq!(signup["domain"], Value::Null);
    assert_eq!(signup["target"], "destination");
    assert_eq!(signup["variant"], 1);
    assert_eq!(signup["rule"], Value::Null);
    assert_eq!(signup["destination"], B);
    assert_eq!(signup["duplicate"], false);
    assert_eq!(signup["value"], Value::Null);
    let (status, sale) = post(
        &h,
        &poster,
        json!({"click_id": on_b[0], "event": "purchase", "value": 4999, "currency": "EUR",
               "external_id": "order-1"}),
    )
    .await;
    assert_eq!(status, 201, "{sale}");
    assert_eq!(
        (&sale["value"], &sale["currency"]),
        (&json!(4999), &json!("EUR"))
    );

    // Posting either again gives the stored one back, counted once; the
    // same order from another click is the same conversion.
    let (status, again) = post(&h, &poster, json!({"click_id": on_b[0], "event": "signup"})).await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["duplicate"], true);
    assert_eq!(again["id"], signup["id"]);
    let (status, same_order) = post(
        &h,
        &poster,
        json!({"click_id": on_a[0], "event": "purchase", "value": 1, "external_id": "order-1"}),
    )
    .await;
    assert_eq!(status, 200, "{same_order}");
    assert_eq!(same_order["id"], sale["id"]);
    assert_eq!(same_order["click_id"], on_b[0].as_str());
    assert_eq!(same_order["variant"], 1);

    // Purchases on A, one in dollars and one without a value.
    for (i, (id, value, currency)) in [
        (&on_a[0], Some(1000), Some("USD")),
        (&on_a[1], Some(2500), Some("USD")),
        (&on_a[1], None, None),
    ]
    .into_iter()
    .enumerate()
    {
        let mut body =
            json!({"click_id": id, "event": "purchase", "external_id": format!("a-{i}")});
        if let Some(v) = value {
            body["value"] = json!(v);
        }
        if let Some(c) = currency {
            body["currency"] = json!(c);
        }
        let (status, c) = post(&h, &poster, body).await;
        assert_eq!(status, 201, "{c}");
        assert_eq!((&c["variant"], &c["destination"]), (&json!(0), &json!(A)));
    }

    // Stats per destination: both variants in order, then nothing else.
    let path = format!("/v1/links/{code}/conversions");
    let (status, stats) = h.api(Method::GET, &path, &h.alice, None).await;
    assert_eq!(status, 200, "{stats}");
    assert_eq!(stats["conversions"], 5);
    assert_eq!(stats["converted_clicks"], 3);
    assert_eq!(stats["events"], json!({"purchase": 4, "signup": 1}));
    assert_eq!(
        stats["values"],
        json!([
            {"currency": "EUR", "total": 4999, "conversions": 1},
            {"currency": "USD", "total": 3500, "conversions": 2},
        ])
    );
    assert_eq!(stats["conversion_window_days"], 7);
    let d = stats["destinations"].as_array().unwrap();
    assert_eq!(d.len(), 2, "{stats}");
    assert_eq!(
        (&d[0]["variant"], &d[0]["destination"], &d[0]["current"]),
        (&json!(0), &json!(A), &json!(true))
    );
    assert_eq!(
        (&d[0]["conversions"], &d[0]["converted_clicks"]),
        (&json!(3), &json!(2))
    );
    assert_eq!(d[0]["events"], json!({"purchase": 3}));
    assert_eq!(
        (&d[1]["variant"], &d[1]["destination"]),
        (&json!(1), &json!(B))
    );
    assert_eq!(
        (&d[1]["conversions"], &d[1]["converted_clicks"]),
        (&json!(2), &json!(1))
    );
    let (_, signups) = h
        .api(Method::GET, &format!("{path}?event=signup"), &h.alice, None)
        .await;
    assert_eq!(signups["conversions"], 1);
    assert_eq!(signups["destinations"][0]["conversions"], 0);
    assert_eq!(signups["destinations"][1]["conversions"], 1);
    let yesterday = (Utc::now() - ChronoDuration::days(1)).date_naive();
    let (_, before) = h
        .api(
            Method::GET,
            &format!("{path}?from={yesterday}&to={yesterday}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(before["conversions"], 0);

    // The destinations change: a click from before still names B, from
    // the link's kept versions, and is listed after the current ones.
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"url": "https://shop.example.com/c"})),
        )
        .await;
    assert_eq!(status, 200);
    let (status, late) = post(&h, &poster, json!({"click_id": on_b[1], "event": "signup"})).await;
    assert_eq!(status, 201, "{late}");
    assert_eq!(
        (&late["variant"], &late["destination"]),
        (&json!(1), &json!(B))
    );
    let (_, stats) = h.api(Method::GET, &path, &h.alice, None).await;
    let d = stats["destinations"].as_array().unwrap();
    let rows: Vec<_> = d
        .iter()
        .map(|d| {
            (
                d["destination"].clone(),
                d["current"].clone(),
                d["conversions"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (json!("https://shop.example.com/c"), json!(true), json!(0)),
            // A tie, so in variant order.
            (json!(A), json!(false), json!(3)),
            (json!(B), json!(false), json!(3)),
        ]
    );
    // A new click goes to the new destination.
    let (to, id) = click(&h, &code, &[]).await;
    assert!(to.starts_with("https://shop.example.com/c?rl_cid="), "{to}");
    let (_, now) = post(&h, &poster, json!({"click_id": id, "event": "signup"})).await;
    assert_eq!(now["destination"], "https://shop.example.com/c");

    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_conversions_total"), 7.0);
    assert_eq!(metric(&m, "relink_conversions_duplicate_total"), 2.0);
    h.shutdown().await;
}

async fn link_id(h: &Harness, code: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM links WHERE code = $1")
        .bind(code)
        .fetch_one(h.store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn postbacks_are_checked() {
    let mut h = harness!();
    let poster = key_with(&h, "alice", Scope::ConversionsWrite.into()).await;
    let link = h
        .create(json!({"url": A, "conversion_window_days": 1}))
        .await;
    let code = link["code"].as_str().unwrap().to_owned();
    let (to, id) = click(&h, &code, &[]).await;
    assert_eq!(to, format!("{A}?rl_cid={id}"));

    // The scope: a key that posts conversions does nothing else, and a key
    // without the scope cannot post.
    let (status, _) = h.api(Method::GET, "/v1/links", &poster, None).await;
    assert_eq!(status, 403);
    let reader = key_with(
        &h,
        "alice",
        Scopes::from(Scope::LinksRead) | Scope::StatsRead,
    )
    .await;
    let (status, body) = post(&h, &reader, json!({"click_id": id, "event": "signup"})).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("conversions:write")
    );

    // Malformed bodies, and ids that are not this deployment's.
    for (body, field) in [
        (json!({"click_id": id, "event": "sign up"}), "event"),
        (
            json!({"click_id": id, "event": "sale", "currency": "EUR"}),
            "currency",
        ),
        (
            json!({"click_id": id, "event": "sale", "value": -1}),
            "value",
        ),
        (
            json!({"click_id": id, "event": "sale",
                   "occurred_at": (Utc::now() + ChronoDuration::hours(1)).to_rfc3339()}),
            "occurred_at",
        ),
        (json!({"click_id": "x", "event": "sale"}), "click_id"),
        (
            json!({"click_id": id.replace(&id[..1], if &id[..1] == "A" { "B" } else { "A" }), "event": "sale"}),
            "click_id",
        ),
        (
            json!({"click_id": id, "event": "sale", "extra": 1}),
            "extra",
        ),
    ] {
        let (status, err) = post(&h, &poster, body.clone()).await;
        assert_eq!(status, 400, "{body}: {err}");
        assert!(
            err["error"]["message"].as_str().unwrap().contains(field),
            "{body}: {err}"
        );
    }
    let forged = ClickId::decode(&Signer::new(KEY), &id).unwrap();
    let other_key = forged.encode(&Signer::new([1; 32]));
    let (status, _) = post(&h, &poster, json!({"click_id": other_key, "event": "sale"})).await;
    assert_eq!(status, 400);

    // Another workspace holding a real click id finds nothing.
    let (status, err) = post(&h, &h.bob, json!({"click_id": id, "event": "signup"})).await;
    assert_eq!(status, 404, "{err}");
    let (status, _) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/conversions"),
            &h.bob,
            None,
        )
        .await;
    assert_eq!(status, 404);

    // The window: a day after the click, and not before it.
    let click_at = ClickId::decode(&Signer::new(KEY), &id).unwrap().at_ms();
    let at = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(click_at + ms)
            .unwrap()
            .to_rfc3339()
    };
    let (status, err) = post(
        &h,
        &poster,
        json!({"click_id": id, "event": "early", "occurred_at": at(-301_000)}),
    )
    .await;
    assert_eq!(status, 409, "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("before the click")
    );
    // A click id from two days ago, as the edge would have minted it.
    let old = ClickId {
        at_secs: forged.at_secs - 2 * 86_400,
        ..forged
    }
    .encode(&Signer::new(KEY));
    let (status, err) = post(&h, &poster, json!({"click_id": old, "event": "late"})).await;
    assert_eq!(status, 409, "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("attribution window of 1 days")
    );
    let (status, ok) = post(&h, &poster, json!({"click_id": id, "event": "ok"})).await;
    assert_eq!(status, 201, "{ok}");

    // Tracking turned off: no more ids, and conversions are refused.
    let (status, patched) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &h.alice,
            Some(json!({"conversion_window_days": null})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(patched["conversion_window_days"], Value::Null);
    let r = h.visit(&code, &[]).await;
    assert_eq!(r.headers()["location"], A);
    let (status, err) = post(&h, &poster, json!({"click_id": id, "event": "after"})).await;
    assert_eq!(status, 409, "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not track conversions")
    );
    for bad in [0, 366] {
        let (status, _) = h
            .api(
                Method::PATCH,
                &format!("/v1/links/{code}"),
                &h.alice,
                Some(json!({"conversion_window_days": bad})),
            )
            .await;
        assert_eq!(status, 400, "{bad}");
    }

    // The window is part of the link's versions: rolling back restores it.
    let (_, versions) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/versions"),
            &h.alice,
            None,
        )
        .await;
    let v = versions["versions"].as_array().unwrap();
    assert_eq!(v[0]["settings"]["conversion_window_days"], Value::Null);
    assert_eq!(v[1]["settings"]["conversion_window_days"], 1);
    let (status, back) = h
        .api(
            Method::POST,
            &format!("/v1/links/{code}/rollback"),
            &h.alice,
            Some(json!({"version": v[1]["version"]})),
        )
        .await;
    assert_eq!(status, 200, "{back}");
    let (_, id) = click(&h, &code, &[]).await;
    let (status, _) = post(&h, &poster, json!({"click_id": id, "event": "restored"})).await;
    assert_eq!(status, 201);

    // Deleting the link deletes its conversions.
    let (status, _) = h
        .api(Method::DELETE, &format!("/v1/links/{code}"), &h.alice, None)
        .await;
    assert_eq!(status, 204);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM conversions")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
    let (status, _) = post(&h, &poster, json!({"click_id": id, "event": "gone"})).await;
    assert_eq!(status, 404);
    assert!(metric(&h.metrics().await, "relink_conversions_rejected_total") >= 12.0);
    h.shutdown().await;
}

#[tokio::test]
async fn rules_apps_and_edge_clicks_are_attributed() {
    let mut h = harness!();
    let poster = key_with(&h, "alice", Scope::ConversionsWrite.into()).await;
    let link = h
        .create(json!({
            "url": A,
            "conversion_window_days": 30,
            "rules": [{"if": {"country": ["DE"]}, "url": "https://shop.example.de/"}],
            "app": {"ios": {"store_url": "https://apps.apple.com/app/id123456789"}},
        }))
        .await;
    let code = link["code"].as_str().unwrap().to_owned();

    let (to, id) = click(&h, &code, &[("cf-ipcountry", "DE")]).await;
    assert!(to.starts_with("https://shop.example.de/?rl_cid="), "{to}");
    let (status, c) = post(&h, &poster, json!({"click_id": id, "event": "signup"})).await;
    assert_eq!(status, 201, "{c}");
    assert_eq!(
        (&c["target"], &c["rule"], &c["variant"]),
        (&json!("rule"), &json!(0), &Value::Null)
    );
    assert_eq!(c["destination"], "https://shop.example.de/");

    let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
    let (to, id) = click(&h, &code, &[("user-agent", iphone)]).await;
    assert!(
        to.starts_with("https://apps.apple.com/app/id123456789?rl_cid="),
        "{to}"
    );
    let (_, c) = post(&h, &poster, json!({"click_id": id, "event": "install"})).await;
    assert_eq!(
        (&c["target"], &c["destination"]),
        (
            &json!("app"),
            &json!("https://apps.apple.com/app/id123456789")
        )
    );

    // The edge evaluates the record it reads from KV with the same code
    // and key; its click ids are accepted like the origin's.
    let stored = h
        .store
        .link_by_key(&relink_server::store::link_key(None, &code))
        .await
        .unwrap()
        .unwrap();
    let record: relink_core::model::Link =
        serde_json::from_str(&serde_json::to_string(&stored.link).unwrap()).unwrap();
    assert_eq!(record.conversion_window_days, Some(30));
    let signer = Signer::new(KEY);
    let settings = Settings {
        signer: &signer,
        cookie_secure: true,
    };
    let visit = Visit {
        now_ms: Utc::now().timestamp_millis(),
        random: 7,
        ..Visit::default()
    };
    let Decision::Redirect(r) = evaluate(&record, &visit, &settings) else {
        panic!("expected a redirect");
    };
    assert!(!r.cacheable);
    let to = conversion::location(&record, &r, &signer, visit.now_ms, visit.random);
    let id = conversion::find(&to).unwrap();
    let (status, c) = post(&h, &poster, json!({"click_id": id, "event": "signup"})).await;
    assert_eq!(status, 201, "{c}");
    assert_eq!(
        (&c["target"], &c["variant"], &c["destination"]),
        (&json!("destination"), &json!(0), &json!(A))
    );

    let (_, stats) = h
        .api(
            Method::GET,
            &format!("/v1/links/{code}/conversions"),
            &h.alice,
            None,
        )
        .await;
    let rows: Vec<_> = stats["destinations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["target"].clone(),
                d["destination"].clone(),
                d["conversions"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (json!("destination"), json!(A), json!(1)),
            (
                json!("app"),
                json!("https://apps.apple.com/app/id123456789"),
                json!(1)
            ),
            (json!("rule"), json!("https://shop.example.de/"), json!(1)),
        ]
    );
    h.shutdown().await;
}

//! Publishing link records to KV, against a local fake of the Cloudflare KV
//! REST API (no account, no network).

mod common;
#[path = "common/kv.rs"]
mod kv;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{FakeDns, Harness, admin_url, config, eventually};
use kv::{FakeKv, TOKEN, fake_kv};
use relink_core::wire::{EdgeDomain, domain_kv_key, host_kv_key};
use relink_server::config::KvConfig;
use relink_server::kvsync::{CloudflareHostnames, CloudflareKv, KvSync};
use relink_server::metrics::Metrics;
use relink_server::model::Link;
use reqwest::Method;
use serde_json::{Value, json};
use tokio::sync::Notify;

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
        common::insert_link(
            &store,
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
                rules: Default::default(),
                app: Default::default(),
                domain: None,
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

const HOST: &str = "go.relink-docs.net";

#[tokio::test]
async fn custom_domains_are_published_with_their_hostnames() {
    let Some(admin) = admin_url() else { return };
    let (addr, kv) = fake_kv().await;
    let dns = FakeDns::start().await;
    let base = format!("http://{addr}/client/v4");
    let dns_addr = dns.addr.to_string();
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_KV_ACCOUNT_ID", "acct1"),
            ("RELINK_KV_NAMESPACE_ID", "ns1"),
            ("RELINK_KV_API_TOKEN", TOKEN),
            ("RELINK_KV_API_BASE", &base),
            ("RELINK_KV_ZONE_ID", "zone1"),
            ("RELINK_KV_POLL_MS", "50"),
            ("RELINK_DNS_SERVERS", &dns_addr),
        ],
    )
    .await;
    // A hostname the operator added by hand stays whatever relink does.
    kv.hostnames
        .lock()
        .unwrap()
        .insert("manual".into(), "www.relink-docs.net".into());

    let (status, d) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({"hostname": HOST})),
        )
        .await;
    assert_eq!(status, 201, "{d}");
    let txt = d["verification"]["value"].as_str().unwrap().to_owned();
    dns.set_txt(&format!("_relink-challenge.{HOST}"), &[&txt]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !kv.keys().iter().any(|k| k.contains(HOST)),
        "nothing is published before the domain is verified"
    );
    let (_, d) = h
        .api(
            Method::POST,
            &format!("/v1/domains/{HOST}/verify"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(d["verified"], true, "{d}");
    let domain_id = h.store.verified_domain_id(HOST).await.unwrap().unwrap();
    let host_key = host_kv_key(HOST);
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.values.lock().unwrap().contains_key(&host_key)
        })
        .await,
        "verifying publishes the domain record"
    );
    let rec: EdgeDomain = serde_json::from_str(&kv.values.lock().unwrap()[&host_key]).unwrap();
    assert_eq!(
        rec,
        EdgeDomain {
            id: domain_id,
            settings: Default::default(),
            files: Default::default(),
        }
    );
    assert_eq!(kv.hostnames(), [HOST, "www.relink-docs.net"]);

    // Changing the domain's settings republishes its record with them.
    let (status, d) = h
        .api(
            Method::PATCH,
            &format!("/v1/domains/{HOST}"),
            &h.alice,
            Some(json!({"prefixes": ["Campaign"], "gone_page": "<p>gone</p>"})),
        )
        .await;
    assert_eq!(status, 200, "{d}");
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.values
                .lock()
                .unwrap()
                .get(&host_key)
                .and_then(|v| serde_json::from_str::<EdgeDomain>(v).ok())
                .is_some_and(|r| r.settings.prefixes == ["campaign"])
        })
        .await,
        "a settings change reaches the edge record"
    );
    let rec: EdgeDomain = serde_json::from_str(&kv.values.lock().unwrap()[&host_key]).unwrap();
    assert_eq!(rec.id, domain_id);
    assert_eq!(rec.settings.gone_page.as_deref(), Some("<p>gone</p>"));

    // Apps reach the edge as rendered association files, not as the list.
    let (status, d) = h
        .api(
            Method::PATCH,
            &format!("/v1/domains/{HOST}"),
            &h.alice,
            Some(json!({"apps": {"android": [{"package": "com.example.app",
                "sha256_cert_fingerprints": ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"]}]}})),
        )
        .await;
    assert_eq!(status, 200, "{d}");
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.values
                .lock()
                .unwrap()
                .get(&host_key)
                .and_then(|v| serde_json::from_str::<EdgeDomain>(v).ok())
                .is_some_and(|r| r.files.android.is_some())
        })
        .await,
        "an apps change reaches the edge record"
    );
    let raw = kv.values.lock().unwrap()[&host_key].clone();
    let rec: EdgeDomain = serde_json::from_str(&raw).unwrap();
    assert!(rec.files.apple.is_none());
    assert!(
        rec.files
            .android
            .unwrap()
            .contains(r#""package_name":"com.example.app""#)
    );
    assert!(!raw.contains(r#""apps""#), "{raw}");

    // The same code on both domains: two records, each under its own key.
    h.create(json!({"url": "https://a.example.org/", "alias": "promo"}))
        .await;
    let (status, b) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://b.example.org/", "alias": "promo", "domain": HOST})),
        )
        .await;
    assert_eq!(status, 201, "{b}");
    let link_key = domain_kv_key(HOST, "promo");
    assert_eq!(link_key, "link:go.relink-docs.net/promo");
    assert!(
        eventually(Duration::from_secs(5), || async {
            let v = kv.values.lock().unwrap();
            v.contains_key(&link_key) && v.contains_key("link:promo")
        })
        .await
    );
    let on_domain: Link = serde_json::from_str(&kv.values.lock().unwrap()[&link_key]).unwrap();
    assert_eq!(on_domain.destinations[0].url, "https://b.example.org/");
    assert_eq!(
        record(&kv, "promo").unwrap().destinations[0].url,
        "https://a.example.org/"
    );

    // Changes to the domain's link reach its key only.
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/promo?domain={HOST}"),
            &h.alice,
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.values
                .lock()
                .unwrap()
                .get(&link_key)
                .is_some_and(|v| !serde_json::from_str::<Link>(v).unwrap().enabled)
        })
        .await
    );
    assert!(record(&kv, "promo").unwrap().enabled);

    // Deleting the link and then the domain removes both records and the
    // custom hostname, but not the operator's.
    let (status, _) = h
        .api(
            Method::DELETE,
            &format!("/v1/links/promo?domain={HOST}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 204);
    // Removal fails for a while; the entry is retried.
    kv.hostnames_down.store(true, Ordering::SeqCst);
    let (status, _) = h
        .api(
            Method::DELETE,
            &format!("/v1/domains/{HOST}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 204);
    assert!(
        eventually(Duration::from_secs(5), || async {
            !kv.values.lock().unwrap().contains_key(&host_key)
                && !kv.values.lock().unwrap().contains_key(&link_key)
        })
        .await
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        kv.hostnames(),
        [HOST, "www.relink-docs.net"],
        "the zone is down"
    );
    kv.hostnames_down.store(false, Ordering::SeqCst);
    assert!(
        eventually(Duration::from_secs(10), || async {
            kv.hostnames() == ["www.relink-docs.net"]
        })
        .await,
        "the retry removes the hostname"
    );
    assert_eq!(kv.keys(), ["link:promo"]);
    assert_eq!(kv.unauthorized.load(Ordering::SeqCst), 0);
    let m = h.metrics().await;
    assert!(m.contains("relink_edge_hostnames_added_total 1"), "{m}");
    assert!(m.contains("relink_edge_hostnames_removed_total 1"), "{m}");
    h.shutdown().await;
}

#[tokio::test]
async fn reconciliation_repairs_domain_drift() {
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
            ("RELINK_KV_ZONE_ID", "zone1"),
        ],
    );
    let store = relink_server::server::open_db(&cfg).unwrap();
    relink_server::server::migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    // Two verified domains and one that is not, straight in the database.
    let ws = store.personal_workspace("alice").await.unwrap();
    let mut ids = Vec::new();
    for (host, verified) in [
        ("a.relink-docs.net", true),
        ("b.relink-docs.net", true),
        ("c.relink-docs.net", false),
    ] {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO domains (workspace_id, hostname, verification_token, created_by, verified_at)
             VALUES ($1, $2, repeat('ab', 16), 'alice', CASE WHEN $3 THEN now() END) RETURNING id",
        )
        .bind(ws)
        .bind(host)
        .bind(verified)
        .fetch_one(store.pool())
        .await
        .unwrap();
        ids.push(id);
    }
    // Links on each, and on the default domain; the unverified domain's
    // link (only possible by hand) is never published.
    for (i, domain) in [None, Some(ids[0]), Some(ids[0]), Some(ids[1]), Some(ids[2])]
        .into_iter()
        .enumerate()
    {
        sqlx::query(
            "INSERT INTO links (code, owner, workspace_id, domain_id, destinations)
             VALUES ($1, 'alice', $2, $3, '[{\"url\":\"https://example.com/\",\"weight\":1}]')",
        )
        .bind(if i == 2 { "other" } else { "promo" })
        .bind(ws)
        .bind(domain)
        .execute(store.pool())
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
    )
    .with_hostnames(Arc::new(
        CloudflareHostnames::new(&kv_cfg).unwrap().unwrap(),
    ));
    // Nothing was queued (the rows went in by hand): reconciliation finds
    // all of it.
    assert_eq!(sync.reconcile_once().await.unwrap(), 6);
    assert_eq!(sync.round().await, 6);
    let all = [
        "host:a.relink-docs.net",
        "host:b.relink-docs.net",
        "link:a.relink-docs.net/other",
        "link:a.relink-docs.net/promo",
        "link:b.relink-docs.net/promo",
        "link:promo",
    ];
    assert_eq!(kv.keys(), all);
    assert_eq!(kv.hostnames(), ["a.relink-docs.net", "b.relink-docs.net"]);
    assert_eq!(sync.reconcile_once().await.unwrap(), 0);

    // Drift: a domain record and a link deleted by hand, stray keys left
    // behind (one not even a key relink writes), a custom hostname removed
    // in the dashboard.
    {
        let mut v = kv.values.lock().unwrap();
        v.remove("host:b.relink-docs.net");
        v.remove("link:a.relink-docs.net/other");
        v.insert("link:c.relink-docs.net/promo".into(), "{}".into());
        v.insert("host:gone.relink-docs.net".into(), "{}".into());
        v.insert("link:Bad/Key".into(), "{}".into());
    }
    kv.hostnames
        .lock()
        .unwrap()
        .retain(|_, h| h != "a.relink-docs.net");
    assert_eq!(sync.reconcile_once().await.unwrap(), 6);
    assert_eq!(sync.round().await, 6);
    assert_eq!(kv.keys(), all);
    assert_eq!(kv.hostnames(), ["a.relink-docs.net", "b.relink-docs.net"]);
    assert_eq!(sync.reconcile_once().await.unwrap(), 0);

    // More hostnames than one page: listing pages through all of them.
    for i in 0..5 {
        kv.hostnames
            .lock()
            .unwrap()
            .insert(format!("x{i}"), format!("x{i}.example.net"));
    }
    assert_eq!(sync.reconcile_once().await.unwrap(), 0);

    // When the hostname API is down, reconciliation fails (and is retried
    // on the next tick) rather than queueing every domain.
    kv.hostnames_down.store(true, Ordering::SeqCst);
    assert!(sync.reconcile_once().await.is_err());
    assert_eq!(metrics.kv_reconciled.get(), 12);
    assert_eq!(metrics.edge_hostnames_added.get(), 3);
    assert_eq!(metrics.edge_hostnames_removed.get(), 0);
}

#[tokio::test]
async fn outbox_entries_queued_before_the_migration_keep_working() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    // The outbox is keyed by whole KV keys now, and only those.
    let err = sqlx::query("INSERT INTO kv_outbox (key) VALUES ('promo')")
        .execute(store.pool())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("kv_outbox_key_shape"), "{err}");
    store
        .enqueue_outbox(&["link:promo".into(), "host:go.example.com".into()])
        .await
        .unwrap();
    let mut due: Vec<String> = store
        .claim_outbox(10)
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    due.sort();
    assert_eq!(due, ["host:go.example.com", "link:promo"]);
}

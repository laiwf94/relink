//! Custom domains (migration 0010) against Postgres and over HTTP: a
//! workspace adds a domain, proves it with a DNS TXT record answered by a
//! local resolver, creates links on it whose codes are unique per domain,
//! and visitors are routed by `Host` on every instance; the first workspace
//! to prove a hostname gets it, plans limit how many domains a workspace
//! holds, only admins and owners manage them, and a domain with links
//! cannot be deleted.

mod common;

use std::time::Duration;

use common::{FakeDns, Harness, admin_url, eventually};
use relink_server::audit::Actor;
use relink_server::auth::{Role, generate_key, hash_key};
use relink_server::quota::PlanChange;
use relink_server::store::{Db, NewApiKey};
use reqwest::Method;
use serde_json::{Value, json};

const HOST: &str = "go.relink-docs.net";

async fn harness(dns: &FakeDns) -> Option<Harness> {
    let admin = admin_url()?;
    let addr = dns.addr.to_string();
    Some(Harness::start(&admin, &[("RELINK_DNS_SERVERS", &addr)]).await)
}

async fn workspace_of(store: &Db, owner: &str) -> i64 {
    store.personal_workspace(owner).await.unwrap()
}

/// GET /{code} with a Host header, without following redirects; returns
/// the status and the Location, if any.
async fn visit_as(h: &Harness, base: &str, host: &str, code: &str) -> (u16, Option<String>) {
    let r = h
        .http
        .get(format!("{base}/{code}"))
        .header("host", host)
        .send()
        .await
        .unwrap();
    let location = r
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_owned());
    (r.status().as_u16(), location)
}

async fn add(h: &Harness, key: &str, hostname: &str) -> (u16, Value) {
    h.api(
        Method::POST,
        "/v1/domains",
        key,
        Some(json!({ "hostname": hostname })),
    )
    .await
}

async fn verify(h: &Harness, key: &str, hostname: &str) -> (u16, Value) {
    h.api(
        Method::POST,
        &format!("/v1/domains/{hostname}/verify"),
        key,
        None,
    )
    .await
}

#[tokio::test]
async fn a_verified_domain_serves_its_own_codes() {
    let dns = FakeDns::start().await;
    let Some(mut h) = harness(&dns).await else {
        return;
    };
    // A second instance, running before the domain is verified, learns of
    // it from the change notification.
    let other = h.second_instance(&[]).await;
    let other_base = format!("http://{}", other.addr);

    let (status, d) = add(&h, &h.alice, "  Go.Relink-Docs.NET. ").await;
    assert_eq!(status, 201, "{d}");
    assert_eq!(d["hostname"], HOST);
    assert_eq!(d["verified"], false);
    assert_eq!(d["created_by"], "alice");
    assert_eq!(d["verification"]["type"], "TXT");
    assert_eq!(
        d["verification"]["name"],
        "_relink-challenge.go.relink-docs.net"
    );
    let record = d["verification"]["value"].as_str().unwrap().to_owned();
    assert!(record.starts_with("relink-domain-verification="));
    // Adding it again is a conflict; listing shows it once.
    assert_eq!(add(&h, &h.alice, HOST).await.0, 409);
    let (_, list) = h.api(Method::GET, "/v1/domains", &h.alice, None).await;
    assert_eq!(list["domains"].as_array().unwrap().len(), 1);

    // Not verified yet: no links on it, and a check without the record
    // says what it found.
    let on_domain = |dest: &str| json!({"url": dest, "alias": "promo", "domain": HOST});
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("https://b.example.org/")),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not a verified domain")
    );
    let (status, d) = verify(&h, &h.alice, HOST).await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(d["verified"], false);
    assert_eq!(d["check_error"], "no TXT record found");
    assert!(d["checked_at"].is_string());
    dns.set_txt("_relink-challenge.go.relink-docs.net", &["v=spf1 -all"]);
    let (_, d) = verify(&h, &h.alice, HOST).await;
    assert!(
        d["check_error"]
            .as_str()
            .unwrap()
            .contains("none starting with"),
        "{d}"
    );

    // With the record published the domain is verified, and stays so.
    dns.set_txt(
        "_relink-challenge.go.relink-docs.net",
        &["v=spf1 -all", &record],
    );
    let (status, d) = verify(&h, &h.alice, &HOST.to_uppercase()).await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(d["verified"], true, "{d}");
    assert_eq!(d["check_error"], Value::Null);
    let verified_at = d["verified_at"].clone();
    assert!(verified_at.is_string());
    let (_, again) = verify(&h, &h.alice, HOST).await;
    assert_eq!(again["verified_at"], verified_at);

    // The same code on the default domain and on the custom one are two
    // links; on one domain a code is still unique.
    let a = h
        .create(json!({"url": "https://a.example.org/", "alias": "promo"}))
        .await;
    assert_eq!(a["domain"], Value::Null);
    assert!(a["short_url"].as_str().unwrap().ends_with("/promo"));
    let (status, b) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("https://b.example.org/")),
        )
        .await;
    assert_eq!(status, 201, "{b}");
    assert_eq!(b["domain"], HOST);
    assert_eq!(b["short_url"], "http://go.relink-docs.net/promo");
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("https://c.example.org/")),
        )
        .await;
    assert_eq!(status, 409);
    let alone = h
        .create(json!({"url": "https://only.example.org/", "alias": "only-default"}))
        .await;
    assert_eq!(alone["domain"], Value::Null);
    let random = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://r.example.org/", "domain": HOST})),
        )
        .await
        .1;
    let random_code = random["code"].as_str().unwrap().to_owned();

    // Visitors are routed by Host, on both instances.
    let b_loc = Some("https://b.example.org/".to_owned());
    let a_loc = Some("https://a.example.org/".to_owned());
    for base in [h.base.clone(), other_base.clone()] {
        assert!(
            eventually(Duration::from_secs(5), || {
                let (h, base, want) = (&h, base.clone(), b_loc.clone());
                async move { visit_as(h, &base, HOST, "promo").await.1 == want }
            })
            .await,
            "{base} does not route {HOST}"
        );
        for host in ["GO.relink-docs.net", "go.relink-docs.net.:8443"] {
            assert_eq!(visit_as(&h, &base, host, "promo").await.1, b_loc, "{host}");
        }
        // The default domain and hosts nobody verified keep the old codes.
        for host in [
            "localhost",
            "localhost:8080",
            "other.example.org",
            "127.0.0.1",
        ] {
            assert_eq!(visit_as(&h, &base, host, "promo").await.1, a_loc, "{host}");
        }
        assert_eq!(h.visit("promo", &[]).await.status(), 302);
        // A code that exists only on the default domain is not found on
        // the custom one, and the other way round.
        assert_eq!(visit_as(&h, &base, HOST, "only-default").await.0, 404);
        assert_eq!(visit_as(&h, &base, HOST, &random_code).await.0, 302);
        assert_eq!(visit_as(&h, &base, "localhost", &random_code).await.0, 404);
    }

    // Behind a trusted proxy (the edge Worker cannot set Host), the
    // visitor's host arrives in x-forwarded-host; the first value counts.
    let forwarded = |base: String, fwd: &'static str| {
        let h = &h;
        async move {
            let r = h
                .http
                .get(format!("{base}/promo"))
                .header("host", "localhost")
                .header("x-forwarded-host", fwd)
                .send()
                .await
                .unwrap();
            r.headers()
                .get("location")
                .map(|v| v.to_str().unwrap().to_owned())
        }
    };
    for fwd in [
        "go.relink-docs.net",
        "Go.Relink-Docs.net:443, proxy.example.org",
    ] {
        assert_eq!(forwarded(h.base.clone(), fwd).await, b_loc, "{fwd}");
    }
    for fwd in ["other.example.org", " , go.relink-docs.net", "127.0.0.1"] {
        assert_eq!(forwarded(h.base.clone(), fwd).await, a_loc, "{fwd}");
    }
    // From a peer that is not a trusted proxy it is ignored.
    let untrusted = h
        .second_instance(&[("RELINK_TRUSTED_PROXIES", "10.9.9.9")])
        .await;
    let untrusted_base = format!("http://{}", untrusted.addr);
    assert!(
        eventually(Duration::from_secs(5), || {
            let (h, base, want) = (&h, untrusted_base.clone(), b_loc.clone());
            async move { visit_as(h, &base, HOST, "promo").await.1 == want }
        })
        .await
    );
    assert_eq!(forwarded(untrusted_base, "go.relink-docs.net").await, a_loc);

    // The API finds a link on a domain with ?domain=.
    let get = |q: &'static str| {
        let h = &h;
        async move {
            h.api(Method::GET, &format!("/v1/links/promo{q}"), &h.alice, None)
                .await
        }
    };
    assert_eq!(
        get("").await.1["destinations"][0]["url"],
        "https://a.example.org/"
    );
    let (status, on) = get("?domain=Go.Relink-Docs.net").await;
    assert_eq!(status, 200);
    assert_eq!(on["destinations"][0]["url"], "https://b.example.org/");
    assert_eq!(get("?domain=nope.example.org").await.0, 404);
    assert_eq!(get("?domain=go.relink-docs.net&x=1").await.0, 400);
    let (status, stats) = h
        .api(
            Method::GET,
            &format!("/v1/links/promo/stats?domain={HOST}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{stats}");
    let (_, list) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    let domains: Vec<&Value> = list["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| &l["domain"])
        .collect();
    assert_eq!(domains.iter().filter(|d| **d == HOST).count(), 2);

    // A change to the link on the domain reaches both instances' caches;
    // the default-domain link with the same code is untouched.
    let (status, patched) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/promo?domain={HOST}"),
            &h.alice,
            Some(json!({"url": "https://c.example.org/"})),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    let c_loc = Some("https://c.example.org/".to_owned());
    for base in [h.base.clone(), other_base.clone()] {
        assert!(
            eventually(Duration::from_secs(5), || {
                let (h, base, want) = (&h, base.clone(), c_loc.clone());
                async move { visit_as(h, &base, HOST, "promo").await.1 == want }
            })
            .await
        );
        assert_eq!(visit_as(&h, &base, "localhost", "promo").await.1, a_loc);
    }

    // Usage counts the domain.
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    assert_eq!(usage["domains"], json!({"used": 1, "limit": null}));

    // A domain with links cannot be deleted; once they are gone it can,
    // and its host falls back to the default domain everywhere.
    let path = format!("/v1/domains/{HOST}");
    let (status, body) = h.api(Method::DELETE, &path, &h.alice, None).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "failed_precondition");
    for code in ["promo", random_code.as_str()] {
        let (status, _) = h
            .api(
                Method::DELETE,
                &format!("/v1/links/{code}?domain={HOST}"),
                &h.alice,
                None,
            )
            .await;
        assert_eq!(status, 204);
    }
    assert_eq!(h.api(Method::DELETE, &path, &h.alice, None).await.0, 204);
    assert_eq!(h.api(Method::GET, &path, &h.alice, None).await.0, 404);
    for base in [h.base.clone(), other_base.clone()] {
        assert!(
            eventually(Duration::from_secs(5), || {
                let (h, base, want) = (&h, base.clone(), a_loc.clone());
                async move { visit_as(h, &base, HOST, "promo").await.1 == want }
            })
            .await,
            "{base} still routes {HOST}"
        );
    }

    // Every step is in the workspace's audit chain.
    let ws = workspace_of(&h.store, "alice").await;
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE workspace_id = $1 AND action LIKE 'domain.%' \
         ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(actions, ["domain.create", "domain.verify", "domain.delete"]);
    let link_on_domain: Value = sqlx::query_scalar(
        "SELECT after FROM audit_log WHERE workspace_id = $1 AND action = 'link.create' \
         AND after->>'code' = 'promo' AND after ? 'domain_id'",
    )
    .bind(ws)
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert!(link_on_domain["domain_id"].as_i64().unwrap() > 0);
    other.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn the_first_workspace_to_prove_a_hostname_gets_it() {
    let dns = FakeDns::start().await;
    let Some(mut h) = harness(&dns).await else {
        return;
    };
    // Both claim the hostname; claims alone block nobody.
    let (_, alice) = add(&h, &h.alice, HOST).await;
    let (status, bob) = add(&h, &h.bob, HOST).await;
    assert_eq!(status, 201, "{bob}");
    let alice_record = alice["verification"]["value"].as_str().unwrap();
    let bob_record = bob["verification"]["value"].as_str().unwrap();
    assert_ne!(alice_record, bob_record);

    // Alice's record does not verify bob.
    let name = "_relink-challenge.go.relink-docs.net";
    dns.set_txt(name, &[alice_record]);
    let (status, d) = verify(&h, &h.bob, HOST).await;
    assert_eq!(status, 200);
    assert_eq!(d["verified"], false);
    assert!(d["check_error"].as_str().unwrap().contains("another token"));
    assert_eq!(verify(&h, &h.alice, HOST).await.1["verified"], true);

    // Even with bob's token published too, alice was first.
    dns.set_txt(name, &[alice_record, bob_record]);
    let (status, body) = verify(&h, &h.bob, HOST).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "already_exists");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("another workspace")
    );
    assert_eq!(
        h.api(Method::GET, &format!("/v1/domains/{HOST}"), &h.bob, None)
            .await
            .1["verified"],
        false
    );
    // Bob cannot put links on it or see alice's.
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://evil.example.org/", "alias": "promo", "domain": HOST})),
        )
        .await;
    assert_eq!(status, 400);
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://b.example.org/", "alias": "promo", "domain": HOST})),
        )
        .await;
    assert_eq!(status, 201);
    for path in [
        format!("/v1/links/promo?domain={HOST}"),
        format!("/v1/links/promo/stats?domain={HOST}"),
    ] {
        assert_eq!(
            h.api(Method::GET, &path, &h.bob, None).await.0,
            404,
            "{path}"
        );
    }
    assert_eq!(
        h.api(
            Method::DELETE,
            &format!("/v1/links/promo?domain={HOST}"),
            &h.bob,
            None
        )
        .await
        .0,
        404
    );
    // Bob deleting his own unverified claim does not touch alice's domain.
    assert_eq!(
        h.api(Method::DELETE, &format!("/v1/domains/{HOST}"), &h.bob, None)
            .await
            .0,
        204
    );
    assert_eq!(
        visit_as(&h, &h.base, HOST, "promo").await.1,
        Some("https://b.example.org/".into())
    );

    // The database refuses a link on another workspace's domain even from
    // the table owner: the foreign key includes the workspace.
    let bob_ws = workspace_of(&h.store, "bob").await;
    let alice_domain: i64 = sqlx::query_scalar("SELECT id FROM domains WHERE hostname = $1")
        .bind(HOST)
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let err = sqlx::query(
        "INSERT INTO links (code, owner, workspace_id, domain_id, destinations) \
         VALUES ('sneaky', 'bob', $1, $2, '[{\"url\":\"https://x.example.org/\",\"weight\":1}]')",
    )
    .bind(bob_ws)
    .bind(alice_domain)
    .execute(h.store.pool())
    .await
    .unwrap_err();
    assert!(err.to_string().contains("links_domain_fkey"), "{err}");
    h.shutdown().await;
}

#[tokio::test]
async fn hostnames_dns_failures_roles_and_plan_limits() {
    let dns = FakeDns::start().await;
    let Some(mut h) = harness(&dns).await else {
        return;
    };
    // Names that are not public hosts, or not bare hostnames, are refused,
    // and so is the server's own domain.
    for bad in [
        "localhost",
        "127.0.0.1",
        "intranet",
        "db.internal",
        "https://go.relink-docs.net",
        "go.relink-docs.net:443",
        "go_x.relink-docs.net",
        "",
    ] {
        let (status, body) = add(&h, &h.alice, bad).await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert_eq!(body["error"]["code"], "invalid_argument");
    }
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({"hostname": HOST, "extra": 1})),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        h.api(
            Method::GET,
            "/v1/domains/nope.relink-docs.net",
            &h.alice,
            None
        )
        .await
        .0,
        404
    );
    assert_eq!(verify(&h, &h.alice, "nope.relink-docs.net").await.0, 404);

    // A resolver that does not answer is reported, not fatal.
    let dead = Harness::start(&admin_url().unwrap(), &[]).await;
    add(&dead, &dead.alice, HOST).await;
    let (status, d) = verify(&dead, &dead.alice, HOST).await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(d["verified"], false);
    assert!(
        d["check_error"]
            .as_str()
            .unwrap()
            .contains("no DNS resolver answered"),
        "{d}"
    );
    let mut dead = dead;
    dead.shutdown().await;

    // Editors and viewers may read domains but not manage them.
    let ws = workspace_of(&h.store, "alice").await;
    let mut keys = Vec::new();
    for (member, role) in [
        ("ed", Role::Editor),
        ("val", Role::Viewer),
        ("adam", Role::Admin),
    ] {
        sqlx::query(
            "INSERT INTO workspace_members (workspace_id, member, role) VALUES ($1, $2, $3)",
        )
        .bind(ws)
        .bind(member)
        .bind(role.as_str())
        .execute(h.store.pool())
        .await
        .unwrap();
        let key = generate_key();
        h.store
            .create_api_key(&NewApiKey {
                owner: member,
                name: "test",
                hash: hash_key(&key),
                workspace_id: Some(ws),
                scopes: role.grants(),
                lifetime: None,
            })
            .await
            .unwrap();
        keys.push(key);
    }
    let [editor, viewer, admin] = &keys[..] else {
        unreachable!()
    };
    let (status, body) = add(&h, editor, "ed.relink-docs.net").await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("admin or owner")
    );
    let (status, _) = add(&h, admin, "adam.relink-docs.net").await;
    assert_eq!(status, 201);
    assert_eq!(verify(&h, editor, "adam.relink-docs.net").await.0, 403);
    assert_eq!(
        h.api(
            Method::DELETE,
            "/v1/domains/adam.relink-docs.net",
            editor,
            None
        )
        .await
        .0,
        403
    );
    for key in [editor, viewer] {
        let (status, list) = h.api(Method::GET, "/v1/domains", key, None).await;
        assert_eq!(status, 200);
        assert_eq!(list["domains"][0]["hostname"], "adam.relink-docs.net");
    }
    assert_eq!(add(&h, viewer, "val.relink-docs.net").await.0, 403);

    // A plan's domain limit is exact under concurrent adds, counts
    // unverified domains, and is reported by the usage endpoint.
    h.store
        .set_plan(
            "three-domains",
            PlanChange {
                max_domains: Some(Some(3)),
                ..PlanChange::default()
            },
        )
        .await
        .unwrap();
    h.store
        .assign_plan(ws, "three-domains", &Actor::cli())
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for i in 0..12 {
        let http = h.http.clone();
        let url = format!("{}/v1/domains", h.base);
        let key = h.alice.clone();
        tasks.push(tokio::spawn(async move {
            let r = http
                .post(url)
                .bearer_auth(key)
                .header("content-type", "application/json")
                .body(json!({"hostname": format!("race{i}.relink-docs.net")}).to_string())
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            let text = r.text().await.unwrap();
            (status, serde_json::from_str::<Value>(&text).unwrap())
        }));
    }
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap());
    }
    let created = results.iter().filter(|(s, _)| *s == 201).count();
    assert_eq!(created, 2, "one slot was taken by adam's domain");
    for (status, body) in results.iter().filter(|(s, _)| *s != 201) {
        assert_eq!(*status, 403, "{body}");
        assert_eq!(body["error"]["code"], "quota_exceeded");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("3 domains")
        );
    }
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    assert_eq!(usage["domains"], json!({"used": 3, "limit": 3}));
    let metrics = h.metrics().await;
    assert!(metrics.contains("relink_quota_exceeded_total{limit=\"domains\"} 10"));
    // Deleting one frees its slot.
    assert_eq!(
        h.api(
            Method::DELETE,
            "/v1/domains/adam.relink-docs.net",
            admin,
            None
        )
        .await
        .0,
        204
    );
    assert_eq!(add(&h, &h.alice, "last.relink-docs.net").await.0, 201);
    // The plan is in the audit chain with its domain limit.
    let after: Value = sqlx::query_scalar(
        "SELECT after FROM audit_log WHERE workspace_id = $1 AND action = 'workspace.plan'",
    )
    .bind(ws)
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert_eq!(after["max_domains"], 3);
    h.shutdown().await;
}

/// GET `/{path}` as `host`: status, Location, Content-Type, whether the
/// page CSP was sent, and the body.
async fn fetch_as(
    h: &Harness,
    host: &str,
    path: &str,
) -> (u16, Option<String>, String, bool, String) {
    let r = h
        .http
        .get(format!("{}/{path}", h.base))
        .header("host", host)
        .send()
        .await
        .unwrap();
    let header = |n: &str| r.headers().get(n).map(|v| v.to_str().unwrap().to_owned());
    let (location, ctype) = (
        header("location"),
        header("content-type").unwrap_or_default(),
    );
    let csp = header("content-security-policy").is_some();
    (
        r.status().as_u16(),
        location,
        ctype,
        csp,
        r.text().await.unwrap(),
    )
}

#[tokio::test]
async fn domain_settings_shape_what_its_paths_serve() {
    let dns = FakeDns::start().await;
    let Some(mut h) = harness(&dns).await else {
        return;
    };
    let (_, d) = add(&h, &h.alice, HOST).await;
    assert_eq!(
        d["settings"],
        json!({"root_url": null, "not_found_page": null, "gone_page": null,
               "prefixes": [], "case_insensitive": false,
               "apps": {"ios": [], "android": []}})
    );
    let record = d["verification"]["value"].as_str().unwrap().to_owned();
    dns.set_txt("_relink-challenge.go.relink-docs.net", &[&record]);
    assert_eq!(verify(&h, &h.alice, HOST).await.1["verified"], true);
    let path = format!("/v1/domains/{HOST}");
    let patch = |body: Value| {
        let (h, path) = (&h, path.clone());
        async move { h.api(Method::PATCH, &path, &h.alice, Some(body)).await }
    };

    // A code with uppercase letters blocks case-insensitivity: it could
    // never be reached again.
    let on_domain = |alias: &str, extra: Value| {
        let mut body = json!({"url": "https://b.example.org/", "alias": alias, "domain": HOST});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("Mixed", json!({}))),
        )
        .await;
    assert_eq!(status, 201);
    let (status, body) = patch(json!({"case_insensitive": true})).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "failed_precondition");
    assert!(body["error"]["message"].as_str().unwrap().contains("Mixed"));
    let del = format!("/v1/links/Mixed?domain={HOST}");
    assert_eq!(h.api(Method::DELETE, &del, &h.alice, None).await.0, 204);

    // Invalid settings name their field; nothing is stored.
    for (bad, field) in [
        (json!({"root_url": "http://10.0.0.1/"}), "root_url"),
        (json!({"root_url": "javascript:alert(1)"}), "root_url"),
        (json!({"prefixes": ["v1"]}), "prefixes"),
        (json!({"prefixes": ["a/b"]}), "prefixes"),
        (json!({"not_found_page": ""}), "not_found_page"),
        (json!({"gone_page": "x".repeat(16 * 1024 + 1)}), "gone_page"),
    ] {
        let (status, body) = patch(bad.clone()).await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with(field),
            "{bad}: {body}"
        );
    }
    assert_eq!(patch(json!({"other": 1})).await.0, 400);
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/domains/nope.relink-docs.net",
            &h.alice,
            Some(json!({"prefixes": []})),
        )
        .await;
    assert_eq!(status, 404);

    let (status, d) = patch(json!({
        "root_url": "HTTPS://WWW.relink-docs.net",
        "not_found_page": "<h1>{{code}} is not on {{host}}</h1>",
        "gone_page": "<p>{{code}} has gone</p>",
        "prefixes": ["Campaign", "promo"],
        "case_insensitive": true,
    }))
    .await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(
        d["settings"],
        json!({"root_url": "https://www.relink-docs.net/",
               "not_found_page": "<h1>{{code}} is not on {{host}}</h1>",
               "gone_page": "<p>{{code}} has gone</p>",
               "prefixes": ["campaign", "promo"], "case_insensitive": true,
               "apps": {"ios": [], "android": []}})
    );
    // Links created on the domain now get lowercase codes.
    let (status, l) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("Summer", json!({}))),
        )
        .await;
    assert_eq!(status, 201, "{l}");
    assert_eq!(l["code"], "summer");
    assert_eq!(l["short_url"], "http://go.relink-docs.net/summer");
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("SUMMER", json!({}))),
        )
        .await;
    assert_eq!(status, 409, "the same code ignoring case is taken");
    let (_, r) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://r.example.org/", "domain": HOST})),
        )
        .await;
    let random = r["code"].as_str().unwrap();
    assert_eq!(random, random.to_ascii_lowercase());
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(on_domain("once", json!({"max_clicks": 1}))),
        )
        .await;
    assert_eq!(status, 201);

    // `/` is the root redirect; prefixes and case lead to the same link.
    let (status, loc, ..) = fetch_as(&h, HOST, "").await;
    assert_eq!(
        (status, loc.as_deref()),
        (302, Some("https://www.relink-docs.net/"))
    );
    for p in [
        "summer",
        "SUMMER",
        "campaign/Summer",
        "CAMPAIGN/summer",
        "promo/summer",
    ] {
        let (status, loc, ..) = fetch_as(&h, HOST, p).await;
        assert_eq!(
            (status, loc.as_deref()),
            (302, Some("https://b.example.org/")),
            "{p}"
        );
    }
    assert_eq!(fetch_as(&h, HOST, &random.to_uppercase()).await.0, 302);

    // Anything else is the domain's own 404 page, escaped and confined.
    for (p, code) in [
        ("other/summer", "summer"),
        ("nope", "nope"),
        ("a.php", "a.php"),
        ("campaign/a%3Cb", "a%3Cb"),
        ("campaign/x/y", "y"),
    ] {
        let (status, _, ctype, csp, body) = fetch_as(&h, HOST, p).await;
        assert_eq!(status, 404, "{p}");
        assert_eq!(ctype, "text/html; charset=utf-8", "{p}");
        assert!(csp, "{p}");
        assert_eq!(
            body,
            format!("<h1>{code} is not on go.relink-docs.net</h1>"),
            "{p}"
        );
    }
    // A link at its click limit is the domain's 410 page.
    assert_eq!(fetch_as(&h, HOST, "once").await.0, 302);
    let (status, _, ctype, _, body) = fetch_as(&h, HOST, "campaign/ONCE").await;
    assert_eq!((status, ctype.as_str()), (410, "text/html; charset=utf-8"));
    assert_eq!(body, "<p>ONCE has gone</p>");

    // The default domain is untouched: no root redirect, no prefixes, no
    // case folding, plain pages.
    for p in ["", "campaign/summer"] {
        let (status, _, ctype, csp, _) = fetch_as(&h, "localhost", p).await;
        assert_eq!(
            (status, ctype.as_str(), csp),
            (404, "application/json", false),
            "{p}"
        );
    }
    let (status, _, ctype, _, body) = fetch_as(&h, "localhost", "nope").await;
    assert_eq!(
        (status, ctype.as_str(), body.as_str()),
        (404, "text/plain; charset=utf-8", "not found\n")
    );

    // Back to the defaults, field by field.
    let (status, d) = patch(json!({"root_url": null, "not_found_page": null})).await;
    assert_eq!(status, 200);
    assert_eq!(d["settings"]["gone_page"], "<p>{{code}} has gone</p>");
    let (status, _, ctype, _, body) = fetch_as(&h, HOST, "").await;
    assert_eq!(
        (status, ctype.as_str(), body.as_str()),
        (404, "text/plain; charset=utf-8", "not found\n")
    );
    let (status, d) = patch(json!({"prefixes": [], "case_insensitive": false})).await;
    assert_eq!(status, 200);
    assert_eq!(d["settings"]["prefixes"], json!([]));
    assert_eq!(fetch_as(&h, HOST, "campaign/summer").await.0, 404);
    assert_eq!(fetch_as(&h, HOST, "SUMMER").await.0, 404);
    assert_eq!(fetch_as(&h, HOST, "summer").await.0, 302);

    // Every change is audited once.
    let ws = workspace_of(&h.store, "alice").await;
    let changes: Vec<Value> = sqlx::query_scalar(
        "SELECT after FROM audit_log WHERE workspace_id = $1 AND action = 'domain.update' \
         ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[0]["settings"]["case_insensitive"], true);
    assert!(changes[2].get("settings").is_some());
    h.shutdown().await;
}

#[tokio::test]
async fn a_domain_serves_the_association_files_of_its_apps() {
    let dns = FakeDns::start().await;
    let Some(mut h) = harness(&dns).await else {
        return;
    };
    let (_, d) = add(&h, &h.alice, HOST).await;
    let record = d["verification"]["value"].as_str().unwrap().to_owned();
    dns.set_txt("_relink-challenge.go.relink-docs.net", &[&record]);
    assert_eq!(verify(&h, &h.alice, HOST).await.1["verified"], true);
    let path = format!("/v1/domains/{HOST}");
    let patch = |body: Value| {
        let (h, path) = (&h, path.clone());
        async move { h.api(Method::PATCH, &path, &h.alice, Some(body)).await }
    };
    let files = [
        ".well-known/apple-app-site-association",
        "apple-app-site-association",
        ".well-known/assetlinks.json",
    ];
    // Without apps the paths are the domain's 404.
    for f in files {
        assert_eq!(fetch_as(&h, HOST, f).await.0, 404, "{f}");
    }

    // Invalid apps name the part at fault; nothing is stored.
    let print = "146de983c5730650d8eeb9952f34fc6416a08342e61dbea88a0496b23fcf44e5";
    for (bad, want) in [
        (
            json!({"ios": [{"team_id": "ABC", "bundle_id": "com.example.app"}]}),
            "apps.ios[0].team_id: ",
        ),
        (
            json!({"ios": [{"team_id": "ABCDE12345", "bundle_id": "app"}]}),
            "apps.ios[0].bundle_id: ",
        ),
        (
            json!({"android": [{"package": "com.example.app", "sha256_cert_fingerprints": []}]}),
            "apps.android[0].sha256_cert_fingerprints: ",
        ),
        (
            json!({"android": [{"package": "com.example.app",
                                "sha256_cert_fingerprints": [print, "zz"]}]}),
            "apps.android[0].sha256_cert_fingerprints[1]: ",
        ),
        (
            json!({"android": [{"package": "example", "sha256_cert_fingerprints": [print]}]}),
            "apps.android[0].package: ",
        ),
    ] {
        let (status, body) = patch(json!({ "apps": bad })).await;
        assert_eq!(status, 400, "{body}");
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.starts_with(want), "{msg}");
    }
    for bad in [
        json!({"apps": {"windows": []}}),
        json!({"apps": {"ios": [{"team_id": "ABCDE12345", "bundle_id": "a.b", "x": 1}]}}),
    ] {
        assert_eq!(patch(bad).await.0, 400);
    }

    let (status, d) = patch(json!({"apps": {
        "ios": [{"team_id": "abcde12345", "bundle_id": "com.example.app"}],
        "android": [{"package": "com.example.app", "sha256_cert_fingerprints": [print]}],
    }}))
    .await;
    assert_eq!(status, 200, "{d}");
    let pretty = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:\
                  B2:3F:CF:44:E5";
    assert_eq!(
        d["settings"]["apps"],
        json!({"ios": [{"team_id": "ABCDE12345", "bundle_id": "com.example.app"}],
               "android": [{"package": "com.example.app", "sha256_cert_fingerprints": [pretty]}]})
    );
    for f in &files[..2] {
        let (status, _, ctype, _, body) = fetch_as(&h, HOST, f).await;
        assert_eq!((status, ctype.as_str()), (200, "application/json"), "{f}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["applinks"]["details"][0]["appIDs"],
            json!(["ABCDE12345.com.example.app"])
        );
        assert_eq!(
            v["applinks"]["details"][0]["components"],
            json!([{"/": "*"}])
        );
    }
    let (status, _, ctype, _, body) = fetch_as(&h, HOST, files[2]).await;
    assert_eq!((status, ctype.as_str()), (200, "application/json"));
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v[0]["target"]["package_name"], "com.example.app");
    assert_eq!(v[0]["target"]["sha256_cert_fingerprints"], json!([pretty]));
    // Only the custom domain has them, and only at exactly these paths.
    assert_eq!(fetch_as(&h, "localhost", files[2]).await.0, 404);
    assert_eq!(
        fetch_as(&h, HOST, ".well-known/assetlinks.json.bak")
            .await
            .0,
        404
    );
    // The reserved name cannot become a code.
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(
                json!({"url": "https://b.example.org/", "alias": "apple-app-site-association",
                        "domain": HOST}),
            ),
        )
        .await;
    assert_eq!(status, 400);

    // One platform removed, then all apps.
    let (status, _) = patch(json!({"apps": {"android": [{"package": "com.example.app",
                                                         "sha256_cert_fingerprints": [print]}]}}))
    .await;
    assert_eq!(status, 200);
    assert_eq!(fetch_as(&h, HOST, files[0]).await.0, 404);
    assert_eq!(fetch_as(&h, HOST, files[2]).await.0, 200);
    let (status, d) = patch(json!({"apps": null})).await;
    assert_eq!(status, 200);
    assert_eq!(d["settings"]["apps"], json!({"ios": [], "android": []}));
    assert_eq!(fetch_as(&h, HOST, files[2]).await.0, 404);
    let m = h.metrics().await;
    assert_eq!(
        common::metric(&m, "relink_redirects_total{outcome=\"app_file\"}"),
        4.0
    );
    h.shutdown().await;
}

//! Protected links and previews, end to end against Postgres: the password
//! page and its grant cookie, attempt limits shared across instances,
//! consent pages, `/{code}+` previews, the API's validation and field by
//! field changes, and that no password hash ever leaves the database.

mod common;

use std::time::Duration;

use common::{FakeDns, Harness, admin_url, eventually, metric};
use reqwest::Method;
use serde_json::{Value, json};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

const FORM: &str = "application/x-www-form-urlencoded";

/// POSTs a form to `path` on `base` (with an optional Host and Cookie).
async fn post(
    h: &Harness,
    base: &str,
    path: &str,
    body: &str,
    host: Option<&str>,
) -> reqwest::Response {
    let mut req = h
        .http
        .post(format!("{base}/{path}"))
        .header("content-type", FORM)
        .body(body.to_owned());
    if let Some(host) = host {
        req = req.header("host", host);
    }
    req.send().await.unwrap()
}

async fn get(h: &Harness, path: &str, cookie: Option<&str>) -> reqwest::Response {
    let mut req = h.http.get(format!("{}/{path}", h.base));
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    req.send().await.unwrap()
}

fn header<'a>(r: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    r.headers().get(name).map(|v| v.to_str().unwrap())
}

/// The `name=value` part of a response's Set-Cookie.
fn cookie_of(r: &reqwest::Response) -> String {
    header(r, "set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn patch(h: &Harness, code: &str, body: Value) -> (u16, Value) {
    h.api(
        Method::PATCH,
        &format!("/v1/links/{code}"),
        &h.alice,
        Some(body),
    )
    .await
}

#[tokio::test]
async fn a_password_lets_visitors_through_until_it_changes() {
    let mut h = harness!();
    let link = h
        .create(json!({
            "url": "https://example.com/secret",
            "alias": "vault",
            "protection": {"password": "open sesame"}
        }))
        .await;
    assert_eq!(
        link["protection"],
        json!({"password": true, "max_attempts": 10})
    );
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM links WHERE code = 'vault'")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert!(
        stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "{stored}"
    );

    // The page, not the destination.
    let r = get(&h, "vault", None).await;
    assert_eq!(r.status(), 200);
    assert!(header(&r, "location").is_none());
    assert_eq!(header(&r, "cache-control"), Some("no-store"));
    assert!(header(&r, "content-type").unwrap().starts_with("text/html"));
    let csp = header(&r, "content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("form-action 'self'"));
    let page = r.text().await.unwrap();
    assert!(page.contains("type=\"password\""));
    assert!(!page.contains("example.com/secret"));

    // Wrong, empty and missing passwords: the page again, 401.
    for body in ["password=open+sesam", "password=", "other=1", ""] {
        let r = post(&h, &h.base, "vault", body, None).await;
        assert_eq!(r.status(), 401, "{body}");
        assert!(header(&r, "set-cookie").is_none());
        assert!(r.text().await.unwrap().contains("not right"));
    }
    // Not a form, or too large a one: refused before anything is checked.
    let r = h
        .http
        .post(format!("{}/vault", h.base))
        .header("content-type", "application/json")
        .body(r#"{"password":"open sesame"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 415);
    let big = format!("password={}", "x".repeat(5000));
    assert_eq!(post(&h, &h.base, "vault", &big, None).await.status(), 413);

    // The right one: back to the same path and query, with a grant.
    let r = post(
        &h,
        &h.base,
        "vault?utm_source=mail",
        "password=open+sesame",
        None,
    )
    .await;
    assert_eq!(r.status(), 303);
    assert_eq!(header(&r, "location"), Some("/vault?utm_source=mail"));
    assert_eq!(header(&r, "cache-control"), Some("no-store"));
    let set = header(&r, "set-cookie").unwrap().to_owned();
    assert!(set.starts_with("rl.vault="), "{set}");
    assert!(
        set.contains("Path=/; Max-Age=43200; HttpOnly; SameSite=Lax"),
        "{set}"
    );
    let grant = cookie_of(&r);
    let r = get(&h, "vault", Some(&grant)).await;
    assert_eq!(r.status(), 302);
    assert_eq!(header(&r, "location"), Some("https://example.com/secret"));
    // Never cached: the next visitor has no grant.
    assert_eq!(header(&r, "cache-control"), Some("no-store"));
    // A grant for another link, or a forged one, is no grant.
    let forged = grant.replace("rl.vault=", "rl.vault=9").to_owned();
    assert_eq!(get(&h, "vault", Some(&forged)).await.status(), 200);
    let other = h
        .create(json!({"url": "https://example.com/o", "alias": "other",
                       "protection": {"password": "open sesame"}}))
        .await;
    assert_eq!(other["code"], "other");
    let moved = grant.replace("rl.vault=", "rl.other=");
    assert_eq!(get(&h, "other", Some(&moved)).await.status(), 200);

    // A new password revokes every grant; the old one no longer opens it.
    let (status, body) = patch(
        &h,
        "vault",
        json!({"protection": {"password": "new words"}}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["protection"]["password"], true);
    assert_eq!(get(&h, "vault", Some(&grant)).await.status(), 200);
    assert_eq!(
        post(&h, &h.base, "vault", "password=open+sesame", None)
            .await
            .status(),
        401
    );
    let r = post(&h, &h.base, "vault", "password=new+words", None).await;
    assert_eq!(r.status(), 303);
    assert_eq!(get(&h, "vault", Some(&cookie_of(&r))).await.status(), 302);

    // A disabled or expired link answers as it would: no page, no form.
    patch(&h, "vault", json!({"enabled": false})).await;
    assert_eq!(get(&h, "vault", None).await.status(), 404);
    assert_eq!(
        post(&h, &h.base, "vault", "password=new+words", None)
            .await
            .status(),
        404
    );
    patch(&h, "vault", json!({"enabled": true})).await;
    sqlx::query("UPDATE links SET expires_at = now() - interval '1 minute' WHERE code = 'vault'")
        .execute(h.store.pool())
        .await
        .unwrap();
    h.app().resolver.invalidate("vault");
    assert_eq!(get(&h, "vault", None).await.status(), 410);
    assert_eq!(
        post(&h, &h.base, "vault", "password=new+words", None)
            .await
            .status(),
        410
    );

    // Removing the protection makes it an ordinary link again.
    patch(&h, "vault", json!({"expires_at": null})).await;
    let (status, body) = patch(&h, "vault", json!({"protection": null})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["protection"], Value::Null);
    let r = get(&h, "vault", None).await;
    assert_eq!(r.status(), 302);
    // A form for a link that asks nothing goes straight back.
    let r = post(&h, &h.base, "vault", "password=x", None).await;
    assert_eq!(r.status(), 303);
    assert!(header(&r, "set-cookie").is_none());

    // No hash ever reached the API or the audit log.
    let (_, listed) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert!(!listed.to_string().contains("argon2"));
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(before::text, '') || coalesce(after::text, '') FROM audit_log",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert!(
        audit.iter().any(|a| a.contains("\"password\": true")),
        "{audit:?}"
    );
    assert!(audit.iter().all(|a| !a.contains("argon2")));

    let m = h.metrics().await;
    assert!(
        metric(&m, "relink_redirects_total{outcome=\"gate\"}") >= 4.0,
        "{m}"
    );
    assert!(metric(&m, "relink_redirects_total{outcome=\"gate_rejected\"}") >= 6.0);
    assert!(metric(&m, "relink_redirects_total{outcome=\"gate_accepted\"}") >= 3.0);
    h.shutdown().await;
}

#[tokio::test]
async fn wrong_passwords_are_limited_per_link_across_instances() {
    let mut h = harness!();
    h.create(json!({"url": "https://example.com/l", "alias": "limited",
                    "protection": {"password": "letmein", "max_attempts": 3}}))
        .await;
    let second = h.second_instance(&[]).await;
    let other = format!("http://{}", second.addr);

    // A right password gives its attempt back: these never run out.
    for _ in 0..5 {
        assert_eq!(
            post(&h, &h.base, "limited", "password=letmein", None)
                .await
                .status(),
            303
        );
    }
    // Three wrong ones, on either instance, use the limit up.
    for base in [&h.base, &other, &h.base] {
        let r = post(&h, base, "limited", "password=guess", None).await;
        assert_eq!(r.status(), 401);
    }
    for base in [&other, &h.base] {
        let r = post(&h, base, "limited", "password=letmein", None).await;
        assert_eq!(r.status(), 429, "even the right password waits");
        let wait: u32 = header(&r, "retry-after").unwrap().parse().unwrap();
        assert!((3500..=3600).contains(&wait), "{wait}");
        let page = r.text().await.unwrap();
        assert!(page.contains("Too many wrong passwords"));
        assert!(!page.contains("<form"));
    }
    let attempts: i32 = sqlx::query_scalar(
        "SELECT attempts FROM link_password_attempts a JOIN links l ON l.id = a.link_id \
         WHERE l.code = 'limited'",
    )
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert_eq!(attempts, 3);

    // Another link is not affected.
    h.create(json!({"url": "https://example.com/f", "alias": "fresh",
                    "protection": {"password": "letmein"}}))
        .await;
    assert_eq!(
        post(&h, &h.base, "fresh", "password=letmein", None)
            .await
            .status(),
        303
    );

    // A new window starts an hour after the first attempt.
    sqlx::query("UPDATE link_password_attempts SET window_start = now() - interval '61 minutes'")
        .execute(h.store.pool())
        .await
        .unwrap();
    assert_eq!(
        post(&h, &other, "limited", "password=letmein", None)
            .await
            .status(),
        303
    );
    // A higher limit applies at once.
    for _ in 0..3 {
        post(&h, &h.base, "limited", "password=guess", None).await;
    }
    assert_eq!(
        post(&h, &h.base, "limited", "password=guess", None)
            .await
            .status(),
        429
    );
    let (status, body) = patch(&h, "limited", json!({"protection": {"max_attempts": 5}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["protection"]["max_attempts"], 5);
    let r = post(&h, &h.base, "limited", "password=letmein", None).await;
    assert_eq!(r.status(), 303);

    let m = h.metrics().await;
    assert!(
        metric(&m, "relink_redirects_total{outcome=\"gate_locked\"}") >= 2.0,
        "{m}"
    );
    second.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn consent_pages_and_previews() {
    let mut h = harness!();
    h.create(
        json!({"url": "https://example.com/wine?a=1&b=2", "alias": "wine",
                    "protection": {"consent": "  You must be <b>18</b> or older.\r\nReally.  "}}),
    )
    .await;
    let (_, view) = h.api(Method::GET, "/v1/links/wine", &h.alice, None).await;
    assert_eq!(
        view["protection"],
        json!({"consent": "You must be <b>18</b> or older.\nReally."})
    );
    let r = get(&h, "wine", None).await;
    assert_eq!(r.status(), 200);
    let page = r.text().await.unwrap();
    assert!(page.contains("You must be &lt;b&gt;18&lt;/b&gt; or older.\nReally."));
    assert!(page.contains("name=\"consent\" value=\"yes\""));
    assert!(!page.contains("type=\"password\""));
    // Without the consent field: asked again.
    let r = post(&h, &h.base, "wine", "", None).await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("Confirm"));
    let r = post(&h, &h.base, "wine", "consent=yes", None).await;
    assert_eq!(r.status(), 303);
    assert!(
        header(&r, "set-cookie")
            .unwrap()
            .contains("Max-Age=2592000")
    );
    let grant = cookie_of(&r);
    let r = get(&h, "wine", Some(&grant)).await;
    assert_eq!(r.status(), 302);
    assert_eq!(
        header(&r, "location"),
        Some("https://example.com/wine?a=1&b=2")
    );
    // New text asks again.
    patch(&h, "wine", json!({"protection": {"consent": "Still 18?"}})).await;
    assert_eq!(get(&h, "wine", Some(&grant)).await.status(), 200);

    // A password and consent together: both on one page, both needed.
    let (status, body) = patch(&h, "wine", json!({"protection": {"password": "grapes"}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["protection"],
        json!({"password": true, "max_attempts": 10, "consent": "Still 18?"})
    );
    let page = get(&h, "wine", None).await.text().await.unwrap();
    assert!(page.contains("type=\"password\"") && page.contains("Still 18?"));
    assert_eq!(
        post(&h, &h.base, "wine", "password=grapes", None)
            .await
            .status(),
        400
    );
    let r = post(&h, &h.base, "wine", "password=grapes&consent=yes", None).await;
    assert_eq!(r.status(), 303);
    assert!(header(&r, "set-cookie").unwrap().contains("Max-Age=43200"));
    // Removing the password keeps the consent page.
    let (_, body) = patch(&h, "wine", json!({"protection": {"password": null}})).await;
    assert_eq!(body["protection"], json!({"consent": "Still 18?"}));

    // Previews: where a link goes, without a click; a protected one says
    // only that it is protected.
    h.create(json!({"url": "https://example.com/plain", "alias": "plain"}))
        .await;
    let r = get(&h, "plain+", None).await;
    assert_eq!(r.status(), 200);
    assert_eq!(header(&r, "cache-control"), Some("no-store"));
    assert!(header(&r, "content-security-policy").is_some());
    let page = r.text().await.unwrap();
    assert!(page.contains("https://example.com/plain"));
    assert!(page.contains("href=\"/plain\""));
    let page = get(&h, "wine+", None).await.text().await.unwrap();
    assert!(page.contains("is protected"));
    assert!(!page.contains("example.com/wine"));
    assert_eq!(get(&h, "nothing+", None).await.status(), 404);
    assert_eq!(get(&h, "plain++", None).await.status(), 404);
    // Only GET previews.
    assert_eq!(post(&h, &h.base, "plain+", "", None).await.status(), 405);
    patch(&h, "plain", json!({"enabled": false})).await;
    assert_eq!(get(&h, "plain+", None).await.status(), 404);
    let m = h.metrics().await;
    assert_eq!(
        metric(&m, "relink_redirects_total{outcome=\"preview\"}"),
        2.0,
        "{m}"
    );
    // No preview or page counted a click.
    let (_, stats) = h
        .api(Method::GET, "/v1/links/plain/stats", &h.alice, None)
        .await;
    assert_eq!(stats["total_clicks"], 0, "{stats}");
    h.shutdown().await;
}

#[tokio::test]
async fn the_api_validates_protection_and_changes_it_field_by_field() {
    let mut h = harness!();
    let long_password = "x".repeat(257);
    let long_consent = "y".repeat(1001);
    for (body, says) in [
        (
            json!({"password": "abc"}),
            "protection.password: must be 4 to 256 bytes",
        ),
        (
            json!({"password": long_password}),
            "protection.password: must be 4 to 256",
        ),
        (
            json!({"password": "tab\there"}),
            "protection.password: must not contain control",
        ),
        (
            json!({"consent": "   "}),
            "protection.consent: must not be empty",
        ),
        (
            json!({"consent": long_consent}),
            "protection.consent: must be at most 1000",
        ),
        (
            json!({"consent": "bell\u{7}"}),
            "protection.consent: must not contain control",
        ),
        (
            json!({"password": "good one", "max_attempts": 0}),
            "protection.max_attempts: must be 1 to 1000",
        ),
        (
            json!({"password": "good one", "max_attempts": 1001}),
            "protection.max_attempts: must be 1 to 1000",
        ),
        (
            json!({"max_attempts": 5}),
            "protection.max_attempts: needs a password",
        ),
        (
            json!({"consent": "ok", "max_attempts": 5}),
            "protection.max_attempts: needs a password",
        ),
        (json!({"password": "good one", "extra": 1}), "unknown field"),
        (json!({"password": 1234}), "invalid type"),
        (json!({"max_attempts": -1}), "invalid value"),
    ] {
        let (status, err) = h
            .api(
                Method::POST,
                "/v1/links",
                &h.alice,
                Some(json!({"url": "https://example.com/", "protection": body})),
            )
            .await;
        assert_eq!(status, 400, "{body}: {err}");
        let message = err["error"]["message"].as_str().unwrap();
        assert!(message.contains(says), "{body}: {message}");
    }
    // Null and empty on a create are no protection.
    for p in [
        json!(null),
        json!({}),
        json!({"password": null, "consent": null}),
    ] {
        let link = h
            .create(json!({"url": "https://example.com/", "protection": p}))
            .await;
        assert_eq!(link["protection"], Value::Null, "{p}");
    }
    let link = h
        .create(json!({"url": "https://example.com/p", "alias": "fields",
                       "protection": {"password": "first one", "max_attempts": 7, "consent": "Go?"}}))
        .await;
    assert_eq!(
        link["protection"],
        json!({"password": true, "max_attempts": 7, "consent": "Go?"})
    );
    // Patches: an absent field is kept.
    let (_, body) = patch(&h, "fields", json!({"protection": {"consent": "Sure?"}})).await;
    assert_eq!(
        body["protection"],
        json!({"password": true, "max_attempts": 7, "consent": "Sure?"})
    );
    let hash_before: String =
        sqlx::query_scalar("SELECT password_hash FROM links WHERE code = 'fields'")
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    let (_, body) = patch(&h, "fields", json!({"protection": {"max_attempts": 2}})).await;
    assert_eq!(body["protection"]["max_attempts"], 2);
    let hash_after: String =
        sqlx::query_scalar("SELECT password_hash FROM links WHERE code = 'fields'")
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(hash_before, hash_after, "the password is kept");
    // A limit cannot come with removing the password.
    let (status, err) = patch(
        &h,
        "fields",
        json!({"protection": {"password": null, "max_attempts": 3}}),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    // An empty change is no change.
    let (status, err) = patch(&h, "fields", json!({"protection": {}})).await;
    assert_eq!(status, 400, "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("changes nothing")
    );
    // Invalid patches name the field.
    let (status, err) = patch(&h, "fields", json!({"protection": {"password": "no"}})).await;
    assert_eq!(status, 400);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("protection.password")
    );

    // Not part of the versions: a rollback keeps the protection as it is.
    patch(&h, "fields", json!({"url": "https://example.com/q"})).await;
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links/fields/rollback",
            &h.alice,
            Some(json!({"version": 1})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (_, now) = h.api(Method::GET, "/v1/links/fields", &h.alice, None).await;
    assert_eq!(now["destinations"][0]["url"], "https://example.com/p");
    assert_eq!(
        now["protection"],
        json!({"password": true, "max_attempts": 2, "consent": "Sure?"})
    );
    // A limit on a link without a password is ignored, not stored.
    h.create(json!({"url": "https://example.com/", "alias": "bare"}))
        .await;
    let (status, body) = patch(&h, "bare", json!({"protection": {"max_attempts": 3}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["protection"], Value::Null);

    // The database holds the same rules.
    for (sql, why) in [
        (
            "UPDATE links SET password_hash = 'plain' , password_attempts = 1 WHERE code = 'bare'",
            "a hash",
        ),
        (
            "UPDATE links SET password_attempts = 3 WHERE code = 'bare'",
            "a limit without a password",
        ),
        (
            "UPDATE links SET consent = '' WHERE code = 'bare'",
            "empty consent",
        ),
    ] {
        let err = sqlx::query(sql).execute(h.store.pool()).await;
        assert!(err.is_err(), "{why}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn protected_links_on_a_custom_domain_post_behind_its_prefixes() {
    let dns = FakeDns::start().await;
    let Some(admin) = admin_url() else { return };
    let addr = dns.addr.to_string();
    let mut h = Harness::start(&admin, &[("RELINK_DNS_SERVERS", &addr)]).await;
    let host = "go.relink-docs.net";
    let (status, d) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({"hostname": host})),
        )
        .await;
    assert_eq!(status, 201, "{d}");
    let record = d["verification"]["value"].as_str().unwrap().to_owned();
    dns.set_txt(&format!("_relink-challenge.{host}"), &[&record]);
    let (_, v) = h
        .api(
            Method::POST,
            &format!("/v1/domains/{host}/verify"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(v["verified"], true, "{v}");
    let (status, _) = h
        .api(
            Method::PATCH,
            &format!("/v1/domains/{host}"),
            &h.alice,
            Some(json!({"prefixes": ["campaign"]})),
        )
        .await;
    assert_eq!(status, 200);
    h.create(
        json!({"url": "https://example.com/d", "alias": "door", "domain": host,
                    "protection": {"password": "knock knock"}}),
    )
    .await;
    let app = h.app().clone();
    assert!(
        eventually(Duration::from_secs(5), || {
            let app = app.clone();
            async move {
                !matches!(
                    app.domains.route(Some(b"go.relink-docs.net"), "x"),
                    relink_server::domains::Route::Default
                )
            }
        })
        .await
    );
    let visit = |path: &str, cookie: Option<String>| {
        let mut req = h
            .http
            .get(format!("{}/{path}", h.base))
            .header("host", host);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        req.send()
    };
    assert_eq!(visit("campaign/door", None).await.unwrap().status(), 200);
    let r = post(
        &h,
        &h.base,
        "campaign/door?x=1",
        "password=knock+knock",
        Some(host),
    )
    .await;
    assert_eq!(r.status(), 303);
    assert_eq!(header(&r, "location"), Some("/campaign/door?x=1"));
    let grant = cookie_of(&r);
    // The grant covers every path that names the link on that domain.
    for path in ["campaign/door", "door"] {
        let r = visit(path, Some(grant.clone())).await.unwrap();
        assert_eq!(r.status(), 302, "{path}");
    }
    let page = visit("campaign/door+", None)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("is protected"));
    // The same code on the default domain is another link (none here).
    assert_eq!(
        post(&h, &h.base, "door", "password=knock+knock", None)
            .await
            .status(),
        404
    );
    // Other POSTs on the domain are still unknown paths.
    let r = post(&h, &h.base, "campaign/door/x", "", Some(host)).await;
    assert_eq!(r.status(), 404);
    h.shutdown().await;
}

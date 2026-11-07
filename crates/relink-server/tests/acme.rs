//! Certificates from an ACME CA (src/acme.rs, migration 0011). The client
//! runs against a local CA that checks signatures, nonces, HTTP-01 and the
//! certificate request as a real one does: first on its own with challenges
//! in memory, through every failure a CA can hand it, then inside two
//! running servers, which order a certificate for a domain as soon as it is
//! verified, answer the CA's HTTP-01 request on whichever instance it
//! reaches, renew at two thirds of the lifetime and back off after
//! failures.

#[path = "common/acme_ca.rs"]
mod acme_ca;
mod common;

use std::sync::Arc;
use std::time::Duration;

use acme_ca::{FakeCa, MemChallenges, serve_challenges};
use chrono::{DateTime, Utc};
use common::{FakeDns, Harness, admin_url, eventually, metric};
use relink_server::acme::{Account, AccountKey, Acme, AcmeConfig, AcmeError, public_key_info};
use relink_server::der;
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::Row;

const HOST: &str = "go.relink-docs.net";

fn config(ca: &FakeCa, order_timeout: Duration) -> AcmeConfig {
    AcmeConfig {
        directory_url: ca.directory.clone(),
        email: Some("ops@relink-docs.net".into()),
        interval: Duration::from_millis(100),
        order_timeout,
    }
}

/// A CA, a client registered with it, and challenges served from memory.
async fn client(ca: &FakeCa) -> (Acme, Account, Arc<MemChallenges>) {
    let challenges = Arc::new(MemChallenges::default());
    let (addr, _task) = serve_challenges(challenges.clone()).await;
    ca.validate_at(addr);
    let acme = Acme::new(config(ca, Duration::from_secs(10))).unwrap();
    let key = AccountKey::generate();
    let url = acme.register(&key).await.unwrap();
    (acme, Account { key, url }, challenges)
}

#[tokio::test]
async fn issues_a_certificate_for_its_own_key_over_http01() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    // Registering the same key again finds the same account.
    assert_eq!(acme.register(&account.key).await.unwrap(), account.url);
    assert_eq!(ca.accounts(), 1);

    let before = Utc::now() - chrono::Duration::seconds(2);
    let cert = acme
        .issue(&account, HOST, challenges.as_ref())
        .await
        .unwrap();
    assert_eq!(ca.issued(), [HOST]);
    // Published for the CA, and withdrawn once done.
    assert_eq!(*challenges.published.lock().unwrap(), 1);
    assert!(challenges.map.lock().unwrap().is_empty());

    let chain = der::pem_decode_all(&cert.chain_pem, "CERTIFICATE").unwrap();
    assert_eq!(chain.len(), 2, "leaf and CA");
    assert_eq!(chain[1], ca.root());
    let leaf = der::parse_certificate(&chain[0]).unwrap();
    assert_eq!(leaf.dns_names, [HOST]);
    assert_eq!(public_key_info(&cert.key_pkcs8).unwrap(), leaf.spki);
    assert_eq!(
        (cert.not_before, cert.not_after),
        (leaf.not_before, leaf.not_after)
    );
    assert!(cert.not_before >= before && cert.not_before <= Utc::now());
    let lifetime = cert.not_after - cert.not_before;
    assert_eq!(lifetime, chrono::Duration::days(90));
    assert_eq!(cert.renew_at, cert.not_before + chrono::Duration::days(60));
}

#[tokio::test]
async fn retries_bad_nonces_but_not_forever() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    ca.set(|k| k.bad_nonces = 2);
    acme.issue(&account, HOST, challenges.as_ref())
        .await
        .unwrap();
    ca.set(|k| k.bad_nonces = 3);
    match acme.register(&account.key).await {
        Err(AcmeError::Problem(p)) => assert_eq!(p.kind, "badNonce"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn says_why_validation_failed_and_withdraws_the_challenge() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    // The CA reaches a server that answers nothing.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    drop(silent);
    ca.validate_at(silent_addr);
    let err = acme
        .issue(&account, HOST, challenges.as_ref())
        .await
        .unwrap_err();
    match &err {
        AcmeError::Invalid(m) => {
            assert!(m.contains(HOST) && m.contains("cannot connect"), "{m}")
        }
        other => panic!("{other:?}"),
    }
    assert!(err.to_string().starts_with("validation failed: "));
    assert!(challenges.map.lock().unwrap().is_empty());
    assert!(ca.issued().is_empty());
}

#[tokio::test]
async fn rate_limits_carry_the_cas_retry_after() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    ca.set(|k| k.rate_limit = Some(3_600));
    let err = acme
        .issue(&account, HOST, challenges.as_ref())
        .await
        .unwrap_err();
    assert_eq!(err.retry_after(), Some(Duration::from_secs(3_600)));
    match err {
        AcmeError::Problem(p) => {
            assert_eq!((p.kind.as_str(), p.status), ("rateLimited", 429));
            assert_eq!(p.detail, "too many orders");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn refuses_a_certificate_for_another_key() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    ca.set(|k| k.wrong_key = true);
    match acme.issue(&account, HOST, challenges.as_ref()).await {
        Err(AcmeError::Transport(m)) => assert!(m.contains("not for the key"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn gives_up_on_an_order_that_never_finishes() {
    let ca = FakeCa::start().await;
    let (_, account, challenges) = client(&ca).await;
    let acme = Acme::new(config(&ca, Duration::from_secs(1))).unwrap();
    ca.set(|k| k.stall = true);
    let started = std::time::Instant::now();
    match acme.issue(&account, HOST, challenges.as_ref()).await {
        Err(AcmeError::Timeout(m)) => assert!(m.contains("validation"), "{m}"),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(challenges.map.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_urls_that_leave_https() {
    let ca = FakeCa::start().await;
    ca.set(|k| k.foreign_urls = true);
    let acme = Acme::new(config(&ca, Duration::from_secs(5))).unwrap();
    match acme.register(&AccountKey::generate()).await {
        Err(AcmeError::Transport(m)) => assert!(m.contains("not https"), "{m}"),
        other => panic!("{other:?}"),
    }
    // A directory that is not there at all.
    let gone = Acme::new(AcmeConfig {
        directory_url: format!("{}/missing", ca.directory),
        ..config(&ca, Duration::from_secs(5))
    })
    .unwrap();
    match gone.register(&AccountKey::generate()).await {
        Err(AcmeError::Transport(m)) => assert!(m.contains("HTTP 404"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_lost_account_is_reported_as_such() {
    let ca = FakeCa::start().await;
    let (acme, account, challenges) = client(&ca).await;
    ca.set(|k| k.forget_accounts = true);
    let err = acme
        .issue(&account, HOST, challenges.as_ref())
        .await
        .unwrap_err();
    assert!(err.lost_account(), "{err:?}");
}

// ---------------------------------------------------------------------------
// In the server, against Postgres

async fn add_and_verify(h: &Harness, dns: &FakeDns, hostname: &str) -> i64 {
    let (status, d) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({ "hostname": hostname })),
        )
        .await;
    assert_eq!(status, 201, "{d}");
    assert_eq!(d["certificate"], Value::Null, "not verified yet");
    dns.set_txt(
        &format!("_relink-challenge.{hostname}"),
        &[d["verification"]["value"].as_str().unwrap()],
    );
    let (status, d) = h
        .api(
            Method::POST,
            &format!("/v1/domains/{hostname}/verify"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!((status, &d["verified"]), (200, &json!(true)), "{d}");
    sqlx::query("SELECT id FROM domains WHERE hostname = $1")
        .bind(hostname)
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("id")
}

async fn domain(h: &Harness, hostname: &str) -> Value {
    let (status, d) = h
        .api(
            Method::GET,
            &format!("/v1/domains/{hostname}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{d}");
    d
}

async fn wait_for_status(h: &Harness, hostname: &str, status: &str) -> Value {
    let ok = eventually(Duration::from_secs(15), || async {
        domain(h, hostname).await["certificate"]["status"] == status
    })
    .await;
    let last = domain(h, hostname).await;
    assert!(ok, "certificate never {status}: {last}");
    last
}

fn ts(v: &Value) -> DateTime<Utc> {
    v.as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn verified_domains_get_certificates_renewed_at_two_thirds() {
    let Some(admin) = admin_url() else {
        return;
    };
    let dns = FakeDns::start().await;
    let ca = FakeCa::start().await;
    // Short-lived certificates, so renewal is due within the test.
    ca.set(|k| k.lifetime = Some(Duration::from_secs(6)));
    let dns_addr = dns.addr.to_string();
    let vars = [
        ("RELINK_DNS_SERVERS", dns_addr.as_str()),
        ("RELINK_ACME_DIRECTORY", ca.directory.as_str()),
        ("RELINK_ACME_EMAIL", "ops@relink-docs.net"),
        ("RELINK_ACME_INTERVAL_MS", "100"),
    ];
    let h = Harness::start(&admin, &vars).await;
    // Both instances run the worker; the CA's HTTP-01 request reaches the
    // second, whichever of them ordered.
    let other = h.second_instance(&vars).await;
    ca.validate_at(other.addr);

    let id = add_and_verify(&h, &dns, HOST).await;
    let d = wait_for_status(&h, HOST, "issued").await;
    let cert = &d["certificate"];
    assert_eq!(cert["error"], Value::Null);
    assert_eq!(cert["next_attempt_at"], Value::Null);
    let (not_after, renew_at) = (ts(&cert["not_after"]), ts(&cert["renew_at"]));
    assert_eq!(renew_at, not_after - chrono::Duration::seconds(2));

    // Stored: the chain, and the key it certifies.
    let (chain, key) = h.store.certificate(id).await.unwrap().unwrap();
    let leaf =
        der::parse_certificate(&der::pem_decode_all(&chain, "CERTIFICATE").unwrap()[0]).unwrap();
    assert_eq!(leaf.dns_names, [HOST]);
    assert_eq!(public_key_info(&key).unwrap(), leaf.spki);
    assert_eq!(leaf.not_after, not_after);

    // Renewed after two thirds of its lifetime, with a new key.
    assert!(
        eventually(Duration::from_secs(15), || async { ca.issued().len() >= 2 }).await,
        "not renewed: {:?}",
        ca.issued()
    );
    let renewed = eventually(Duration::from_secs(5), || async {
        let d = domain(&h, HOST).await;
        d["certificate"]["not_after"]
            .as_str()
            .map(|s| s.parse::<DateTime<Utc>>().unwrap())
            > Some(not_after)
    })
    .await;
    assert!(renewed);
    let (_, key2) = h.store.certificate(id).await.unwrap().unwrap();
    assert_ne!(key2, key, "each certificate gets a fresh key");
    // No renewal before two thirds: the second came after renew_at.
    let issued_at: DateTime<Utc> = sqlx::query("SELECT issued_at FROM domain_certificates")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("issued_at");
    assert!(issued_at >= renew_at, "{issued_at} before {renew_at}");

    // Every order ended in a certificate: the two instances never ordered
    // the same domain at once. One account is kept, whoever registered.
    assert_eq!(ca.orders(), ca.issued().len());
    let accounts: i64 = sqlx::query("SELECT count(*) AS n FROM acme_accounts")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("n");
    assert_eq!(accounts, 1);
    // Challenges are withdrawn once used.
    let pending: i64 = sqlx::query("SELECT count(*) AS n FROM acme_challenges")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("n");
    assert_eq!(pending, 0);
    assert!(metric(&h.metrics().await, "relink_certificate_failures_total") == 0.0);
    other.shutdown().await;
}

#[tokio::test]
async fn failures_back_off_and_are_shown_until_an_attempt_succeeds() {
    let Some(admin) = admin_url() else {
        return;
    };
    let dns = FakeDns::start().await;
    let ca = FakeCa::start().await;
    let dns_addr = dns.addr.to_string();
    let h = Harness::start(
        &admin,
        &[
            ("RELINK_DNS_SERVERS", dns_addr.as_str()),
            ("RELINK_ACME_DIRECTORY", ca.directory.as_str()),
            ("RELINK_ACME_INTERVAL_MS", "100"),
        ],
    )
    .await;
    // First the CA has lost the account, then it cannot reach the server.
    ca.set(|k| k.forget_accounts = true);
    let id = add_and_verify(&h, &dns, HOST).await;
    let d = wait_for_status(&h, HOST, "failed").await;
    assert!(
        d["certificate"]["error"]
            .as_str()
            .unwrap()
            .contains("accountDoesNotExist"),
        "{d}"
    );
    // The account is forgotten, to be registered again.
    assert!(
        eventually(Duration::from_secs(5), || async {
            sqlx::query("SELECT 1 FROM acme_accounts")
                .fetch_optional(h.store.pool())
                .await
                .unwrap()
                .is_none()
        })
        .await
    );
    let retry_now = || async {
        sqlx::query("UPDATE domains SET tls_next_attempt_at = now() WHERE id = $1")
            .bind(id)
            .execute(h.store.pool())
            .await
            .unwrap();
    };
    ca.set(|k| k.forget_accounts = false);
    retry_now().await;
    assert!(
        eventually(Duration::from_secs(10), || async {
            domain(&h, HOST).await["certificate"]["error"]
                .as_str()
                .is_some_and(|e| e.contains("validation failed"))
        })
        .await,
        "{}",
        domain(&h, HOST).await
    );
    let d = domain(&h, HOST).await;
    let cert = &d["certificate"];
    assert_eq!(cert["status"], "failed");
    // The second failure in a row waits ten minutes.
    let wait = ts(&cert["next_attempt_at"]) - ts(&cert["checked_at"]);
    assert!(
        (wait - chrono::Duration::seconds(600)).num_seconds().abs() <= 2,
        "{wait}"
    );
    let failures: i32 = sqlx::query("SELECT tls_failures FROM domains WHERE id = $1")
        .bind(id)
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("tls_failures");
    assert_eq!(failures, 2);
    // Nothing more happens while it waits.
    let orders = ca.orders();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(ca.orders(), orders);

    // Reachable now; the next attempt succeeds and clears the failures.
    ca.validate_at(h.server.as_ref().unwrap().addr);
    retry_now().await;
    let d = wait_for_status(&h, HOST, "issued").await;
    assert_eq!(d["certificate"]["error"], Value::Null);
    assert_eq!(d["certificate"]["next_attempt_at"], Value::Null);
    let failures: i32 = sqlx::query("SELECT tls_failures FROM domains WHERE id = $1")
        .bind(id)
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("tls_failures");
    assert_eq!(failures, 0);
    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_certificates_issued_total"), 1.0);
    assert_eq!(metric(&m, "relink_certificate_failures_total"), 2.0);
    assert!(metric(&m, "relink_acme_challenges_served_total") >= 1.0);
    // Tenants see the state but never the keys.
    let mut tx = h
        .store
        .begin_tenant(h.store.personal_workspace("alice").await.unwrap())
        .await
        .unwrap();
    let denied = sqlx::query("SELECT key_pkcs8 FROM domain_certificates")
        .fetch_all(&mut *tx)
        .await;
    assert!(denied.is_err());
}

#[tokio::test]
async fn http01_answers_only_its_host_on_every_instance() {
    let Some(admin) = admin_url() else {
        return;
    };
    let h = Harness::start(&admin, &[]).await;
    let other = h.second_instance(&[]).await;
    let token = "T".repeat(43);
    let get = |base: String, host: &'static str, token: String| {
        let http = h.http.clone();
        async move {
            let r = http
                .get(format!("{base}/.well-known/acme-challenge/{token}"))
                .header("host", host)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let other_base = format!("http://{}", other.addr);
    assert_eq!(get(h.base.clone(), HOST, token.clone()).await.0, 404);

    // Published on one instance, answered on both: from memory once the
    // notification arrives.
    h.store
        .put_challenge(&token, &format!("{token}.thumb"), HOST)
        .await
        .unwrap();
    assert!(
        eventually(Duration::from_secs(5), || async {
            other.app.challenges.len() == 1 && h.app().challenges.len() == 1
        })
        .await
    );
    for base in [h.base.clone(), other_base.clone()] {
        let (status, body) = get(base, HOST, token.clone()).await;
        assert_eq!(
            (status, body.as_str()),
            (200, format!("{token}.thumb").as_str())
        );
    }
    let (status, _) = get(h.base.clone(), "GO.relink-docs.net:80", token.clone()).await;
    assert_eq!(status, 200, "host matched without case or port");
    // Another host, a malformed token, an unknown token.
    assert_eq!(
        get(h.base.clone(), "other.relink-docs.net", token.clone())
            .await
            .0,
        404
    );
    assert_eq!(get(h.base.clone(), HOST, "short".into()).await.0, 404);
    assert_eq!(get(h.base.clone(), HOST, "U".repeat(43)).await.0, 404);
    assert_eq!(get(h.base.clone(), "[::1]", token.clone()).await.0, 404);

    // Written without a notification (as if it were lost): found in the
    // database, then by the next reload.
    let quiet = "Q".repeat(43);
    sqlx::query(
        "INSERT INTO acme_challenges (token, hostname, key_authorization, expires_at)
         VALUES ($1, $2, 'q.k', now() + interval '1 hour')",
    )
    .bind(&quiet)
    .bind(HOST)
    .execute(h.store.pool())
    .await
    .unwrap();
    let (status, body) = get(other_base.clone(), HOST, quiet.clone()).await;
    assert_eq!((status, body.as_str()), (200, "q.k"));
    // Expired ones are not served, and are deleted on reload.
    sqlx::query(
        "UPDATE acme_challenges SET expires_at = now() - interval '1 second' WHERE token = $1",
    )
    .bind(&quiet)
    .execute(h.store.pool())
    .await
    .unwrap();
    assert_eq!(get(other_base.clone(), HOST, quiet.clone()).await.0, 404);
    other.app.reload_challenges().await.unwrap();
    assert_eq!(other.app.challenges.len(), 1);

    // Withdrawn: gone everywhere.
    h.store.delete_challenge(&token).await.unwrap();
    assert!(
        eventually(Duration::from_secs(5), || async {
            other.app.challenges.is_empty() && h.app().challenges.is_empty()
        })
        .await
    );
    assert_eq!(get(other_base, HOST, token).await.0, 404);
    other.shutdown().await;
}

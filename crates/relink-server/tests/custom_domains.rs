//! Week 2 end to end: a branded domain used the way a customer would use
//! it, through the HTTP API, the `relink` binary, real TLS connections and
//! the edge's own request logic.
//!
//! A workspace on a one-domain plan adds a domain and proves it with a DNS
//! TXT record (a local resolver); a second domain is over the plan. Links
//! on the domain have codes of their own, unique per domain. relink's ACME
//! client gets a certificate from a local CA, both instances serve it by
//! SNI to a client that checks it, and a renewal is served without a
//! restart. The domain's settings (root redirect, path prefix, case-free
//! codes, its 404 and 410 pages) shape what it serves over TLS, and the KV
//! sync publishes the domain and its links, so the edge, reading those
//! records and forwarding the rest to the origin as the Worker does, gives
//! the same answers, most of them without asking the origin. Deleting the
//! domain takes it off TLS, KV and the zone's custom hostnames, and every
//! step is in the workspace's audit chain, which the binary verifies.

#[path = "common/acme_ca.rs"]
mod acme_ca;
mod common;
#[path = "common/kv.rs"]
mod kv;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use acme_ca::FakeCa;
use common::{FakeDns, Harness, admin_url, eventually};
use kv::{FakeKv, TOKEN, fake_kv};
use relink_core::abtest::Signer;
use relink_core::rules::Settings;
use relink_core::wire::{EdgeDomain, domain_kv_key, host_kv_key};
use relink_edge::logic::{
    EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, Served, forwarded_host, handle,
};
use relink_server::der;
use relink_server::util::now_ms;
use reqwest::Method;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const BIN: &str = env!("CARGO_BIN_EXE_relink");

const HOST: &str = "go.relink-docs.net";

/// The origin's own host (the test servers' public base URL).
const DEFAULT_HOST: &str = "localhost";

/// The headers both the origin and the edge must send alike.
const COMPARED: [&str; 4] = [
    "location",
    "content-type",
    "content-security-policy",
    "x-content-type-options",
];

/// Runs the binary against `db_url` and returns its stdout; panics with its
/// stderr if it fails.
fn relink(db_url: &str, args: &[&str]) -> String {
    let mut c = Command::new(BIN);
    c.env_clear();
    if let Ok(v) = std::env::var("LLVM_PROFILE_FILE") {
        c.env("LLVM_PROFILE_FILE", v);
    }
    let out = c
        .args(args)
        .env("RELINK_DATABASE_URL", db_url)
        .env("RELINK_LOG", "warn")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "relink {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A response reduced to what a visitor sees: status, the compared
/// headers and the body.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

impl Seen {
    fn location(&self) -> Option<&str> {
        self.headers.get("location").map(String::as_str)
    }

    fn content_type(&self) -> &str {
        self.headers.get("content-type").map_or("", String::as_str)
    }
}

/// A client that trusts only the test CA, as a browser trusts a public
/// one, and makes a full handshake every time (a resumed session would
/// report the certificate of the session it resumes).
fn verifying_client(ca: &FakeCa) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.root())).unwrap();
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

/// `GET /{path}` over TLS to `addr`, with SNI and `Host` both `host`: the
/// leaf certificate presented, and the response.
async fn over_tls(
    client: &TlsConnector,
    addr: SocketAddr,
    host: &str,
    path: &str,
) -> Result<(Vec<u8>, Seen), String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.to_owned()).unwrap();
    let mut tls = client.connect(name, tcp).await.map_err(|e| e.to_string())?;
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    tls.write_all(
        format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
    Ok((leaf, parse_http(&String::from_utf8(raw).unwrap())))
}

/// An HTTP/1.1 response with a `Content-Length` (or no) body.
fn parse_http(raw: &str) -> Seen {
    let (head, body) = raw.split_once("\r\n\r\n").expect("a complete response");
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap();
    let mut headers = BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once(':').unwrap();
        let k = k.trim().to_ascii_lowercase();
        if COMPARED.contains(&k.as_str()) {
            headers.insert(k, v.trim().to_owned());
        }
    }
    Seen {
        status: status.parse().unwrap(),
        headers,
        body: body.to_owned(),
    }
}

fn names(leaf: &[u8]) -> Vec<String> {
    der::parse_certificate(leaf).unwrap().dns_names
}

/// The edge's KV namespace: what the origin's KV sync published to the
/// fake KV API.
struct PublishedKv(Arc<FakeKv>);

impl Kv for PublishedKv {
    async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
        Ok(self.0.values.lock().unwrap().get(key).cloned())
    }
}

/// The origin behind the edge, called over HTTP the way the Worker calls
/// it: `Host` the origin's own, the visitor's host in `x-forwarded-host`,
/// from a trusted address (loopback, in the test configuration).
struct Behind {
    base: String,
    http: reqwest::Client,
}

impl Origin for Behind {
    async fn redirect(&self, req: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
        let mut r = self
            .http
            .get(format!("{}/{}", self.base, req.code))
            .header("host", DEFAULT_HOST);
        if let Some(h) = forwarded_host(req) {
            r = r.header("x-forwarded-host", h);
        }
        let resp = r.send().await.map_err(|e| EdgeError(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        let body = resp.text().await.map_err(|e| EdgeError(e.to_string()))?;
        Ok(EdgeResponse {
            status,
            headers,
            body,
        })
    }
}

/// What the edge answers for `path` on `host`, and whether it asked the
/// origin.
async fn at_edge(kv: &PublishedKv, origin: &Behind, host: &str, path: &str) -> (Seen, Served) {
    let signer = Signer::new([0x5a; 32]);
    let settings = Settings {
        signer: &signer,
        cookie_secure: true,
    };
    let req = EdgeRequest {
        code: path.to_owned(),
        host: Some(host.as_bytes().to_vec()),
        now_ms: now_ms(),
        random: 7,
        ..EdgeRequest::default()
    };
    let out = handle(kv, origin, &settings, DEFAULT_HOST, &req).await;
    let headers = out
        .response
        .headers
        .into_iter()
        .filter(|(k, _)| COMPARED.contains(&k.as_str()))
        .collect();
    let seen = Seen {
        status: out.response.status,
        headers,
        body: out.response.body,
    };
    (seen, out.served)
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

async fn link_on(h: &Harness, body: Value) -> Value {
    let (status, l) = h.api(Method::POST, "/v1/links", &h.alice, Some(body)).await;
    assert_eq!(status, 201, "{l}");
    l
}

#[tokio::test]
async fn a_branded_domain_from_dns_proof_to_tls_and_the_edge() {
    let Some(admin) = admin_url() else {
        return;
    };
    let dns = FakeDns::start().await;
    let ca = FakeCa::start().await;
    // Short-lived certificates, so a renewal comes within the test.
    ca.set(|k| k.lifetime = Some(Duration::from_secs(6)));
    let (kv_addr, kv) = fake_kv().await;
    let kv_base = format!("http://{kv_addr}/client/v4");
    let dns_addr = dns.addr.to_string();
    let vars = [
        ("RELINK_DNS_SERVERS", dns_addr.as_str()),
        ("RELINK_ACME_DIRECTORY", ca.directory.as_str()),
        ("RELINK_ACME_INTERVAL_MS", "100"),
        ("RELINK_TLS_ADDR", "127.0.0.1:0"),
        ("RELINK_KV_ACCOUNT_ID", "acct1"),
        ("RELINK_KV_NAMESPACE_ID", "ns1"),
        ("RELINK_KV_API_TOKEN", TOKEN),
        ("RELINK_KV_API_BASE", &kv_base),
        ("RELINK_KV_ZONE_ID", "zone1"),
        ("RELINK_KV_POLL_MS", "50"),
    ];
    let mut h = Harness::start(&admin, &vars).await;
    let other = h.second_instance(&vars).await;
    ca.validate_at(h.server.as_ref().unwrap().addr);
    let tls_addrs = [
        h.server.as_ref().unwrap().tls_addr.unwrap(),
        other.tls_addr.unwrap(),
    ];
    let client = verifying_client(&ca);
    let db = h.db.url.clone();

    // 1. The workspace is on a plan with one domain.
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    let ws = usage["workspace_id"].as_i64().unwrap().to_string();
    relink(&db, &["plan-set", "brand", "--domains", "1"]);
    relink(&db, &["plan-assign", &ws, "brand"]);

    // 2. It adds the domain; the domain is not served until it is proved.
    let (status, d) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({"hostname": "Go.Relink-Docs.NET"})),
        )
        .await;
    assert_eq!(status, 201, "{d}");
    assert_eq!(
        (&d["hostname"], &d["verified"]),
        (&json!(HOST), &json!(false))
    );
    assert_eq!(d["verification"]["type"], "TXT");
    assert_eq!(
        d["verification"]["name"],
        "_relink-challenge.go.relink-docs.net"
    );
    let proof = d["verification"]["value"].as_str().unwrap().to_owned();
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/domains",
            &h.alice,
            Some(json!({"hostname": "links.relink-docs.net"})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "quota_exceeded");
    let verify = format!("/v1/domains/{HOST}/verify");
    let (_, d) = h.api(Method::POST, &verify, &h.alice, None).await;
    assert_eq!(d["verified"], false);
    assert_eq!(d["check_error"], "no TXT record found");
    assert!(
        kv.keys().is_empty(),
        "nothing is published before the proof"
    );
    assert!(kv.hostnames().is_empty());

    // 3. The TXT record proves it.
    dns.set_txt("_relink-challenge.go.relink-docs.net", &[&proof]);
    let (status, d) = h.api(Method::POST, &verify, &h.alice, None).await;
    assert_eq!((status, &d["verified"]), (200, &json!(true)), "{d}");
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    assert_eq!(usage["domains"], json!({"used": 1, "limit": 1}));

    // 4. Codes are unique per domain: `promo` on the domain and `promo` on
    // the default domain are two links.
    let promo = link_on(
        &h,
        json!({"url": "https://shop.example.org/promo", "alias": "promo", "domain": HOST}),
    )
    .await;
    assert_eq!(promo["short_url"], "http://go.relink-docs.net/promo");
    link_on(
        &h,
        json!({"url": "https://example.org/default-promo", "alias": "promo"}),
    )
    .await;
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.org/x", "alias": "promo", "domain": HOST})),
        )
        .await;
    assert_eq!(status, 409, "the code is taken on this domain");

    // 5. relink's ACME client gets the domain a certificate, and both
    // instances serve it by SNI to a client that checks it chains to the
    // CA and names the host.
    assert!(
        eventually(Duration::from_secs(15), || async {
            domain(&h, HOST).await["certificate"]["status"] == "issued"
        })
        .await,
        "no certificate: {}",
        domain(&h, HOST).await
    );
    let mut first = Vec::new();
    for addr in tls_addrs {
        assert!(
            eventually(Duration::from_secs(5), || async {
                over_tls(&client, addr, HOST, "promo").await.is_ok()
            })
            .await,
            "{addr} never served the certificate"
        );
        let (leaf, seen) = over_tls(&client, addr, HOST, "promo").await.unwrap();
        assert_eq!(names(&leaf), [HOST]);
        assert_eq!(
            (seen.status, seen.location()),
            (302, Some("https://shop.example.org/promo"))
        );
        first.push(leaf);
    }
    let plain = h.visit("promo", &[]).await;
    assert_eq!(
        plain.headers()["location"],
        "https://example.org/default-promo",
        "the default domain keeps its own promo"
    );

    // 6. The domain's settings: a root redirect, a path prefix, codes in
    // any case, and its own 404 and 410 pages.
    let (status, d) = h
        .api(
            Method::PATCH,
            &format!("/v1/domains/{HOST}"),
            &h.alice,
            Some(json!({
                "root_url": "https://www.relink-docs.net/",
                "not_found_page": "<h1>{{code}} is not on {{host}}</h1>",
                "gone_page": "<p>{{code}} has ended</p>",
                "prefixes": ["Campaign"],
                "case_insensitive": true,
            })),
        )
        .await;
    assert_eq!(status, 200, "{d}");
    assert_eq!(d["settings"]["prefixes"], json!(["campaign"]));
    link_on(
        &h,
        json!({"url": "https://shop.example.org/flash", "alias": "Flash",
               "domain": HOST, "max_clicks": 1}),
    )
    .await;
    // The edge has the settings and the links once the sync has run.
    let host_key = host_kv_key(HOST);
    assert!(
        eventually(Duration::from_secs(5), || async {
            let v = kv.values.lock().unwrap();
            v.contains_key(&domain_kv_key(HOST, "flash"))
                && v.get(&host_key)
                    .and_then(|r| serde_json::from_str::<EdgeDomain>(r).ok())
                    .is_some_and(|r| r.settings.case_insensitive)
        })
        .await,
        "the edge never got the domain: {:?}",
        kv.keys()
    );
    assert!(kv.keys().contains(&domain_kv_key(HOST, "promo")));
    assert!(kv.keys().contains(&"link:promo".to_owned()));
    assert_eq!(kv.hostnames(), [HOST], "registered as a custom hostname");

    // Over TLS, from either instance, and at the edge, which must give the
    // same answer, answering most of them without the origin.
    let edge_kv = PublishedKv(kv.clone());
    let behind = Behind {
        base: h.base.clone(),
        http: common::client(),
    };
    let page = "text/html; charset=utf-8";
    let cases: [(&str, u16, Option<&str>, &str, Served); 7] = [
        (
            "",
            302,
            Some("https://www.relink-docs.net/"),
            "",
            Served::Edge,
        ),
        (
            "promo",
            302,
            Some("https://shop.example.org/promo"),
            "",
            Served::Edge,
        ),
        (
            "PROMO",
            302,
            Some("https://shop.example.org/promo"),
            "",
            Served::Edge,
        ),
        (
            "campaign/Promo",
            302,
            Some("https://shop.example.org/promo"),
            "",
            Served::Edge,
        ),
        // A code the edge has no record of may be newer than KV: the
        // origin decides. A path that can't name a code can't be.
        (
            "nope",
            404,
            None,
            "<h1>nope is not on go.relink-docs.net</h1>",
            Served::Origin,
        ),
        (
            "other/promo",
            404,
            None,
            "<h1>promo is not on go.relink-docs.net</h1>",
            Served::Edge,
        ),
        // A click-limited link is counted at the origin.
        (
            "campaign/FLASH",
            302,
            Some("https://shop.example.org/flash"),
            "",
            Served::Origin,
        ),
    ];
    for (i, (path, status, location, body, served)) in cases.into_iter().enumerate() {
        let (_, tls) = over_tls(&client, tls_addrs[i % 2], HOST, path)
            .await
            .unwrap();
        assert_eq!((tls.status, tls.location()), (status, location), "/{path}");
        if status == 404 {
            assert_eq!(
                (tls.content_type(), tls.body.as_str()),
                (page, body),
                "/{path}"
            );
            assert!(tls.headers.contains_key("content-security-policy"));
            assert_eq!(tls.headers["x-content-type-options"], "nosniff");
        }
        if path == "campaign/FLASH" {
            // That was its one click; the edge would have spent it too, so
            // compare it below with what both answer now.
            continue;
        }
        let (edge, by) = at_edge(&edge_kv, &behind, HOST, path).await;
        assert_eq!(edge, tls, "/{path}: the edge and the origin disagree");
        assert_eq!(by, served, "/{path}");
    }
    // Its click spent, the limited link is the domain's 410 page, from the
    // origin over TLS and from the edge alike, in whatever case.
    let (_, tls) = over_tls(&client, tls_addrs[1], HOST, "Flash")
        .await
        .unwrap();
    assert_eq!(
        (tls.status, tls.content_type(), tls.body.as_str()),
        (410, page, "<p>Flash has ended</p>")
    );
    let (edge, _) = at_edge(&edge_kv, &behind, HOST, "Flash").await;
    assert_eq!(edge, tls);
    // The default domain at the edge keeps its own link and plain pages.
    let (edge, by) = at_edge(&edge_kv, &behind, DEFAULT_HOST, "promo").await;
    assert_eq!(
        (edge.status, edge.location(), by),
        (302, Some("https://example.org/default-promo"), Served::Edge)
    );
    let (edge, _) = at_edge(&edge_kv, &behind, DEFAULT_HOST, "campaign/promo").await;
    assert_eq!(
        (edge.status, edge.content_type()),
        (404, "text/plain; charset=utf-8")
    );

    // 7. The certificate is renewed at two thirds of its lifetime and both
    // instances serve the new one on the next connection, without a
    // restart.
    for (i, addr) in tls_addrs.into_iter().enumerate() {
        assert!(
            eventually(Duration::from_secs(15), || async {
                matches!(over_tls(&client, addr, HOST, "promo").await,
                    Ok((leaf, seen)) if leaf != first[i] && seen.status == 302)
            })
            .await,
            "{addr} kept serving the first certificate"
        );
    }
    assert!(ca.issued().len() >= 2, "{:?}", ca.issued());

    // 8. A domain with links can't be deleted; once they are gone, deleting
    // it takes it off TLS, KV and the zone.
    let path = format!("/v1/domains/{HOST}");
    let (status, body) = h.api(Method::DELETE, &path, &h.alice, None).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "failed_precondition");
    for code in ["promo", "flash"] {
        let del = format!("/v1/links/{code}?domain={HOST}");
        assert_eq!(h.api(Method::DELETE, &del, &h.alice, None).await.0, 204);
    }
    assert_eq!(h.api(Method::DELETE, &path, &h.alice, None).await.0, 204);
    assert!(
        eventually(Duration::from_secs(10), || async {
            kv.keys() == ["link:promo"] && kv.hostnames().is_empty()
        })
        .await,
        "left at the edge: {:?} {:?}",
        kv.keys(),
        kv.hostnames()
    );
    for addr in tls_addrs {
        assert!(
            eventually(Duration::from_secs(5), || async {
                over_tls(&client, addr, HOST, "").await.is_err()
            })
            .await,
            "{addr} still serves the deleted domain"
        );
    }
    // The hostname is the default domain again, at the origin and at the
    // edge.
    let r = h
        .http
        .get(format!("{}/promo", h.base))
        .header("host", HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "https://example.org/default-promo");
    let (edge, _) = at_edge(&edge_kv, &behind, HOST, "promo").await;
    assert_eq!(edge.location(), Some("https://example.org/default-promo"));
    // A slot is free again on the plan.
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    assert_eq!(usage["domains"], json!({"used": 0, "limit": 1}));

    // 9. Every step is in the workspace's audit chain, which verifies.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE workspace_id = $1 AND action LIKE 'domain.%' \
         ORDER BY seq",
    )
    .bind(ws.parse::<i64>().unwrap())
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "domain.create",
            "domain.verify",
            "domain.update",
            "domain.delete"
        ]
    );
    let text = relink(&db, &["audit-verify", "--workspace", &ws]);
    assert!(text.starts_with(&format!("{ws}:")), "{text}");
    assert_eq!(kv.unauthorized.load(std::sync::atomic::Ordering::SeqCst), 0);

    other.shutdown().await;
    h.shutdown().await;
}

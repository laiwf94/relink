//! Terminating TLS (src/tls.rs, migration 0012). Two servers on one
//! database get certificates for a custom domain from a local ACME CA and
//! serve them on their TLS listeners by SNI; a renewal on either instance
//! is served by both without a restart; keys are sealed in Postgres, which
//! refuses any key that is not; a default certificate from files covers
//! clients without SNI; and slow or failed handshakes are cut off and
//! counted.

#[path = "common/acme_ca.rs"]
mod acme_ca;
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use acme_ca::FakeCa;
use common::{FakeDns, Harness, TEST_KEK, admin_url, eventually, hex32, metric};
use relink_server::der;
use relink_server::tls::{SEAL_MAGIC, Sealer, certificate_context};
use reqwest::Method;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde_json::{Value, json};
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const HOST: &str = "go.relink-docs.net";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A client that trusts only the test CA, as a browser would trust a
/// public one.
fn verifying_client(ca: &FakeCa) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.root())).unwrap();
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    fresh_handshakes(cfg)
}

/// A resumed session reports the certificate of the session it resumes,
/// so every connection here makes a full handshake.
fn fresh_handshakes(mut cfg: ClientConfig) -> TlsConnector {
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

/// Accepts any certificate: for looking at what is presented.
#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn looking_client() -> TlsConnector {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    fresh_handshakes(cfg)
}

/// Handshakes with `addr` as `name` (a DNS name sends SNI, an IP address
/// does not), sends one request for `path` on `host`, and returns the leaf
/// certificate presented and the response's status line and headers.
async fn fetch(
    connector: &TlsConnector,
    addr: SocketAddr,
    name: &str,
    host: &str,
    path: &str,
) -> Result<(Vec<u8>, String), String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let server_name = ServerName::try_from(name.to_owned()).unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (_, conn) = tls.get_ref();
    let leaf = conn.peer_certificates().unwrap()[0].as_ref().to_vec();
    assert_eq!(conn.alpn_protocol(), None, "the client offered no ALPN");
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response)
        .await
        .map_err(|e| e.to_string())?;
    let response = String::from_utf8_lossy(&response).into_owned();
    Ok((leaf, response))
}

fn names(leaf: &[u8]) -> Vec<String> {
    der::parse_certificate(leaf).unwrap().dns_names
}

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

async fn certificate_status(h: &Harness, hostname: &str) -> Value {
    let (status, d) = h
        .api(
            Method::GET,
            &format!("/v1/domains/{hostname}"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{d}");
    d["certificate"]["status"].clone()
}

/// PEM from DER, standard base64 with padding, as files hold it.
fn pem(label: &str, der: &[u8]) -> String {
    let url = relink_server::util::b64url_encode(der)
        .replace('-', "+")
        .replace('_', "/");
    let padded = format!("{url}{}", "=".repeat((4 - url.len() % 4) % 4));
    let lines: Vec<&str> = padded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

#[tokio::test]
async fn serves_each_domain_its_certificate_and_swaps_renewals_live() {
    let Some(admin) = admin_url() else {
        return;
    };
    let dns = FakeDns::start().await;
    let ca = FakeCa::start().await;
    // Short-lived certificates, so a renewal comes within the test.
    ca.set(|k| k.lifetime = Some(Duration::from_secs(6)));
    let dns_addr = dns.addr.to_string();
    let vars = [
        ("RELINK_DNS_SERVERS", dns_addr.as_str()),
        ("RELINK_ACME_DIRECTORY", ca.directory.as_str()),
        ("RELINK_ACME_INTERVAL_MS", "100"),
        ("RELINK_TLS_ADDR", "127.0.0.1:0"),
        ("RELINK_TLS_HANDSHAKE_TIMEOUT_MS", "500"),
    ];
    let h = Harness::start(&admin, &vars).await;
    let other = h.second_instance(&vars).await;
    ca.validate_at(h.server.as_ref().unwrap().addr);
    let tls_addrs = [
        h.server.as_ref().unwrap().tls_addr.unwrap(),
        other.tls_addr.unwrap(),
    ];
    let client = verifying_client(&ca);

    // Nothing to serve yet: no default certificate, no domain.
    let err = fetch(&client, tls_addrs[0], HOST, HOST, "/")
        .await
        .unwrap_err();
    assert!(!err.is_empty());

    let id = add_and_verify(&h, &dns, HOST).await;
    let (status, link) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.org/landing", "alias": "promo", "domain": HOST})),
        )
        .await;
    assert_eq!(status, 201, "{link}");
    assert!(
        eventually(Duration::from_secs(15), || async {
            certificate_status(&h, HOST).await == "issued"
        })
        .await
    );

    // Both instances serve it, by SNI, to a client that checks it chains
    // to the CA and names the host, and redirect on the custom domain.
    let mut first = Vec::new();
    for addr in tls_addrs {
        let ok = eventually(Duration::from_secs(5), || async {
            fetch(&client, addr, HOST, HOST, "/promo").await.is_ok()
        })
        .await;
        assert!(ok, "{addr} never served the certificate");
        let (leaf, response) = fetch(&client, addr, HOST, HOST, "/promo").await.unwrap();
        assert!(response.starts_with("HTTP/1.1 302"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("location: https://example.org/landing"),
            "{response}"
        );
        assert_eq!(names(&leaf), [HOST]);
        first.push(leaf);
    }
    // Any case and a final dot are the same host.
    let (leaf, _) = fetch(&client, tls_addrs[1], "GO.Relink-Docs.NET", HOST, "/promo")
        .await
        .unwrap();
    assert_eq!(names(&leaf), [HOST]);
    // The redirect sees the visitor's address through TLS as through
    // plain HTTP: the click is counted.
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, stats) = h
                .api(
                    Method::GET,
                    &format!("/v1/links/promo/stats?domain={HOST}"),
                    &h.alice,
                    None,
                )
                .await;
            stats["total_clicks"].as_i64() >= Some(3)
        })
        .await
    );

    // Another name gets no certificate (and no handshake) without a default.
    let err = fetch(&client, tls_addrs[0], "other.relink-docs.net", HOST, "/")
        .await
        .unwrap_err();
    assert!(!err.is_empty());

    // The key is sealed for this domain in Postgres.
    let sealed: Vec<u8> =
        sqlx::query("SELECT key_sealed FROM domain_certificates WHERE domain_id = $1")
            .bind(id)
            .fetch_one(h.store.pool())
            .await
            .unwrap()
            .get("key_sealed");
    assert!(sealed.starts_with(&SEAL_MAGIC));
    let sealer = Sealer::new(&hex32(TEST_KEK));
    let pkcs8 = sealer.open(&sealed, &certificate_context(id)).unwrap();
    assert_eq!(pkcs8[0], 0x30, "PKCS#8 inside");
    assert!(sealer.open(&sealed, &certificate_context(id + 1)).is_err());
    assert!(!sealed.windows(pkcs8.len()).any(|w| w == &pkcs8[..]));
    let account: Vec<u8> = sqlx::query("SELECT key_sealed FROM acme_accounts")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get("key_sealed");
    assert!(account.starts_with(&SEAL_MAGIC));
    // Postgres itself refuses a key that is not sealed.
    let refused =
        sqlx::query("UPDATE domain_certificates SET key_sealed = $1 WHERE domain_id = $2")
            .bind(&pkcs8)
            .bind(id)
            .execute(h.store.pool())
            .await
            .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("domain_certificates_key_sealed"),
        "{refused}"
    );
    let refused = sqlx::query("UPDATE acme_accounts SET key_sealed = $1")
        .bind(b"rlk\x01short".to_vec())
        .execute(h.store.pool())
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("acme_accounts_key_sealed"),
        "{refused}"
    );

    // Renewed at two thirds of the lifetime, by whichever instance claimed
    // it: both serve the new certificate on the connections that follow,
    // without a restart.
    for (i, addr) in tls_addrs.into_iter().enumerate() {
        let swapped = eventually(Duration::from_secs(15), || async {
            matches!(fetch(&client, addr, HOST, HOST, "/promo").await,
                Ok((leaf, _)) if leaf != first[i])
        })
        .await;
        assert!(swapped, "{addr} kept serving the first certificate");
    }
    let m = h.metrics().await;
    assert!(metric(&m, "relink_tls_handshakes_total") >= 3.0);
    assert!(metric(&m, "relink_tls_handshake_failures_total") >= 2.0);
    assert_eq!(metric(&m, "relink_tls_certificates"), 1.0);
    assert_eq!(metric(&m, "relink_tls_certificate_errors_total"), 0.0);

    // A third instance with the default certificate from files, and
    // another key encryption key: it serves the files to clients without
    // SNI and to names it has no certificate for, and logs and counts the
    // domain's certificate it cannot open instead of serving it.
    let dir = std::env::temp_dir().join(format!("relink-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_file, key_file) = (dir.join("cert.pem"), dir.join("key.pem"));
    // Chain and key read together: renewals keep coming.
    let (chain, sealed) = h.store.certificate(id).await.unwrap().unwrap();
    let pkcs8 = sealer.open(&sealed, &certificate_context(id)).unwrap();
    std::fs::write(&cert_file, &chain).unwrap();
    std::fs::write(&key_file, pem("PRIVATE KEY", &pkcs8)).unwrap();
    let path = |p: &Path| p.to_str().unwrap().to_owned();
    let (cert_path, key_path) = (path(&cert_file), path(&key_file));
    let other_kek = "11".repeat(32);
    let third = h
        .second_instance(&[
            ("RELINK_TLS_ADDR", "127.0.0.1:0"),
            ("RELINK_TLS_CERT_FILE", &cert_path),
            ("RELINK_TLS_KEY_FILE", &key_path),
            ("RELINK_KEY_ENCRYPTION_KEY", &other_kek),
            ("RELINK_TLS_HANDSHAKE_TIMEOUT_MS", "500"),
        ])
        .await;
    let addr = third.tls_addr.unwrap();
    let looking = looking_client();
    let default_leaf = der::pem_decode_all(&chain, "CERTIFICATE")
        .unwrap()
        .remove(0);
    for name in ["127.0.0.1", "unknown.relink-docs.net", HOST] {
        let (leaf, response) = fetch(&looking, addr, name, HOST, "/promo").await.unwrap();
        assert_eq!(leaf, default_leaf, "{name}");
        assert!(response.starts_with("HTTP/1.1 302"), "{response}");
    }
    let errors = metric(
        &third.app.metrics.render(&third.app.gauges()),
        "relink_tls_certificate_errors_total",
    );
    assert!(errors >= 1.0);
    assert_eq!(third.app.tls.as_ref().unwrap().store.len(), 0);

    // New files are picked up by a reload (every minute), a broken one is
    // not.
    assert!(
        eventually(Duration::from_secs(10), || async {
            h.store.certificate(id).await.unwrap().unwrap().0 != chain
        })
        .await
    );
    let (renewed_chain, renewed_sealed) = h.store.certificate(id).await.unwrap().unwrap();
    let renewed_key = sealer
        .open(&renewed_sealed, &certificate_context(id))
        .unwrap();
    std::fs::write(&cert_file, &renewed_chain).unwrap();
    std::fs::write(&key_file, pem("PRIVATE KEY", &renewed_key)).unwrap();
    let tls = third.app.tls.as_ref().unwrap();
    tls.reload_files().unwrap();
    let (leaf, _) = fetch(&looking, addr, "127.0.0.1", HOST, "/").await.unwrap();
    assert_eq!(
        leaf,
        der::pem_decode_all(&renewed_chain, "CERTIFICATE").unwrap()[0]
    );
    let stranger =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    std::fs::write(&key_file, pem("PRIVATE KEY", stranger.as_ref())).unwrap();
    let err = tls.reload_files().unwrap_err();
    assert!(
        err.contains("not the one the certificate certifies"),
        "{err}"
    );
    let (still, _) = fetch(&looking, addr, "127.0.0.1", HOST, "/").await.unwrap();
    assert_eq!(still, leaf);

    // A client that never finishes its handshake is cut off.
    let mut idle = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf))
        .await
        .expect("the server closes a stalled handshake");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    let _ = std::fs::remove_dir_all(&dir);

    third.shutdown().await;
    other.shutdown().await;
    // Shut down, the listener no longer accepts.
    assert!(
        eventually(Duration::from_secs(5), || async {
            TcpStream::connect(tls_addrs[1]).await.is_err()
        })
        .await
    );
}

#[tokio::test]
async fn a_default_certificate_that_cannot_be_read_stops_the_start() {
    let Some(admin) = admin_url() else {
        return;
    };
    let h = Harness::start(&admin, &[]).await;
    let missing = std::env::temp_dir().join("relink-tls-missing.pem");
    let missing = missing.to_str().unwrap();
    let cfg = common::config(
        &h.db.url_via(h.proxy.addr),
        &[
            ("RELINK_TLS_ADDR", "127.0.0.1:0"),
            ("RELINK_TLS_CERT_FILE", missing),
            ("RELINK_TLS_KEY_FILE", missing),
        ],
    );
    let db = relink_server::server::open_db(&cfg).unwrap();
    let err = relink_server::server::start(cfg, db).await.err().unwrap();
    assert!(err.contains("relink-tls-missing.pem"), "{err}");
}

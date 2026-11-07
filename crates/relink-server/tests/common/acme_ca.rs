#![allow(dead_code)]

//! A small ACME certificate authority (RFC 8555) for tests. It checks what
//! a real one checks: every request is a JWS signed by the account key (or
//! the embedded JWK for a new account) over a nonce it issued and the URL
//! requested; HTTP-01 is validated by fetching the key authorization from
//! the address it is pointed at, with the identifier as `Host`; the
//! certificate request must be signed by its own key and name exactly the
//! order's identifiers. It then signs a real X.509 certificate with its
//! own P-256 key. Knobs inject the failures a client must survive.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use relink_server::der;
use relink_server::util::{b64url_decode, b64url_encode};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED, EcdsaKeyPair,
    KeyPair, UnparsedPublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

/// What the CA does wrong on purpose.
#[derive(Clone, Debug, Default)]
pub struct Knobs {
    /// Refuse this many signed requests with `badNonce`.
    pub bad_nonces: usize,
    /// Refuse new orders as `rateLimited` with this `Retry-After`.
    pub rate_limit: Option<u64>,
    /// Answer every account-authenticated request `accountDoesNotExist`.
    pub forget_accounts: bool,
    /// Leave authorizations pending forever.
    pub stall: bool,
    /// Sign the certificate for a fresh key instead of the requested one.
    pub wrong_key: bool,
    /// Hand out a plain-http order URL on another host.
    pub foreign_urls: bool,
    /// Lifetime of issued certificates.
    pub lifetime: Option<Duration>,
}

#[derive(Debug)]
struct Authz {
    identifier: String,
    token: String,
    account: usize,
    status: &'static str,
    error: Option<String>,
}

#[derive(Debug)]
struct Order {
    account: usize,
    identifiers: Vec<String>,
    authzs: Vec<usize>,
    status: &'static str,
    cert: Option<usize>,
    /// Polls left before a finalized order turns valid.
    processing: u8,
}

#[derive(Default)]
struct Inner {
    nonces: HashSet<String>,
    /// Account public keys (uncompressed points) by ID.
    accounts: Vec<Vec<u8>>,
    orders: Vec<Order>,
    authzs: Vec<Authz>,
    certs: Vec<String>,
    knobs: Knobs,
    validate_at: Option<SocketAddr>,
    /// Identifiers of every certificate issued, in order.
    issued: Vec<String>,
}

struct Ca {
    base: String,
    inner: Mutex<Inner>,
    key: EcdsaKeyPair,
    cert: Vec<u8>,
    http: reqwest::Client,
}

pub struct FakeCa {
    pub addr: SocketAddr,
    pub directory: String,
    ca: Arc<Ca>,
    task: JoinHandle<()>,
}

impl Drop for FakeCa {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn utc_time(t: chrono::DateTime<Utc>) -> Vec<u8> {
    der::tlv(
        der::TAG_UTC_TIME,
        t.format("%y%m%d%H%M%SZ").to_string().as_bytes(),
    )
}

impl Ca {
    /// Signs a certificate for `spki` naming `names`, valid from now.
    fn sign(&self, names: &[&str], spki: &[u8], lifetime: Duration, ca: bool) -> Vec<u8> {
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).unwrap();
        serial[0] &= 0x7f;
        let now = Utc::now();
        let mut exts = vec![der::extension(
            der::OID_SUBJECT_ALT_NAME,
            &der::dns_names(names),
        )];
        if ca {
            exts.push(der::sequence(&[
                &der::oid(&[0x55, 0x1d, 0x13]),
                &der::tlv(der::TAG_BOOLEAN, &[0xff]),
                &der::tlv(
                    der::TAG_OCTET_STRING,
                    &der::sequence(&[&der::tlv(der::TAG_BOOLEAN, &[0xff])]),
                ),
            ]));
        }
        let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
        let tbs = der::sequence(&[
            &der::constructed(der::context(0), &[&der::unsigned_integer(&[2])]),
            &der::unsigned_integer(&serial),
            &der::ecdsa_sha256_algorithm(),
            &der::common_name("relink test CA"),
            &der::sequence(&[
                &utc_time(now),
                &utc_time(now + chrono::Duration::from_std(lifetime).unwrap()),
            ]),
            &der::common_name(names[0]),
            spki,
            &der::constructed(der::context(3), &[&der::sequence(&ext_refs)]),
        ]);
        let sig = self.key.sign(&SystemRandom::new(), &tbs).unwrap();
        der::sequence(&[
            &tbs,
            &der::ecdsa_sha256_algorithm(),
            &der::bit_string(sig.as_ref()),
        ])
    }

    fn nonce(&self) -> String {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).unwrap();
        let n = b64url_encode(&b);
        self.inner.lock().unwrap().nonces.insert(n.clone());
        n
    }

    fn reply(&self, status: StatusCode, location: Option<String>, body: Value) -> Response {
        let mut r = (status, body.to_string()).into_response();
        let h = r.headers_mut();
        h.insert(
            "replay-nonce",
            HeaderValue::from_str(&self.nonce()).unwrap(),
        );
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(l) = location {
            h.insert(header::LOCATION, HeaderValue::from_str(&l).unwrap());
        }
        r
    }

    fn problem(&self, status: StatusCode, kind: &str, detail: &str) -> Response {
        let mut r = self.reply(
            status,
            None,
            json!({"type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail}),
        );
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        r
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn refuse(&self, status: StatusCode, kind: &str, detail: &str) -> Box<Response> {
        Box::new(self.problem(status, kind, detail))
    }

    /// Checks a JWS: its nonce, URL, key and signature. Returns the
    /// account ID (or the JWK's point for a new account) and the payload.
    fn verify(
        &self,
        path: &str,
        body: &[u8],
        new_account: bool,
    ) -> Result<Verified, Box<Response>> {
        let bad = |detail: &str| self.refuse(StatusCode::BAD_REQUEST, "malformed", detail);
        let jws: Value = serde_json::from_slice(body).map_err(|_| bad("not JSON"))?;
        let field = |k: &str| jws[k].as_str().map(str::to_owned).ok_or_else(|| bad(k));
        let (protected_b64, payload_b64, sig_b64) =
            (field("protected")?, field("payload")?, field("signature")?);
        let protected: Value = b64url_decode(&protected_b64)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| bad("protected header"))?;
        if protected["alg"] != "ES256" {
            return Err(self.refuse(
                StatusCode::BAD_REQUEST,
                "badSignatureAlgorithm",
                "ES256 only",
            ));
        }
        {
            let mut inner = self.inner.lock().unwrap();
            let nonce = protected["nonce"].as_str().unwrap_or_default();
            if !inner.nonces.remove(nonce) {
                drop(inner);
                return Err(self.refuse(StatusCode::BAD_REQUEST, "badNonce", "unknown nonce"));
            }
            if inner.knobs.bad_nonces > 0 {
                inner.knobs.bad_nonces -= 1;
                drop(inner);
                return Err(self.refuse(StatusCode::BAD_REQUEST, "badNonce", "try again"));
            }
        }
        if protected["url"] != self.url(path) {
            return Err(self.refuse(StatusCode::UNAUTHORIZED, "unauthorized", "url mismatch"));
        }
        let (who, point) = if new_account {
            let jwk = &protected["jwk"];
            if protected.get("kid").is_some() || jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
                return Err(bad("a new account needs an EC P-256 jwk and no kid"));
            }
            let coord = |k: &str| {
                jwk[k]
                    .as_str()
                    .and_then(b64url_decode)
                    .filter(|c| c.len() == 32)
            };
            let (x, y) = (
                coord("x").ok_or_else(|| bad("x"))?,
                coord("y").ok_or_else(|| bad("y"))?,
            );
            let point = [&[4u8][..], &x, &y].concat();
            (Err(point.clone()), point)
        } else {
            if protected.get("jwk").is_some() {
                return Err(bad("jwk and kid"));
            }
            let inner = self.inner.lock().unwrap();
            if inner.knobs.forget_accounts {
                drop(inner);
                return Err(self.refuse(
                    StatusCode::BAD_REQUEST,
                    "accountDoesNotExist",
                    "no such account",
                ));
            }
            let id = protected["kid"]
                .as_str()
                .and_then(|k| k.strip_prefix(&self.url("/acct/")))
                .and_then(|id| id.parse::<usize>().ok())
                .filter(|&id| id < inner.accounts.len());
            let Some(id) = id else {
                drop(inner);
                return Err(self.refuse(
                    StatusCode::BAD_REQUEST,
                    "accountDoesNotExist",
                    "unknown kid",
                ));
            };
            (Ok(id), inner.accounts[id].clone())
        };
        let sig = b64url_decode(&sig_b64).ok_or_else(|| bad("signature"))?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(format!("{protected_b64}.{payload_b64}").as_bytes(), &sig)
            .map_err(|_| self.refuse(StatusCode::BAD_REQUEST, "malformed", "bad signature"))?;
        let payload = if payload_b64.is_empty() {
            None
        } else {
            Some(
                b64url_decode(&payload_b64)
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .ok_or_else(|| bad("payload"))?,
            )
        };
        Ok((who, payload))
    }

    fn order_json(&self, inner: &Inner, id: usize) -> Value {
        let o = &inner.orders[id];
        let mut v = json!({
            "status": o.status,
            "identifiers": o.identifiers.iter().map(|i| json!({"type": "dns", "value": i})).collect::<Vec<_>>(),
            "authorizations": o.authzs.iter().map(|a| self.url(&format!("/authz/{a}"))).collect::<Vec<_>>(),
            "finalize": self.url(&format!("/finalize/{id}")),
        });
        if let Some(c) = o.cert {
            v["certificate"] = json!(self.url(&format!("/cert/{c}")));
        }
        v
    }

    fn authz_json(&self, inner: &Inner, id: usize) -> Value {
        let a = &inner.authzs[id];
        let mut challenge = json!({
            "type": "http-01",
            "url": self.url(&format!("/chall/{id}")),
            "token": a.token,
            "status": a.status,
        });
        if let Some(e) = &a.error {
            challenge["error"] =
                json!({"type": "urn:ietf:params:acme:error:connection", "detail": e});
        }
        json!({
            "status": a.status,
            "identifier": {"type": "dns", "value": a.identifier},
            "challenges": [
                {"type": "dns-01", "url": self.url("/chall/unused"), "token": "x", "status": "pending"},
                challenge,
            ],
        })
    }

    /// Orders whose authorizations are all valid become ready.
    fn advance(inner: &mut Inner) {
        for i in 0..inner.orders.len() {
            let o = &inner.orders[i];
            if o.status == "pending" {
                let states: Vec<&str> = o.authzs.iter().map(|&a| inner.authzs[a].status).collect();
                if states.iter().all(|s| *s == "valid") {
                    inner.orders[i].status = "ready";
                } else if states.contains(&"invalid") {
                    inner.orders[i].status = "invalid";
                }
            }
        }
    }
}

fn thumbprint(point: &[u8]) -> String {
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        b64url_encode(&point[1..33]),
        b64url_encode(&point[33..65])
    );
    b64url_encode(&Sha256::digest(canonical.as_bytes()))
}

/// The DNS names and SPKI of a CSR whose signature checks out.
fn read_csr(csr: &[u8]) -> Option<(Vec<String>, Vec<u8>)> {
    let outer = der::parse_one(csr, der::TAG_SEQUENCE)?;
    let mut r = outer.contents();
    let info = r.expect(der::TAG_SEQUENCE)?;
    let alg = r.expect(der::TAG_SEQUENCE)?;
    let sig = r.expect(der::TAG_BIT_STRING)?;
    r.finish()?;
    if alg.raw != der::ecdsa_sha256_algorithm() || sig.value.first() != Some(&0) {
        return None;
    }
    let mut i = info.contents();
    if i.expect(der::TAG_INTEGER)?.value != [0] {
        return None;
    }
    i.expect(der::TAG_SEQUENCE)?;
    let spki = i.expect(der::TAG_SEQUENCE)?;
    let attrs = i.expect(der::context(0))?;
    i.finish()?;
    let point = &spki.raw[spki.raw.len() - 65..];
    if spki.raw != der::p256_spki(point) {
        return None;
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(info.raw, &sig.value[1..])
        .ok()?;
    // extensionRequest -> SET -> Extensions -> subjectAltName.
    let attr = der::parse_one(attrs.value, der::TAG_SEQUENCE)?;
    let mut a = attr.contents();
    if a.expect(der::TAG_OID)?.value != der::OID_EXTENSION_REQUEST {
        return None;
    }
    let set = a.expect(der::TAG_SET)?;
    let exts = der::parse_one(set.value, der::TAG_SEQUENCE)?;
    let mut e = exts.contents();
    let mut names = Vec::new();
    while let Some(ext) = e.read() {
        let mut x = ext.contents();
        if x.expect(der::TAG_OID)?.value == der::OID_SUBJECT_ALT_NAME {
            let value = x.expect(der::TAG_OCTET_STRING)?;
            let list = der::parse_one(value.value, der::TAG_SEQUENCE)?;
            let mut l = list.contents();
            while let Some(n) = l.read() {
                names.push(String::from_utf8(n.value.to_vec()).ok()?);
            }
        }
    }
    Some((names, spki.raw.to_vec()))
}

type S = State<Arc<Ca>>;

/// Who signed (an account ID, or a new account's key as a point) and the
/// payload, if not a POST-as-GET.
type Verified = (Result<usize, Vec<u8>>, Option<Value>);

async fn directory(State(ca): S) -> Response {
    let foreign = ca.inner.lock().unwrap().knobs.foreign_urls;
    let order = if foreign {
        "http://ca.example.net/order".to_owned()
    } else {
        ca.url("/order")
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        json!({
            "newNonce": ca.url("/nonce"),
            "newAccount": ca.url("/acct"),
            "newOrder": order,
            "meta": {"termsOfService": ca.url("/terms")},
        })
        .to_string(),
    )
        .into_response()
}

async fn new_nonce(State(ca): S) -> Response {
    let mut r = StatusCode::OK.into_response();
    r.headers_mut()
        .insert("replay-nonce", HeaderValue::from_str(&ca.nonce()).unwrap());
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn new_account(State(ca): S, body: Bytes) -> Response {
    let (who, payload) = match ca.verify("/acct", &body, true) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let point = who.unwrap_err();
    let payload = payload.unwrap_or_default();
    if payload["termsOfServiceAgreed"] != true {
        return ca.problem(
            StatusCode::FORBIDDEN,
            "userActionRequired",
            "agree to the terms",
        );
    }
    let mut inner = ca.inner.lock().unwrap();
    let (status, id) = match inner.accounts.iter().position(|p| *p == point) {
        Some(id) => (StatusCode::OK, id),
        None => {
            inner.accounts.push(point);
            (StatusCode::CREATED, inner.accounts.len() - 1)
        }
    };
    drop(inner);
    ca.reply(
        status,
        Some(ca.url(&format!("/acct/{id}"))),
        json!({"status": "valid", "contact": payload["contact"]}),
    )
}

async fn new_order(State(ca): S, body: Bytes) -> Response {
    let (who, payload) = match ca.verify("/order", &body, false) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let account = who.unwrap();
    let mut inner = ca.inner.lock().unwrap();
    if let Some(secs) = inner.knobs.rate_limit {
        drop(inner);
        let mut r = ca.problem(
            StatusCode::TOO_MANY_REQUESTS,
            "rateLimited",
            "too many orders",
        );
        r.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&secs.to_string()).unwrap(),
        );
        return r;
    }
    let identifiers: Vec<String> = payload.unwrap_or_default()["identifiers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i["value"].as_str().map(str::to_owned))
        .collect();
    let mut authzs = Vec::new();
    for ident in &identifiers {
        let mut t = [0u8; 32];
        getrandom::fill(&mut t).unwrap();
        inner.authzs.push(Authz {
            identifier: ident.clone(),
            token: b64url_encode(&t),
            account,
            status: "pending",
            error: None,
        });
        authzs.push(inner.authzs.len() - 1);
    }
    inner.orders.push(Order {
        account,
        identifiers,
        authzs,
        status: "pending",
        cert: None,
        processing: 2,
    });
    let id = inner.orders.len() - 1;
    let body = ca.order_json(&inner, id);
    drop(inner);
    ca.reply(
        StatusCode::CREATED,
        Some(ca.url(&format!("/order/{id}"))),
        body,
    )
}

async fn get_order(State(ca): S, Path(id): Path<usize>, body: Bytes) -> Response {
    let (who, _) = match ca.verify(&format!("/order/{id}"), &body, false) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let mut inner = ca.inner.lock().unwrap();
    if inner.orders.get(id).map(|o| o.account) != Some(who.unwrap()) {
        drop(inner);
        return ca.problem(StatusCode::NOT_FOUND, "malformed", "no such order");
    }
    Ca::advance(&mut inner);
    let o = &mut inner.orders[id];
    if o.status == "processing" {
        o.processing = o.processing.saturating_sub(1);
        if o.processing == 0 {
            o.status = "valid";
        }
    }
    let body = ca.order_json(&inner, id);
    drop(inner);
    let mut r = ca.reply(StatusCode::OK, None, body);
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("0"));
    r
}

async fn get_authz(State(ca): S, Path(id): Path<usize>, body: Bytes) -> Response {
    let (who, _) = match ca.verify(&format!("/authz/{id}"), &body, false) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let inner = ca.inner.lock().unwrap();
    if inner.authzs.get(id).map(|a| a.account) != Some(who.unwrap()) {
        drop(inner);
        return ca.problem(StatusCode::NOT_FOUND, "malformed", "no such authorization");
    }
    let body = ca.authz_json(&inner, id);
    drop(inner);
    ca.reply(StatusCode::OK, None, body)
}

async fn respond(State(ca): S, Path(id): Path<usize>, body: Bytes) -> Response {
    let (who, payload) = match ca.verify(&format!("/chall/{id}"), &body, false) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if payload != Some(json!({})) {
        return ca.problem(StatusCode::BAD_REQUEST, "malformed", "respond with {}");
    }
    let account = who.unwrap();
    let (identifier, token, point, target, stall) = {
        let inner = ca.inner.lock().unwrap();
        let Some(a) = inner.authzs.get(id).filter(|a| a.account == account) else {
            drop(inner);
            return ca.problem(StatusCode::NOT_FOUND, "malformed", "no such challenge");
        };
        (
            a.identifier.clone(),
            a.token.clone(),
            inner.accounts[account].clone(),
            inner.validate_at,
            inner.knobs.stall,
        )
    };
    let reply_token = token.clone();
    if !stall {
        let ca2 = ca.clone();
        tokio::spawn(async move {
            let expected = format!("{token}.{}", thumbprint(&point));
            let outcome = match target {
                None => Err("nothing to validate against".to_owned()),
                Some(addr) => {
                    let got = ca2
                        .http
                        .get(format!("http://{addr}/.well-known/acme-challenge/{token}"))
                        .header(header::HOST, &identifier)
                        .send()
                        .await;
                    match got {
                        Ok(r) if r.status() == 200 => {
                            let body = r.text().await.unwrap_or_default();
                            if body.trim_end() == expected {
                                Ok(())
                            } else {
                                Err(format!("wrong key authorization {body:?}"))
                            }
                        }
                        Ok(r) => Err(format!("HTTP {} from {identifier}", r.status().as_u16())),
                        Err(e) => Err(format!("cannot connect to {identifier}: {e}")),
                    }
                }
            };
            let mut inner = ca2.inner.lock().unwrap();
            let a = &mut inner.authzs[id];
            match outcome {
                Ok(()) => a.status = "valid",
                Err(e) => {
                    a.status = "invalid";
                    a.error = Some(e);
                }
            }
        });
    }
    ca.reply(
        StatusCode::OK,
        None,
        json!({"type": "http-01", "url": ca.url(&format!("/chall/{id}")), "token": reply_token, "status": "processing"}),
    )
}

async fn finalize(State(ca): S, Path(id): Path<usize>, body: Bytes) -> Response {
    let (who, payload) = match ca.verify(&format!("/finalize/{id}"), &body, false) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let mut inner = ca.inner.lock().unwrap();
    Ca::advance(&mut inner);
    let Some(order) = inner
        .orders
        .get(id)
        .filter(|o| o.account == who.clone().unwrap())
    else {
        drop(inner);
        return ca.problem(StatusCode::NOT_FOUND, "malformed", "no such order");
    };
    if order.status != "ready" {
        drop(inner);
        return ca.problem(StatusCode::FORBIDDEN, "orderNotReady", "not ready");
    }
    let csr = payload
        .as_ref()
        .and_then(|p| p["csr"].as_str())
        .and_then(b64url_decode);
    let Some((names, spki)) = csr.as_deref().and_then(read_csr) else {
        drop(inner);
        return ca.problem(StatusCode::BAD_REQUEST, "badCSR", "the CSR does not verify");
    };
    let mut wanted = order.identifiers.clone();
    let mut got = names.clone();
    wanted.sort();
    got.sort();
    if wanted != got {
        drop(inner);
        return ca.problem(
            StatusCode::BAD_REQUEST,
            "badCSR",
            "names differ from the order",
        );
    }
    let lifetime = inner
        .knobs
        .lifetime
        .unwrap_or(Duration::from_secs(90 * 86_400));
    let spki = if inner.knobs.wrong_key {
        let other =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            other.as_ref(),
            &SystemRandom::new(),
        )
        .unwrap();
        der::p256_spki(pair.public_key().as_ref())
    } else {
        spki
    };
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let leaf = ca.sign(&name_refs, &spki, lifetime, false);
    let chain = format!(
        "{}{}",
        der::pem_encode("CERTIFICATE", &leaf),
        der::pem_encode("CERTIFICATE", &ca.cert)
    );
    inner.certs.push(chain);
    let cert = inner.certs.len() - 1;
    inner.issued.push(names.join(","));
    let o = &mut inner.orders[id];
    o.status = "processing";
    o.cert = Some(cert);
    let body = ca.order_json(&inner, id);
    drop(inner);
    ca.reply(StatusCode::OK, Some(ca.url(&format!("/order/{id}"))), body)
}

async fn certificate(
    State(ca): S,
    Path(id): Path<usize>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = ca.verify(&format!("/cert/{id}"), &body, false) {
        return *r;
    }
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok())
        != Some("application/pem-certificate-chain")
    {
        return ca.problem(StatusCode::NOT_ACCEPTABLE, "malformed", "PEM only");
    }
    let chain = ca.inner.lock().unwrap().certs.get(id).cloned();
    match chain {
        Some(c) => {
            let mut r = ca.reply(StatusCode::OK, None, Value::Null);
            *r.body_mut() = c.into();
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pem-certificate-chain"),
            );
            r
        }
        None => ca.problem(StatusCode::NOT_FOUND, "malformed", "no such certificate"),
    }
}

impl FakeCa {
    pub async fn start() -> FakeCa {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let mut ca = Ca {
            base: base.clone(),
            inner: Mutex::new(Inner::default()),
            cert: Vec::new(),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            key,
        };
        let spki = der::p256_spki(ca.key.public_key().as_ref());
        ca.cert = ca.sign(
            &["relink test CA"],
            &spki,
            Duration::from_secs(365 * 86_400),
            true,
        );
        let ca = Arc::new(ca);
        let app = Router::new()
            .route("/dir", get(directory))
            .route("/nonce", get(new_nonce))
            .route("/acct", post(new_account))
            .route("/order", post(new_order))
            .route("/order/{id}", post(get_order))
            .route("/authz/{id}", post(get_authz))
            .route("/chall/{id}", post(respond))
            .route("/finalize/{id}", post(finalize))
            .route("/cert/{id}", post(certificate))
            .with_state(ca.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeCa {
            addr,
            directory: format!("{base}/dir"),
            ca,
            task,
        }
    }

    /// Where HTTP-01 challenges are fetched from.
    pub fn validate_at(&self, addr: SocketAddr) {
        self.ca.inner.lock().unwrap().validate_at = Some(addr);
    }

    pub fn set(&self, f: impl FnOnce(&mut Knobs)) {
        f(&mut self.ca.inner.lock().unwrap().knobs);
    }

    /// The identifiers of every certificate issued so far.
    pub fn issued(&self) -> Vec<String> {
        self.ca.inner.lock().unwrap().issued.clone()
    }

    pub fn orders(&self) -> usize {
        self.ca.inner.lock().unwrap().orders.len()
    }

    pub fn accounts(&self) -> usize {
        self.ca.inner.lock().unwrap().accounts.len()
    }

    /// The CA certificate, DER.
    pub fn root(&self) -> Vec<u8> {
        self.ca.cert.clone()
    }
}

/// Challenges kept in memory and served over HTTP, for driving the client
/// without a database.
#[derive(Default)]
pub struct MemChallenges {
    pub map: Mutex<HashMap<String, (String, String)>>,
    pub published: Mutex<usize>,
}

impl relink_server::acme::Challenges for MemChallenges {
    fn publish<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
        hostname: &'a str,
    ) -> relink_server::util::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            *self.published.lock().unwrap() += 1;
            self.map.lock().unwrap().insert(
                token.to_owned(),
                (hostname.to_owned(), key_authorization.to_owned()),
            );
            Ok(())
        })
    }

    fn withdraw<'a>(
        &'a self,
        token: &'a str,
    ) -> relink_server::util::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.map.lock().unwrap().remove(token);
            Ok(())
        })
    }
}

/// Serves `challenges` at /.well-known/acme-challenge/{token}, by Host.
pub async fn serve_challenges(challenges: Arc<MemChallenges>) -> (SocketAddr, JoinHandle<()>) {
    async fn answer(
        State(c): State<Arc<MemChallenges>>,
        Path(token): Path<String>,
        headers: HeaderMap,
    ) -> Response {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        match c.map.lock().unwrap().get(&token) {
            Some((h, ka)) if *h == host => ka.clone().into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(answer))
        .with_state(challenges);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, task)
}

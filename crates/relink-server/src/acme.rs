//! Certificates for custom domains from an ACME certificate authority
//! (RFC 8555), such as Let's Encrypt.
//!
//! [`Acme`] is the protocol: the directory, replay nonces, an account
//! whose ES256 key signs every request as a JWS (RFC 7515, signed with
//! `ring`), orders, HTTP-01 authorizations, finalization with a PKCS#10
//! request ([`crate::der`]) and the certificate download. It keeps no state
//! but the directory and spare nonces; challenges are published through
//! [`Challenges`], so the same client runs against Postgres in the server
//! and against memory in tests.
//!
//! [`AcmeWorker`] is the schedule: it claims verified domains that have no
//! certificate or whose certificate has used two thirds of its lifetime,
//! with `SKIP LOCKED` so several instances share the work without ordering
//! twice, issues, and stores the chain and key (migration 0011). Failures
//! back off exponentially, or as long as the CA's `Retry-After` says.
//!
//! The CA validates by fetching `http://<domain>/.well-known/acme-challenge/
//! <token>` from whichever instance the domain's address reaches, so every
//! instance answers [`http01`] from a map of pending challenges kept like
//! the verified domains: loaded at start, on a change notification, when the
//! listener reconnects and once a minute, with a rate-limited database
//! lookup for a token the map has not caught up with yet.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::sync::{Notify, watch};

use crate::der;
use crate::domains::host_part;
use crate::metrics::{DbOp, Metrics};
use crate::oidc::is_loopback_http;
use crate::server::App;
use crate::store::{CHANGES_CHANNEL, Db, DbError};
use crate::util::{BoxFuture, b64url_encode, stopped};

/// The change notification payload sent when a challenge is published.
pub const CHALLENGES_CHANGED: &str = "acme_challenges";

/// Largest response read from the CA. A chain is a few kilobytes.
const MAX_RESPONSE: usize = 1 << 20;
/// Spare nonces kept; each one is good for one request.
const MAX_NONCES: usize = 16;
/// Attempts for one request when the CA refuses its nonce.
const BAD_NONCE_ATTEMPTS: usize = 3;
/// How long a published challenge answers, past which it is forgotten.
const CHALLENGE_TTL: Duration = Duration::from_secs(3_600);
/// How long a claimed domain is left to its instance before another may
/// try, in case the first one stops mid-order.
const CLAIM_LEASE: Duration = Duration::from_secs(900);
/// Domains claimed per round.
const CLAIM_BATCH: i64 = 4;
/// First retry delay after a failure; doubled per further failure.
const RETRY_BASE: Duration = Duration::from_secs(300);
/// The longest wait between attempts.
const RETRY_MAX: Duration = Duration::from_secs(86_400);
/// Longest stored error; the column allows 300.
const MAX_ERROR: usize = 300;
/// Database lookups per second for tokens not in the local map.
const LOOKUP_RATE: f64 = 20.0;

/// ACME settings, from `RELINK_ACME_*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeConfig {
    /// The CA's directory URL. Setting it accepts the CA's terms of service.
    pub directory_url: String,
    /// An address the CA may write to about the account (expiry notices).
    pub email: Option<String>,
    /// How often to look for domains that need a certificate.
    pub interval: Duration,
    /// How long one order may take, validation and issuance included.
    pub order_timeout: Duration,
}

impl AcmeConfig {
    /// Checks the settings that can be checked without the network.
    pub fn validate(&self) -> Result<(), String> {
        if !acceptable(&self.directory_url, true) {
            return Err(
                "RELINK_ACME_DIRECTORY must be an https URL (or http on localhost for tests)"
                    .into(),
            );
        }
        if let Some(e) = &self.email {
            let ok = e.len() <= 254
                && e.split_once('@')
                    .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'))
                && e.bytes().all(|b| b.is_ascii_graphic() && b != b',');
            if !ok {
                return Err("RELINK_ACME_EMAIL must be an email address".into());
            }
        }
        Ok(())
    }
}

/// https with a host, or plain http to loopback when `loopback`.
fn acceptable(url: &str, loopback: bool) -> bool {
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" && u.host().is_some() => true,
        Ok(_) => loopback && is_loopback_http(url),
        Err(_) => false,
    }
}

/// Two thirds of the way from `not_before` to `not_after`: when a
/// certificate is renewed. A 90-day certificate is renewed after 60 days,
/// leaving 30 for retries.
pub fn renew_at(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> DateTime<Utc> {
    not_before + (not_after - not_before) * 2 / 3
}

/// How long to wait after the `failures`th failure in a row (1 or more):
/// five minutes, doubling, at most a day, and never less than the CA asked.
pub fn retry_delay(failures: u32, retry_after: Option<Duration>) -> Duration {
    let backoff = RETRY_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(RETRY_MAX);
    backoff.max(retry_after.unwrap_or_default().min(RETRY_MAX))
}

// ---------------------------------------------------------------------------
// Keys and JWS

/// An account key: ECDSA P-256, signing JWS with ES256.
pub struct AccountKey {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKey")
            .field("thumbprint", &self.thumbprint())
            .finish_non_exhaustive()
    }
}

impl AccountKey {
    pub fn generate() -> AccountKey {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("the system random generator works");
        AccountKey::from_pkcs8(doc.as_ref()).expect("a generated key parses")
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<AccountKey, String> {
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            &SystemRandom::new(),
        )
        .map_err(|_| "not a P-256 PKCS#8 key".to_owned())?;
        Ok(AccountKey {
            pkcs8: pkcs8.to_vec(),
            pair,
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    fn coordinates(&self) -> (String, String) {
        // Uncompressed point: 0x04, then x and y of 32 bytes each.
        let point = self.pair.public_key().as_ref();
        (b64url_encode(&point[1..33]), b64url_encode(&point[33..65]))
    }

    /// The public key as a JWK (RFC 7517).
    pub fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({"crv": "P-256", "kty": "EC", "x": x, "y": y})
    }

    /// The JWK thumbprint (RFC 7638): SHA-256 over the required members in
    /// lexicographic order without whitespace, base64url.
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        b64url_encode(&Sha256::digest(canonical.as_bytes()))
    }

    /// What the HTTP-01 resource must contain for `token` (RFC 8555 8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// A flattened JWS (RFC 7515 7.2.2) of `payload` with `protected`
    /// headers. `None` is the empty payload of a POST-as-GET.
    pub fn sign(&self, protected: &Value, payload: Option<&Value>) -> Value {
        let protected = b64url_encode(protected.to_string().as_bytes());
        let payload = payload
            .map(|p| b64url_encode(p.to_string().as_bytes()))
            .unwrap_or_default();
        let signature = self
            .pair
            .sign(
                &SystemRandom::new(),
                format!("{protected}.{payload}").as_bytes(),
            )
            .expect("signing with a valid key works");
        json!({
            "protected": protected,
            "payload": payload,
            "signature": b64url_encode(signature.as_ref()),
        })
    }
}

/// A fresh certificate key and the request to certify it for `hostname`:
/// (PKCS#8 key, DER request). P-256, which every CA and client accepts and
/// which is far cheaper in TLS handshakes than RSA.
pub fn certificate_request(hostname: &str) -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("the system random generator works");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng)
        .expect("a generated key parses");
    let info = der::certification_request_info(&[hostname], pair.public_key().as_ref());
    let signature = pair.sign(&rng, &info).expect("signing works");
    (
        doc.as_ref().to_vec(),
        der::certification_request(&info, signature.as_ref()),
    )
}

/// The `SubjectPublicKeyInfo` of a P-256 PKCS#8 key.
pub fn public_key_info(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &SystemRandom::new())
            .ok()?;
    Some(der::p256_spki(pair.public_key().as_ref()))
}

// ---------------------------------------------------------------------------
// Errors

/// An RFC 7807 problem document from the CA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The type without `urn:ietf:params:acme:error:`, such as `badNonce`.
    pub kind: String,
    pub detail: String,
    pub status: u16,
    /// From the `Retry-After` header, when the CA sent one.
    pub retry_after: Option<Duration>,
}

impl Problem {
    fn parse(status: u16, body: &[u8], retry_after: Option<Duration>) -> Problem {
        let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
        let kind = text("type");
        Problem {
            kind: kind
                .strip_prefix("urn:ietf:params:acme:error:")
                .unwrap_or(kind)
                .chars()
                .take(64)
                .collect(),
            detail: text("detail").chars().take(200).collect(),
            status,
            retry_after,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.kind.is_empty() {
            "error"
        } else {
            &self.kind
        };
        write!(f, "{kind} (HTTP {})", self.status)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcmeError {
    /// The CA could not be reached or answered something unusable.
    Transport(String),
    /// The CA refused a request.
    Problem(Problem),
    /// An authorization or the order ended invalid; the CA's reason.
    Invalid(String),
    /// The order did not finish within the order timeout.
    Timeout(String),
    /// A challenge could not be published.
    Publish(String),
}

impl AcmeError {
    /// The wait the CA asked for, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            AcmeError::Problem(p) => p.retry_after,
            _ => None,
        }
    }

    /// Whether the CA no longer knows the account, so a new one is needed.
    pub fn lost_account(&self) -> bool {
        matches!(self, AcmeError::Problem(p) if p.kind == "accountDoesNotExist")
    }
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcmeError::Transport(m) => write!(f, "certificate authority unreachable: {m}"),
            AcmeError::Problem(p) => write!(f, "certificate authority refused: {p}"),
            AcmeError::Invalid(m) => write!(f, "validation failed: {m}"),
            AcmeError::Timeout(m) => write!(f, "timed out: {m}"),
            AcmeError::Publish(m) => write!(f, "could not publish the challenge: {m}"),
        }
    }
}

impl std::error::Error for AcmeError {}

/// `Retry-After` as seconds or an HTTP date.
pub fn parse_retry_after(v: &str, now: DateTime<Utc>) -> Option<Duration> {
    let v = v.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = DateTime::parse_from_rfc2822(v).ok()?.with_timezone(&Utc);
    Some((at - now).to_std().unwrap_or_default())
}

// ---------------------------------------------------------------------------
// The client

/// Where challenges are published for the CA to fetch.
pub trait Challenges: Send + Sync {
    fn publish<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;

    fn withdraw<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// A registered account: its key and the URL that names it (the `kid`).
#[derive(Debug)]
pub struct Account {
    pub key: AccountKey,
    pub url: String,
}

/// An issued certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The chain as the CA sent it, leaf first, PEM.
    pub chain_pem: String,
    /// The leaf's private key, PKCS#8 DER.
    pub key_pkcs8: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub renew_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

struct Reply {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    retry_after: Option<Duration>,
}

impl Reply {
    fn json(&self) -> Result<Value, AcmeError> {
        serde_json::from_slice(&self.body)
            .map_err(|_| AcmeError::Transport("the response is not JSON".into()))
    }
}

/// An ACME client for one CA.
pub struct Acme {
    cfg: AcmeConfig,
    http: reqwest::Client,
    directory: tokio::sync::Mutex<Option<Directory>>,
    nonces: Mutex<Vec<String>>,
    /// Whether the directory is plain http to loopback, which then allows
    /// the same for the URLs it hands out (tests only).
    loopback: bool,
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, AcmeError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AcmeError::Transport(format!("the response has no {key}")))
}

impl Acme {
    pub fn new(cfg: AcmeConfig) -> Result<Acme, String> {
        cfg.validate()?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("relink/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Acme {
            loopback: is_loopback_http(&cfg.directory_url),
            cfg,
            http,
            directory: tokio::sync::Mutex::new(None),
            nonces: Mutex::new(Vec::new()),
        })
    }

    pub fn config(&self) -> &AcmeConfig {
        &self.cfg
    }

    /// A URL the CA handed out, which must be https like the directory.
    fn checked<'a>(&self, url: &'a str) -> Result<&'a str, AcmeError> {
        if acceptable(url, self.loopback) {
            Ok(url)
        } else {
            Err(AcmeError::Transport(format!(
                "the certificate authority gave a URL that is not https: {url:.100}"
            )))
        }
    }

    fn keep_nonce(&self, headers: &reqwest::header::HeaderMap) {
        let Some(n) = headers
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .filter(|n| !n.is_empty() && n.len() <= 256 && n.bytes().all(is_b64url))
        else {
            return;
        };
        let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        if nonces.len() < MAX_NONCES {
            nonces.push(n.to_owned());
        }
    }

    async fn read(&self, resp: reqwest::Response) -> Result<Reply, AcmeError> {
        self.keep_nonce(resp.headers());
        let status = resp.status().as_u16();
        let header = |name| {
            resp.headers()
                .get(name)
                .and_then(|v: &HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        let location = header(header::LOCATION);
        let retry_after = header(header::RETRY_AFTER)
            .and_then(|v| parse_retry_after(&v, Utc::now()))
            .map(|d| d.min(RETRY_MAX));
        let mut resp = resp;
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| AcmeError::Transport(format!("reading the response: {e}")))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE {
                return Err(AcmeError::Transport("response too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Reply {
            status,
            location,
            body,
            retry_after,
        })
    }

    async fn directory(&self) -> Result<Directory, AcmeError> {
        let mut cached = self.directory.lock().await;
        if let Some(d) = cached.as_ref() {
            return Ok(d.clone());
        }
        let url = &self.cfg.directory_url;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| AcmeError::Transport(format!("GET {url}: {e}")))?;
        let reply = self.read(resp).await?;
        if reply.status != 200 {
            return Err(AcmeError::Transport(format!(
                "GET {url}: HTTP {}",
                reply.status
            )));
        }
        let v = reply.json()?;
        let field = |k| -> Result<String, AcmeError> { Ok(self.checked(text(&v, k)?)?.to_owned()) };
        let d = Directory {
            new_nonce: field("newNonce")?,
            new_account: field("newAccount")?,
            new_order: field("newOrder")?,
        };
        *cached = Some(d.clone());
        Ok(d)
    }

    async fn nonce(&self, dir: &Directory) -> Result<String, AcmeError> {
        if let Some(n) = self.nonces.lock().unwrap_or_else(|e| e.into_inner()).pop() {
            return Ok(n);
        }
        let resp = self
            .http
            .head(&dir.new_nonce)
            .send()
            .await
            .map_err(|e| AcmeError::Transport(format!("new nonce: {e}")))?;
        self.read(resp).await?;
        self.nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .ok_or_else(|| AcmeError::Transport("the certificate authority sent no nonce".into()))
    }

    /// A signed POST: with the account's `kid`, or with the key itself
    /// before there is an account. Retried with a fresh nonce when the CA
    /// says the nonce was bad, as RFC 8555 6.5 expects clients to.
    async fn post(
        &self,
        key: &AccountKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&Value>,
        accept: &'static str,
    ) -> Result<Reply, AcmeError> {
        let dir = self.directory().await?;
        let url = self.checked(url)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut protected = json!({
                "alg": "ES256",
                "nonce": self.nonce(&dir).await?,
                "url": url,
            });
            match kid {
                Some(kid) => protected["kid"] = json!(kid),
                None => protected["jwk"] = key.jwk(),
            }
            let body = key.sign(&protected, payload);
            let resp = self
                .http
                .post(url)
                .header(header::CONTENT_TYPE, "application/jose+json")
                .header(header::ACCEPT, accept)
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| AcmeError::Transport(format!("POST {url}: {e}")))?;
            let reply = self.read(resp).await?;
            if reply.status < 400 {
                return Ok(reply);
            }
            let problem = Problem::parse(reply.status, &reply.body, reply.retry_after);
            if problem.kind == "badNonce" && attempt < BAD_NONCE_ATTEMPTS {
                continue;
            }
            return Err(AcmeError::Problem(problem));
        }
    }

    /// Registers `key` (or finds its existing account), agreeing to the
    /// CA's terms. Returns the account URL.
    pub async fn register(&self, key: &AccountKey) -> Result<String, AcmeError> {
        let dir = self.directory().await?;
        let mut payload = json!({"termsOfServiceAgreed": true});
        if let Some(email) = &self.cfg.email {
            payload["contact"] = json!([format!("mailto:{email}")]);
        }
        let reply = self
            .post(
                key,
                None,
                &dir.new_account,
                Some(&payload),
                "application/json",
            )
            .await?;
        let status = reply.json()?["status"].as_str().map(str::to_owned);
        if status.as_deref().is_some_and(|s| s != "valid") {
            return Err(AcmeError::Transport(format!(
                "the account is {}",
                status.unwrap_or_default()
            )));
        }
        let url = reply
            .location
            .ok_or_else(|| AcmeError::Transport("the new account has no Location".into()))?;
        Ok(self.checked(&url)?.to_owned())
    }

    async fn get_json(&self, account: &Account, url: &str) -> Result<Reply, AcmeError> {
        self.post(
            &account.key,
            Some(&account.url),
            url,
            None,
            "application/json",
        )
        .await
    }

    /// Waits before the next poll: the CA's `Retry-After` if it gave one
    /// (within reason), else a short doubling delay. `Timeout` once the
    /// deadline would pass.
    async fn pause(
        &self,
        reply: &Reply,
        wait: &mut Duration,
        deadline: Instant,
        what: &str,
    ) -> Result<(), AcmeError> {
        let pause = reply
            .retry_after
            .unwrap_or(*wait)
            .clamp(Duration::from_millis(50), Duration::from_secs(10));
        *wait = (*wait * 2).min(Duration::from_secs(5));
        if Instant::now() + pause > deadline {
            return Err(AcmeError::Timeout(format!("{what} took too long")));
        }
        tokio::time::sleep(pause).await;
        Ok(())
    }

    /// Polls `url` until its status is not one of `waiting`.
    async fn poll(
        &self,
        account: &Account,
        url: &str,
        waiting: &[&str],
        deadline: Instant,
        what: &str,
    ) -> Result<Value, AcmeError> {
        let mut wait = Duration::from_millis(100);
        loop {
            let reply = self.get_json(account, url).await?;
            let v = reply.json()?;
            if !waiting.contains(&text(&v, "status")?) {
                return Ok(v);
            }
            self.pause(&reply, &mut wait, deadline, what).await?;
        }
    }

    /// Proves control of one authorization's identifier over HTTP-01.
    async fn authorize(
        &self,
        account: &Account,
        authz_url: &str,
        challenges: &dyn Challenges,
        published: &mut Vec<String>,
        deadline: Instant,
    ) -> Result<(), AcmeError> {
        let authz = self.get_json(account, authz_url).await?.json()?;
        match text(&authz, "status")? {
            "valid" => return Ok(()),
            "pending" => {}
            other => return Err(AcmeError::Invalid(format!("the authorization is {other}"))),
        }
        let identifier = authz["identifier"]["value"]
            .as_str()
            .ok_or_else(|| AcmeError::Transport("the authorization has no identifier".into()))?;
        let challenge = authz["challenges"]
            .as_array()
            .and_then(|list| list.iter().find(|c| c["type"] == "http-01"))
            .ok_or_else(|| {
                AcmeError::Invalid("the certificate authority offered no http-01 challenge".into())
            })?;
        let token = text(challenge, "token")?;
        if !is_token(token) {
            return Err(AcmeError::Transport(
                "the challenge token is malformed".into(),
            ));
        }
        let challenge_url = text(challenge, "url")?;
        challenges
            .publish(token, &account.key.key_authorization(token), identifier)
            .await
            .map_err(AcmeError::Publish)?;
        published.push(token.to_owned());
        // Tells the CA to validate; the empty object is the response.
        self.post(
            &account.key,
            Some(&account.url),
            challenge_url,
            Some(&json!({})),
            "application/json",
        )
        .await?;
        let done = self
            .poll(account, authz_url, &["pending"], deadline, "validation")
            .await?;
        match text(&done, "status")? {
            "valid" => Ok(()),
            other => {
                // The reason is on the challenge that failed.
                let reason = done["challenges"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["error"]["detail"].as_str())
                    .next()
                    .unwrap_or("no reason given");
                Err(AcmeError::Invalid(format!(
                    "{identifier}: the authorization is {other}: {}",
                    reason.chars().take(200).collect::<String>()
                )))
            }
        }
    }

    /// Orders, validates and downloads a certificate for `hostname`.
    /// Published challenges are withdrawn however it ends.
    pub async fn issue(
        &self,
        account: &Account,
        hostname: &str,
        challenges: &dyn Challenges,
    ) -> Result<Issued, AcmeError> {
        let mut published = Vec::new();
        let result = self
            .issue_inner(account, hostname, challenges, &mut published)
            .await;
        for token in &published {
            if let Err(e) = challenges.withdraw(token).await {
                tracing::warn!(error = %e, "could not withdraw an ACME challenge; it expires on its own");
            }
        }
        result
    }

    async fn issue_inner(
        &self,
        account: &Account,
        hostname: &str,
        challenges: &dyn Challenges,
        published: &mut Vec<String>,
    ) -> Result<Issued, AcmeError> {
        let deadline = Instant::now() + self.cfg.order_timeout;
        let dir = self.directory().await?;
        let reply = self
            .post(
                &account.key,
                Some(&account.url),
                &dir.new_order,
                Some(&json!({"identifiers": [{"type": "dns", "value": hostname}]})),
                "application/json",
            )
            .await?;
        let order_url = reply
            .location
            .clone()
            .ok_or_else(|| AcmeError::Transport("the new order has no Location".into()))?;
        let order = reply.json()?;
        let finalize = text(&order, "finalize")?.to_owned();
        let authorizations: Vec<String> = order["authorizations"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if authorizations.is_empty() || authorizations.len() > 10 {
            return Err(AcmeError::Transport(
                "the order has no usable authorizations".into(),
            ));
        }
        for authz in &authorizations {
            self.authorize(account, authz, challenges, published, deadline)
                .await?;
        }
        let order = self
            .poll(account, &order_url, &["pending"], deadline, "the order")
            .await?;
        let status = text(&order, "status")?;
        if status != "ready" {
            return Err(AcmeError::Invalid(format!(
                "the order is {status} after validation"
            )));
        }
        let (key_pkcs8, csr) = certificate_request(hostname);
        self.post(
            &account.key,
            Some(&account.url),
            &finalize,
            Some(&json!({"csr": b64url_encode(&csr)})),
            "application/json",
        )
        .await?;
        let order = self
            .poll(account, &order_url, &["processing"], deadline, "issuance")
            .await?;
        let status = text(&order, "status")?;
        if status != "valid" {
            return Err(AcmeError::Invalid(format!(
                "the order is {status} after finalization"
            )));
        }
        let cert_url = text(&order, "certificate")?;
        let reply = self
            .post(
                &account.key,
                Some(&account.url),
                cert_url,
                None,
                "application/pem-certificate-chain",
            )
            .await?;
        let chain_pem = String::from_utf8(reply.body)
            .map_err(|_| AcmeError::Transport("the certificate is not text".into()))?;
        let leaf = der::pem_decode_all(&chain_pem, "CERTIFICATE")
            .and_then(|certs| certs.into_iter().next())
            .and_then(|c| der::parse_certificate(&c))
            .ok_or_else(|| AcmeError::Transport("the certificate chain does not parse".into()))?;
        if !leaf
            .dns_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(hostname))
        {
            return Err(AcmeError::Transport(format!(
                "the certificate is not for {hostname}"
            )));
        }
        if public_key_info(&key_pkcs8).as_deref() != Some(&leaf.spki[..]) {
            return Err(AcmeError::Transport(
                "the certificate is not for the key that was requested".into(),
            ));
        }
        Ok(Issued {
            chain_pem,
            key_pkcs8,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            renew_at: renew_at(leaf.not_before, leaf.not_after),
        })
    }
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// An HTTP-01 token as RFC 8555 8.3 defines it: base64url, and in practice
/// 43 characters (256 bits). At least 128 bits are required.
pub fn is_token(t: &str) -> bool {
    (22..=128).contains(&t.len()) && t.bytes().all(is_b64url)
}

// ---------------------------------------------------------------------------
// Storage

/// A domain that needs a certificate, as claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertWork {
    pub domain_id: i64,
    pub hostname: String,
    /// Failures in a row so far.
    pub failures: i32,
}

fn clip(s: &str) -> String {
    let mut end = s.len().min(MAX_ERROR);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

impl Db {
    /// The stored account for a directory: (URL, PKCS#8 key).
    pub async fn acme_account(
        &self,
        directory: &str,
    ) -> Result<Option<(String, Vec<u8>)>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT account_url, key_pkcs8 FROM acme_accounts WHERE directory_url = $1",
                )
                .bind(directory)
                .fetch_optional(self.pool()),
            )
            .await?;
        row.map(|r| Ok((r.try_get("account_url")?, r.try_get("key_pkcs8")?)))
            .transpose()
            .map_err(|e: sqlx::Error| DbError::from(e))
    }

    /// Stores an account unless another instance stored one first; returns
    /// the one stored either way.
    pub async fn save_acme_account(
        &self,
        directory: &str,
        url: &str,
        key_pkcs8: &[u8],
    ) -> Result<(String, Vec<u8>), DbError> {
        self.timed(
            sqlx::query(
                "INSERT INTO acme_accounts (directory_url, account_url, key_pkcs8)
                 VALUES ($1, $2, $3) ON CONFLICT (directory_url) DO NOTHING",
            )
            .bind(directory)
            .bind(url)
            .bind(key_pkcs8)
            .execute(self.pool()),
        )
        .await?;
        self.acme_account(directory).await?.ok_or(DbError::NotFound)
    }

    /// Forgets the account for a directory, after the CA said it no longer
    /// exists.
    pub async fn delete_acme_account(&self, directory: &str) -> Result<(), DbError> {
        self.timed(
            sqlx::query("DELETE FROM acme_accounts WHERE directory_url = $1")
                .bind(directory)
                .execute(self.pool()),
        )
        .await
        .map(|_| ())
    }

    /// Publishes a challenge for every instance to answer, and tells them.
    pub async fn put_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        hostname: &str,
    ) -> Result<(), DbError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            sqlx::query(
                "INSERT INTO acme_challenges (token, hostname, key_authorization, expires_at)
                 VALUES ($1, $2, $3, now() + make_interval(secs => $4))
                 ON CONFLICT (token) DO UPDATE
                    SET hostname = EXCLUDED.hostname,
                        key_authorization = EXCLUDED.key_authorization,
                        expires_at = EXCLUDED.expires_at",
            )
            .bind(token)
            .bind(hostname)
            .bind(key_authorization)
            .bind(CHALLENGE_TTL.as_secs_f64())
            .execute(&mut *tx)
            .await?;
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(CHANGES_CHANNEL)
                .bind(CHALLENGES_CHANGED)
                .execute(&mut *tx)
                .await?;
            tx.commit().await
        })
        .await
    }

    /// Withdraws a challenge, and tells every instance.
    pub async fn delete_challenge(&self, token: &str) -> Result<(), DbError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            sqlx::query("DELETE FROM acme_challenges WHERE token = $1")
                .bind(token)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(CHANGES_CHANNEL)
                .bind(CHALLENGES_CHANGED)
                .execute(&mut *tx)
                .await?;
            tx.commit().await
        })
        .await
    }

    /// The key authorization for `token` on `hostname`, if pending.
    pub async fn challenge(&self, token: &str, hostname: &str) -> Result<Option<String>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT key_authorization FROM acme_challenges
                      WHERE token = $1 AND hostname = $2 AND expires_at > now()",
                )
                .bind(token)
                .bind(hostname)
                .fetch_optional(self.pool()),
            )
            .await?;
        row.map(|r| r.try_get("key_authorization"))
            .transpose()
            .map_err(DbError::from)
    }

    /// Every pending challenge, (token, hostname, key authorization), after
    /// deleting expired ones.
    pub async fn pending_challenges(&self) -> Result<Vec<(String, String, String)>, DbError> {
        let rows = self
            .timed(async {
                sqlx::query("DELETE FROM acme_challenges WHERE expires_at <= now()")
                    .execute(self.pool())
                    .await?;
                sqlx::query("SELECT token, hostname, key_authorization FROM acme_challenges")
                    .fetch_all(self.pool())
                    .await
            })
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("token")?,
                    r.try_get("hostname")?,
                    r.try_get("key_authorization")?,
                ))
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Claims up to `limit` verified domains that have no certificate or
    /// are due for renewal and are not waiting out a failure, holding each
    /// for [`CLAIM_LEASE`]. `SKIP LOCKED` keeps two instances from claiming
    /// one domain; `NO KEY UPDATE` does not wait on link inserts, which
    /// hold key-share locks on their domain through the foreign key.
    pub async fn claim_certificate_work(&self, limit: i64) -> Result<Vec<CertWork>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "UPDATE domains SET tls_next_attempt_at = now() + make_interval(secs => $2)
                      WHERE id IN (
                            SELECT id FROM domains
                             WHERE verified_at IS NOT NULL
                               AND (tls_renew_at IS NULL OR tls_renew_at <= now())
                               AND (tls_next_attempt_at IS NULL OR tls_next_attempt_at <= now())
                             ORDER BY tls_next_attempt_at NULLS FIRST, id
                             LIMIT $1
                               FOR NO KEY UPDATE SKIP LOCKED)
                  RETURNING id, hostname, tls_failures",
                )
                .bind(limit)
                .bind(CLAIM_LEASE.as_secs_f64())
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(CertWork {
                    domain_id: r.try_get("id")?,
                    hostname: r.try_get("hostname")?,
                    failures: r.try_get("tls_failures")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Stores a newly issued certificate for a domain, replacing the old
    /// one, and clears its failures.
    pub async fn store_certificate(&self, domain_id: i64, cert: &Issued) -> Result<(), DbError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            sqlx::query(
                "INSERT INTO domain_certificates
                        (domain_id, chain_pem, key_pkcs8, not_before, not_after, renew_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (domain_id) DO UPDATE
                    SET chain_pem = EXCLUDED.chain_pem, key_pkcs8 = EXCLUDED.key_pkcs8,
                        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
                        renew_at = EXCLUDED.renew_at, issued_at = now()",
            )
            .bind(domain_id)
            .bind(&cert.chain_pem)
            .bind(&cert.key_pkcs8)
            .bind(cert.not_before)
            .bind(cert.not_after)
            .bind(cert.renew_at)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE domains SET tls_not_after = $2, tls_renew_at = $3, tls_failures = 0,
                        tls_error = NULL, tls_next_attempt_at = NULL, tls_checked_at = now()
                  WHERE id = $1",
            )
            .bind(domain_id)
            .bind(cert.not_after)
            .bind(cert.renew_at)
            .execute(&mut *tx)
            .await?;
            tx.commit().await
        })
        .await
    }

    /// Records a failed attempt: the error, and when to try again.
    pub async fn record_certificate_failure(
        &self,
        work: &CertWork,
        error: &str,
        retry_in: Duration,
    ) -> Result<(), DbError> {
        self.timed(
            sqlx::query(
                "UPDATE domains SET tls_failures = tls_failures + 1, tls_error = $2,
                        tls_next_attempt_at = now() + make_interval(secs => $3),
                        tls_checked_at = now()
                  WHERE id = $1",
            )
            .bind(work.domain_id)
            .bind(clip(error))
            .bind(retry_in.as_secs_f64())
            .execute(self.pool()),
        )
        .await
        .map(|_| ())
    }

    /// A domain's stored certificate: (chain PEM, PKCS#8 key).
    pub async fn certificate(&self, domain_id: i64) -> Result<Option<(String, Vec<u8>)>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT chain_pem, key_pkcs8 FROM domain_certificates WHERE domain_id = $1",
                )
                .bind(domain_id)
                .fetch_optional(self.pool()),
            )
            .await?;
        row.map(|r| Ok((r.try_get("chain_pem")?, r.try_get("key_pkcs8")?)))
            .transpose()
            .map_err(|e: sqlx::Error| DbError::from(e))
    }
}

impl Challenges for Db {
    fn publish<'a>(
        &'a self,
        token: &'a str,
        key_authorization: &'a str,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.put_challenge(token, key_authorization, hostname)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn withdraw<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.delete_challenge(token)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

// ---------------------------------------------------------------------------
// Answering HTTP-01

/// Pending challenges on this instance, by token: (hostname, key
/// authorization). A handful at a time.
#[derive(Default)]
pub struct ChallengeMap {
    map: RwLock<HashMap<String, (String, String)>>,
    lookups: Mutex<Option<(Instant, f64)>>,
}

impl ChallengeMap {
    pub fn replace(&self, pending: Vec<(String, String, String)>) {
        let fresh = pending
            .into_iter()
            .map(|(token, host, ka)| (token, (host, ka)))
            .collect();
        *self.map.write().unwrap_or_else(|e| e.into_inner()) = fresh;
    }

    pub fn get(&self, token: &str, hostname: &str) -> Option<String> {
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .filter(|(h, _)| h == hostname)
            .map(|(_, ka)| ka.clone())
    }

    pub fn len(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// One token from a bucket of [`LOOKUP_RATE`] per second, for a
    /// database lookup of a token the map does not have. Unknown tokens
    /// cost nothing once the bucket is empty.
    fn take_lookup(&self, now: Instant) -> bool {
        let mut b = self.lookups.lock().unwrap_or_else(|e| e.into_inner());
        let (last, tokens) = b.get_or_insert((now, LOOKUP_RATE));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * LOOKUP_RATE;
        *tokens = (*tokens + refill).min(LOOKUP_RATE);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl App {
    /// Reloads the pending challenges. On failure the previous set stays.
    pub async fn reload_challenges(&self) -> Result<(), DbError> {
        let pending = self.db.pending_challenges().await?;
        self.challenges.replace(pending);
        Ok(())
    }
}

/// Reloads the pending challenges in the background (from the change
/// listener, which must not wait on a query).
pub fn spawn_reload(app: Arc<App>) {
    tokio::spawn(async move {
        if let Err(e) = app.reload_challenges().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload ACME challenges");
        }
    });
}

fn plain(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

/// `GET /.well-known/acme-challenge/{token}` on any host: the key
/// authorization, when that host has a pending challenge with that token.
pub async fn http01(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let not_found = || plain(StatusCode::NOT_FOUND, "not found\n".into());
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|h| host_part(h.as_bytes()))
        .map(str::to_ascii_lowercase)
    else {
        return not_found();
    };
    if !is_token(&token) {
        return not_found();
    }
    if let Some(ka) = app.challenges.get(&token, &host) {
        app.metrics.acme_challenges_served.inc();
        return plain(StatusCode::OK, ka);
    }
    // Published a moment ago by another instance, before its notification
    // arrived, or the notification was lost.
    if !app.challenges.take_lookup(Instant::now()) {
        return not_found();
    }
    match app.db.challenge(&token, &host).await {
        Ok(Some(ka)) => {
            app.metrics.acme_challenges_served.inc();
            plain(StatusCode::OK, ka)
        }
        Ok(None) => not_found(),
        Err(_) => {
            app.metrics.db_error(DbOp::Maintenance);
            let mut r = plain(StatusCode::SERVICE_UNAVAILABLE, "retry shortly\n".into());
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
            r
        }
    }
}

// ---------------------------------------------------------------------------
// The worker

/// Issues and renews certificates for verified domains.
pub struct AcmeWorker {
    acme: Acme,
    db: Db,
    metrics: Arc<Metrics>,
    wake: Arc<Notify>,
    account: tokio::sync::Mutex<Option<Arc<Account>>>,
}

impl AcmeWorker {
    pub fn new(
        cfg: AcmeConfig,
        db: Db,
        metrics: Arc<Metrics>,
        wake: Arc<Notify>,
    ) -> Result<Self, String> {
        Ok(AcmeWorker {
            acme: Acme::new(cfg)?,
            db,
            metrics,
            wake,
            account: tokio::sync::Mutex::new(None),
        })
    }

    /// The account, from the database or registered now.
    async fn account(&self) -> Result<Arc<Account>, String> {
        let mut cached = self.account.lock().await;
        if let Some(a) = cached.as_ref() {
            return Ok(a.clone());
        }
        let directory = &self.acme.config().directory_url;
        let (url, pkcs8) = match self
            .db
            .acme_account(directory)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(stored) => stored,
            None => {
                let key = AccountKey::generate();
                let url = self.acme.register(&key).await.map_err(|e| e.to_string())?;
                tracing::info!(account = %url, "registered an ACME account");
                // If another instance stored one meanwhile, theirs is kept
                // and this registration is simply never used.
                self.db
                    .save_acme_account(directory, &url, key.pkcs8())
                    .await
                    .map_err(|e| e.to_string())?
            }
        };
        let account = Arc::new(Account {
            key: AccountKey::from_pkcs8(&pkcs8)?,
            url,
        });
        *cached = Some(account.clone());
        Ok(account)
    }

    /// One round: claims due domains and issues for each. Returns how many
    /// certificates were issued.
    pub async fn round(&self) -> Result<usize, String> {
        let work = self
            .db
            .claim_certificate_work(CLAIM_BATCH)
            .await
            .map_err(|e| e.to_string())?;
        if work.is_empty() {
            return Ok(0);
        }
        let mut issued = 0;
        for item in work {
            let result = match self.account().await {
                Ok(account) => self.acme.issue(&account, &item.hostname, &self.db).await,
                Err(e) => Err(AcmeError::Transport(e)),
            };
            if result.as_ref().is_err_and(AcmeError::lost_account) {
                self.forget_account().await;
            }
            match result {
                Ok(cert) => {
                    self.db
                        .store_certificate(item.domain_id, &cert)
                        .await
                        .map_err(|e| e.to_string())?;
                    self.metrics.certificates_issued.inc();
                    issued += 1;
                    tracing::info!(
                        domain = item.domain_id,
                        not_after = %cert.not_after,
                        "certificate issued"
                    );
                }
                Err(e) => {
                    self.metrics.certificate_failures.inc();
                    let failures = u32::try_from(item.failures).unwrap_or(0) + 1;
                    let retry = retry_delay(failures, e.retry_after());
                    tracing::warn!(domain = item.domain_id, error = %e, retry_in_s = retry.as_secs(), "certificate not issued");
                    self.db
                        .record_certificate_failure(&item, &e.to_string(), retry)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(issued)
    }

    /// Drops the account the CA no longer knows, so the next attempt
    /// registers a new one.
    async fn forget_account(&self) {
        *self.account.lock().await = None;
        if let Err(e) = self
            .db
            .delete_acme_account(&self.acme.config().directory_url)
            .await
        {
            tracing::warn!(error = %e, "could not forget the lost ACME account");
        } else {
            tracing::warn!(
                "the certificate authority no longer knows the ACME account; registering a new one"
            );
        }
    }

    /// Runs rounds every interval, or sooner when woken (a domain was
    /// verified), until stopped. A round in progress when the stop comes is
    /// abandoned; its claims lapse after [`CLAIM_LEASE`].
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let interval = self.acme.config().interval;
        loop {
            tokio::select! {
                r = self.round() => match r {
                    // More may be due right away.
                    Ok(n) if n > 0 => continue,
                    Ok(_) => {}
                    Err(e) => {
                        self.metrics.db_error(DbOp::Maintenance);
                        tracing::warn!(error = %e, "certificate round failed");
                    }
                },
                _ = stopped(&mut stop) => return,
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.wake.notified() => {}
                _ = stopped(&mut stop) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    use crate::util::b64url_decode;

    #[test]
    fn config_checks() {
        let ok = AcmeConfig {
            directory_url: "https://acme.example.org/directory".into(),
            email: Some("ops@example.org".into()),
            interval: Duration::from_secs(60),
            order_timeout: Duration::from_secs(60),
        };
        ok.validate().unwrap();
        let with = |f: &dyn Fn(&mut AcmeConfig)| {
            let mut c = ok.clone();
            f(&mut c);
            c.validate()
        };
        with(&|c| c.directory_url = "http://127.0.0.1:1/dir".into()).unwrap();
        with(&|c| c.email = None).unwrap();
        for bad in ["http://acme.example.org/dir", "ftp://x", "not a url"] {
            assert!(with(&|c| c.directory_url = bad.into()).is_err(), "{bad}");
        }
        for bad in [
            "ops",
            "@example.org",
            "ops@localhost",
            "a@b@c.d",
            "a b@c.d",
            "a,b@c.d",
        ] {
            assert!(with(&|c| c.email = Some(bad.into())).is_err(), "{bad}");
        }
        assert!(Acme::new(ok).is_ok());
    }

    #[test]
    fn renews_at_two_thirds_of_the_lifetime() {
        let nb: DateTime<Utc> = "2026-11-09T00:00:00Z".parse().unwrap();
        let na = nb + chrono::Duration::days(90);
        assert_eq!(renew_at(nb, na), nb + chrono::Duration::days(60));
        let short = nb + chrono::Duration::seconds(6);
        assert_eq!(renew_at(nb, short), nb + chrono::Duration::seconds(4));
    }

    #[test]
    fn retries_back_off_and_respect_the_ca() {
        assert_eq!(retry_delay(1, None), Duration::from_secs(300));
        assert_eq!(retry_delay(2, None), Duration::from_secs(600));
        assert_eq!(retry_delay(4, None), Duration::from_secs(2_400));
        assert_eq!(retry_delay(30, None), RETRY_MAX);
        assert_eq!(retry_delay(0, None), Duration::from_secs(300));
        assert_eq!(
            retry_delay(1, Some(Duration::from_secs(3_600))),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            retry_delay(1, Some(Duration::from_secs(10))),
            Duration::from_secs(300)
        );
        assert_eq!(
            retry_delay(1, Some(Duration::from_secs(10 << 20))),
            RETRY_MAX
        );
    }

    #[test]
    fn parses_retry_after() {
        let now: DateTime<Utc> = "2026-11-09T08:49:37Z".parse().unwrap();
        assert_eq!(
            parse_retry_after(" 120 ", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("Mon, 09 Nov 2026 08:50:37 GMT", now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            parse_retry_after("Mon, 09 Nov 2026 08:40:37 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-5", now), None);
    }

    #[test]
    fn jws_verifies_with_the_jwk() {
        let key = AccountKey::generate();
        let jwk = key.jwk();
        let x = b64url_decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = b64url_decode(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!((x.len(), y.len()), (32, 32));
        let point = [&[4u8][..], &x, &y].concat();
        let protected = json!({"alg": "ES256", "nonce": "n", "url": "https://ca/x"});
        for payload in [Some(json!({"a": 1})), None] {
            let jws = key.sign(&protected, payload.as_ref());
            let signing_input = format!(
                "{}.{}",
                jws["protected"].as_str().unwrap(),
                jws["payload"].as_str().unwrap()
            );
            let sig = b64url_decode(jws["signature"].as_str().unwrap()).unwrap();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
                .verify(signing_input.as_bytes(), &sig)
                .unwrap();
            let header: Value =
                serde_json::from_slice(&b64url_decode(jws["protected"].as_str().unwrap()).unwrap())
                    .unwrap();
            assert_eq!(header, protected);
            assert_eq!(jws["payload"] == "", payload.is_none());
        }
        // The key survives a round trip through its PKCS#8 form.
        let again = AccountKey::from_pkcs8(key.pkcs8()).unwrap();
        assert_eq!(again.thumbprint(), key.thumbprint());
        assert!(AccountKey::from_pkcs8(b"nope").is_err());
        assert!(format!("{key:?}").contains(&key.thumbprint()));
    }

    #[test]
    fn thumbprint_is_rfc_7638() {
        let key = AccountKey::generate();
        let jwk = key.jwk();
        // Members in lexicographic order, no whitespace, hashed.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
            jwk["x"], jwk["y"]
        );
        assert_eq!(
            key.thumbprint(),
            b64url_encode(&Sha256::digest(canonical.as_bytes()))
        );
        assert_eq!(key.thumbprint().len(), 43);
        assert_eq!(
            key.key_authorization("tok"),
            format!("tok.{}", key.thumbprint())
        );
    }

    #[test]
    fn the_request_is_signed_by_its_key() {
        let (pkcs8, csr) = certificate_request("go.example.com");
        let spki = public_key_info(&pkcs8).unwrap();
        let outer = der::parse_one(&csr, der::TAG_SEQUENCE).unwrap();
        let mut r = outer.contents();
        let info = r.expect(der::TAG_SEQUENCE).unwrap();
        r.expect(der::TAG_SEQUENCE).unwrap();
        let sig = r.expect(der::TAG_BIT_STRING).unwrap();
        let mut i = info.contents();
        i.expect(der::TAG_INTEGER).unwrap();
        i.expect(der::TAG_SEQUENCE).unwrap();
        let key = i.expect(der::TAG_SEQUENCE).unwrap();
        assert_eq!(key.raw, &spki[..]);
        let point = &spki[spki.len() - 65..];
        UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point)
            .verify(info.raw, &sig.value[1..])
            .unwrap();
        assert_eq!(public_key_info(b"junk"), None);
    }

    #[test]
    fn problems_are_parsed_and_shown() {
        let p = Problem::parse(
            400,
            br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}"#,
            None,
        );
        assert_eq!(p.kind, "badNonce");
        assert_eq!(p.to_string(), "badNonce (HTTP 400): stale");
        let empty = Problem::parse(500, b"<html>", Some(Duration::from_secs(1)));
        assert_eq!(empty.to_string(), "error (HTTP 500)");
        let e = AcmeError::Problem(empty);
        assert_eq!(e.retry_after(), Some(Duration::from_secs(1)));
        assert!(!e.lost_account());
        let lost = AcmeError::Problem(Problem::parse(
            400,
            br#"{"type":"urn:ietf:params:acme:error:accountDoesNotExist"}"#,
            None,
        ));
        assert!(lost.lost_account());
        for (e, text) in [
            (AcmeError::Transport("x".into()), "unreachable: x"),
            (AcmeError::Invalid("x".into()), "validation failed: x"),
            (AcmeError::Timeout("x".into()), "timed out: x"),
            (AcmeError::Publish("x".into()), "publish the challenge: x"),
        ] {
            assert!(e.to_string().contains(text), "{e}");
            assert_eq!(e.retry_after(), None);
        }
    }

    #[test]
    fn tokens_are_base64url_of_at_least_128_bits() {
        assert!(is_token(&"A".repeat(43)));
        assert!(is_token("abcdefghij-_0123456789"));
        assert!(!is_token("short"));
        assert!(!is_token(&"A".repeat(129)));
        assert!(!is_token(&format!("{}/..", "A".repeat(30))));
        assert!(!is_token(&format!("{}=", "A".repeat(30))));
    }

    #[test]
    fn the_challenge_map_matches_token_and_host() {
        let m = ChallengeMap::default();
        assert!(m.is_empty());
        m.replace(vec![("t".into(), "go.example.com".into(), "t.k".into())]);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("t", "go.example.com").as_deref(), Some("t.k"));
        assert_eq!(m.get("t", "other.example.com"), None);
        assert_eq!(m.get("u", "go.example.com"), None);
        m.replace(vec![]);
        assert!(m.is_empty());
    }

    #[test]
    fn database_lookups_are_rate_limited() {
        let m = ChallengeMap::default();
        let t0 = Instant::now();
        let granted = (0..100).filter(|_| m.take_lookup(t0)).count();
        assert_eq!(granted, LOOKUP_RATE as usize);
        assert!(!m.take_lookup(t0));
        assert!(m.take_lookup(t0 + Duration::from_millis(100)));
    }

    #[test]
    fn errors_are_clipped_on_a_character_boundary() {
        let long = "é".repeat(400);
        let c = clip(&long);
        assert!(c.len() <= MAX_ERROR);
        assert!(c.chars().all(|ch| ch == 'é'));
        assert_eq!(clip("short"), "short");
    }
}

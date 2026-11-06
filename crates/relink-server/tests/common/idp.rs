//! A fake OpenID Connect provider that runs inside a test: discovery, a
//! key set, a token endpoint that checks PKCE and signs ES256 ID tokens,
//! and helpers that drive relink's sign-in against it. Shared by the tests
//! that sign people in through the real flow.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use relink_server::util::b64url_encode;
use reqwest::Method;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::{Harness, admin_url};

pub const CLIENT_ID: &str = "relink-console";
pub const CLIENT_SECRET: &str = "s3cret:with/odd chars";

pub struct Key {
    pub pair: EcdsaKeyPair,
    pub kid: String,
}

impl Key {
    pub fn new(kid: &str) -> Key {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Key {
            pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
            kid: kid.into(),
        }
    }

    pub fn jwk(&self) -> Value {
        let p = self.pair.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "use": "sig", "kid": self.kid,
               "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..])})
    }

    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"});
        let msg = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), msg.as_bytes())
            .unwrap();
        format!("{msg}.{}", b64url_encode(sig.as_ref()))
    }
}

/// A code the fake provider has issued, and what it was issued for.
pub struct Grant {
    pub challenge: String,
    pub redirect_uri: String,
    pub claims: Value,
}

#[derive(Default)]
pub struct IdpState {
    /// Keys published in the key set.
    pub published: Vec<Arc<Key>>,
    /// The key ID tokens are signed with.
    pub signing: Option<Arc<Key>>,
    pub codes: HashMap<String, Grant>,
    /// Makes the token endpoint answer with this OAuth error.
    pub token_error: Option<String>,
    /// What the last token request authenticated with.
    pub last_auth: Option<String>,
    pub last_form: HashMap<String, String>,
    /// Makes discovery fail.
    pub down: bool,
}

pub struct Idp {
    pub issuer: String,
    pub state: Arc<Mutex<IdpState>>,
    pub jwks_hits: Arc<AtomicUsize>,
    pub next_code: AtomicUsize,
}

pub type Shared = (String, Arc<Mutex<IdpState>>, Arc<AtomicUsize>);

pub fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

pub async fn discovery(State((issuer, st, _)): State<Shared>) -> Response {
    if st.lock().unwrap().down {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    reply(
        StatusCode::OK,
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        }),
    )
}

pub async fn jwks(State((_, st, hits)): State<Shared>) -> Response {
    hits.fetch_add(1, Ordering::SeqCst);
    let keys: Vec<Value> = st
        .lock()
        .unwrap()
        .published
        .iter()
        .map(|k| k.jwk())
        .collect();
    reply(StatusCode::OK, json!({ "keys": keys }))
}

pub async fn token(
    State((issuer, st, _)): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let mut st = st.lock().unwrap();
    st.last_auth = headers
        .get("authorization")
        .map(|v| v.to_str().unwrap().to_owned());
    st.last_form = form.clone();
    let refuse = |code: &str| reply(StatusCode::BAD_REQUEST, json!({"error": code}));
    if let Some(e) = st.token_error.clone() {
        return refuse(&e);
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return refuse("unsupported_grant_type");
    }
    let Some(grant) = form.get("code").and_then(|c| st.codes.remove(c)) else {
        return refuse("invalid_grant");
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if b64url_encode(&Sha256::digest(verifier.as_bytes())) != grant.challenge
        || form.get("redirect_uri") != Some(&grant.redirect_uri)
    {
        return refuse("invalid_grant");
    }
    let mut claims = json!({
        "iss": issuer, "aud": CLIENT_ID,
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 300,
    });
    for (k, v) in grant.claims.as_object().unwrap() {
        claims[k] = v.clone();
    }
    let id_token = st.signing.as_ref().unwrap().sign(&claims);
    reply(
        StatusCode::OK,
        json!({"access_token": "at", "token_type": "Bearer", "id_token": id_token}),
    )
}

impl Idp {
    pub async fn start() -> Idp {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let key = Arc::new(Key::new("k1"));
        let state = Arc::new(Mutex::new(IdpState {
            published: vec![key.clone()],
            signing: Some(key),
            ..IdpState::default()
        }));
        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route(
                "/authorize",
                get(|Query(_): Query<HashMap<String, String>>| async { "sign in here" }),
            )
            .with_state((issuer.clone(), state.clone(), hits.clone()));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Idp {
            issuer,
            state,
            jwks_hits: hits,
            next_code: AtomicUsize::new(1),
        }
    }

    pub fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("RELINK_OIDC_ISSUER", self.issuer.clone()),
            ("RELINK_OIDC_CLIENT_ID", CLIENT_ID.into()),
            ("RELINK_OIDC_CLIENT_SECRET", CLIENT_SECRET.into()),
        ]
    }

    /// What the person does at the provider: approves, and the provider
    /// issues a code for these claims.
    pub fn approve(&self, authorize: &HashMap<String, String>, claims: Value) -> String {
        let code = format!("code-{}", self.next_code.fetch_add(1, Ordering::SeqCst));
        let mut claims = claims;
        if claims.get("nonce").is_none() {
            claims["nonce"] = json!(authorize["nonce"]);
        }
        self.state.lock().unwrap().codes.insert(
            code.clone(),
            Grant {
                challenge: authorize["code_challenge"].clone(),
                redirect_uri: authorize["redirect_uri"].clone(),
                claims,
            },
        );
        code
    }
}

pub async fn start(idp: &Idp, extra: &[(&str, &str)]) -> Option<Harness> {
    let admin = admin_url()?;
    let env = idp.env();
    let mut vars: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // Every request here comes from loopback; the limit has its own test.
    vars.push(("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000"));
    vars.extend_from_slice(extra);
    Some(Harness::start(&admin, &vars).await)
}

pub fn set_cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

pub fn cookie_value(set_cookies: &[String], name: &str) -> Option<String> {
    set_cookies.iter().find_map(|c| {
        c.split(';')
            .next()
            .and_then(|kv| kv.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    })
}

/// The start of a sign-in: the login redirect, its query and the state cookie.
pub struct Started {
    pub authorize: HashMap<String, String>,
    pub login_cookie: String,
}

pub async fn begin(h: &Harness, return_to: Option<&str>) -> Started {
    let mut url = format!("{}/v1/auth/login", h.base);
    if let Some(r) = return_to {
        url = format!(
            "{url}?return_to={}",
            url::form_urlencoded::byte_serialize(r.as_bytes()).collect::<String>()
        );
    }
    let resp = h.http.get(url).send().await.unwrap();
    assert_eq!(resp.status(), 302, "{:?}", resp.text().await);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let cookies = set_cookies(&resp);
    let location = url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    let authorize: HashMap<String, String> = location.query_pairs().into_owned().collect();
    Started {
        authorize,
        login_cookie: cookie_value(&cookies, "relink_login").expect("login cookie"),
    }
}

pub async fn callback(h: &Harness, query: &str, login_cookie: Option<&str>) -> reqwest::Response {
    let mut req = h.http.get(format!("{}/v1/auth/callback?{query}", h.base));
    if let Some(c) = login_cookie {
        req = req.header("cookie", format!("relink_login={c}"));
    }
    req.send().await.unwrap()
}

pub fn q(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// A full sign-in for `claims`; returns the session cookie value.
pub async fn sign_in(h: &Harness, idp: &Idp, claims: Value) -> String {
    let s = begin(h, None).await;
    let code = idp.approve(&s.authorize, claims);
    let resp = callback(
        h,
        &q(&[
            ("code", &code),
            ("state", &s.authorize["state"]),
            ("session_state", "x"),
        ]),
        Some(&s.login_cookie),
    )
    .await;
    let status = resp.status();
    let cookies = set_cookies(&resp);
    assert_eq!(status, 302, "{:?}", resp.text().await);
    cookie_value(&cookies, "relink_session").expect("session cookie")
}

/// A request with the session cookie, optionally with the CSRF token and a
/// workspace.
pub async fn with_session(
    h: &Harness,
    method: Method,
    path: &str,
    session: &str,
    csrf: Option<&str>,
    workspace: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = h
        .http
        .request(method, format!("{}{path}", h.base))
        .header("cookie", format!("theme=dark; relink_session={session}"));
    if let Some(t) = csrf {
        req = req.header("x-csrf-token", t);
    }
    if let Some(w) = workspace {
        req = req.header("relink-workspace", w);
    }
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

pub async fn me(h: &Harness, session: &str) -> (u16, Value) {
    with_session(
        h,
        Method::GET,
        "/v1/auth/session",
        session,
        None,
        None,
        None,
    )
    .await
}

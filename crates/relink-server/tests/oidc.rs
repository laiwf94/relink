//! OpenID Connect sign-in end to end, against a fake provider that runs in
//! the test: discovery, authorization code with PKCE, ES256 ID tokens,
//! sessions, CSRF tokens, roles and sign-out.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use common::{Harness, admin_url, metric};
use relink_server::oidc::{Oidc, OidcConfig, OidcError, pkce_challenge};
use relink_server::util::b64url_encode;
use reqwest::Method;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "relink-console";
const CLIENT_SECRET: &str = "s3cret:with/odd chars";

struct Key {
    pair: EcdsaKeyPair,
    kid: String,
}

impl Key {
    fn new(kid: &str) -> Key {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Key {
            pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
            kid: kid.into(),
        }
    }

    fn jwk(&self) -> Value {
        let p = self.pair.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "use": "sig", "kid": self.kid,
               "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..])})
    }

    fn sign(&self, claims: &Value) -> String {
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
struct Grant {
    challenge: String,
    redirect_uri: String,
    claims: Value,
}

#[derive(Default)]
struct IdpState {
    /// Keys published in the key set.
    published: Vec<Arc<Key>>,
    /// The key ID tokens are signed with.
    signing: Option<Arc<Key>>,
    codes: HashMap<String, Grant>,
    /// Makes the token endpoint answer with this OAuth error.
    token_error: Option<String>,
    /// What the last token request authenticated with.
    last_auth: Option<String>,
    last_form: HashMap<String, String>,
    /// Makes discovery fail.
    down: bool,
}

struct Idp {
    issuer: String,
    state: Arc<Mutex<IdpState>>,
    jwks_hits: Arc<AtomicUsize>,
    next_code: AtomicUsize,
}

type Shared = (String, Arc<Mutex<IdpState>>, Arc<AtomicUsize>);

fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn discovery(State((issuer, st, _)): State<Shared>) -> Response {
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

async fn jwks(State((_, st, hits)): State<Shared>) -> Response {
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

async fn token(
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
    async fn start() -> Idp {
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

    fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("RELINK_OIDC_ISSUER", self.issuer.clone()),
            ("RELINK_OIDC_CLIENT_ID", CLIENT_ID.into()),
            ("RELINK_OIDC_CLIENT_SECRET", CLIENT_SECRET.into()),
        ]
    }

    /// What the person does at the provider: approves, and the provider
    /// issues a code for these claims.
    fn approve(&self, authorize: &HashMap<String, String>, claims: Value) -> String {
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

async fn start(idp: &Idp, extra: &[(&str, &str)]) -> Option<Harness> {
    let admin = admin_url()?;
    let env = idp.env();
    let mut vars: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // Every request here comes from loopback; the limit has its own test.
    vars.push(("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000"));
    vars.extend_from_slice(extra);
    Some(Harness::start(&admin, &vars).await)
}

fn set_cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_value(set_cookies: &[String], name: &str) -> Option<String> {
    set_cookies.iter().find_map(|c| {
        c.split(';')
            .next()
            .and_then(|kv| kv.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    })
}

/// The start of a sign-in: the login redirect, its query and the state cookie.
struct Started {
    authorize: HashMap<String, String>,
    login_cookie: String,
}

async fn begin(h: &Harness, return_to: Option<&str>) -> Started {
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

async fn callback(h: &Harness, query: &str, login_cookie: Option<&str>) -> reqwest::Response {
    let mut req = h.http.get(format!("{}/v1/auth/callback?{query}", h.base));
    if let Some(c) = login_cookie {
        req = req.header("cookie", format!("relink_login={c}"));
    }
    req.send().await.unwrap()
}

fn q(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// A full sign-in for `claims`; returns the session cookie value.
async fn sign_in(h: &Harness, idp: &Idp, claims: Value) -> String {
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
async fn with_session(
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

async fn me(h: &Harness, session: &str) -> (u16, Value) {
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

fn ada() -> Value {
    json!({"sub": "ada-1", "email": "ada@example.com", "email_verified": true,
           "name": "Ada Lovelace", "preferred_username": "Ada"})
}

#[tokio::test]
async fn signs_in_acts_with_csrf_and_signs_out() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };

    let s = begin(&h, Some("/console?tab=links")).await;
    let a = &s.authorize;
    assert_eq!(a["response_type"], "code");
    assert_eq!(a["client_id"], CLIENT_ID);
    assert_eq!(a["scope"], "openid email profile");
    assert_eq!(a["code_challenge_method"], "S256");
    assert_eq!(a["redirect_uri"], "http://localhost:8080/v1/auth/callback");
    assert_eq!(
        a["state"], s.login_cookie,
        "the cookie binds the browser to the state"
    );
    assert_eq!(a["state"].len(), 43);
    assert_ne!(a["state"], a["nonce"]);
    assert_eq!(a["code_challenge"].len(), 43);

    let code = idp.approve(a, ada());
    let resp = callback(
        &h,
        &q(&[("code", &code), ("state", &a["state"])]),
        Some(&s.login_cookie),
    )
    .await;
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers()["location"], "/console?tab=links");
    let cookies = set_cookies(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("relink_session="))
        .unwrap();
    assert!(
        session_cookie.contains("Path=/v1; HttpOnly; SameSite=Lax; Max-Age=43200"),
        "{session_cookie}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("relink_login=;") && c.contains("Max-Age=0"))
    );
    let session = cookie_value(&cookies, "relink_session").unwrap();
    assert!(session.starts_with("rls_") && session.len() == 68);

    // The provider got the verifier for the challenge and our credentials.
    {
        let st = idp.state.lock().unwrap();
        assert_eq!(
            pkce_challenge(&st.last_form["code_verifier"]),
            a["code_challenge"]
        );
        let basic = st
            .last_auth
            .as_deref()
            .unwrap()
            .strip_prefix("Basic ")
            .unwrap();
        let expected = format!(
            "{}:{}",
            CLIENT_ID,
            url::form_urlencoded::byte_serialize(CLIENT_SECRET.as_bytes()).collect::<String>()
        );
        assert_eq!(
            basic,
            relink_server_b64(expected.as_bytes()),
            "client_secret_basic with form-encoded parts"
        );
        assert!(!st.last_form.contains_key("client_id"));
    }

    let (status, body) = me(&h, &session).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user"]["member"], "ada");
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(body["user"]["name"], "Ada Lovelace");
    let csrf = body["csrf_token"].as_str().unwrap().to_owned();
    assert_eq!(csrf.len(), 64);
    let workspaces = body["workspaces"].as_array().unwrap();
    assert_eq!(workspaces.len(), 1);
    assert_eq!(workspaces[0]["name"], "ada");
    assert_eq!(workspaces[0]["role"], "owner");

    // Reads need no CSRF token; writes do.
    let (status, body) =
        with_session(&h, Method::GET, "/v1/links", &session, None, None, None).await;
    assert_eq!(status, 200, "{body}");
    let link = json!({"url": "https://example.com/ada", "alias": "ada-link"});
    let (status, body) = with_session(
        &h,
        Method::POST,
        "/v1/links",
        &session,
        None,
        None,
        Some(link.clone()),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "permission_denied");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("X-CSRF-Token")
    );
    let wrong = "0".repeat(64);
    let (status, _) = with_session(
        &h,
        Method::POST,
        "/v1/links",
        &session,
        Some(&wrong),
        None,
        Some(link.clone()),
    )
    .await;
    assert_eq!(status, 403);
    let (status, body) = with_session(
        &h,
        Method::POST,
        "/v1/links",
        &session,
        Some(&csrf),
        None,
        Some(link),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = with_session(
        &h,
        Method::DELETE,
        "/v1/links/ada-link",
        &session,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_api_csrf_rejected_total"), 3.0);
    assert_eq!(metric(&m, "relink_sign_ins_total"), 1.0);

    // The link landed in ada's personal workspace, created by ada.
    let (_, body) = with_session(
        &h,
        Method::GET,
        "/v1/links/ada-link",
        &session,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(body["code"], "ada-link");
    let owner: String = sqlx::query_scalar("SELECT owner FROM links WHERE code = 'ada-link'")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(owner, "ada");

    // An API key in Authorization wins over a cookie and needs no token.
    let resp = h
        .http
        .post(format!("{}/v1/links", h.base))
        .bearer_auth(&h.alice)
        .header("cookie", format!("relink_session={session}"))
        .header("content-type", "application/json")
        .body(json!({"url": "https://example.com/alice", "alias": "alice-link"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let (status, _) = with_session(
        &h,
        Method::GET,
        "/v1/links/alice-link",
        &session,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 404, "alice's key acted in alice's workspace");

    // Sessions live in Postgres: another instance accepts the cookie.
    let second = h.second_instance(&[]).await;
    let other = reqwest::Client::new()
        .get(format!("http://{}/v1/auth/session", second.addr))
        .header("cookie", format!("relink_session={session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 200);

    // Sign-out needs the token, ends the session and clears the cookie.
    let (status, _) = with_session(
        &h,
        Method::POST,
        "/v1/auth/logout",
        &session,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 403);
    let resp = h
        .http
        .post(format!("{}/v1/auth/logout", h.base))
        .header("cookie", format!("relink_session={session}"))
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(set_cookies(&resp)[0].starts_with("relink_session=;"));
    let (status, body) = me(&h, &session).await;
    assert_eq!(status, 401, "signed out at once on this instance: {body}");
    let (status, _) = with_session(&h, Method::GET, "/v1/links", &session, None, None, None).await;
    assert_eq!(status, 401);
    let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(gone, 0);
    second.shutdown().await;
    h.shutdown().await;
}

/// Standard base64 with padding, as HTTP basic authentication uses.
fn relink_server_b64(bytes: &[u8]) -> String {
    b64url_encode(bytes).replace('-', "+").replace('_', "/")
        + &"=".repeat((3 - bytes.len() % 3) % 3)
}

#[tokio::test]
async fn people_keep_their_identity_and_never_inherit_a_name() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };
    let first = sign_in(&h, &idp, ada()).await;
    let again = sign_in(
        &h,
        &idp,
        json!({"sub": "ada-1", "email": "ada@new.example.com", "preferred_username": "someone-else"}),
    )
    .await;
    assert_ne!(first, again, "every sign-in gets its own session");
    let (_, a) = me(&h, &first).await;
    let (_, b) = me(&h, &again).await;
    assert_eq!(a["user"]["id"], b["user"]["id"]);
    assert_eq!(b["user"]["member"], "ada", "the name is chosen once");
    assert_eq!(b["user"]["email"], "ada@new.example.com");

    // Someone calling themselves alice at the provider does not become the
    // alice who owns API keys and links here.
    h.create(json!({"url": "https://example.com/a", "alias": "alices"}))
        .await;
    let mallory = sign_in(
        &h,
        &idp,
        json!({"sub": "m-1", "preferred_username": "alice"}),
    )
    .await;
    let (_, body) = me(&h, &mallory).await;
    assert_eq!(body["user"]["member"], "alice-2");
    assert_eq!(body["workspaces"].as_array().unwrap().len(), 1);
    let (status, _) = with_session(
        &h,
        Method::GET,
        "/v1/links/alices",
        &mallory,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);
    // Nor does a second "Ada" become the first.
    let ada2 = sign_in(&h, &idp, json!({"sub": "ada-2", "name": "Ada"})).await;
    let (_, body) = me(&h, &ada2).await;
    assert_eq!(body["user"]["member"], "ada-2");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(users, 3);
    h.shutdown().await;
}

#[tokio::test]
async fn people_act_with_their_role_in_the_workspace_they_name() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };
    h.create(json!({"url": "https://example.com/a", "alias": "team-link"}))
        .await;
    let team = h.store.personal_workspace("alice").await.unwrap();
    let bob_ws = h.store.personal_workspace("bob").await.unwrap();
    let session = sign_in(&h, &idp, ada()).await;
    let (_, body) = me(&h, &session).await;
    let csrf = body["csrf_token"].as_str().unwrap().to_owned();
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, member, role) VALUES ($1, 'ada', 'viewer')",
    )
    .bind(team)
    .execute(h.store.pool())
    .await
    .unwrap();
    let ws = team.to_string();
    let w = Some(ws.as_str());

    let (_, body) = me(&h, &session).await;
    let roles: Vec<(i64, String)> = body["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["id"].as_i64().unwrap(),
                m["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(roles.contains(&(team, "viewer".into())), "{roles:?}");

    let (status, body) = with_session(
        &h,
        Method::GET,
        "/v1/links/team-link",
        &session,
        None,
        w,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = with_session(
        &h,
        Method::GET,
        "/v1/links/team-link/stats",
        &session,
        None,
        w,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = with_session(
        &h,
        Method::PATCH,
        "/v1/links/team-link",
        &session,
        Some(&csrf),
        w,
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("viewer role"),
        "{body}"
    );

    // Promoted to editor, ada can write there (within the role cache TTL).
    sqlx::query(
        "UPDATE workspace_members SET role = 'editor' WHERE workspace_id = $1 AND member = 'ada'",
    )
    .bind(team)
    .execute(h.store.pool())
    .await
    .unwrap();
    let fresh = h.second_instance(&[]).await;
    let resp = reqwest::Client::new()
        .patch(format!("http://{}/v1/links/team-link", fresh.addr))
        .header("cookie", format!("relink_session={session}"))
        .header("x-csrf-token", &csrf)
        .header("relink-workspace", &ws)
        .header("content-type", "application/json")
        .body(json!({"enabled": false}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    fresh.shutdown().await;

    // Not a member: refused; malformed: invalid.
    let other = bob_ws.to_string();
    let (status, body) = with_session(
        &h,
        Method::GET,
        "/v1/links",
        &session,
        None,
        Some(&other),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not a member")
    );
    let (status, _) = with_session(
        &h,
        Method::GET,
        "/v1/links",
        &session,
        None,
        Some("x"),
        None,
    )
    .await;
    assert_eq!(status, 400);
    // Without the header, ada acts in her own workspace, where the link is not.
    let (status, _) = with_session(
        &h,
        Method::GET,
        "/v1/links/team-link",
        &session,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);
    h.shutdown().await;
}

#[tokio::test]
async fn refuses_sign_ins_that_do_not_check_out() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };
    let message = |body: &str| -> String {
        serde_json::from_str::<Value>(body).unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let refused = async |resp: reqwest::Response, status: u16, needle: &str| {
        assert_eq!(resp.status().as_u16(), status);
        assert!(
            set_cookies(&resp)
                .iter()
                .all(|c| !c.starts_with("relink_session="))
        );
        let m = message(&resp.text().await.unwrap());
        assert!(m.contains(needle), "{m:?} should mention {needle:?}");
    };

    // No cookie, or a cookie for another sign-in.
    let s = begin(&h, None).await;
    let code = idp.approve(&s.authorize, ada());
    let query = q(&[("code", &code), ("state", &s.authorize["state"])]);
    refused(callback(&h, &query, None).await, 401, "did not start").await;
    let other = begin(&h, None).await;
    refused(
        callback(&h, &query, Some(&other.login_cookie)).await,
        401,
        "did not start",
    )
    .await;
    refused(
        callback(&h, "code=x", Some(&s.login_cookie)).await,
        401,
        "did not start",
    )
    .await;
    // The real one works once; a replay finds nothing.
    let ok = callback(&h, &query, Some(&s.login_cookie)).await;
    assert_eq!(ok.status(), 302);
    refused(
        callback(&h, &query, Some(&s.login_cookie)).await,
        401,
        "already used",
    )
    .await;

    // Expired before the person came back.
    let s = begin(&h, None).await;
    sqlx::query("UPDATE oidc_logins SET expires_at = now() - interval '1 second'")
        .execute(h.store.pool())
        .await
        .unwrap();
    let code = idp.approve(&s.authorize, ada());
    refused(
        callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await,
        401,
        "expired",
    )
    .await;

    // The person declined at the provider: the sign-in is used up.
    let s = begin(&h, None).await;
    let declined = q(&[
        ("error", "access_denied"),
        ("error_description", "<b>no</b>"),
        ("state", &s.authorize["state"]),
    ]);
    refused(
        callback(&h, &declined, Some(&s.login_cookie)).await,
        401,
        "access_denied",
    )
    .await;
    refused(
        callback(&h, &declined, Some(&s.login_cookie)).await,
        401,
        "already used",
    )
    .await;

    // A token for someone else's sign-in (wrong nonce).
    let s = begin(&h, None).await;
    let mut claims = ada();
    claims["nonce"] = json!("not-this-one");
    let code = idp.approve(&s.authorize, claims);
    refused(
        callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await,
        401,
        "nonce",
    )
    .await;

    // A token from another audience.
    let s = begin(&h, None).await;
    let mut claims = ada();
    claims["aud"] = json!("some-other-app");
    let code = idp.approve(&s.authorize, claims);
    refused(
        callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await,
        401,
        "aud",
    )
    .await;

    // Signed by a key the provider does not publish.
    idp.state.lock().unwrap().signing = Some(Arc::new(Key::new("rogue")));
    let s = begin(&h, None).await;
    let code = idp.approve(&s.authorize, ada());
    refused(
        callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await,
        401,
        "unknown key",
    )
    .await;
    let published = idp.state.lock().unwrap().published[0].clone();
    idp.state.lock().unwrap().signing = Some(published);

    // The token endpoint refuses the code.
    idp.state.lock().unwrap().token_error = Some("invalid_grant".into());
    let s = begin(&h, None).await;
    let code = idp.approve(&s.authorize, ada());
    refused(
        callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await,
        401,
        "invalid_grant",
    )
    .await;
    idp.state.lock().unwrap().token_error = None;

    // A return path off this server is refused before anything starts.
    let resp = h
        .http
        .get(format!(
            "{}/v1/auth/login?return_to=https://evil.example.com/",
            h.base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = h
        .http
        .get(format!("{}/v1/auth/login?next=/", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "unknown parameters are refused");

    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_sign_ins_total"), 1.0);
    assert_eq!(metric(&m, "relink_sign_in_failures_total"), 11.0);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(sessions, 1);
    h.shutdown().await;
}

#[tokio::test]
async fn bad_session_cookies_and_expiry() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };
    for bad in ["", "nope", &format!("rls_{}", "0".repeat(64))] {
        let (status, body) = me(&h, bad).await;
        assert_eq!(status, 401, "{bad:?}: {body}");
        assert_eq!(body["error"]["code"], "unauthenticated");
    }
    let resp = h
        .http
        .get(format!("{}/v1/auth/session", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no cookie at all");
    let (status, _) = h.api(Method::GET, "/v1/auth/session", &h.alice, None).await;
    assert_eq!(status, 401, "an API key is not a session");

    let session = sign_in(&h, &idp, ada()).await;
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second', created_at = now() - interval '1 hour'")
        .execute(h.store.pool())
        .await
        .unwrap();
    // The row is still there, but the lookup no longer returns it.
    let hash = relink_server::session::hash_session(&session);
    assert!(h.store.session_by_hash(&hash).await.unwrap().is_none());

    // Clean-up removes expired sessions and abandoned sign-ins.
    begin(&h, None).await;
    sqlx::query("UPDATE oidc_logins SET expires_at = now() - interval '1 second'")
        .execute(h.store.pool())
        .await
        .unwrap();
    assert_eq!(h.store.purge_expired_sessions().await.unwrap(), 2);
    assert_eq!(h.store.purge_expired_sessions().await.unwrap(), 0);

    // An instance that has never seen the session refuses it.
    let fresh = h.second_instance(&[]).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{}/v1/links", fresh.addr))
        .header("cookie", format!("relink_session={session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    fresh.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn allowed_domains_need_a_verified_address() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[("RELINK_OIDC_ALLOWED_DOMAINS", "example.com")]).await else {
        return;
    };
    for (claims, ok) in [
        (
            json!({"sub": "1", "email": "a@example.com", "email_verified": false}),
            false,
        ),
        (
            json!({"sub": "2", "email": "a@example.org", "email_verified": true}),
            false,
        ),
        (json!({"sub": "3"}), false),
        (
            json!({"sub": "4", "email": "b@EXAMPLE.com", "email_verified": true}),
            true,
        ),
    ] {
        let s = begin(&h, None).await;
        let code = idp.approve(&s.authorize, claims.clone());
        let resp = callback(
            &h,
            &q(&[("code", &code), ("state", &s.authorize["state"])]),
            Some(&s.login_cookie),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            if ok { 302 } else { 403 },
            "{claims}"
        );
    }
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(users, 1, "refused people are not created");
    h.shutdown().await;
}

#[tokio::test]
async fn public_clients_and_provider_outages() {
    let idp = Idp::start().await;
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(
        &admin,
        &[
            ("RELINK_OIDC_ISSUER", &idp.issuer),
            ("RELINK_OIDC_CLIENT_ID", CLIENT_ID),
            ("RELINK_OIDC_REDIRECT_URL", "http://127.0.0.1:9/cb"),
            ("RELINK_SESSION_TTL_S", "600"),
            ("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000"),
        ],
    )
    .await;
    idp.state.lock().unwrap().down = true;
    let resp = h
        .http
        .get(format!("{}/v1/auth/login", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        503,
        "discovery failing is an outage, not a client error"
    );
    idp.state.lock().unwrap().down = false;

    let s = begin(&h, None).await;
    assert_eq!(s.authorize["redirect_uri"], "http://127.0.0.1:9/cb");
    let code = idp.approve(&s.authorize, ada());
    let resp = callback(
        &h,
        &q(&[("code", &code), ("state", &s.authorize["state"])]),
        Some(&s.login_cookie),
    )
    .await;
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers()["location"], "/v1/auth/session");
    assert!(set_cookies(&resp)[0].contains("Max-Age=600"));
    {
        let st = idp.state.lock().unwrap();
        assert_eq!(st.last_auth, None, "a public client has no secret to send");
        assert_eq!(st.last_form["client_id"], CLIENT_ID);
    }
    h.shutdown().await;
}

#[tokio::test]
async fn sign_in_is_off_unless_configured() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(&admin, &[]).await;
    for path in ["/v1/auth/login", "/v1/auth/callback?code=x&state=y"] {
        let resp = h
            .http
            .get(format!("{}{path}", h.base))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{path}");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not configured")
        );
    }
    h.shutdown().await;
}

#[tokio::test]
async fn follows_key_rotation_with_a_bounded_refetch() {
    let idp = Idp::start().await;
    let cfg = OidcConfig {
        issuer: idp.issuer.clone(),
        client_id: CLIENT_ID.into(),
        client_secret: None,
        redirect_url: "http://127.0.0.1:9/cb".into(),
        scopes: "openid".into(),
        allowed_domains: vec![],
    };
    let token = |key: &Key| {
        let now = chrono::Utc::now().timestamp();
        key.sign(
            &json!({"iss": idp.issuer, "aud": CLIENT_ID, "sub": "s", "nonce": "n",
                         "iat": now, "exp": now + 60}),
        )
    };
    let k1 = idp.state.lock().unwrap().published[0].clone();
    let k2 = Arc::new(Key::new("k2"));

    // Default: an unknown key within 30 s of the last fetch is refused
    // without hitting the provider again.
    let slow = Oidc::new(cfg.clone()).unwrap();
    let provider = slow.provider().await.unwrap();
    assert_eq!(provider.jwks_uri, format!("{}/jwks", idp.issuer));
    assert!(slow.verify(&provider, &token(&k1), "n").await.is_ok());
    assert!(slow.verify(&provider, &token(&k1), "n").await.is_ok());
    assert_eq!(idp.jwks_hits.load(Ordering::SeqCst), 1, "keys are cached");
    idp.state.lock().unwrap().published.push(k2.clone());
    assert!(matches!(
        slow.verify(&provider, &token(&k2), "n").await,
        Err(OidcError::IdToken(_))
    ));
    assert_eq!(idp.jwks_hits.load(Ordering::SeqCst), 1);

    // With the bound lifted, the unknown key triggers one refetch.
    let fast = Oidc::with_key_refresh(cfg, Duration::ZERO).unwrap();
    let provider = fast.provider().await.unwrap();
    idp.state
        .lock()
        .unwrap()
        .published
        .retain(|k| k.kid == "k1");
    assert!(fast.verify(&provider, &token(&k1), "n").await.is_ok());
    let before = idp.jwks_hits.load(Ordering::SeqCst);
    idp.state.lock().unwrap().published = vec![k2.clone()];
    assert!(fast.verify(&provider, &token(&k2), "n").await.is_ok());
    assert_eq!(idp.jwks_hits.load(Ordering::SeqCst), before + 1);
    assert!(matches!(
        fast.verify(&provider, &token(&k2), "other").await,
        Err(OidcError::IdToken(_))
    ));

    // A discovery document for another issuer is refused.
    let wrong = Oidc::new(OidcConfig {
        issuer: format!("{}/", idp.issuer),
        client_id: CLIENT_ID.into(),
        client_secret: None,
        redirect_url: "http://127.0.0.1:9/cb".into(),
        scopes: "openid".into(),
        allowed_domains: vec![],
    })
    .unwrap();
    assert!(matches!(
        wrong.provider().await,
        Err(OidcError::Provider(_))
    ));
}

#[tokio::test]
async fn anonymous_sign_in_requests_are_rate_limited_per_address() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[("RELINK_AUTH_LOOKUP_RATE_PER_IP", "0.01")]).await else {
        return;
    };
    // The burst is at least one request; then the address must wait.
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let resp = h
            .http
            .get(format!("{}/v1/auth/login", h.base))
            .send()
            .await
            .unwrap();
        statuses.push(resp.status().as_u16());
    }
    assert_eq!(statuses[0], 302);
    assert_eq!(statuses[2], 429, "{statuses:?}");
    let resp = callback(&h, "code=x&state=y", Some("y")).await;
    assert_eq!(resp.status(), 429);
    assert!(resp.headers().contains_key("retry-after"));
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_logins")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert!(pending <= 2, "refused requests store nothing: {pending}");
    h.shutdown().await;
}

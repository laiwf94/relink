//! OpenID Connect sign-in for people, as opposed to API keys for programs.
//!
//! The flow is the authorization code flow with PKCE (RFC 7636), against any
//! provider that publishes discovery metadata:
//!
//! 1. `GET /v1/auth/login` stores a pending sign-in in Postgres (the SHA-256
//!    of a random `state`, a `nonce`, the PKCE verifier and where to return),
//!    sets the `state` in a short-lived cookie and redirects to the
//!    provider's authorization endpoint with the S256 challenge.
//! 2. `GET /v1/auth/callback` requires the cookie to match `state`, takes the
//!    pending sign-in (once: it is deleted), exchanges the code with the
//!    verifier at the token endpoint and checks the ID token
//!    ([`verify_id_token`]): signature by a provider key (RS256 or ES256,
//!    verified with `ring`), issuer, audience, authorized party, expiry,
//!    issue time and nonce. It then finds or creates the person
//!    ([`crate::session`]) and starts a session.
//!
//! Provider metadata and keys are fetched on first use and cached; an ID
//! token signed by a key we have not seen refetches the key set, at most
//! once every [`JWKS_MIN_REFRESH`], which is how key rotation is followed.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::api::ApiError;
use crate::server::App;
use crate::session::{self, LOGIN_COOKIE, NewUser};
use crate::util::{b64url_decode, b64url_encode, secure_random};

/// How long a sign-in may take between leaving for the provider and coming
/// back.
pub const LOGIN_TTL: Duration = Duration::from_secs(600);

/// Clock difference tolerated between us and the provider, in seconds.
pub const CLOCK_SKEW_S: i64 = 60;

/// How long provider metadata and keys are used before being refetched.
pub const METADATA_TTL: Duration = Duration::from_secs(3_600);

/// Least time between two key set fetches caused by an unknown key.
pub const JWKS_MIN_REFRESH: Duration = Duration::from_secs(30);

/// Largest ID token accepted.
pub const MAX_ID_TOKEN: usize = 16 * 1024;

/// Largest response body read from the provider.
const MAX_PROVIDER_BODY: usize = 256 * 1024;

/// Where to go after signing in when the login request does not say.
pub const DEFAULT_RETURN_TO: &str = "/v1/auth/session";

/// Sign-in settings, from `RELINK_OIDC_*`.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The provider's issuer identifier, exactly as it appears in its ID
    /// tokens and discovery document.
    pub issuer: String,
    pub client_id: String,
    /// Sent with HTTP basic authentication to the token endpoint. Without
    /// one the client is public and relies on PKCE alone.
    pub client_secret: Option<String>,
    /// Our callback, registered with the provider.
    pub redirect_url: String,
    /// Space-separated scopes requested; always includes `openid`.
    pub scopes: String,
    /// When not empty, only people whose verified email address is at one of
    /// these domains may sign in.
    pub allowed_domains: Vec<String>,
}

impl fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_url", &self.redirect_url)
            .field("scopes", &self.scopes)
            .field("allowed_domains", &self.allowed_domains)
            .finish()
    }
}

/// Whether `url` is plain http to this machine, which is allowed for tests
/// and local development in place of https.
pub fn is_loopback_http(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url) else {
        return false;
    };
    u.scheme() == "http"
        && match u.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
}

/// An absolute https URL, or http to loopback when `allow_loopback`.
fn acceptable_url(url: &str, allow_loopback: bool) -> bool {
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" && u.host().is_some() => true,
        Ok(_) => allow_loopback && is_loopback_http(url),
        Err(_) => false,
    }
}

impl OidcConfig {
    /// Checks the settings that can be checked without the network.
    pub fn validate(&self) -> Result<(), String> {
        if !acceptable_url(&self.issuer, true) {
            return Err(
                "RELINK_OIDC_ISSUER must be an https URL (or http on localhost for tests)".into(),
            );
        }
        if self.client_id.is_empty() || self.client_id.len() > 255 {
            return Err("RELINK_OIDC_CLIENT_ID must be 1 to 255 characters".into());
        }
        if !acceptable_url(&self.redirect_url, true) {
            return Err(
                "RELINK_OIDC_REDIRECT_URL must be an https URL (or http on localhost)".into(),
            );
        }
        if !self.scopes.split(' ').any(|s| s == "openid") {
            return Err("RELINK_OIDC_SCOPES must include openid".into());
        }
        if !self
            .scopes
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\' || b == b' ')
        {
            return Err("RELINK_OIDC_SCOPES must be space-separated scope names".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ID tokens

/// A public key from the provider's key set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Jwk {
    /// RSA, for RS256: big-endian modulus and exponent without leading zeros.
    Rsa {
        kid: Option<String>,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// P-256, for ES256: the uncompressed point `04 || x || y`.
    P256 { kid: Option<String>, point: Vec<u8> },
}

impl Jwk {
    fn kid(&self) -> Option<&str> {
        match self {
            Jwk::Rsa { kid, .. } | Jwk::P256 { kid, .. } => kid.as_deref(),
        }
    }

    fn fits(&self, alg: Alg) -> bool {
        matches!(
            (self, alg),
            (Jwk::Rsa { .. }, Alg::Rs256) | (Jwk::P256 { .. }, Alg::Es256)
        )
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use ring::signature;
        match self {
            Jwk::Rsa { n, e, .. } => signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            Jwk::P256 { point, .. } => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
        }
    }
}

/// The provider's signing keys that we can use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Jwks(pub Vec<Jwk>);

#[derive(Deserialize)]
struct RawJwk {
    kty: Option<String>,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn strip_leading_zeros(mut v: Vec<u8>) -> Vec<u8> {
    let zeros = v.iter().take_while(|&&b| b == 0).count();
    v.drain(..zeros);
    v
}

impl Jwks {
    /// Parses a JWK set (RFC 7517). Keys we cannot use (encryption keys,
    /// other key types, curves or algorithms) are skipped, not errors:
    /// providers publish them alongside signing keys. A malformed key of a
    /// type we do use is an error.
    pub fn parse(body: &[u8]) -> Result<Jwks, String> {
        #[derive(Deserialize)]
        struct Set {
            keys: Vec<RawJwk>,
        }
        let set: Set = serde_json::from_slice(body).map_err(|e| format!("not a JWK set: {e}"))?;
        let mut keys = Vec::new();
        for k in set.keys {
            if k.use_.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            let b64 = |field: &Option<String>, name: &str| {
                field
                    .as_deref()
                    .and_then(b64url_decode)
                    .ok_or_else(|| format!("JWK {:?}: missing or invalid {name}", k.kid))
            };
            match (k.kty.as_deref(), k.alg.as_deref()) {
                (Some("RSA"), None | Some("RS256")) => {
                    let n = strip_leading_zeros(b64(&k.n, "n")?);
                    let e = strip_leading_zeros(b64(&k.e, "e")?);
                    if n.is_empty() || e.is_empty() {
                        return Err(format!("JWK {:?}: empty RSA component", k.kid));
                    }
                    keys.push(Jwk::Rsa { kid: k.kid, n, e });
                }
                (Some("EC"), None | Some("ES256")) if k.crv.as_deref() == Some("P-256") => {
                    let (x, y) = (b64(&k.x, "x")?, b64(&k.y, "y")?);
                    if x.len() != 32 || y.len() != 32 {
                        return Err(format!("JWK {:?}: P-256 coordinates are 32 bytes", k.kid));
                    }
                    let mut point = Vec::with_capacity(65);
                    point.push(4);
                    point.extend_from_slice(&x);
                    point.extend_from_slice(&y);
                    keys.push(Jwk::P256 { kid: k.kid, point });
                }
                _ => {}
            }
        }
        Ok(Jwks(keys))
    }
}

/// A signature algorithm we accept. Everything else, `none` and the HMAC
/// algorithms in particular, is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Es256,
}

/// What the ID token must say.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// The current time, in seconds since the Unix epoch.
    pub now: i64,
}

/// The claims we use from a verified ID token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdClaims {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

/// Why an ID token was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdTokenError {
    /// Not three base64url parts of JSON, or too large.
    Malformed(&'static str),
    /// Signed with an algorithm we do not accept.
    Algorithm(String),
    /// No key in the set fits the token's `kid` and algorithm; refetching
    /// the key set may help.
    UnknownKey,
    /// A fitting key exists but the signature does not verify.
    Signature,
    /// A claim is missing or wrong.
    Claim(&'static str),
}

impl fmt::Display for IdTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdTokenError::Malformed(why) => write!(f, "malformed ID token: {why}"),
            IdTokenError::Algorithm(alg) => {
                write!(
                    f,
                    "ID token algorithm {alg:?} is not accepted (RS256, ES256)"
                )
            }
            IdTokenError::UnknownKey => f.write_str("ID token signed by an unknown key"),
            IdTokenError::Signature => f.write_str("ID token signature does not verify"),
            IdTokenError::Claim(why) => write!(f, "ID token claim check failed: {why}"),
        }
    }
}

/// A JSON number claim as whole seconds. Providers send integers; a
/// fractional value is truncated, as RFC 7519 allows non-integer times.
fn seconds(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64()
        .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
}

fn short_string(v: Option<&Value>, max: usize) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(str::to_owned)
}

/// Verifies an ID token (OpenID Connect Core 1.0, section 3.1.3.7) and
/// returns its claims. Pure: the caller supplies the keys and the time.
pub fn verify_id_token(
    token: &str,
    keys: &Jwks,
    expected: &Expected<'_>,
) -> Result<IdClaims, IdTokenError> {
    if token.len() > MAX_ID_TOKEN {
        return Err(IdTokenError::Malformed("too large"));
    }
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IdTokenError::Malformed("not three parts"));
    };
    let header: Value = b64url_decode(h64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(Value::is_object)
        .ok_or(IdTokenError::Malformed("header"))?;
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some("RS256") => Alg::Rs256,
        Some("ES256") => Alg::Es256,
        other => return Err(IdTokenError::Algorithm(other.unwrap_or("").to_owned())),
    };
    if header.get("crit").is_some() {
        return Err(IdTokenError::Malformed("critical header extensions"));
    }
    let signature = b64url_decode(s64).ok_or(IdTokenError::Malformed("signature"))?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.as_str()),
        Some(_) => return Err(IdTokenError::Malformed("kid")),
    };
    let message = &token.as_bytes()[..h64.len() + 1 + p64.len()];
    let mut candidates = keys
        .0
        .iter()
        .filter(|k| k.fits(alg) && (kid.is_none() || k.kid() == kid))
        .peekable();
    if candidates.peek().is_none() {
        return Err(IdTokenError::UnknownKey);
    }
    if !candidates.any(|k| k.verify(message, &signature)) {
        return Err(IdTokenError::Signature);
    }

    // Only now is the payload trusted enough to read.
    let claims: Value = b64url_decode(p64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(Value::is_object)
        .ok_or(IdTokenError::Malformed("payload"))?;
    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(IdTokenError::Claim("iss is not the configured issuer"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => return Err(IdTokenError::Claim("aud is missing")),
    };
    if !audiences.contains(&expected.client_id) {
        return Err(IdTokenError::Claim("aud does not include this client"));
    }
    match claims.get("azp") {
        None if audiences.len() == 1 => {}
        None => {
            return Err(IdTokenError::Claim(
                "azp is required with several audiences",
            ));
        }
        Some(azp) if azp.as_str() == Some(expected.client_id) => {}
        Some(_) => return Err(IdTokenError::Claim("azp is not this client")),
    }
    let exp = seconds(claims.get("exp")).ok_or(IdTokenError::Claim("exp is missing"))?;
    if exp.saturating_add(CLOCK_SKEW_S) <= expected.now {
        return Err(IdTokenError::Claim("the token has expired"));
    }
    let iat = seconds(claims.get("iat")).ok_or(IdTokenError::Claim("iat is missing"))?;
    if iat > expected.now.saturating_add(CLOCK_SKEW_S) {
        return Err(IdTokenError::Claim("iat is in the future"));
    }
    if seconds(claims.get("nbf")).is_some_and(|nbf| nbf > expected.now.saturating_add(CLOCK_SKEW_S))
    {
        return Err(IdTokenError::Claim("the token is not valid yet"));
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
    if !bool::from(nonce.as_bytes().ct_eq(expected.nonce.as_bytes())) {
        return Err(IdTokenError::Claim("nonce does not match this sign-in"));
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or(IdTokenError::Claim("sub is missing or longer than 255"))?
        .to_owned();
    // Some providers send email_verified as a string.
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    Ok(IdClaims {
        subject,
        email: short_string(claims.get("email"), 320).filter(|e| e.contains('@')),
        email_verified,
        name: short_string(claims.get("name"), 200),
        preferred_username: short_string(claims.get("preferred_username"), 200),
    })
}

/// Whether a person with these claims may sign in under `allowed` domains:
/// any, when the list is empty; otherwise only with a verified email address
/// at one of them (compared case-insensitively).
pub fn domain_allowed(claims: &IdClaims, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(email) = claims.email.as_deref().filter(|_| claims.email_verified) else {
        return false;
    };
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    allowed.iter().any(|d| d.eq_ignore_ascii_case(domain))
}

// ---------------------------------------------------------------------------
// PKCE, state and return paths

/// 32 random bytes in base64url: 43 characters, used for `state`, `nonce`
/// and the PKCE verifier.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    secure_random(&mut b);
    b64url_encode(&b)
}

/// The S256 code challenge for a PKCE verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    b64url_encode(&Sha256::digest(verifier.as_bytes()))
}

/// The SHA-256 of a `state` value, as stored.
pub fn state_hash(state: &str) -> [u8; 32] {
    Sha256::digest(state.as_bytes()).into()
}

/// A path on this server to send the browser to after signing in, or `None`
/// if `s` could lead elsewhere. Only absolute paths are accepted: no scheme,
/// no `//host` or `/\host` (which browsers treat as another host), no
/// control characters or spaces.
pub fn safe_return_to(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    (b.first() == Some(&b'/')
        && !matches!(b.get(1), Some(b'/' | b'\\'))
        && b.len() <= 512
        && b.iter().all(|&c| c.is_ascii_graphic()))
    .then_some(s)
}

// ---------------------------------------------------------------------------
// The provider

/// Endpoints from the provider's discovery document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Why talking to the provider failed.
#[derive(Debug)]
pub enum OidcError {
    /// The provider could not be reached or answered with nonsense.
    Provider(String),
    /// The token endpoint refused the code.
    Token(String),
    /// The ID token is not acceptable.
    IdToken(IdTokenError),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcError::Provider(why) => write!(f, "identity provider error: {why}"),
            OidcError::Token(code) => write!(f, "the identity provider refused the code: {code}"),
            OidcError::IdToken(e) => e.fmt(f),
        }
    }
}

struct Cached<T> {
    value: Arc<T>,
    fetched: Instant,
}

/// A client for one provider, with its metadata and keys cached.
pub struct Oidc {
    cfg: OidcConfig,
    http: reqwest::Client,
    provider: Mutex<Option<Cached<Provider>>>,
    keys: Mutex<Option<Cached<Jwks>>>,
    min_key_refresh: Duration,
}

/// A provider error code made safe to show: lowercase letters and
/// underscores, as RFC 6749 defines them.
fn error_code(s: &str) -> String {
    let clean: String = s
        .chars()
        .filter(|c| c.is_ascii_lowercase() || *c == '_')
        .take(64)
        .collect();
    if clean.is_empty() {
        "unknown_error".into()
    } else {
        clean
    }
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Result<Oidc, String> {
        Oidc::with_key_refresh(cfg, JWKS_MIN_REFRESH)
    }

    /// [`Oidc::new`] with a different least time between key set fetches
    /// caused by unknown keys (tests use zero).
    pub fn with_key_refresh(cfg: OidcConfig, min_key_refresh: Duration) -> Result<Oidc, String> {
        cfg.validate()?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Oidc {
            cfg,
            http,
            provider: Mutex::new(None),
            keys: Mutex::new(None),
            min_key_refresh,
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.cfg
    }

    async fn get_json(&self, url: &str) -> Result<Vec<u8>, OidcError> {
        let resp = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| OidcError::Provider(format!("GET {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::Provider(format!(
                "GET {url}: HTTP {}",
                resp.status().as_u16()
            )));
        }
        read_limited(resp).await
    }

    /// The provider's endpoints, from its discovery document.
    pub async fn provider(&self) -> Result<Arc<Provider>, OidcError> {
        let mut slot = self.provider.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| c.fetched.elapsed() < METADATA_TTL) {
            return Ok(c.value.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.trim_end_matches('/')
        );
        let body = self.get_json(&url).await?;
        let doc: Value = serde_json::from_slice(&body)
            .map_err(|e| OidcError::Provider(format!("discovery document: {e}")))?;
        if doc.get("issuer").and_then(Value::as_str) != Some(self.cfg.issuer.as_str()) {
            return Err(OidcError::Provider(
                "the discovery document names a different issuer".into(),
            ));
        }
        let loopback = is_loopback_http(&self.cfg.issuer);
        let endpoint = |name: &str| {
            doc.get(name)
                .and_then(Value::as_str)
                .filter(|u| acceptable_url(u, loopback))
                .map(str::to_owned)
                .ok_or_else(|| {
                    OidcError::Provider(format!("discovery document: missing or non-https {name}"))
                })
        };
        let provider = Arc::new(Provider {
            authorization_endpoint: endpoint("authorization_endpoint")?,
            token_endpoint: endpoint("token_endpoint")?,
            jwks_uri: endpoint("jwks_uri")?,
        });
        *slot = Some(Cached {
            value: provider.clone(),
            fetched: Instant::now(),
        });
        Ok(provider)
    }

    /// The provider's keys. `refresh` asks for a fresh copy, which is
    /// honoured only if the cached one is older than [`JWKS_MIN_REFRESH`]
    /// (by default).
    async fn keys(&self, provider: &Provider, refresh: bool) -> Result<Arc<Jwks>, OidcError> {
        let mut slot = self.keys.lock().await;
        if let Some(c) = slot.as_ref() {
            let age = c.fetched.elapsed();
            if age < METADATA_TTL && !(refresh && age >= self.min_key_refresh) {
                return Ok(c.value.clone());
            }
        }
        let body = self.get_json(&provider.jwks_uri).await?;
        let keys =
            Arc::new(Jwks::parse(&body).map_err(|e| OidcError::Provider(format!("key set: {e}")))?);
        *slot = Some(Cached {
            value: keys.clone(),
            fetched: Instant::now(),
        });
        Ok(keys)
    }

    /// Where to send the browser to sign in.
    pub fn authorize_url(
        &self,
        provider: &Provider,
        state: &str,
        nonce: &str,
        verifier: &str,
    ) -> String {
        let mut url = url::Url::parse(&provider.authorization_endpoint)
            .expect("checked when the discovery document was read");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &pkce_challenge(verifier))
            .append_pair("code_challenge_method", "S256");
        url.into()
    }

    /// Exchanges an authorization code for an ID token.
    pub async fn exchange(
        &self,
        provider: &Provider,
        code: &str,
        verifier: &str,
    ) -> Result<String, OidcError> {
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", code)
                .append_pair("redirect_uri", &self.cfg.redirect_url)
                .append_pair("code_verifier", verifier);
            if self.cfg.client_secret.is_none() {
                form.append_pair("client_id", &self.cfg.client_id);
            }
            form.finish()
        };
        let mut req = self
            .http
            .post(&provider.token_endpoint)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(secret) = &self.cfg.client_secret {
            // RFC 6749 section 2.3.1: both parts form-encoded, then basic.
            req = req.basic_auth(form_encode(&self.cfg.client_id), Some(form_encode(secret)));
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| OidcError::Provider(format!("token endpoint: {e}")))?;
        let status = resp.status();
        let body = read_limited(resp).await?;
        let doc: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(match doc.get("error").and_then(Value::as_str) {
                Some(code) => OidcError::Token(error_code(code)),
                None => OidcError::Provider(format!("token endpoint: HTTP {}", status.as_u16())),
            });
        }
        doc.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| OidcError::Provider("token response has no id_token".into()))
    }

    /// Verifies an ID token from this provider, refetching the key set once
    /// if it was signed by a key we do not have yet.
    pub async fn verify(
        &self,
        provider: &Provider,
        id_token: &str,
        nonce: &str,
    ) -> Result<IdClaims, OidcError> {
        let now = chrono::Utc::now().timestamp();
        let expected = Expected {
            issuer: &self.cfg.issuer,
            client_id: &self.cfg.client_id,
            nonce,
            now,
        };
        let keys = self.keys(provider, false).await?;
        match verify_id_token(id_token, &keys, &expected) {
            Err(IdTokenError::UnknownKey) => {
                let keys = self.keys(provider, true).await?;
                verify_id_token(id_token, &keys, &expected).map_err(OidcError::IdToken)
            }
            other => other.map_err(OidcError::IdToken),
        }
    }
}

fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn read_limited(mut resp: reqwest::Response) -> Result<Vec<u8>, OidcError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| OidcError::Provider(format!("reading the response: {e}")))?
    {
        if body.len() + chunk.len() > MAX_PROVIDER_BODY {
            return Err(OidcError::Provider("response too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Handlers

fn oidc(app: &App) -> Result<&Oidc, ApiError> {
    app.oidc
        .as_deref()
        .ok_or_else(|| ApiError::not_found_msg("sign-in is not configured on this server"))
}

fn provider_unavailable(e: &OidcError) -> ApiError {
    tracing::warn!(error = %e, "identity provider unavailable");
    ApiError::unavailable_msg("the identity provider cannot be reached; retry later")
}

/// An unauthenticated request admitted by the per-address and global limit
/// on lookups of unknown credentials: each sign-in request writes to
/// Postgres, so anonymous clients must not be able to send them unbounded.
pub struct Anonymous;

impl FromRequestParts<Arc<App>> for Anonymous {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let client = crate::api::client_addr(app, parts);
        app.auth
            .admit_anonymous(client)
            .map(|()| Anonymous)
            .map_err(crate::session::auth_error)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginQuery {
    return_to: Option<String>,
}

/// `GET /v1/auth/login`: starts a sign-in and redirects to the provider.
pub async fn login(
    State(app): State<Arc<App>>,
    Anonymous: Anonymous,
    crate::api::StrictQuery(q): crate::api::StrictQuery<LoginQuery>,
) -> Result<Response, ApiError> {
    let oidc = oidc(&app)?;
    let return_to = match q.return_to.as_deref() {
        None => DEFAULT_RETURN_TO,
        Some(r) => safe_return_to(r)
            .ok_or_else(|| ApiError::invalid("return_to must be a path on this server"))?,
    };
    let provider = oidc
        .provider()
        .await
        .map_err(|e| provider_unavailable(&e))?;
    let (state, nonce, verifier) = (random_token(), random_token(), random_token());
    app.db
        .insert_login(&state_hash(&state), &nonce, &verifier, return_to, LOGIN_TTL)
        .await?;
    let location = oidc.authorize_url(&provider, &state, &nonce, &verifier);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session::cookie(
            LOGIN_COOKIE,
            &state,
            session::LOGIN_COOKIE_PATH,
            Some(LOGIN_TTL),
            app.cfg.cookie_secure,
        ),
    );
    Ok(found(&location, headers))
}

/// A 302 to `location` that no cache keeps.
fn found(location: &str, mut headers: HeaderMap) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => {
            headers.insert(header::LOCATION, v);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            (StatusCode::FOUND, headers).into_response()
        }
        Err(_) => ApiError::internal().into_response(),
    }
}

/// The callback's query. Providers add parameters of their own
/// (`session_state`, `iss`, `scope`...), so unknown ones are ignored.
#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /v1/auth/callback`: finishes a sign-in and starts a session.
pub async fn callback(
    State(app): State<Arc<App>>,
    Anonymous: Anonymous,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let oidc = oidc(&app)?;
    let result = finish_sign_in(&app, oidc, &headers, q).await;
    match &result {
        Ok(_) => app.metrics.sign_ins.inc(),
        Err(e) => {
            app.metrics.sign_in_failures.inc();
            tracing::info!(code = e.code, message = %e.message, "sign-in failed");
        }
    }
    result
}

async fn finish_sign_in(
    app: &App,
    oidc: &Oidc,
    headers: &HeaderMap,
    q: CallbackQuery,
) -> Result<Response, ApiError> {
    let failed = |why: &str| ApiError::unauthenticated_msg(format!("sign-in failed: {why}"));
    let state = q.state.as_deref().unwrap_or("");
    let cookie = session::read_cookie(headers, LOGIN_COOKIE).unwrap_or("");
    // The cookie ties the callback to the browser that started the sign-in,
    // so nobody can complete their own sign-in in someone else's browser.
    if state.is_empty() || !bool::from(cookie.as_bytes().ct_eq(state.as_bytes())) {
        return Err(failed("this browser did not start this sign-in"));
    }
    let login = app
        .db
        .take_login(&state_hash(state))
        .await?
        .ok_or_else(|| failed("the sign-in expired or was already used; start again"))?;
    if let Some(err) = q.error.as_deref() {
        return Err(failed(&format!(
            "the identity provider answered {}",
            error_code(err)
        )));
    }
    let code = q
        .code
        .as_deref()
        .filter(|c| !c.is_empty() && c.len() <= 2048)
        .ok_or_else(|| failed("the identity provider sent no code"))?;
    let provider = oidc
        .provider()
        .await
        .map_err(|e| provider_unavailable(&e))?;
    let claims = async {
        let id_token = oidc.exchange(&provider, code, &login.code_verifier).await?;
        oidc.verify(&provider, &id_token, &login.nonce).await
    }
    .await
    .map_err(|e| match e {
        OidcError::Provider(_) => provider_unavailable(&e),
        other => failed(&other.to_string()),
    })?;
    if !domain_allowed(&claims, &oidc.cfg.allowed_domains) {
        return Err(ApiError::permission_denied(
            "sign-in failed: your verified email address is not at a domain allowed to sign in",
        ));
    }
    let user = app
        .db
        .sign_in_user(&NewUser {
            issuer: &oidc.cfg.issuer,
            claims: &claims,
        })
        .await?;
    let (token, _) = app.db.create_session(user.id, app.cfg.session_ttl).await?;
    tracing::info!(user_id = user.id, member = %user.member, created = user.created, "signed in");
    let mut out = HeaderMap::new();
    out.append(
        header::SET_COOKIE,
        session::cookie(
            session::SESSION_COOKIE,
            &token,
            session::SESSION_COOKIE_PATH,
            Some(app.cfg.session_ttl),
            app.cfg.cookie_secure,
        ),
    );
    out.append(
        header::SET_COOKIE,
        session::clear_cookie(
            LOGIN_COOKIE,
            session::LOGIN_COOKIE_PATH,
            app.cfg.cookie_secure,
        ),
    );
    Ok(found(&login.return_to, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::json;

    struct Signer {
        pair: EcdsaKeyPair,
        kid: &'static str,
    }

    impl Signer {
        fn new(kid: &'static str) -> Signer {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Signer { pair, kid }
        }

        fn jwk(&self) -> Value {
            let p = self.pair.public_key().as_ref();
            json!({"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": self.kid,
                   "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..])})
        }

        fn sign_raw(&self, header: &Value, claims: &Value) -> String {
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

        fn sign(&self, claims: &Value) -> String {
            self.sign_raw(
                &json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"}),
                claims,
            )
        }
    }

    const NOW: i64 = 1_800_000_000;

    fn expected() -> Expected<'static> {
        Expected {
            issuer: "https://id.example.com",
            client_id: "relink",
            nonce: "n-0S6_WzA2Mj",
            now: NOW,
        }
    }

    fn claims() -> Value {
        json!({"iss": "https://id.example.com", "aud": "relink", "sub": "24400320",
               "exp": NOW + 300, "iat": NOW, "nonce": "n-0S6_WzA2Mj",
               "email": "ada@example.com", "email_verified": true, "name": "Ada"})
    }

    fn keys(signers: &[&Signer]) -> Jwks {
        let set = json!({"keys": signers.iter().map(|s| s.jwk()).collect::<Vec<_>>()});
        Jwks::parse(set.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn accepts_a_good_es256_token() {
        let s = Signer::new("k1");
        let got = verify_id_token(&s.sign(&claims()), &keys(&[&s]), &expected()).unwrap();
        assert_eq!(
            got,
            IdClaims {
                subject: "24400320".into(),
                email: Some("ada@example.com".into()),
                email_verified: true,
                name: Some("Ada".into()),
                preferred_username: None,
            }
        );
    }

    #[test]
    fn picks_the_key_by_kid_and_tries_all_without_one() {
        let (a, b) = (Signer::new("a"), Signer::new("b"));
        let set = keys(&[&a, &b]);
        assert!(verify_id_token(&b.sign(&claims()), &set, &expected()).is_ok());
        let no_kid = b.sign_raw(&json!({"alg": "ES256"}), &claims());
        assert!(verify_id_token(&no_kid, &set, &expected()).is_ok());
        // A kid we do not have is "unknown key" (refetch), not a bad signature.
        let c = Signer::new("c");
        assert_eq!(
            verify_id_token(&c.sign(&claims()), &set, &expected()),
            Err(IdTokenError::UnknownKey)
        );
        // Signed by c but claiming to be b.
        let forged = c.sign_raw(&json!({"alg": "ES256", "kid": "b"}), &claims());
        assert_eq!(
            verify_id_token(&forged, &set, &expected()),
            Err(IdTokenError::Signature)
        );
        assert_eq!(
            verify_id_token(&s_rs256_header(&a), &set, &expected()),
            Err(IdTokenError::UnknownKey),
            "an RS256 token cannot use an EC key"
        );
    }

    fn s_rs256_header(s: &Signer) -> String {
        s.sign_raw(&json!({"alg": "RS256", "kid": s.kid}), &claims())
    }

    #[test]
    fn refuses_other_algorithms() {
        let s = Signer::new("k1");
        let set = keys(&[&s]);
        for alg in ["none", "HS256", "ES384", "PS256", ""] {
            let t = s.sign_raw(&json!({"alg": alg, "kid": "k1"}), &claims());
            assert!(
                matches!(
                    verify_id_token(&t, &set, &expected()),
                    Err(IdTokenError::Algorithm(_))
                ),
                "{alg}"
            );
        }
        // An unsigned token in the classic shape.
        let unsigned = format!(
            "{}.{}.",
            b64url_encode(br#"{"alg":"none"}"#),
            b64url_encode(claims().to_string().as_bytes())
        );
        assert!(matches!(
            verify_id_token(&unsigned, &set, &expected()),
            Err(IdTokenError::Algorithm(_))
        ));
        let crit = s.sign_raw(&json!({"alg": "ES256", "crit": ["exp"]}), &claims());
        assert!(matches!(
            verify_id_token(&crit, &set, &expected()),
            Err(IdTokenError::Malformed(_))
        ));
    }

    #[test]
    fn refuses_a_tampered_payload() {
        let s = Signer::new("k1");
        let t = s.sign(&claims());
        let mut parts: Vec<&str> = t.split('.').collect();
        let mut evil = claims();
        evil["sub"] = json!("admin");
        let p = b64url_encode(evil.to_string().as_bytes());
        parts[1] = &p;
        assert_eq!(
            verify_id_token(&parts.join("."), &keys(&[&s]), &expected()),
            Err(IdTokenError::Signature)
        );
    }

    #[test]
    fn checks_every_claim() {
        let s = Signer::new("k1");
        let set = keys(&[&s]);
        let check = |edit: &dyn Fn(&mut Value)| {
            let mut c = claims();
            edit(&mut c);
            verify_id_token(&s.sign(&c), &set, &expected())
        };
        let refused =
            |edit: &dyn Fn(&mut Value)| matches!(check(edit), Err(IdTokenError::Claim(_)));
        assert!(refused(&|c| c["iss"] = json!("https://evil.example.com")));
        assert!(refused(&|c| c["iss"] = json!("https://id.example.com/")));
        assert!(refused(&|c| {
            c.as_object_mut().unwrap().remove("iss");
        }));
        assert!(refused(&|c| c["aud"] = json!("someone-else")));
        assert!(refused(&|c| {
            c.as_object_mut().unwrap().remove("aud");
        }));
        assert!(
            refused(&|c| c["aud"] = json!(["relink", "other"])),
            "azp needed"
        );
        assert!(
            check(&|c| {
                c["aud"] = json!(["relink", "other"]);
                c["azp"] = json!("relink");
            })
            .is_ok()
        );
        assert!(check(&|c| c["aud"] = json!(["relink"])).is_ok());
        assert!(refused(&|c| c["azp"] = json!("other")));
        assert!(refused(&|c| c["exp"] = json!(NOW - CLOCK_SKEW_S)));
        assert!(
            check(&|c| c["exp"] = json!(NOW - CLOCK_SKEW_S + 1)).is_ok(),
            "within skew"
        );
        assert!(refused(&|c| {
            c.as_object_mut().unwrap().remove("exp");
        }));
        assert!(refused(&|c| c["exp"] = json!("tomorrow")));
        assert!(check(&|c| c["exp"] = json!((NOW + 10) as f64 + 0.5)).is_ok());
        assert!(refused(&|c| c["iat"] = json!(NOW + CLOCK_SKEW_S + 1)));
        assert!(refused(&|c| {
            c.as_object_mut().unwrap().remove("iat");
        }));
        assert!(refused(&|c| c["nbf"] = json!(NOW + CLOCK_SKEW_S + 1)));
        assert!(check(&|c| c["nbf"] = json!(NOW)).is_ok());
        assert!(refused(&|c| c["nonce"] = json!("replayed")));
        assert!(refused(&|c| {
            c.as_object_mut().unwrap().remove("nonce");
        }));
        assert!(refused(&|c| c["sub"] = json!("")));
        assert!(refused(&|c| c["sub"] = json!("x".repeat(256))));
        assert!(refused(&|c| c["sub"] = json!(42)));
    }

    #[test]
    fn reads_optional_claims_leniently() {
        let s = Signer::new("k1");
        let set = keys(&[&s]);
        let get = |edit: &dyn Fn(&mut Value)| {
            let mut c = claims();
            edit(&mut c);
            verify_id_token(&s.sign(&c), &set, &expected()).unwrap()
        };
        assert!(get(&|c| c["email_verified"] = json!("true")).email_verified);
        assert!(!get(&|c| c["email_verified"] = json!("false")).email_verified);
        assert!(!get(&|c| c["email_verified"] = json!(false)).email_verified);
        assert!(
            !get(&|c| {
                c.as_object_mut().unwrap().remove("email_verified");
            })
            .email_verified
        );
        assert_eq!(get(&|c| c["email"] = json!("not-an-address")).email, None);
        assert_eq!(get(&|c| c["name"] = json!("bad\nname")).name, None);
        assert_eq!(get(&|c| c["name"] = json!(7)).name, None);
        assert_eq!(
            get(&|c| c["preferred_username"] = json!("ada.l")).preferred_username,
            Some("ada.l".into())
        );
    }

    #[test]
    fn refuses_malformed_tokens() {
        let s = Signer::new("k1");
        let set = keys(&[&s]);
        let good = s.sign(&claims());
        let malformed = |t: &str| {
            matches!(
                verify_id_token(t, &set, &expected()),
                Err(IdTokenError::Malformed(_))
            )
        };
        assert!(malformed(""));
        assert!(malformed("a.b"));
        assert!(malformed(&format!("{good}.extra")));
        assert!(malformed("!!.e30.e30"));
        assert!(malformed(&format!("{}.e30.sig", b64url_encode(b"[1]"))));
        assert!(malformed(&"a".repeat(MAX_ID_TOKEN + 1)));
        let bad_sig = format!("{}.+++", &good[..good.rfind('.').unwrap()]);
        assert!(malformed(&bad_sig));
        let kid_number = s.sign_raw(&json!({"alg": "ES256", "kid": 7}), &claims());
        assert!(malformed(&kid_number));
        // A signed payload that is not a JSON object.
        let msg = format!(
            "{}.{}",
            b64url_encode(br#"{"alg":"ES256"}"#),
            b64url_encode(b"[]")
        );
        let sig = s.pair.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
        assert!(malformed(&format!("{msg}.{}", b64url_encode(sig.as_ref()))));
    }

    #[test]
    fn verifies_rs256_against_a_known_signature() {
        // RFC 7515 appendix A.2: an RS256 JWS with its key. The payload is
        // not an ID token, so verification gets past the signature and then
        // stops at the first claim check.
        let jwk = json!({"keys": [{"kty": "RSA",
            "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e": "AQAB"}]});
        let set = Jwks::parse(jwk.to_string().as_bytes()).unwrap();
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        assert_eq!(
            verify_id_token(token, &set, &expected()),
            Err(IdTokenError::Claim("iss is not the configured issuer"))
        );
        let mut tampered = token.to_owned();
        let sig = token.rfind('.').unwrap() + 1;
        assert_eq!(&token[sig..sig + 1], "c");
        tampered.replace_range(sig..sig + 1, "d");
        assert_eq!(
            verify_id_token(&tampered, &set, &expected()),
            Err(IdTokenError::Signature)
        );
    }

    #[test]
    fn parses_key_sets() {
        let s = Signer::new("ec");
        let set = json!({"keys": [
            s.jwk(),
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "ps", "alg": "PS256", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "p384", "crv": "P-384", "x": "AA", "y": "AA"},
            {"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AA"},
            {"kty": "oct", "kid": "hmac", "k": "AA"},
            {"kty": "RSA", "kid": "rsa", "n": "AACrzQ", "e": "AAEAAQ"}
        ]});
        let parsed = Jwks::parse(set.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.0.len(), 2, "{parsed:?}");
        assert_eq!(
            parsed.0[1],
            Jwk::Rsa {
                kid: Some("rsa".into()),
                n: vec![0xab, 0xcd],
                e: vec![1, 0, 1]
            },
            "leading zeros are stripped"
        );
        for bad in [
            json!({"keys": [{"kty": "RSA", "e": "AQAB"}]}),
            json!({"keys": [{"kty": "RSA", "n": "AA", "e": "AQAB"}]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "!", "y": "AA"}]}),
            json!({"nokeys": []}),
            json!([1, 2]),
        ] {
            assert!(Jwks::parse(bad.to_string().as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn pkce_matches_rfc_7636() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let t = random_token();
        assert_eq!(t.len(), 43);
        assert_ne!(t, random_token());
    }

    #[test]
    fn return_paths_stay_on_this_server() {
        for ok in [
            "/",
            "/v1/auth/session",
            "/console?tab=links#top",
            "/a/b%2Fc",
        ] {
            assert_eq!(safe_return_to(ok), Some(ok));
        }
        for bad in [
            "",
            "https://evil.example.com/",
            "//evil.example.com",
            "/\\evil.example.com",
            "evil",
            "/a b",
            "/a\r\nSet-Cookie: x=y",
            "/é",
            &format!("/{}", "a".repeat(512)),
        ] {
            assert_eq!(safe_return_to(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn domains() {
        let mut c = IdClaims {
            subject: "1".into(),
            email: Some("ada@Example.COM".into()),
            email_verified: true,
            name: None,
            preferred_username: None,
        };
        let allowed = vec!["example.com".to_owned()];
        assert!(domain_allowed(&c, &[]));
        assert!(domain_allowed(&c, &allowed));
        assert!(!domain_allowed(&c, &["example.org".to_owned()]));
        c.email_verified = false;
        assert!(
            !domain_allowed(&c, &allowed),
            "only verified addresses count"
        );
        assert!(domain_allowed(&c, &[]));
        c.email_verified = true;
        c.email = None;
        assert!(!domain_allowed(&c, &allowed));
    }

    #[test]
    fn config_checks() {
        let good = OidcConfig {
            issuer: "https://id.example.com".into(),
            client_id: "relink".into(),
            client_secret: Some("s3cret".into()),
            redirect_url: "https://s.example.com/v1/auth/callback".into(),
            scopes: "openid email profile".into(),
            allowed_domains: vec![],
        };
        assert!(good.validate().is_ok());
        assert!(!format!("{good:?}").contains("s3cret"));
        let local = OidcConfig {
            issuer: "http://127.0.0.1:5556".into(),
            redirect_url: "http://localhost:8080/v1/auth/callback".into(),
            ..good.clone()
        };
        assert!(local.validate().is_ok());
        for bad in [
            OidcConfig {
                issuer: "http://id.example.com".into(),
                ..good.clone()
            },
            OidcConfig {
                issuer: "not a url".into(),
                ..good.clone()
            },
            OidcConfig {
                client_id: String::new(),
                ..good.clone()
            },
            OidcConfig {
                redirect_url: "http://s.example.com/cb".into(),
                ..good.clone()
            },
            OidcConfig {
                scopes: "email profile".into(),
                ..good.clone()
            },
            OidcConfig {
                scopes: "openid \"x\"".into(),
                ..good.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(is_loopback_http("http://[::1]:80/"));
        assert!(!is_loopback_http("https://localhost/"));
        assert!(!is_loopback_http("http://10.0.0.1/"));
    }

    #[test]
    fn provider_error_codes_are_sanitized() {
        assert_eq!(error_code("invalid_grant"), "invalid_grant");
        assert_eq!(error_code("<script>"), "script");
        assert_eq!(error_code("!!!"), "unknown_error");
        assert_eq!(error_code(&"a".repeat(100)).len(), 64);
    }
}

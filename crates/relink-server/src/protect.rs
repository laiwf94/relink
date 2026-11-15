//! Protected links at the origin: password hashing, the grant check on the
//! redirect path and the form the interstitial posts
//! (`relink_core::gate` has the pages and the cookie).
//!
//! Passwords are hashed with argon2id at 19 MiB, two passes and one lane
//! ([`PARAMS`], the OWASP baseline). Hashing is memory-hard on purpose, so
//! it runs on the blocking pool, at most [`MAX_HASHES`] at a time: the
//! memory it can take is bounded at `MAX_HASHES` × 19 MiB, whatever the
//! traffic, and the async workers never stall on it.
//!
//! Every password attempt takes one of the link's attempts for the hour
//! (`Db::password_attempt`) before it is checked, and a right password
//! gives it back, so a link's limit counts wrong passwords across every
//! instance and bounds the hashes an attacker can make the origin compute
//! for it. A link whose attempts are used up answers 429 without hashing.

use std::net::SocketAddr;
use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::metrics::Outcome;
use crate::model::Link;
use crate::redirect::{Located, locate, stopped, visit_settings};
use crate::rules::{Decision, evaluate};
use crate::server::App;
use crate::util::now_ms;
use relink_core::abtest::find_cookie;
use relink_core::gate::{GATE_CSP, Notice, form_field, gate_page, grant_cookie, grant_cookie_name};
use relink_core::site::HTML;

/// Hashes computed at once. Each takes 19 MiB while it runs.
pub const MAX_HASHES: usize = 2;

/// argon2id: 19 MiB, 2 passes, 1 lane, a 32-byte hash.
pub const PARAMS: (u32, u32, u32) = (19 * 1024, 2, 1);

/// Largest form body read.
pub const MAX_FORM_BYTES: usize = 4096;

/// The only body a protected link takes.
pub const FORM_TYPE: &str = "application/x-www-form-urlencoded";

fn argon2() -> Argon2<'static> {
    let (m, t, p) = PARAMS;
    let params = Params::new(m, t, p, None).expect("the parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// The hash could not be computed or the stored one would not parse.
#[derive(Debug)]
pub struct HashError(pub String);

/// Runs argon2 on the blocking pool, [`MAX_HASHES`] at a time.
pub struct Hasher {
    slots: Arc<Semaphore>,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher {
            slots: Arc::new(Semaphore::new(MAX_HASHES)),
        }
    }
}

impl Hasher {
    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, HashError> {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| HashError(e.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let out = f();
            drop(permit);
            out
        })
        .await
        .map_err(|e| HashError(e.to_string()))
    }

    /// `password`'s argon2id hash in PHC form, with a fresh random salt.
    pub async fn hash(&self, password: String) -> Result<String, HashError> {
        self.run(move || {
            argon2()
                .hash_password(password.as_bytes())
                .map(|h| h.to_string())
                .map_err(|e| HashError(e.to_string()))
        })
        .await?
    }

    /// Whether `password` matches `hash`. The hash's own parameters are
    /// used, so passwords hashed under older parameters keep working.
    pub async fn verify(&self, hash: String, password: String) -> Result<bool, HashError> {
        self.run(
            move || match argon2().verify_password(password.as_bytes(), hash.as_str()) {
                Ok(()) => Ok(true),
                Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
                Err(e) => Err(HashError(e.to_string())),
            },
        )
        .await?
    }
}

/// Whether the visitor holds a grant for `link` as it is protected now.
pub fn granted(app: &App, link: &Link, cookies: &[&[u8]]) -> bool {
    let name = grant_cookie_name(&link.code);
    find_cookie(cookies.iter().copied(), &name).is_some_and(|v| {
        app.signer
            .verify_grant(link.id, &link.protection, v, now_ms().div_euclid(1000))
    })
}

/// An interstitial or preview page: HTML that runs nothing, never cached.
pub fn html(status: StatusCode, body: String) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(HTML));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(GATE_CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// The interstitial for `link`, with `notice` about the last submission.
pub fn gate(link: &Link, notice: Option<Notice>) -> Response {
    let status = notice.map_or(StatusCode::OK, |n| {
        StatusCode::from_u16(n.status()).unwrap_or(StatusCode::BAD_REQUEST)
    });
    let mut resp = html(status, gate_page(&link.protection, notice));
    if let Some(Notice::Locked(secs)) = notice {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    }
    resp
}

fn plain(status: StatusCode, body: &'static str) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `POST /{code}` (and every other path that names a link): the form of a
/// protected link's interstitial.
pub async fn submit(
    State(app): State<Arc<App>>,
    uri: Uri,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let path = uri.path().strip_prefix('/').unwrap_or(uri.path());
    let (response, outcome) = answer(&app, path, uri.query(), &headers, peer.ip(), body).await;
    app.metrics.outcome(outcome);
    response
}

async fn answer(
    app: &App,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    body: Body,
) -> (Response, Outcome) {
    let found: Located<'_> = match locate(app, path, headers, peer).await {
        Ok(f) if f.preview => {
            return (
                plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n"),
                Outcome::NotFound,
            );
        }
        Ok(f) => f,
        Err(answer) => return answer,
    };
    let link = &found.link;
    let cookies: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let (visit, settings) = visit_settings(app, query, headers, peer, &cookies);
    // A disabled, expired or geo-blocked link answers as it would to a
    // GET: its form is not taken.
    match evaluate(link, &visit, &settings) {
        Decision::Redirect(_) => {}
        other => return stopped(other, found.pages(), path),
    }
    // Back to the same path and query, which now redirects.
    let back = match query {
        Some(q) => format!("/{path}?{q}"),
        None => format!("/{path}"),
    };
    if !link.is_protected() {
        return (see_other(&back, None), Outcome::GateAccepted);
    }
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case(FORM_TYPE));
    if !is_form {
        return (
            plain(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "expected an application/x-www-form-urlencoded form\n",
            ),
            Outcome::GateRejected,
        );
    }
    let Ok(form) = to_bytes(body, MAX_FORM_BYTES).await else {
        return (
            plain(StatusCode::PAYLOAD_TOO_LARGE, "form too large\n"),
            Outcome::GateRejected,
        );
    };
    let p = &link.protection;
    if p.consent.is_some() && form_field(&form, "consent").as_deref() != Some("yes") {
        return (gate(link, Some(Notice::NoConsent)), Outcome::GateRejected);
    }
    if let Some(hash) = &p.password_hash {
        let Some(password) = form_field(&form, "password").filter(|p| !p.is_empty()) else {
            return (
                gate(link, Some(Notice::WrongPassword)),
                Outcome::GateRejected,
            );
        };
        match app.db.password_attempt(link.id, p.attempt_limit()).await {
            Ok(None) => {}
            Ok(Some(wait)) => return (gate(link, Some(Notice::Locked(wait))), Outcome::GateLocked),
            Err(e) => {
                tracing::warn!(error = %e, "password attempt not recorded");
                return (unavailable(), Outcome::Unavailable);
            }
        }
        match app.hasher.verify(hash.clone(), password).await {
            Ok(true) => {
                if let Err(e) = app.db.password_refund(link.id).await {
                    tracing::warn!(error = %e, "password attempt not given back");
                }
            }
            Ok(false) => {
                return (
                    gate(link, Some(Notice::WrongPassword)),
                    Outcome::GateRejected,
                );
            }
            Err(e) => {
                tracing::error!(error = %e.0, code = %link.code, "stored password hash unusable");
                return (
                    plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n"),
                    Outcome::Unavailable,
                );
            }
        }
    }
    let secs = p.grant_secs();
    let value = app
        .signer
        .grant(link.id, p, now_ms().div_euclid(1000) + i64::from(secs));
    let cookie = grant_cookie(&link.code, &value, secs, app.cfg.cookie_secure);
    (see_other(&back, Some(cookie)), Outcome::GateAccepted)
}

fn unavailable() -> Response {
    let mut r = plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily unavailable, retry shortly\n",
    );
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    r
}

/// 303 to `location` on this host, never cached.
fn see_other(location: &str, cookie: Option<String>) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    let h = resp.headers_mut();
    // The path came in a request line, so it is a valid header value.
    if let Ok(v) = HeaderValue::from_str(location) {
        h.insert(header::LOCATION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(c) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        h.insert(header::SET_COOKIE, c);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_verify_and_differ() {
        let h = Hasher::default();
        let a = h.hash("correct horse".into()).await.unwrap();
        let b = h.hash("correct horse".into()).await.unwrap();
        assert!(a.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{a}");
        assert!(a.len() <= 256);
        // A fresh salt each time.
        assert_ne!(a, b);
        assert!(h.verify(a.clone(), "correct horse".into()).await.unwrap());
        assert!(!h.verify(a.clone(), "correct horsE".into()).await.unwrap());
        assert!(!h.verify(a, String::new()).await.unwrap());
        assert!(
            h.verify("$argon2id$nonsense".into(), "x".into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn at_most_max_hashes_run_at_once() {
        let h = Arc::new(Hasher::default());
        let hash = h.hash("pw".into()).await.unwrap();
        let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let (h, running, peak) = (h.clone(), running.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                h.run(move || {
                    use std::sync::atomic::Ordering::SeqCst;
                    let now = running.fetch_add(1, SeqCst) + 1;
                    peak.fetch_max(now, SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    running.fetch_sub(1, SeqCst);
                })
                .await
                .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let peak = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!((1..=MAX_HASHES).contains(&peak), "{peak}");
        assert!(h.verify(hash, "pw".into()).await.unwrap());
    }
}

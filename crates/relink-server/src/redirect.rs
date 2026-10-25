//! `GET /{code}` on the origin. The decision itself is
//! `relink_core::rules::evaluate`, shared with the edge worker; this module
//! adds what only the origin has: the cache, the click limiter and the click
//! queue.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::classify::{UNKNOWN_COUNTRY, country, device_class, referrer_host};
use crate::clicks::{ClickEvent, fingerprint};
use crate::code::is_plausible_code;
use crate::limiter::Admit;
use crate::metrics::Outcome;
use crate::model::Link;
use crate::resolver::Resolved;
use crate::rules::{Decision, Settings, Visit, evaluate};
use crate::server::App;
use crate::util::{fast_random, now_ms, utc_day};

pub async fn redirect(
    State(app): State<Arc<App>>,
    Path(code): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let start = Instant::now();
    let (response, outcome) = handle(&app, &code, &headers, peer.ip()).await;
    app.metrics.redirect_latency.observe(start.elapsed());
    app.metrics.outcome(outcome);
    response
}

fn plain(status: StatusCode, body: &'static str) -> Response {
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

fn unavailable() -> Response {
    let mut r = plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily unavailable, retry shortly\n",
    );
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    r
}

/// The country header, believed only from a trusted proxy.
pub fn visitor_country(app: &App, headers: &HeaderMap, peer: IpAddr) -> Option<[u8; 2]> {
    let name = app.cfg.country_header.as_ref()?;
    if !app.cfg.trusted_proxies.contains(peer) {
        return None;
    }
    country(headers.get(name).map(HeaderValue::as_bytes))
}

/// Evaluates a request. Separate from the handler so tests and benchmarks
/// can call it without a socket.
pub async fn handle(
    app: &App,
    code: &str,
    headers: &HeaderMap,
    peer: IpAddr,
) -> (Response, Outcome) {
    if !is_plausible_code(code) {
        return (
            plain(StatusCode::NOT_FOUND, "not found\n"),
            Outcome::NotFound,
        );
    }
    let link = match app.resolver.resolve(code).await {
        Resolved::Found(link) => link,
        Resolved::NotFound => {
            return (
                plain(StatusCode::NOT_FOUND, "not found\n"),
                Outcome::NotFound,
            );
        }
        Resolved::Unavailable => return (unavailable(), Outcome::Unavailable),
    };
    let country = visitor_country(app, headers, peer);
    let cookies: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let visit = Visit {
        now_ms: now_ms(),
        country,
        cookies: &cookies,
        random: fast_random(),
    };
    let settings = Settings {
        signer: &app.signer,
        cookie_secure: app.cfg.cookie_secure,
    };
    let redirect = match evaluate(&link, &visit, &settings) {
        Decision::NotFound => {
            return (
                plain(StatusCode::NOT_FOUND, "not found\n"),
                Outcome::NotFound,
            );
        }
        Decision::Expired => {
            return (
                plain(StatusCode::GONE, "this link has expired\n"),
                Outcome::Gone,
            );
        }
        Decision::GeoBlocked {
            fallback: Some(url),
        } => return (location(302, url, None, None), Outcome::GeoBlocked),
        Decision::GeoBlocked { fallback: None } => {
            return (
                plain(
                    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                    "this link is not available in your region\n",
                ),
                Outcome::GeoBlocked,
            );
        }
        Decision::Redirect(r) => r,
    };
    if redirect.needs_admission {
        match app.limiter.admit(link.id).await {
            Admit::Yes => {}
            Admit::LimitReached => {
                return (
                    plain(StatusCode::GONE, "this link has reached its click limit\n"),
                    Outcome::Gone,
                );
            }
            Admit::Unavailable => return (unavailable(), Outcome::Unavailable),
        }
    }
    record_click(app, &link, headers, peer, country);
    let cookie = redirect
        .set_cookie
        .as_deref()
        .and_then(|c| HeaderValue::from_str(c).ok());
    let cache = redirect.cacheable.then(|| app.cache_control.clone());
    let outcome = if redirect.fallback {
        Outcome::Fallback
    } else {
        Outcome::Redirect
    };
    (
        location(redirect.status, redirect.location, cache, cookie),
        outcome,
    )
}

/// A redirect response. Without a `Cache-Control` value it is `no-store`.
fn location(
    status: u16,
    url: &str,
    cache_control: Option<HeaderValue>,
    cookie: Option<HeaderValue>,
) -> Response {
    let Ok(loc) = HeaderValue::from_str(url) else {
        // Stored URLs are normalised ASCII; this would be a bug.
        tracing::error!("stored destination is not a valid header value");
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n");
    };
    let mut resp = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::FOUND)
        .into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, loc);
    h.insert(
        header::CACHE_CONTROL,
        cache_control.unwrap_or(HeaderValue::from_static("no-store")),
    );
    if let Some(c) = cookie {
        h.insert(header::SET_COOKIE, c);
    }
    resp
}

/// The client address: from the configured header when the peer is a
/// trusted proxy, otherwise the socket peer.
pub fn client_ip(app: &App, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let forwarded = app
        .cfg
        .client_ip_header
        .as_ref()
        .and_then(|h| headers.get(h))
        .and_then(|v| v.to_str().ok());
    app.cfg.trusted_proxies.client_ip(peer, forwarded)
}

fn record_click(
    app: &App,
    link: &Link,
    headers: &HeaderMap,
    peer: IpAddr,
    country: Option<[u8; 2]>,
) {
    let ua = headers.get(header::USER_AGENT).map(HeaderValue::as_bytes);
    let referrer = referrer_host(headers.get(header::REFERER).map(HeaderValue::as_bytes));
    app.clicks.record(ClickEvent {
        link_id: link.id,
        day: utc_day(now_ms()),
        country: country.unwrap_or(UNKNOWN_COUNTRY),
        device: device_class(ua),
        referrer: referrer.map(String::into_boxed_str),
        fingerprint: fingerprint(client_ip(app, headers, peer), ua.unwrap_or_default()),
    });
}

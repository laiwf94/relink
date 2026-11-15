//! `GET /{code}` on the origin. The decision itself is
//! `relink_core::rules::evaluate`, shared with the edge worker; this module
//! adds what only the origin has: routing by `Host` to a custom domain
//! (src/domains.rs), the cache, the click limiter and the click queue.
//!
//! On a custom domain the path is read by `relink_core::site::target`, as
//! at the edge: `/` is the domain's root redirect, `/{prefix}/{code}` a
//! code behind one of its prefixes, and codes are lowercased on a
//! case-insensitive domain. Its own 404 and 410 pages replace the built-in
//! ones. On the default domain nothing changes: `/` and two-segment paths
//! are unknown API paths, as before.
//!
//! `/{code}+` is the link's preview (`relink_core::gate::preview`), and a
//! protected link shows its password or consent page (src/protect.rs)
//! until the visitor holds a grant for it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::api::ApiError;
use crate::classify::{UNKNOWN_COUNTRY, country, device_class, referrer_host};
use crate::clicks::{ClickEvent, fingerprint};
use crate::domains::{Route, Site};
use crate::limiter::Admit;
use crate::metrics::Outcome;
use crate::model::Link;
use crate::protect;
use crate::resolver::Resolved;
use crate::rules::{Decision, Settings, Visit, evaluate};
use crate::server::App;
use crate::store::link_key;
use crate::util::{fast_random, now_ms, utc_day};
use relink_core::deeplink::{APP_FILE_CACHE, JSON, app_file};
use relink_core::gate::preview;
use relink_core::site::{
    DomainSettings, EXPIRED_TEXT, HTML, PAGE_CSP, PageKind, Target, page, target,
};

pub async fn redirect(
    State(app): State<Arc<App>>,
    uri: Uri,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let start = Instant::now();
    // The path as sent, still percent-encoded, as the edge sees it: codes
    // are plain ASCII, so an encoded path never names one.
    let path = uri.path().strip_prefix('/').unwrap_or(uri.path());
    let (response, outcome) = handle(&app, path, uri.query(), &headers, peer.ip()).await;
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

/// The region header (the subdivision code, `CA` for `US-CA`), believed
/// only from a trusted proxy.
pub fn visitor_region<'a>(app: &App, headers: &'a HeaderMap, peer: IpAddr) -> Option<&'a [u8]> {
    let name = app.cfg.region_header.as_ref()?;
    if !app.cfg.trusted_proxies.contains(peer) {
        return None;
    }
    headers.get(name).map(HeaderValue::as_bytes)
}

/// The public router's fallback: on a custom domain a GET or HEAD is read
/// as a redirect path (so it is answered as the edge would) and a POST as
/// a protected link's form; anything else is an unknown path.
pub async fn fallback(
    State(app): State<Arc<App>>,
    method: Method,
    uri: Uri,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let ConnectInfo(peer) = connect;
    let host = request_host(&app, &headers, peer.ip());
    // Only a custom domain gives these paths a meaning; elsewhere they are
    // not counted as redirects.
    let custom = !matches!(
        app.domains.route(host, &app.cfg.default_host),
        Route::Default
    );
    if custom && (method == Method::GET || method == Method::HEAD) {
        redirect(State(app), uri, connect, headers).await
    } else if custom && method == Method::POST {
        protect::submit(State(app), uri, connect, headers, body).await
    } else {
        ApiError::not_found().into_response()
    }
}

/// A 404 or 410 page: a custom domain's own when it has one. `site` is the
/// request's host header and the domain's settings.
fn error_page(
    kind: PageKind,
    site: Option<(Option<&[u8]>, &DomainSettings)>,
    path: &str,
    gone_text: &str,
) -> (Response, Outcome) {
    let outcome = match kind {
        PageKind::NotFound => Outcome::NotFound,
        PageKind::Gone => Outcome::Gone,
    };
    // The domain's lowercase hostname, worked out only for a page.
    let (host, settings) = match site {
        Some((h, s)) => (
            h.and_then(relink_core::host::host_part)
                .map(str::to_ascii_lowercase)
                .unwrap_or_default(),
            Some(s),
        ),
        None => (String::new(), None),
    };
    let p = page(kind, settings, &host, path, gone_text);
    let status = StatusCode::from_u16(p.status).unwrap_or(StatusCode::NOT_FOUND);
    let mut resp = (status, p.body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(p.content_type),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if p.content_type == HTML {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        );
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    (resp, outcome)
}

/// A request routed to a link.
pub struct Located<'h> {
    /// The request's host header, for the domain's pages.
    host: Option<&'h [u8]>,
    /// The custom domain, `None` on the default domain.
    site: Option<Arc<Site>>,
    pub link: Arc<Link>,
    /// The path is the link's preview, `/{code}+`.
    pub preview: bool,
}

impl Located<'_> {
    /// Where the link's error pages come from: the domain's settings.
    pub fn pages(&self) -> Option<(Option<&[u8]>, &DomainSettings)> {
        self.site.as_ref().map(|s| (self.host, &s.settings))
    }
}

/// Routes `path` (without the leading `/`, as sent) to a link: by `Host`
/// to a custom domain, then the code. Anything else (the domain's root,
/// an association file, an unknown code) is answered here.
pub async fn locate<'h>(
    app: &App,
    path: &str,
    headers: &'h HeaderMap,
    peer: IpAddr,
) -> Result<Located<'h>, (Response, Outcome)> {
    let host_header = request_host(app, headers, peer);
    let site = match app.domains.route(host_header, &app.cfg.default_host) {
        Route::Default => None,
        Route::Domain(site) => Some(site),
        Route::Unavailable => return Err((unavailable(), Outcome::Unavailable)),
    };
    let pages = site.as_ref().map(|s| (host_header, &s.settings));
    let (code, preview) = match (target(path, site.as_ref().map(|s| &s.settings)), &site) {
        (Target::Code(code), _) => (code, false),
        (Target::Preview(code), _) => (code, true),
        (Target::Root, Some(s)) => match &s.settings.root_url {
            Some(url) => return Err((location(302, url, None, None), Outcome::Root)),
            None => return Err(error_page(PageKind::NotFound, pages, path, EXPIRED_TEXT)),
        },
        (Target::Miss, Some(_)) => {
            return Err(error_page(PageKind::NotFound, pages, path, EXPIRED_TEXT));
        }
        (Target::AppFile(file), Some(s)) => match app_file(file, &s.settings.apps) {
            Some(body) => return Err((json_file(body), Outcome::AppFile)),
            None => return Err(error_page(PageKind::NotFound, pages, path, EXPIRED_TEXT)),
        },
        // The default domain: `/` and paths with a `/` were never
        // redirects, and are answered as unknown paths, as before.
        (_, None) if path.is_empty() || path.contains('/') => {
            return Err((ApiError::not_found().into_response(), Outcome::NotFound));
        }
        (_, None) => return Err(error_page(PageKind::NotFound, None, path, EXPIRED_TEXT)),
    };
    let key = site.as_ref().map(|s| link_key(Some(s.id), &code));
    let link = match app.resolver.resolve(key.as_deref().unwrap_or(&code)).await {
        Resolved::Found(link) => link,
        Resolved::NotFound => {
            return Err(error_page(PageKind::NotFound, pages, path, EXPIRED_TEXT));
        }
        Resolved::Unavailable => return Err((unavailable(), Outcome::Unavailable)),
    };
    Ok(Located {
        host: host_header,
        site,
        link,
        preview,
    })
}

/// The facts the decisions read from a request, and the cookie settings.
pub fn visit_settings<'a>(
    app: &'a App,
    query: Option<&'a str>,
    headers: &'a HeaderMap,
    peer: IpAddr,
    cookies: &'a [&'a [u8]],
) -> (Visit<'a>, Settings<'a>) {
    let raw = |name| headers.get(name).map(HeaderValue::as_bytes);
    let visit = Visit {
        now_ms: now_ms(),
        country: visitor_country(app, headers, peer),
        region: visitor_region(app, headers, peer),
        user_agent: raw(header::USER_AGENT),
        accept_language: raw(header::ACCEPT_LANGUAGE),
        referer: raw(header::REFERER),
        query: query.map(str::as_bytes),
        cookies,
        random: fast_random(),
    };
    let settings = Settings {
        signer: &app.signer,
        cookie_secure: app.cfg.cookie_secure,
    };
    (visit, settings)
}

/// The answer to a decision that is not a redirect.
pub fn stopped(
    decision: Decision<'_>,
    pages: Option<(Option<&[u8]>, &DomainSettings)>,
    path: &str,
) -> (Response, Outcome) {
    match decision {
        Decision::NotFound | Decision::Redirect(_) => {
            error_page(PageKind::NotFound, pages, path, EXPIRED_TEXT)
        }
        Decision::Expired => error_page(PageKind::Gone, pages, path, EXPIRED_TEXT),
        Decision::GeoBlocked {
            fallback: Some(url),
        } => (location(302, url, None, None), Outcome::GeoBlocked),
        Decision::GeoBlocked { fallback: None } => (
            plain(
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                "this link is not available in your region\n",
            ),
            Outcome::GeoBlocked,
        ),
    }
}

/// Evaluates a request for `path` (without the leading `/`, as sent) with
/// the query string `query` (without the `?`). Separate from the handler so
/// tests and benchmarks can call it without a socket.
pub async fn handle(
    app: &App,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    peer: IpAddr,
) -> (Response, Outcome) {
    let found = match locate(app, path, headers, peer).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let link = &found.link;
    let pages = found.pages();
    let cookies: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let (visit, settings) = visit_settings(app, query, headers, peer, &cookies);
    if found.preview {
        let own = path.strip_suffix('+').unwrap_or(path);
        return match preview(link, own, &visit, &settings) {
            Ok(page) => (protect::html(StatusCode::OK, page), Outcome::Preview),
            Err(decision) => stopped(decision, pages, path),
        };
    }
    let redirect = match evaluate(link, &visit, &settings) {
        Decision::Redirect(r) => r,
        other => return stopped(other, pages, path),
    };
    // Disabled, expired and geo-blocked links answered as they would
    // without protection; a protected one asks before it redirects.
    if link.is_protected() && !protect::granted(app, link, &cookies) {
        return (protect::gate(link, None), Outcome::Gate);
    }
    if redirect.needs_admission {
        match app.limiter.admit(link.id).await {
            Admit::Yes => {}
            Admit::LimitReached => {
                return error_page(PageKind::Gone, pages, path, LIMIT_TEXT);
            }
            Admit::Unavailable => return (unavailable(), Outcome::Unavailable),
        }
    }
    record_click(app, link, headers, peer, visit.country);
    let cookie = redirect
        .set_cookie
        .as_deref()
        .and_then(|c| HeaderValue::from_str(c).ok());
    let cache = redirect.cacheable.then(|| app.cache_control.clone());
    let outcome = if redirect.fallback {
        Outcome::Fallback
    } else if redirect.rule.is_some() {
        Outcome::Rule
    } else if redirect.app {
        Outcome::App
    } else {
        Outcome::Redirect
    };
    (
        location(redirect.status, redirect.location, cache, cookie),
        outcome,
    )
}

/// An app association file (`relink_core::deeplink::app_file`).
fn json_file(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(JSON)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(APP_FILE_CACHE),
            ),
        ],
        body,
    )
        .into_response()
}

/// Text of the built-in 410 page for a link at its click limit.
pub const LIMIT_TEXT: &str = "this link has reached its click limit\n";

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

/// The header a trusted proxy names the visitor's host in. The edge Worker
/// sends it, because a Worker cannot set `Host` on a fetch to the origin.
pub const FORWARDED_HOST: &str = "x-forwarded-host";

/// The host a redirect request is for: the first `x-forwarded-host` value
/// when the peer is a trusted proxy and sent one, otherwise `Host`.
pub fn request_host<'a>(app: &App, headers: &'a HeaderMap, peer: IpAddr) -> Option<&'a [u8]> {
    let forwarded = headers
        .get(FORWARDED_HOST)
        .filter(|_| app.cfg.trusted_proxies.contains(peer))
        .map(|v| {
            let raw = v.as_bytes();
            let first = raw.split(|&b| b == b',').next().unwrap_or(raw);
            first.trim_ascii()
        })
        .filter(|h| !h.is_empty());
    forwarded.or_else(|| headers.get(header::HOST).map(HeaderValue::as_bytes))
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

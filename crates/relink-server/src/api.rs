//! Management API: links CRUD and stats under `/v1`, plus the shared HTTP
//! plumbing (errors, strict JSON, request IDs, access logs).
//!
//! Errors are always `{"error":{"code","message","request_id"}}` with a
//! stable `code`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::body::{Body, Bytes};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::Instrument;

use relink_core::wire::{ClickBatch, MAX_BATCH, WireClick};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::{AuthError, Principal};
use crate::classify::{self, Device, UNKNOWN_COUNTRY};
use crate::clicks::ClickEvent;
use crate::code::validate_alias;
use crate::destination::normalize;
use crate::model::{Destination, GeoMode, GeoRule};
use crate::server::App;
use crate::store::{DbError, LinkPatch, NewLink, Stats, StoredLink};
use crate::util::{fast_random, hex_decode, hex_encode, now_ms, utc_day};

/// Largest accepted request body.
pub const MAX_BODY: usize = 64 * 1024;
/// Most destinations in one A/B split.
pub const MAX_DESTINATIONS: usize = 10;
/// Largest weight of one destination.
pub const MAX_WEIGHT: u32 = 1000;
/// Most countries in a geo rule (there are 249 ISO 3166-1 codes).
pub const MAX_COUNTRIES: usize = 300;
/// Largest max_clicks value.
pub const MAX_CLICKS_LIMIT: i64 = 1_000_000_000_000;
/// Furthest expiry accepted, in days from now.
pub const MAX_EXPIRY_DAYS: i64 = 3653;
/// Longest stats range, in days.
pub const MAX_STATS_DAYS: i64 = 366;
/// Page size bounds for listing.
pub const DEFAULT_PAGE: u32 = 50;
pub const MAX_PAGE: u32 = 100;

/// An API error with a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }
    pub fn invalid(message: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid_argument", message)
    }
    pub fn unauthenticated() -> ApiError {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "a valid API key is required: Authorization: Bearer rlk_...",
        )
    }
    pub fn not_found() -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such resource")
    }
    pub fn method_not_allowed() -> ApiError {
        ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method not allowed for this path",
        )
    }
    pub fn conflict(message: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::CONFLICT, "already_exists", message)
    }
    pub fn too_large() -> ApiError {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body is larger than {MAX_BODY} bytes"),
        )
    }
    pub fn unsupported_media_type() -> ApiError {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be application/json",
        )
    }
    pub fn rate_limited(retry_after_secs: u64) -> ApiError {
        ApiError {
            retry_after: Some(retry_after_secs),
            ..ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "resource_exhausted",
                "rate limit exceeded for this API key",
            )
        }
    }
    pub fn unavailable() -> ApiError {
        ApiError {
            retry_after: Some(5),
            ..ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "the database is unavailable; retry later",
            )
        }
    }
    pub fn internal() -> ApiError {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error; see the server log for this request ID",
        )
    }
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> ApiError {
        match e {
            DbError::NotFound => ApiError::not_found(),
            DbError::Conflict => ApiError::conflict("this alias is already taken"),
            DbError::Unavailable(detail) => {
                tracing::warn!(error = %detail, "database unavailable");
                ApiError::unavailable()
            }
            DbError::Other(detail) => {
                tracing::error!(error = %detail, "database error");
                ApiError::internal()
            }
        }
    }
}

/// Carried from a handler to the request middleware, which renders it with
/// the request ID.
#[derive(Clone, Debug)]
struct ErrorInfo {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = self.status.into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp.extensions_mut().insert(ErrorInfo {
            code: self.code,
            message: self.message,
        });
        resp
    }
}

/// A JSON response.
pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "response serialisation failed");
            ApiError::internal().into_response()
        }
    }
}

/// The request's ID, available to handlers as an extension.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Accepts a client-supplied request ID only if it is short and safe to log.
pub fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn new_request_id() -> String {
    hex_encode(&fast_random().to_be_bytes())
}

/// Assigns a request ID, renders API errors as JSON, sets `X-Request-Id` and
/// writes the access log. Redirects log at debug level so the hot path does
/// not pay for a log line per request.
pub async fn request_context(
    State(app): State<Arc<App>>,
    mut req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_request_id(v))
        .map_or_else(new_request_id, str::to_owned);
    req.extensions_mut().insert(RequestId(id.clone()));
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let is_api = path.starts_with("/v1/") || path == "/v1";
    let mut resp = if is_api {
        let span = tracing::info_span!("request", request_id = %id);
        next.run(req).instrument(span).await
    } else {
        let span = tracing::debug_span!("request", request_id = %id);
        next.run(req).instrument(span).await
    };
    let mut info = resp.extensions_mut().remove::<ErrorInfo>();
    if info.is_none() && (is_api || resp.status() == StatusCode::METHOD_NOT_ALLOWED) {
        // Rejections produced by axum itself (wrong method, undecodable path)
        // get the same JSON shape as our own errors.
        info = framework_error(resp.status());
    }
    if let Some(info) = info {
        let body = serde_json::json!({
            "error": {"code": info.code, "message": info.message, "request_id": id}
        });
        *resp.body_mut() = Body::from(body.to_string());
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp.headers_mut().remove(header::CONTENT_LENGTH);
    }
    if let Ok(v) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    let status = resp.status().as_u16();
    let elapsed = start.elapsed();
    if is_api {
        app.metrics.api_requests.inc();
        app.metrics.api_latency.observe(elapsed);
        if status >= 400 {
            app.metrics.api_errors.inc();
        }
        tracing::info!(request_id = %id, %method, %path, status, duration_us = elapsed.as_micros() as u64, "request");
    } else {
        tracing::debug!(request_id = %id, %method, %path, status, duration_us = elapsed.as_micros() as u64, "request");
    }
    resp
}

fn framework_error(status: StatusCode) -> Option<ErrorInfo> {
    let e = match status {
        StatusCode::METHOD_NOT_ALLOWED => ApiError::method_not_allowed(),
        StatusCode::NOT_FOUND => ApiError::not_found(),
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::too_large(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::unsupported_media_type(),
        s if s.is_client_error() => ApiError::invalid("the request could not be parsed"),
        s if s.is_server_error() => ApiError::internal(),
        _ => return None,
    };
    Some(ErrorInfo {
        code: e.code,
        message: e.message,
    })
}

/// Fallback for unknown paths.
pub async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// JSON body with a required `application/json` content type, the body
/// limit applied before parsing, unknown fields and trailing data rejected.
pub struct StrictJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for StrictJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(ApiError::unsupported_media_type());
        }
        let bytes = Bytes::from_request(req, state).await.map_err(|e| {
            if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::too_large()
            } else {
                ApiError::invalid("could not read the request body")
            }
        })?;
        serde_json::from_slice(&bytes)
            .map(StrictJson)
            .map_err(|e| ApiError::invalid(format!("invalid JSON body: {e}")))
    }
}

/// An authenticated, rate-limited caller.
pub struct Authed(pub Principal);

impl FromRequestParts<Arc<App>> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let header = parts
            .headers
            .get(header::AUTHORIZATION)
            .map(HeaderValue::as_bytes);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
        let client = crate::redirect::client_ip(app, &parts.headers, peer);
        let principal = app
            .auth
            .authenticate(header, client)
            .await
            .map_err(|e| match e {
                AuthError::Unauthenticated => ApiError::unauthenticated(),
                AuthError::Unavailable => ApiError::unavailable(),
                AuthError::Busy => ApiError::rate_limited(1),
            })?;
        if let Err(wait) = app.api_limiter.check(&principal.key_id, Instant::now()) {
            app.metrics.rate_limited.inc();
            return Err(ApiError::rate_limited(
                wait.as_secs_f64().ceil().max(1.0) as u64
            ));
        }
        Ok(Authed(principal))
    }
}

/// Query string with unknown parameters rejected.
pub struct StrictQuery<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for StrictQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| StrictQuery(v))
            .map_err(|e| ApiError::invalid(format!("invalid query string: {}", e.body_text())))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoInput {
    pub mode: GeoMode,
    pub countries: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLink {
    pub url: Option<String>,
    pub destinations: Option<Vec<Destination>>,
    pub alias: Option<String>,
    pub redirect_type: Option<u16>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_clicks: Option<i64>,
    pub geo: Option<GeoInput>,
    pub fallback_url: Option<String>,
    pub enabled: Option<bool>,
    pub health_check: Option<bool>,
}

/// Distinguishes "absent" (outer None) from "null" (Some(None)).
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchLink {
    pub url: Option<String>,
    pub destinations: Option<Vec<Destination>>,
    pub redirect_type: Option<u16>,
    #[serde(default, deserialize_with = "nullable")]
    pub expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(default, deserialize_with = "nullable")]
    pub max_clicks: Option<Option<i64>>,
    #[serde(default, deserialize_with = "nullable")]
    pub geo: Option<Option<GeoInput>>,
    #[serde(default, deserialize_with = "nullable")]
    pub fallback_url: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub health_check: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DestinationView {
    pub url: String,
    pub weight: u32,
    /// `null` when health checks are off for the link.
    pub healthy: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct GeoView {
    pub mode: GeoMode,
    pub countries: Vec<String>,
}

/// A link as returned by the API.
#[derive(Debug, Serialize)]
pub struct LinkView {
    pub code: String,
    pub short_url: String,
    pub destinations: Vec<DestinationView>,
    pub redirect_type: u16,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_clicks: Option<i64>,
    pub geo: Option<GeoView>,
    pub fallback_url: Option<String>,
    pub enabled: bool,
    pub health_check: bool,
    pub health_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LinkView {
    pub fn new(link: &StoredLink, base_url: &str) -> LinkView {
        LinkView {
            code: link.code.clone(),
            short_url: format!("{base_url}/{}", link.code),
            destinations: link
                .destinations
                .iter()
                .enumerate()
                .map(|(i, d)| DestinationView {
                    url: d.url.clone(),
                    weight: d.weight,
                    healthy: link.health_check.then(|| link.is_healthy(i)),
                })
                .collect(),
            redirect_type: link.redirect_status,
            expires_at: link.expires_at,
            max_clicks: link.max_clicks,
            geo: link.geo.as_ref().map(|g| GeoView {
                mode: g.mode,
                countries: g.country_strings(),
            }),
            fallback_url: link.fallback_url.clone(),
            enabled: link.enabled,
            health_check: link.health_check,
            health_checked_at: link.health_checked_at,
            created_at: link.created_at,
            updated_at: link.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct LinkList {
    links: Vec<LinkView>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsQuery {
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
}

#[derive(Debug, Serialize)]
struct StatsView {
    code: String,
    from: NaiveDate,
    to: NaiveDate,
    #[serde(flatten)]
    stats: Stats,
}

/// Encodes a list position (the last link ID on the page) as an opaque cursor.
pub fn encode_cursor(id: i64) -> String {
    hex_encode(&id.to_be_bytes())
}

/// Decodes a cursor; anything but 16 hex characters of a positive ID fails.
pub fn decode_cursor(s: &str) -> Option<i64> {
    if s.len() != 16 {
        return None;
    }
    let bytes: [u8; 8] = hex_decode(s)?.try_into().ok()?;
    let id = i64::from_be_bytes(bytes);
    (id > 0).then_some(id)
}

fn validate_destinations(
    app: &App,
    url: Option<String>,
    destinations: Option<Vec<Destination>>,
    required: bool,
) -> Result<Option<Vec<Destination>>, ApiError> {
    let list = match (url, destinations) {
        (Some(_), Some(_)) => {
            return Err(ApiError::invalid(
                "give either url or destinations, not both",
            ));
        }
        (Some(u), None) => vec![Destination { url: u, weight: 1 }],
        (None, Some(d)) => d,
        (None, None) if required => {
            return Err(ApiError::invalid("url or destinations is required"));
        }
        (None, None) => return Ok(None),
    };
    if list.is_empty() || list.len() > MAX_DESTINATIONS {
        return Err(ApiError::invalid(format!(
            "destinations must have 1 to {MAX_DESTINATIONS} entries"
        )));
    }
    let mut out = Vec::with_capacity(list.len());
    for (i, d) in list.into_iter().enumerate() {
        if d.weight == 0 || d.weight > MAX_WEIGHT {
            return Err(ApiError::invalid(format!(
                "destinations[{i}].weight must be 1 to {MAX_WEIGHT}"
            )));
        }
        let url = normalize(&d.url, app.cfg.destination_policy)
            .map_err(|e| ApiError::invalid(format!("destinations[{i}].url: {e}")))?;
        out.push(Destination {
            url,
            weight: d.weight,
        });
    }
    Ok(Some(out))
}

fn validate_status(s: u16) -> Result<u16, ApiError> {
    match s {
        301 | 302 | 307 | 308 => Ok(s),
        _ => Err(ApiError::invalid(
            "redirect_type must be 301, 302, 307 or 308",
        )),
    }
}

fn validate_expiry(t: DateTime<Utc>) -> Result<DateTime<Utc>, ApiError> {
    let now = Utc::now();
    if t <= now {
        return Err(ApiError::invalid("expires_at must be in the future"));
    }
    if t > now + ChronoDuration::days(MAX_EXPIRY_DAYS) {
        return Err(ApiError::invalid("expires_at must be within 10 years"));
    }
    Ok(t)
}

fn validate_max_clicks(n: i64) -> Result<i64, ApiError> {
    if (1..=MAX_CLICKS_LIMIT).contains(&n) {
        Ok(n)
    } else {
        Err(ApiError::invalid(format!(
            "max_clicks must be 1 to {MAX_CLICKS_LIMIT}"
        )))
    }
}

fn validate_geo(g: GeoInput) -> Result<GeoRule, ApiError> {
    if g.countries.is_empty() || g.countries.len() > MAX_COUNTRIES {
        return Err(ApiError::invalid(format!(
            "geo.countries must have 1 to {MAX_COUNTRIES} entries"
        )));
    }
    let mut countries: Vec<[u8; 2]> = Vec::with_capacity(g.countries.len());
    for (i, c) in g.countries.iter().enumerate() {
        let code: [u8; 2] = match c.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                [a.to_ascii_uppercase(), b.to_ascii_uppercase()]
            }
            _ => {
                return Err(ApiError::invalid(format!(
                    "geo.countries[{i}] must be a two-letter country code"
                )));
            }
        };
        if !countries.contains(&code) {
            countries.push(code);
        }
    }
    Ok(GeoRule {
        mode: g.mode,
        countries,
    })
}

fn validate_fallback(app: &App, url: String) -> Result<String, ApiError> {
    normalize(&url, app.cfg.destination_policy)
        .map_err(|e| ApiError::invalid(format!("fallback_url: {e}")))
}

pub async fn create_link(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    StrictJson(req): StrictJson<CreateLink>,
) -> Result<Response, ApiError> {
    if let Some(alias) = &req.alias {
        validate_alias(alias).map_err(|e| ApiError::invalid(format!("alias: {e}")))?;
    }
    let destinations = validate_destinations(&app, req.url, req.destinations, true)?
        .expect("required destinations are present");
    let new = NewLink {
        owner: principal.owner,
        alias: req.alias,
        destinations,
        redirect_status: validate_status(req.redirect_type.unwrap_or(302))?,
        expires_at: req.expires_at.map(validate_expiry).transpose()?,
        max_clicks: req.max_clicks.map(validate_max_clicks).transpose()?,
        geo: req.geo.map(validate_geo).transpose()?,
        fallback_url: req
            .fallback_url
            .map(|u| validate_fallback(&app, u))
            .transpose()?,
        enabled: req.enabled.unwrap_or(true),
        health_check: req.health_check.unwrap_or(false),
    };
    let link = app.db.insert_link(&new, app.cfg.code_length).await?;
    // The code may be cached as "not found" here; other instances hear
    // about it through the change notification sent with the insert.
    app.resolver.invalidate(&link.code);
    tracing::info!(code = %link.code, "link created");
    let mut resp = json(
        StatusCode::CREATED,
        &LinkView::new(&link, &app.cfg.public_base_url),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/links/{}", link.code)) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(resp)
}

pub async fn list_links(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    StrictQuery(q): StrictQuery<ListQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(ApiError::invalid(format!("limit must be 1 to {MAX_PAGE}")));
    }
    let before = match q.cursor.as_deref() {
        None => None,
        Some(c) => Some(decode_cursor(c).ok_or_else(|| ApiError::invalid("cursor is not valid"))?),
    };
    // One extra row tells whether another page exists.
    let mut links = app
        .db
        .list_links(&principal.owner, before, i64::from(limit) + 1)
        .await?;
    let next_cursor = if links.len() > limit as usize {
        links.truncate(limit as usize);
        links.last().map(|l| encode_cursor(l.id))
    } else {
        None
    };
    let body = LinkList {
        links: links
            .iter()
            .map(|l| LinkView::new(l, &app.cfg.public_base_url))
            .collect(),
        next_cursor,
    };
    Ok(json(StatusCode::OK, &body))
}

pub async fn get_link(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    Path(code): Path<String>,
) -> Result<Response, ApiError> {
    let link = app.db.owned_link(&principal.owner, &code).await?;
    Ok(json(
        StatusCode::OK,
        &LinkView::new(&link, &app.cfg.public_base_url),
    ))
}

pub async fn update_link(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    Path(code): Path<String>,
    StrictJson(req): StrictJson<PatchLink>,
) -> Result<Response, ApiError> {
    let patch = LinkPatch {
        destinations: validate_destinations(&app, req.url, req.destinations, false)?,
        redirect_status: req.redirect_type.map(validate_status).transpose()?,
        expires_at: req
            .expires_at
            .map(|e| e.map(validate_expiry).transpose())
            .transpose()?,
        max_clicks: req
            .max_clicks
            .map(|m| m.map(validate_max_clicks).transpose())
            .transpose()?,
        geo: req
            .geo
            .map(|g| g.map(validate_geo).transpose())
            .transpose()?,
        fallback_url: req
            .fallback_url
            .map(|f| f.map(|u| validate_fallback(&app, u)).transpose())
            .transpose()?,
        enabled: req.enabled,
        health_check: req.health_check,
    };
    let empty = patch.destinations.is_none()
        && patch.redirect_status.is_none()
        && patch.expires_at.is_none()
        && patch.max_clicks.is_none()
        && patch.geo.is_none()
        && patch.fallback_url.is_none()
        && patch.enabled.is_none()
        && patch.health_check.is_none();
    if empty {
        return Err(ApiError::invalid("the request changes nothing"));
    }
    let link = app.db.update_link(&principal.owner, &code, &patch).await?;
    app.resolver.invalidate(&link.code);
    app.limiter.invalidate(link.id).await;
    tracing::info!(code = %link.code, "link updated");
    Ok(json(
        StatusCode::OK,
        &LinkView::new(&link, &app.cfg.public_base_url),
    ))
}

pub async fn delete_link(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    Path(code): Path<String>,
) -> Result<Response, ApiError> {
    let id = app.db.delete_link(&principal.owner, &code).await?;
    app.resolver.invalidate(&code);
    app.limiter.invalidate(id).await;
    tracing::info!(code = %code, "link deleted");
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn link_stats(
    State(app): State<Arc<App>>,
    Authed(principal): Authed,
    Path(code): Path<String>,
    StrictQuery(q): StrictQuery<StatsQuery>,
) -> Result<Response, ApiError> {
    let to = q.to.unwrap_or_else(|| Utc::now().date_naive());
    let from = q.from.unwrap_or(to - ChronoDuration::days(29));
    if from > to {
        return Err(ApiError::invalid("from must not be after to"));
    }
    if (to - from).num_days() >= MAX_STATS_DAYS {
        return Err(ApiError::invalid(format!(
            "the range must be at most {MAX_STATS_DAYS} days"
        )));
    }
    let stats = app.db.stats(&principal.owner, &code, from, to).await?;
    Ok(json(
        StatusCode::OK,
        &StatsView {
            code,
            from,
            to,
            stats,
        },
    ))
}

/// Largest `POST /v1/edge/clicks` body (1,000 clicks of about 200 bytes).
pub const MAX_EDGE_BODY: usize = 256 * 1024;

/// Authenticates the edge worker by its shared token. The endpoint does not
/// exist (404) unless `RELINK_EDGE_TOKEN` is set.
pub struct EdgeAuthed;

impl FromRequestParts<Arc<App>> for EdgeAuthed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let Some(expected) = &app.cfg.edge_token else {
            return Err(ApiError::not_found());
        };
        let given = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        // Compare digests so the comparison is constant time whatever the lengths.
        let a = Sha256::digest(given.as_bytes());
        let b = Sha256::digest(expected.as_bytes());
        if bool::from(a.as_slice().ct_eq(b.as_slice())) {
            Ok(EdgeAuthed)
        } else {
            Err(ApiError::unauthenticated())
        }
    }
}

/// Checks one click reported by the edge and turns it into a queue event.
/// The edge is trusted to have measured honestly, not to send well-formed
/// data, so every field is checked as strictly as on the origin.
pub fn click_from_wire(w: &WireClick, today: i32) -> Result<ClickEvent, String> {
    if w.link_id <= 0 {
        return Err("link_id must be positive".into());
    }
    if (w.day - today).abs() > 1 {
        return Err("day must be within a day of today (UTC)".into());
    }
    let country = match w.country.as_bytes() {
        b"XX" => UNKNOWN_COUNTRY,
        c => classify::country(Some(c))
            .filter(|parsed| parsed == c)
            .ok_or("country must be two uppercase letters or XX")?,
    };
    let device = Device::parse(&w.device).ok_or("unknown device class")?;
    let referrer = match &w.referrer {
        None => None,
        Some(r) => {
            let parsed = classify::referrer_host(Some(format!("https://{r}/").as_bytes()));
            if parsed.as_deref() != Some(r.as_str()) {
                return Err("referrer must be a lowercase host name".into());
            }
            Some(r.clone().into_boxed_str())
        }
    };
    let fingerprint: [u8; 16] = hex_decode(&w.fingerprint)
        .and_then(|b| b.try_into().ok())
        .ok_or("fingerprint must be 32 hex characters")?;
    Ok(ClickEvent {
        link_id: w.link_id,
        day: w.day,
        country,
        device,
        referrer,
        fingerprint,
    })
}

pub async fn edge_clicks(
    State(app): State<Arc<App>>,
    _: EdgeAuthed,
    StrictJson(batch): StrictJson<ClickBatch>,
) -> Result<Response, ApiError> {
    if batch.clicks.len() > MAX_BATCH {
        return Err(ApiError::invalid(format!(
            "at most {MAX_BATCH} clicks per batch"
        )));
    }
    let today = utc_day(now_ms());
    let events = batch
        .clicks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            click_from_wire(c, today).map_err(|e| ApiError::invalid(format!("clicks[{i}]: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accepted = events.len();
    for ev in events {
        app.clicks.record(ev);
    }
    app.metrics.edge_clicks.add(accepted as u64);
    Ok(json(
        StatusCode::ACCEPTED,
        &serde_json::json!({ "accepted": accepted }),
    ))
}

pub async fn healthz() -> Response {
    json(StatusCode::OK, &serde_json::json!({"status": "ok"}))
}

/// Ready while not shutting down. Stays ready when the database is down,
/// because cached redirects are still served; the body says so.
pub async fn readyz(State(app): State<Arc<App>>) -> Response {
    if app.shutting_down.load(Ordering::Acquire) {
        return json(
            StatusCode::SERVICE_UNAVAILABLE,
            &serde_json::json!({"status": "shutting_down"}),
        );
    }
    let database =
        match tokio::time::timeout(std::time::Duration::from_secs(1), app.db.ping()).await {
            Ok(Ok(())) => "up",
            _ => "down",
        };
    json(
        StatusCode::OK,
        &serde_json::json!({"status": "ready", "database": database}),
    )
}

/// The OpenAPI 3.1 description of this API.
pub const OPENAPI: &str = include_str!("openapi.json");

pub async fn openapi() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        OPENAPI,
    )
        .into_response()
}

/// Every route on the public listener, as (method, OpenAPI path). The
/// OpenAPI test checks this list against the document and the router.
pub const ROUTES: &[(&str, &str)] = &[
    ("get", "/{code}"),
    ("get", "/healthz"),
    ("get", "/readyz"),
    ("get", "/openapi.json"),
    ("post", "/v1/links"),
    ("get", "/v1/links"),
    ("get", "/v1/links/{code}"),
    ("patch", "/v1/links/{code}"),
    ("delete", "/v1/links/{code}"),
    ("get", "/v1/links/{code}/stats"),
    ("post", "/v1/edge/clicks"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip() {
        for id in [1, 42, i64::MAX] {
            assert_eq!(decode_cursor(&encode_cursor(id)), Some(id));
        }
        assert_eq!(decode_cursor(&encode_cursor(0)), None);
        assert_eq!(decode_cursor(&encode_cursor(-5)), None);
        assert_eq!(decode_cursor("zz"), None);
        assert_eq!(decode_cursor("000000000000000g"), None);
        assert_eq!(decode_cursor(""), None);
    }

    #[test]
    fn framework_errors_map_to_codes() {
        let code = |s: u16| framework_error(StatusCode::from_u16(s).unwrap()).map(|i| i.code);
        assert_eq!(code(405), Some("method_not_allowed"));
        assert_eq!(code(404), Some("not_found"));
        assert_eq!(code(413), Some("payload_too_large"));
        assert_eq!(code(415), Some("unsupported_media_type"));
        assert_eq!(code(400), Some("invalid_argument"));
        assert_eq!(code(500), Some("internal"));
        assert_eq!(code(200), None);
        assert_eq!(code(204), None);
    }

    #[test]
    fn edge_clicks_are_validated() {
        let ok = WireClick {
            link_id: 3,
            day: 100,
            country: "DE".into(),
            device: "mobile".into(),
            referrer: Some("news.example.org".into()),
            fingerprint: "ab".repeat(16),
        };
        let ev = click_from_wire(&ok, 100).unwrap();
        assert_eq!(
            (ev.link_id, ev.country, ev.device),
            (3, *b"DE", Device::Mobile)
        );
        assert_eq!(ev.fingerprint, [0xab; 16]);
        assert!(
            click_from_wire(
                &WireClick {
                    country: "XX".into(),
                    referrer: None,
                    ..ok.clone()
                },
                101
            )
            .is_ok()
        );
        let bad = [
            WireClick {
                link_id: 0,
                ..ok.clone()
            },
            WireClick {
                day: 98,
                ..ok.clone()
            },
            WireClick {
                country: "de".into(),
                ..ok.clone()
            },
            WireClick {
                country: "DEU".into(),
                ..ok.clone()
            },
            WireClick {
                device: "phone".into(),
                ..ok.clone()
            },
            WireClick {
                referrer: Some("News.Example.org".into()),
                ..ok.clone()
            },
            WireClick {
                referrer: Some("a/b".into()),
                ..ok.clone()
            },
            WireClick {
                referrer: Some(String::new()),
                ..ok.clone()
            },
            WireClick {
                fingerprint: "ab".into(),
                ..ok.clone()
            },
            WireClick {
                fingerprint: "zz".repeat(16),
                ..ok.clone()
            },
        ];
        for b in bad {
            assert!(click_from_wire(&b, 100).is_err(), "{b:?}");
        }
    }

    #[test]
    fn request_ids() {
        assert!(valid_request_id("abc-123_x.y"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("a b"));
        assert!(!valid_request_id("<script>"));
        assert!(!valid_request_id(&"a".repeat(65)));
        assert_eq!(new_request_id().len(), 16);
    }

    #[test]
    fn patch_distinguishes_null_from_absent() {
        let p: PatchLink = serde_json::from_str(r#"{"expires_at":null,"enabled":false}"#).unwrap();
        assert_eq!(p.expires_at, Some(None));
        assert!(p.max_clicks.is_none());
        let p: PatchLink = serde_json::from_str(r#"{"max_clicks":5}"#).unwrap();
        assert_eq!(p.max_clicks, Some(Some(5)));
        assert!(serde_json::from_str::<PatchLink>(r#"{"nope":1}"#).is_err());
    }

    #[test]
    fn simple_validators() {
        for s in [301, 302, 307, 308] {
            assert_eq!(validate_status(s), Ok(s));
        }
        assert!(validate_status(303).is_err());
        assert!(validate_max_clicks(0).is_err());
        assert!(validate_max_clicks(MAX_CLICKS_LIMIT + 1).is_err());
        assert!(validate_expiry(Utc::now() - ChronoDuration::seconds(1)).is_err());
        assert!(validate_expiry(Utc::now() + ChronoDuration::days(MAX_EXPIRY_DAYS + 1)).is_err());
        assert!(validate_expiry(Utc::now() + ChronoDuration::days(1)).is_ok());
        let g = validate_geo(GeoInput {
            mode: GeoMode::Allow,
            countries: vec!["us".into(), "US".into(), "de".into()],
        })
        .unwrap();
        assert_eq!(g.countries, vec![*b"US", *b"DE"]);
        for bad in [vec![], vec!["USA".to_string()], vec!["1A".to_string()]] {
            assert!(
                validate_geo(GeoInput {
                    mode: GeoMode::Deny,
                    countries: bad
                })
                .is_err()
            );
        }
    }

    #[test]
    fn db_errors_map_to_api_errors() {
        assert_eq!(ApiError::from(DbError::NotFound).code, "not_found");
        assert_eq!(ApiError::from(DbError::Conflict).code, "already_exists");
        assert_eq!(
            ApiError::from(DbError::Unavailable("x".into())).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(ApiError::from(DbError::Other("x".into())).code, "internal");
    }
}

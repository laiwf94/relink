//! Webhooks: signed HTTP callbacks for what happens to a workspace's links
//! (migration 0022, docs/DESIGN.md "Webhooks").
//!
//! A workspace admin registers an endpoint with `POST /v1/webhooks`, naming
//! the [`Event`]s it wants, and gets its signing secret once. Events:
//!
//! - `link.created`, `link.updated`: written by [`emit`] inside the
//!   transaction that makes the change ([`crate::tenant::Tenant`]), so
//!   scheduled changes and rollbacks are covered too, and a change that
//!   rolls back sends nothing;
//! - `link.expired`: a link's `expires_at` passed. The worker finds such
//!   links with [`Db::announce_expiries`] and announces each expiry once,
//!   in the transaction that marks it announced;
//! - `health.changed`: a destination became healthy or unhealthy, written
//!   with the health result ([`Db::record_health`]).
//!
//! Delivery is at least once. Each event becomes one row per subscribed
//! endpoint in `webhook_deliveries`. [`WebhookWorker`] claims due rows with
//! `SKIP LOCKED` (so instances share the work), moving each one's due time
//! past the request timeout first: a worker that dies mid-request leaves
//! the row to be claimed again. A 2xx answer marks the delivery delivered;
//! anything else schedules a retry after an exponentially growing, jittered
//! delay ([`backoff`]) until `max_attempts`, after which it is failed and
//! can be retried by hand. Every try is kept in `webhook_attempts`: that and
//! the delivery rows are the delivery log, read through the API.
//!
//! Each request carries `Relink-Signature: t=<unix seconds>,v1=<hex>`, an
//! HMAC-SHA256 under the endpoint's secret of `<t>.<body>` ([`sign`]), and
//! `Relink-Event-Id`, the same on every retry and for every endpoint, so a
//! receiver can check the sender, refuse old replays and drop duplicates
//! ([`verify`] is the check). The body is the stored payload, byte for byte
//! the same on every try.
//!
//! Requests go to a URL a workspace chose, so they follow the health
//! checker's SSRF rules (src/health.rs): https only, public hosts only, the
//! resolver drops non-public addresses, redirects are not followed and no
//! proxy is used. Only the first 512 bytes of a response are read.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::api::{ApiError, LinkView, StrictJson, StrictQuery, decode_cursor, encode_cursor, json};
use crate::audit::{self, Action, Change};
use crate::auth::Role;
use crate::config::WebhookConfig;
use crate::destination::{Policy, normalize};
use crate::health::{SafeResolver, blocked_literal, is_blocked};
use crate::metrics::{DbOp, Metrics};
use crate::server::App;
use crate::store::{Db, DbError, StoredLink, api_columns, columns};
use crate::tenant::{Allowed, LinksRead, LinksWrite, Tenant};
use crate::util::{fast_random, hex_decode, hex_encode, secure_random, stopped};

/// Most endpoints one workspace may register.
pub const MAX_WEBHOOKS: i64 = 50;

/// The longest description of an endpoint, in characters.
pub const MAX_DESCRIPTION: usize = 200;

/// Response bytes kept in the delivery log.
pub const MAX_RESPONSE: usize = 512;

/// Characters of an error kept in the delivery log.
const MAX_ERROR: usize = 300;

/// Links whose expiry one sweep announces.
const EXPIRY_BATCH: i64 = 500;

/// Deliveries one purge deletes.
const PURGE_BATCH: i64 = 10_000;

/// How often finished deliveries past the retention are purged.
const PURGE_EVERY: Duration = Duration::from_secs(60);

/// Header with the signature.
pub const SIGNATURE_HEADER: &str = "relink-signature";
/// Header with the event's ID, the same on every retry.
pub const EVENT_ID_HEADER: &str = "relink-event-id";
/// Header with the event's type.
pub const EVENT_HEADER: &str = "relink-event";
/// Header with the delivery's ID, as the delivery log shows it.
pub const DELIVERY_HEADER: &str = "relink-delivery";

type HmacSha256 = Hmac<Sha256>;

/// What an endpoint can subscribe to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Event {
    LinkCreated,
    LinkUpdated,
    LinkExpired,
    HealthChanged,
}

impl Event {
    pub const ALL: [Event; 4] = [
        Event::LinkCreated,
        Event::LinkUpdated,
        Event::LinkExpired,
        Event::HealthChanged,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Event::LinkCreated => "link.created",
            Event::LinkUpdated => "link.updated",
            Event::LinkExpired => "link.expired",
            Event::HealthChanged => "health.changed",
        }
    }

    pub fn parse(s: &str) -> Option<Event> {
        Event::ALL.into_iter().find(|e| e.as_str() == s)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses a list of event names into a sorted set without duplicates; an
/// empty list or an unknown name is refused.
pub fn parse_events(names: &[String]) -> Result<Vec<Event>, String> {
    if names.is_empty() {
        return Err("events must name at least one event".into());
    }
    let mut events = Vec::with_capacity(names.len());
    for n in names {
        let e = Event::parse(n.trim()).ok_or_else(|| {
            format!(
                "events: unknown event {n:?}; known events are {}",
                Event::ALL.map(Event::as_str).join(", ")
            )
        })?;
        events.push(e);
    }
    events.sort();
    events.dedup();
    Ok(events)
}

fn event_names(events: &[Event]) -> Vec<&'static str> {
    events.iter().map(|e| e.as_str()).collect()
}

/// A new signing secret: `whsec_` and 32 random bytes in hex. The whole
/// string, as shown, is the HMAC key.
pub fn generate_secret() -> String {
    let mut b = [0u8; 32];
    secure_random(&mut b);
    format!("whsec_{}", hex_encode(&b))
}

/// A new event ID: `evt_` and 16 random bytes in hex.
pub fn generate_event_id() -> String {
    let mut b = [0u8; 16];
    secure_random(&mut b);
    format!("evt_{}", hex_encode(&b))
}

fn mac(secret: &str, timestamp: i64, body: &[u8]) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

/// The `Relink-Signature` header for `body` sent at `timestamp` (Unix
/// seconds): `t=<timestamp>,v1=<hex HMAC-SHA256 of "<timestamp>.<body>">`.
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let tag = mac(secret, timestamp, body).finalize().into_bytes();
    format!("t={timestamp},v1={}", hex_encode(&tag))
}

/// Why [`verify`] refused a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Not `t=...,v1=...`.
    Malformed,
    /// Signed longer ago (or further ahead) than the tolerance.
    Stale,
    /// No `v1` value matches.
    Mismatch,
}

/// Checks a `Relink-Signature` header as a receiver should: the timestamp
/// within `tolerance` of `now` (Unix seconds), and one of its `v1` values
/// the HMAC of `<t>.<body>`, compared in constant time.
pub fn verify(
    secret: &str,
    header: &str,
    body: &[u8],
    now: i64,
    tolerance: Duration,
) -> Result<(), VerifyError> {
    let mut timestamp = None;
    let mut tags = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => {
                timestamp = Some(v.parse::<i64>().map_err(|_| VerifyError::Malformed)?)
            }
            Some(("v1", v)) => tags.push(hex_decode(v).ok_or(VerifyError::Malformed)?),
            Some(_) => {}
            None => return Err(VerifyError::Malformed),
        }
    }
    let t = timestamp.ok_or(VerifyError::Malformed)?;
    if tags.is_empty() {
        return Err(VerifyError::Malformed);
    }
    if now.abs_diff(t) > tolerance.as_secs() {
        return Err(VerifyError::Stale);
    }
    let expected = mac(secret, t, body);
    if tags
        .iter()
        .any(|tag| expected.clone().verify_slice(tag).is_ok())
    {
        Ok(())
    } else {
        Err(VerifyError::Mismatch)
    }
}

/// The wait before try `failures + 1`, after `failures` (at least 1) failed
/// tries: `base * 2^(failures - 1)`, at most `max`, then scaled by a factor
/// in [0.5, 1) from `random` so endpoints that failed together do not
/// retry together.
pub fn backoff(failures: u32, base: Duration, max: Duration, random: u64) -> Duration {
    let exp = failures.saturating_sub(1).min(40);
    let full = base.saturating_mul(1u32 << exp.min(31)).min(max);
    let full = if exp > 31 { max } else { full };
    // Half the delay, plus that half times 32 random bits over 2^32: in
    // integers, so the top stays below the full delay.
    let half = full.as_nanos() / 2;
    let extra = (half * u128::from(random >> 32)) >> 32;
    Duration::from_nanos(u64::try_from(half + extra).unwrap_or(u64::MAX))
}

/// Writes `event` with `data` for every enabled endpoint of `workspace_id`
/// that subscribes to it, inside `tx`, and returns how many deliveries were
/// queued. In a tenant transaction row-level security keeps it to that
/// workspace; system work (the health worker, the expiry sweep) passes the
/// link's own.
pub async fn emit(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: i64,
    event: Event,
    data: Value,
) -> Result<u64, sqlx::Error> {
    let id = generate_event_id();
    let payload = json!({
        "id": id,
        "type": event.as_str(),
        "created_at": Utc::now(),
        "workspace_id": workspace_id,
        "data": data,
    });
    let done = sqlx::query(
        "INSERT INTO webhook_deliveries (webhook_id, workspace_id, event_id, event, payload) \
         SELECT id, workspace_id, $2, $3, $4 FROM webhooks \
          WHERE workspace_id = $1 AND enabled AND $3 = ANY (events)",
    )
    .bind(workspace_id)
    .bind(&id)
    .bind(event.as_str())
    .bind(&payload)
    .execute(&mut **tx)
    .await?;
    Ok(done.rows_affected())
}

/// `link.created` data.
pub fn link_created(link: &StoredLink, base_url: &str) -> Value {
    json!({ "link": LinkView::new(link, base_url) })
}

/// Fields of a link view that change without anyone changing the link.
const BOOKKEEPING: [&str; 3] = ["updated_at", "version", "health_checked_at"];

/// `link.updated` data: the link now, the fields that changed and their
/// previous values; `None` when nothing a client sees changed.
pub fn link_updated(before: &StoredLink, after: &StoredLink, base_url: &str) -> Option<Value> {
    let old = serde_json::to_value(LinkView::new(before, base_url)).ok()?;
    let new = serde_json::to_value(LinkView::new(after, base_url)).ok()?;
    let (Value::Object(old), Value::Object(new_map)) = (old, &new) else {
        return None;
    };
    let mut changed = Vec::new();
    let mut previous = Map::new();
    for (k, v) in new_map {
        if BOOKKEEPING.contains(&k.as_str()) {
            continue;
        }
        let was = old.get(k).cloned().unwrap_or(Value::Null);
        if &was != v {
            changed.push(Value::String(k.clone()));
            previous.insert(k.clone(), was);
        }
    }
    if changed.is_empty() {
        return None;
    }
    Some(json!({ "link": new, "changed": changed, "previous": previous }))
}

/// `link.expired` data.
pub fn link_expired(link: &StoredLink, base_url: &str) -> Value {
    json!({ "link": LinkView::new(link, base_url) })
}

/// `health.changed` data: the link with its destinations' health now, and
/// the destinations whose health flipped.
pub fn health_changed(link: &StoredLink, flipped: &[usize], base_url: &str) -> Value {
    let changes: Vec<Value> = flipped
        .iter()
        .filter_map(|&i| {
            link.destinations
                .get(i)
                .map(|d| json!({ "index": i, "url": d.url, "healthy": link.is_healthy(i) }))
        })
        .collect();
    json!({ "link": LinkView::new(link, base_url), "destinations": changes })
}

// Endpoints as stored.

/// An endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    pub id: i64,
    pub url: String,
    pub secret: String,
    pub events: Vec<Event>,
    pub description: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! webhook_columns {
    () => {
        "id, url, secret, events, description, enabled, created_by, created_at, updated_at"
    };
}

fn row_to_webhook(r: &PgRow) -> Result<Webhook, sqlx::Error> {
    let names: Vec<String> = r.try_get("events")?;
    Ok(Webhook {
        id: r.try_get("id")?,
        url: r.try_get("url")?,
        secret: r.try_get("secret")?,
        // Written only by the server from known names; an unknown one
        // (from a newer version) is skipped rather than failing the read.
        events: names.iter().filter_map(|n| Event::parse(n)).collect(),
        description: r.try_get("description")?,
        enabled: r.try_get("enabled")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// An endpoint as the audit log shows it; never its secret.
pub fn webhook_state(w: &Webhook) -> Value {
    json!({
        "id": w.id,
        "url": w.url,
        "events": event_names(&w.events),
        "description": w.description,
        "enabled": w.enabled,
    })
}

/// Validates an endpoint URL: a destination by the usual rules, and https
/// unless private destinations are allowed (development).
pub fn parse_webhook_url(raw: &str, policy: Policy) -> Result<String, String> {
    let url = normalize(raw, policy).map_err(|e| format!("url: {e}"))?;
    if !policy.allow_private && !url.starts_with("https://") {
        return Err("url: webhook endpoints must use https".into());
    }
    Ok(url)
}

/// A change to an endpoint, already validated.
#[derive(Clone, Debug, Default)]
pub struct WebhookPatch {
    pub url: Option<String>,
    pub events: Option<Vec<Event>>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub rotate_secret: bool,
}

/// A delivery as the log shows it.
#[derive(Clone, Debug, Serialize)]
pub struct Delivery {
    pub id: i64,
    pub event_id: String,
    pub event: String,
    pub state: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    /// When a pending delivery is next tried; `null` once finished.
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub last_status: Option<i16>,
    pub last_error: Option<String>,
}

/// One try of a delivery.
#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub attempt: i32,
    pub at: DateTime<Utc>,
    pub status: Option<i16>,
    pub duration_ms: i32,
    pub error: Option<String>,
    pub response: Option<String>,
}

macro_rules! delivery_columns {
    () => {
        "id, event_id, event, state, attempts, created_at, \
         CASE WHEN state = 'pending' THEN next_attempt_at END AS next_attempt_at, \
         delivered_at, last_status, last_error"
    };
}

fn row_to_delivery(r: &PgRow) -> Result<Delivery, sqlx::Error> {
    Ok(Delivery {
        id: r.try_get("id")?,
        event_id: r.try_get("event_id")?,
        event: r.try_get("event")?,
        state: r.try_get("state")?,
        attempts: r.try_get("attempts")?,
        created_at: r.try_get("created_at")?,
        next_attempt_at: r.try_get("next_attempt_at")?,
        delivered_at: r.try_get("delivered_at")?,
        last_status: r.try_get("last_status")?,
        last_error: r.try_get("last_error")?,
    })
}

/// The states a delivery can be in, for `?state=`.
pub const STATES: [&str; 3] = ["pending", "delivered", "failed"];

impl Tenant<'_> {
    /// Registers an endpoint with a fresh secret, if the workspace has fewer
    /// than [`MAX_WEBHOOKS`]. The workspace row is locked first, so
    /// concurrent requests cannot both take the last slot.
    pub async fn create_webhook(
        &self,
        url: &str,
        events: &[Event],
        description: &str,
        enabled: bool,
        created_by: &str,
    ) -> Result<Webhook, DbError> {
        let secret = generate_secret();
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                sqlx::query("SELECT 1 FROM workspaces FOR NO KEY UPDATE")
                    .execute(&mut *tx)
                    .await?;
                let n: i64 = sqlx::query_scalar("SELECT count(*) FROM webhooks")
                    .fetch_one(&mut *tx)
                    .await?;
                if n >= MAX_WEBHOOKS {
                    return Ok(Err(DbError::Precondition(format!(
                        "a workspace can have at most {MAX_WEBHOOKS} webhooks"
                    ))));
                }
                let row = sqlx::query(concat!(
                    "INSERT INTO webhooks (url, secret, events, description, enabled, created_by) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING ",
                    webhook_columns!()
                ))
                .bind(url)
                .bind(&secret)
                .bind(event_names(events))
                .bind(description)
                .bind(enabled)
                .bind(created_by)
                .fetch_one(&mut *tx)
                .await?;
                let hook = row_to_webhook(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::WebhookCreate,
                    target: format!("webhook:{}", hook.id),
                    before: None,
                    after: Some(webhook_state(&hook)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(hook))
            })
            .await?
    }

    /// This workspace's endpoints, oldest first.
    pub async fn webhooks(&self) -> Result<Vec<Webhook>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    webhook_columns!(),
                    " FROM webhooks ORDER BY id"
                ))
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_webhook)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// One endpoint of this workspace.
    pub async fn webhook(&self, id: i64) -> Result<Webhook, DbError> {
        let row = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    webhook_columns!(),
                    " FROM webhooks WHERE id = $1"
                ))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(row)
            })
            .await?
            .ok_or(DbError::NotFound)?;
        row_to_webhook(&row).map_err(DbError::from)
    }

    /// Applies `patch` to an endpoint. Disabling one fails its pending
    /// deliveries (they can be retried once it is enabled again), so a
    /// paused endpoint does not pile up work for the worker.
    pub async fn update_webhook(&self, id: i64, patch: &WebhookPatch) -> Result<Webhook, DbError> {
        let secret = patch.rotate_secret.then(generate_secret);
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    webhook_columns!(),
                    " FROM webhooks WHERE id = $1 FOR UPDATE"
                ))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let before = row_to_webhook(&row)?;
                let events = patch.events.as_deref().unwrap_or(&before.events);
                let row = sqlx::query(concat!(
                    "UPDATE webhooks SET url = $2, events = $3, description = $4, enabled = $5, \
                     secret = COALESCE($6, secret), updated_at = now() \
                     WHERE id = $1 RETURNING ",
                    webhook_columns!()
                ))
                .bind(id)
                .bind(patch.url.as_deref().unwrap_or(&before.url))
                .bind(event_names(events))
                .bind(patch.description.as_deref().unwrap_or(&before.description))
                .bind(patch.enabled.unwrap_or(before.enabled))
                .bind(secret.as_deref())
                .fetch_one(&mut *tx)
                .await?;
                let after = row_to_webhook(&row)?;
                if before.enabled && !after.enabled {
                    sqlx::query(
                        "UPDATE webhook_deliveries SET state = 'failed', \
                         last_error = 'the endpoint was disabled' \
                         WHERE webhook_id = $1 AND state = 'pending'",
                    )
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                }
                let mut after_state = webhook_state(&after);
                if patch.rotate_secret
                    && let Value::Object(m) = &mut after_state
                {
                    m.insert("secret_rotated".into(), Value::Bool(true));
                }
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::WebhookUpdate,
                    target: format!("webhook:{id}"),
                    before: Some(webhook_state(&before)),
                    after: Some(after_state),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(after)
            })
            .await
    }

    /// Deletes an endpoint and its delivery log.
    pub async fn delete_webhook(&self, id: i64) -> Result<Webhook, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "DELETE FROM webhooks WHERE id = $1 RETURNING ",
                    webhook_columns!()
                ))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let hook = row_to_webhook(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::WebhookDelete,
                    target: format!("webhook:{id}"),
                    before: Some(webhook_state(&hook)),
                    after: None,
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(hook)
            })
            .await
    }

    /// An endpoint's deliveries, newest first, before the cursor (a
    /// delivery ID), optionally only those in `state`.
    pub async fn deliveries(
        &self,
        webhook_id: i64,
        state: Option<&str>,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Delivery>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let exists: Option<i64> =
                    sqlx::query_scalar("SELECT id FROM webhooks WHERE id = $1")
                        .bind(webhook_id)
                        .fetch_optional(&mut *tx)
                        .await?;
                if exists.is_none() {
                    return Err(sqlx::Error::RowNotFound);
                }
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    delivery_columns!(),
                    " FROM webhook_deliveries \
                     WHERE webhook_id = $1 AND ($2::text IS NULL OR state = $2) \
                       AND ($3::bigint IS NULL OR id < $3) \
                     ORDER BY id DESC LIMIT $4"
                ))
                .bind(webhook_id)
                .bind(state)
                .bind(before_id)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_delivery)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// One delivery of an endpoint, with the payload sent and every try.
    pub async fn delivery(
        &self,
        webhook_id: i64,
        id: i64,
    ) -> Result<(Delivery, Value, Vec<Attempt>), DbError> {
        let (row, attempts) = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    delivery_columns!(),
                    ", payload FROM webhook_deliveries \
                     WHERE webhook_id = $1 AND id = $2"
                ))
                .bind(webhook_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let attempts = sqlx::query(
                    "SELECT attempt, at, status, duration_ms, error, response \
                     FROM webhook_attempts WHERE delivery_id = $1 ORDER BY attempt",
                )
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok((row, attempts))
            })
            .await?;
        let delivery = row_to_delivery(&row)?;
        let payload: Value = row.try_get("payload").map_err(DbError::from)?;
        let attempts = attempts
            .iter()
            .map(|r| {
                Ok(Attempt {
                    attempt: r.try_get("attempt")?,
                    at: r.try_get("at")?,
                    status: r.try_get("status")?,
                    duration_ms: r.try_get("duration_ms")?,
                    error: r.try_get("error")?,
                    response: r.try_get("response")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        Ok((delivery, payload, attempts))
    }

    /// Makes a delivery due now: a failed one gets one more try (and
    /// further retries only if it has tries left), a pending one is
    /// brought forward. A delivered one, or one of a disabled endpoint, is
    /// `Precondition`.
    pub async fn retry_delivery(&self, webhook_id: i64, id: i64) -> Result<Delivery, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row: Option<(String, bool)> = sqlx::query_as(
                    "SELECT d.state, w.enabled FROM webhook_deliveries d \
                     JOIN webhooks w ON w.id = d.webhook_id \
                     WHERE d.webhook_id = $1 AND d.id = $2 FOR UPDATE OF d",
                )
                .bind(webhook_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some((state, enabled)) = row else {
                    return Err(sqlx::Error::RowNotFound);
                };
                if state == "delivered" {
                    return Ok(Err(DbError::Precondition(
                        "this delivery was already delivered".into(),
                    )));
                }
                if !enabled {
                    return Ok(Err(DbError::Precondition(
                        "the endpoint is disabled; enable it first".into(),
                    )));
                }
                let row = sqlx::query(concat!(
                    "UPDATE webhook_deliveries SET state = 'pending', next_attempt_at = now() \
                     WHERE id = $1 RETURNING ",
                    delivery_columns!()
                ))
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
                let d = row_to_delivery(&row)?;
                tx.commit().await?;
                Ok(Ok(d))
            })
            .await?
    }
}

// Delivery.

/// A delivery claimed by the worker.
#[derive(Clone, Debug)]
pub struct Claimed {
    pub id: i64,
    pub event_id: String,
    pub event: String,
    pub body: String,
    /// Tries before this one.
    pub attempts: i32,
    pub url: String,
    pub secret: String,
}

/// How one try went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Option<u16>,
    pub duration: Duration,
    pub error: Option<String>,
    pub response: Option<String>,
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        self.error.is_none() && self.status.is_some_and(|s| (200..300).contains(&s))
    }
}

/// What finishing a try did to the delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finished {
    Delivered,
    /// Failed; tried again later.
    Retrying,
    /// Failed for the last time.
    Failed,
    /// The delivery was gone (its endpoint deleted) or no longer pending.
    Gone,
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

impl Db {
    /// Claims up to `limit` due deliveries of enabled endpoints, moving
    /// their due time `lease` ahead so no other worker takes them while
    /// this one tries.
    pub async fn claim_deliveries(
        &self,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<Claimed>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "UPDATE webhook_deliveries d \
                        SET next_attempt_at = now() + make_interval(secs => $2) \
                       FROM webhooks w \
                      WHERE w.id = d.webhook_id AND d.id IN ( \
                            SELECT id FROM webhook_deliveries \
                             WHERE state = 'pending' AND next_attempt_at <= now() \
                             ORDER BY next_attempt_at LIMIT $1 \
                               FOR UPDATE SKIP LOCKED) \
                  RETURNING d.id, d.event_id, d.event, d.payload::text AS body, d.attempts, \
                            w.url, w.secret",
                )
                .bind(limit)
                .bind(lease.as_secs_f64())
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(Claimed {
                    id: r.try_get("id")?,
                    event_id: r.try_get("event_id")?,
                    event: r.try_get("event")?,
                    body: r.try_get("body")?,
                    attempts: r.try_get("attempts")?,
                    url: r.try_get("url")?,
                    secret: r.try_get("secret")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Records a try of delivery `id` and settles it: delivered, retried
    /// after `retry_in`, or failed once `max_attempts` tries are spent.
    pub async fn finish_delivery(
        &self,
        id: i64,
        outcome: &Outcome,
        max_attempts: u32,
        retry_in: Duration,
    ) -> Result<Finished, DbError> {
        let ok = outcome.succeeded();
        let status = outcome.status.map(|s| s as i16);
        let error = outcome.error.as_deref().map(|e| clip(e, MAX_ERROR));
        let last_error = match (&error, status, ok) {
            (Some(e), _, _) => Some(e.clone()),
            (None, Some(s), false) => Some(format!("the endpoint answered {s}")),
            _ => None,
        };
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            let row: Option<(i32, String)> = sqlx::query_as(
                "UPDATE webhook_deliveries SET attempts = attempts + 1, last_status = $2, \
                    last_error = $3, \
                    state = CASE WHEN $4 THEN 'delivered' \
                                 WHEN attempts + 1 >= $5 THEN 'failed' ELSE 'pending' END, \
                    delivered_at = CASE WHEN $4 THEN now() END, \
                    next_attempt_at = CASE WHEN $4 THEN next_attempt_at \
                                           ELSE now() + make_interval(secs => $6) END \
                  WHERE id = $1 AND state = 'pending' \
              RETURNING attempts, state",
            )
            .bind(id)
            .bind(status)
            .bind(&last_error)
            .bind(ok)
            .bind(max_attempts as i32)
            .bind(retry_in.as_secs_f64())
            .fetch_optional(&mut *tx)
            .await?;
            let Some((attempt, state)) = row else {
                tx.commit().await?;
                return Ok(Finished::Gone);
            };
            sqlx::query(
                "INSERT INTO webhook_attempts (delivery_id, attempt, status, duration_ms, error, \
                 response) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id)
            .bind(attempt)
            .bind(status)
            .bind(outcome.duration.as_millis().min(i32::MAX as u128) as i32)
            .bind(&error)
            .bind(outcome.response.as_deref().map(|r| clip(r, MAX_RESPONSE)))
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(match state.as_str() {
                "delivered" => Finished::Delivered,
                "failed" => Finished::Failed,
                _ => Finished::Retrying,
            })
        })
        .await
    }

    /// Announces up to `limit` link expiries that passed: marks each link's
    /// current expiry announced and writes `link.expired` for it, in one
    /// transaction. Returns how many links expired.
    pub async fn announce_expiries(&self, limit: i64) -> Result<usize, DbError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            let ids: Vec<i64> = sqlx::query_scalar(
                "WITH due AS ( \
                    SELECT id FROM links \
                     WHERE expires_at IS NOT NULL AND expiry_announced IS DISTINCT FROM expires_at \
                       AND expires_at <= now() \
                     ORDER BY expires_at LIMIT $1 \
                       FOR NO KEY UPDATE SKIP LOCKED) \
                 UPDATE links l SET expiry_announced = l.expires_at FROM due \
                  WHERE l.id = due.id RETURNING l.id",
            )
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
            if ids.is_empty() {
                tx.commit().await?;
                return Ok(0);
            }
            let rows = sqlx::query(concat!(
                "SELECT ",
                api_columns!(),
                " FROM links WHERE id = ANY ($1) ORDER BY expires_at, id"
            ))
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
            for row in &rows {
                let link = self.row_to_link(row)?;
                emit(
                    &mut tx,
                    link.workspace_id,
                    Event::LinkExpired,
                    link_expired(&link, self.base_url()),
                )
                .await?;
            }
            tx.commit().await?;
            Ok(ids.len())
        })
        .await
    }

    /// Deletes up to `limit` finished deliveries (and their tries) older
    /// than `days` days. Returns how many.
    pub async fn purge_deliveries(&self, days: u32, limit: i64) -> Result<u64, DbError> {
        self.timed(
            sqlx::query(
                "DELETE FROM webhook_deliveries WHERE id = ANY (ARRAY( \
                    SELECT id FROM webhook_deliveries \
                     WHERE created_at < now() - make_interval(days => $1) \
                       AND state <> 'pending' LIMIT $2))",
            )
            .bind(days as i32)
            .bind(limit)
            .execute(self.pool()),
        )
        .await
        .map(|r| r.rows_affected())
    }
}

/// Describes a request error with its causes, for the delivery log.
fn describe(e: &(dyn std::error::Error + 'static)) -> String {
    if is_blocked(e) {
        return "the endpoint's host resolves only to non-public addresses".into();
    }
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    clip(&out, MAX_ERROR)
}

/// Posts one delivery and reports how it went. Never follows redirects.
pub async fn deliver(
    client: &reqwest::Client,
    resolver: SafeResolver,
    d: &Claimed,
    now_unix: i64,
) -> Outcome {
    let started = Instant::now();
    let fail = |error: String| Outcome {
        status: None,
        duration: started.elapsed(),
        error: Some(error),
        response: None,
    };
    let Ok(url) = url::Url::parse(&d.url) else {
        return fail("the endpoint URL is not valid".into());
    };
    if blocked_literal(&url, resolver) {
        return fail("the endpoint's address is not public".into());
    }
    let signature = sign(&d.secret, now_unix, d.body.as_bytes());
    let sent = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(SIGNATURE_HEADER, signature)
        .header(EVENT_ID_HEADER, &d.event_id)
        .header(EVENT_HEADER, &d.event)
        .header(DELIVERY_HEADER, d.id.to_string())
        .body(d.body.clone())
        .send()
        .await;
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => return fail(describe(&e)),
    };
    let status = resp.status().as_u16();
    // The start of the body, for the log; the rest is not read.
    let mut body = Vec::new();
    while body.len() < MAX_RESPONSE {
        match resp.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) | Err(_) => break,
        }
    }
    body.truncate(MAX_RESPONSE);
    let text = String::from_utf8_lossy(&body).into_owned();
    Outcome {
        status: Some(status),
        duration: started.elapsed(),
        error: None,
        response: (!text.is_empty()).then_some(text),
    }
}

/// The delivery worker: announces expiries, claims due deliveries, posts
/// them and settles them, and purges old ones.
pub struct WebhookWorker {
    db: Db,
    client: reqwest::Client,
    resolver: SafeResolver,
    cfg: WebhookConfig,
    metrics: Arc<Metrics>,
}

impl WebhookWorker {
    pub fn new(
        db: Db,
        cfg: WebhookConfig,
        allow_private: bool,
        metrics: Arc<Metrics>,
    ) -> Result<WebhookWorker, reqwest::Error> {
        let resolver = SafeResolver { allow_private };
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(cfg.timeout)
            .connect_timeout(cfg.timeout)
            .user_agent("relink-webhooks/1.0")
            .build()?;
        Ok(WebhookWorker {
            db,
            client,
            resolver,
            cfg,
            metrics,
        })
    }

    /// How long a claim keeps other workers off a delivery: longer than any
    /// one try can take.
    fn lease(&self) -> Duration {
        self.cfg.timeout * 2 + Duration::from_secs(5)
    }

    /// One round: announces expiries, then claims and tries one batch.
    /// Returns how many deliveries were tried.
    pub async fn round(&self) -> usize {
        match self.db.announce_expiries(EXPIRY_BATCH).await {
            Ok(0) => {}
            Ok(n) => {
                self.metrics.webhook_expiries.add(n as u64);
                tracing::debug!(links = n, "link expiries announced");
            }
            Err(e) => {
                self.metrics.db_error(DbOp::Webhook);
                tracing::warn!(error = %e, "could not announce link expiries");
            }
        }
        let claimed = match self
            .db
            .claim_deliveries(self.cfg.concurrency as i64, self.lease())
            .await
        {
            Ok(c) => c,
            Err(e) => {
                self.metrics.db_error(DbOp::Webhook);
                tracing::warn!(error = %e, "could not claim webhook deliveries");
                return 0;
            }
        };
        let n = claimed.len();
        let mut tries = JoinSet::new();
        for d in claimed {
            let client = self.client.clone();
            let resolver = self.resolver;
            tries.spawn(async move {
                let outcome = deliver(&client, resolver, &d, Utc::now().timestamp()).await;
                (d, outcome)
            });
        }
        while let Some(joined) = tries.join_next().await {
            let Ok((d, outcome)) = joined else { continue };
            let retry_in = backoff(
                (d.attempts + 1) as u32,
                self.cfg.retry_base,
                self.cfg.retry_max,
                fast_random(),
            );
            match self
                .db
                .finish_delivery(d.id, &outcome, self.cfg.max_attempts, retry_in)
                .await
            {
                Ok(Finished::Delivered) => self.metrics.webhook_delivered.inc(),
                Ok(Finished::Retrying) => {
                    self.metrics.webhook_retried.inc();
                    tracing::debug!(delivery = d.id, error = ?outcome.error,
                                    status = ?outcome.status, "webhook delivery will be retried");
                }
                Ok(Finished::Failed) => {
                    self.metrics.webhook_failed.inc();
                    tracing::info!(delivery = d.id, error = ?outcome.error,
                                   status = ?outcome.status, "webhook delivery failed for good");
                }
                Ok(Finished::Gone) => {}
                Err(e) => {
                    // The claim runs out and the delivery is tried again:
                    // at least once.
                    self.metrics.db_error(DbOp::Webhook);
                    tracing::warn!(error = %e, delivery = d.id, "could not record a webhook try");
                }
            }
        }
        n
    }

    /// Runs until `stop` turns true. A full batch is followed at once by
    /// the next; otherwise the worker waits `poll`.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut last_purge: Option<Instant> = None;
        loop {
            if last_purge.is_none_or(|t| t.elapsed() >= PURGE_EVERY) {
                last_purge = Some(Instant::now());
                match self
                    .db
                    .purge_deliveries(self.cfg.retention_days, PURGE_BATCH)
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(deliveries = n, "old webhook deliveries purged"),
                    Err(e) => {
                        self.metrics.db_error(DbOp::Webhook);
                        tracing::warn!(error = %e, "could not purge webhook deliveries");
                    }
                }
            }
            let tried = tokio::select! {
                n = self.round() => n,
                _ = stopped(&mut stop) => return,
            };
            if tried < self.cfg.concurrency {
                tokio::select! {
                    _ = tokio::time::sleep(self.cfg.poll) => {}
                    _ = stopped(&mut stop) => return,
                }
            }
        }
    }
}

// The API.

/// Webhooks are for admins and owners: an endpoint receives every link of
/// the workspace, and its URL may carry a token.
fn require_admin(app: &App, role: Role) -> Result<(), ApiError> {
    if role.manages(Role::Editor) {
        Ok(())
    } else {
        app.metrics.permission_denied.inc();
        Err(ApiError::permission_denied(format!(
            "managing webhooks needs the admin or owner role; this member is {}",
            role.as_str()
        )))
    }
}

fn not_found(id: i64) -> impl Fn(DbError) -> ApiError {
    move |e| match e {
        DbError::NotFound => ApiError::not_found_msg(format!("no webhook {id} in this workspace")),
        other => ApiError::from(other),
    }
}

fn parse_description(raw: Option<String>) -> Result<String, ApiError> {
    let d = raw.unwrap_or_default().trim().to_owned();
    if d.chars().count() > MAX_DESCRIPTION || d.chars().any(char::is_control) {
        return Err(ApiError::invalid(format!(
            "description must be at most {MAX_DESCRIPTION} characters, without control characters"
        )));
    }
    Ok(d)
}

/// `POST /v1/webhooks` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhook {
    pub url: String,
    pub events: Vec<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

/// `PATCH /v1/webhooks/{id}` body: absent fields keep their value.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhook {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    /// Replaces the secret; the new one is in the answer, once.
    #[serde(default)]
    pub rotate_secret: bool,
}

/// An endpoint as the API shows it; the secret only when it was just made.
#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub id: i64,
    pub url: String,
    pub events: Vec<&'static str>,
    pub description: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl WebhookView {
    fn new(w: &Webhook, show_secret: bool) -> WebhookView {
        WebhookView {
            id: w.id,
            url: w.url.clone(),
            events: event_names(&w.events),
            description: w.description.clone(),
            enabled: w.enabled,
            created_by: w.created_by.clone(),
            created_at: w.created_at,
            updated_at: w.updated_at,
            secret: show_secret.then(|| w.secret.clone()),
        }
    }
}

#[derive(Serialize)]
struct WebhookList {
    webhooks: Vec<WebhookView>,
}

/// `GET /v1/webhooks/{id}/deliveries` query.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryQuery {
    pub state: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 200;

#[derive(Serialize)]
struct DeliveryList {
    deliveries: Vec<Delivery>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct DeliveryDetail {
    #[serde(flatten)]
    delivery: Delivery,
    payload: Value,
    attempt_log: Vec<Attempt>,
}

/// `POST /v1/webhooks`: registers an endpoint; the answer carries its
/// secret, which is not shown again.
pub async fn create_webhook(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    StrictJson(req): StrictJson<CreateWebhook>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let url = parse_webhook_url(&req.url, app.cfg.destination_policy).map_err(ApiError::invalid)?;
    let events = parse_events(&req.events).map_err(ApiError::invalid)?;
    let description = parse_description(req.description)?;
    let hook = ws
        .tenant(&app.db)
        .create_webhook(
            &url,
            &events,
            &description,
            req.enabled.unwrap_or(true),
            &ws.principal.owner,
        )
        .await?;
    tracing::info!(webhook = hook.id, "webhook created");
    let mut resp = json(StatusCode::CREATED, &WebhookView::new(&hook, true));
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/webhooks/{}", hook.id)) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(resp)
}

/// `GET /v1/webhooks`: every endpoint of the workspace.
pub async fn list_webhooks(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hooks = ws.tenant(&app.db).webhooks().await?;
    Ok(json(
        StatusCode::OK,
        &WebhookList {
            webhooks: hooks.iter().map(|h| WebhookView::new(h, false)).collect(),
        },
    ))
}

/// `GET /v1/webhooks/{id}`.
pub async fn get_webhook(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hook = ws
        .tenant(&app.db)
        .webhook(id)
        .await
        .map_err(not_found(id))?;
    Ok(json(StatusCode::OK, &WebhookView::new(&hook, false)))
}

/// `PATCH /v1/webhooks/{id}`.
pub async fn update_webhook(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(id): Path<i64>,
    StrictJson(req): StrictJson<UpdateWebhook>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let patch = WebhookPatch {
        url: req
            .url
            .map(|u| parse_webhook_url(&u, app.cfg.destination_policy))
            .transpose()
            .map_err(ApiError::invalid)?,
        events: req
            .events
            .map(|e| parse_events(&e))
            .transpose()
            .map_err(ApiError::invalid)?,
        description: req
            .description
            .map(Some)
            .map(parse_description)
            .transpose()?,
        enabled: req.enabled,
        rotate_secret: req.rotate_secret,
    };
    let hook = ws
        .tenant(&app.db)
        .update_webhook(id, &patch)
        .await
        .map_err(not_found(id))?;
    tracing::info!(webhook = id, "webhook changed");
    Ok(json(
        StatusCode::OK,
        &WebhookView::new(&hook, patch.rotate_secret),
    ))
}

/// `DELETE /v1/webhooks/{id}`: the endpoint and its delivery log.
pub async fn delete_webhook(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    ws.tenant(&app.db)
        .delete_webhook(id)
        .await
        .map_err(not_found(id))?;
    tracing::info!(webhook = id, "webhook deleted");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /v1/webhooks/{id}/deliveries`: the delivery log, newest first.
pub async fn list_deliveries(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(id): Path<i64>,
    StrictQuery(q): StrictQuery<DeliveryQuery>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let limit = q.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(ApiError::invalid(format!("limit must be 1 to {MAX_PAGE}")));
    }
    if let Some(s) = &q.state
        && !STATES.contains(&s.as_str())
    {
        return Err(ApiError::invalid(format!(
            "state must be one of {}",
            STATES.join(", ")
        )));
    }
    let before = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(|| ApiError::invalid("cursor is not valid")))
        .transpose()?;
    let mut deliveries = ws
        .tenant(&app.db)
        .deliveries(id, q.state.as_deref(), before, limit as i64 + 1)
        .await
        .map_err(not_found(id))?;
    let next_cursor = if deliveries.len() > limit as usize {
        deliveries.truncate(limit as usize);
        deliveries.last().map(|d| encode_cursor(d.id))
    } else {
        None
    };
    Ok(json(
        StatusCode::OK,
        &DeliveryList {
            deliveries,
            next_cursor,
        },
    ))
}

/// `GET /v1/webhooks/{id}/deliveries/{delivery}`: one delivery, with the
/// payload sent and every try.
pub async fn get_delivery(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path((id, delivery)): Path<(i64, i64)>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let (delivery, payload, attempt_log) = ws
        .tenant(&app.db)
        .delivery(id, delivery)
        .await
        .map_err(|e| match e {
            DbError::NotFound => ApiError::not_found_msg(format!(
                "no delivery {delivery} of webhook {id} in this workspace"
            )),
            other => ApiError::from(other),
        })?;
    Ok(json(
        StatusCode::OK,
        &DeliveryDetail {
            delivery,
            payload,
            attempt_log,
        },
    ))
}

/// `POST /v1/webhooks/{id}/deliveries/{delivery}/retry`: tries a failed
/// or pending delivery again now.
pub async fn retry_delivery(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path((id, delivery)): Path<(i64, i64)>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let d = ws
        .tenant(&app.db)
        .retry_delivery(id, delivery)
        .await
        .map_err(|e| match e {
            DbError::NotFound => ApiError::not_found_msg(format!(
                "no delivery {delivery} of webhook {id} in this workspace"
            )),
            other => ApiError::from(other),
        })?;
    Ok(json(StatusCode::ACCEPTED, &d))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn events_round_trip_and_parse_as_sets() {
        for e in Event::ALL {
            assert_eq!(Event::parse(e.as_str()), Some(e));
            assert_eq!(e.to_string(), e.as_str());
        }
        assert_eq!(Event::parse("link.deleted"), None);
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_events(&names(&["health.changed", " link.created", "link.created"])).unwrap(),
            vec![Event::LinkCreated, Event::HealthChanged]
        );
        assert!(parse_events(&[]).unwrap_err().contains("at least one"));
        let e = parse_events(&names(&["link.created", "link.clicked"])).unwrap_err();
        assert!(
            e.contains("\"link.clicked\"") && e.contains("health.changed"),
            "{e}"
        );
    }

    #[test]
    fn secrets_and_event_ids_are_random_and_well_formed() {
        let (a, b) = (generate_secret(), generate_secret());
        assert_ne!(a, b);
        assert!(a.starts_with("whsec_") && a.len() == 6 + 64);
        assert!(a[6..].bytes().all(|c| c.is_ascii_hexdigit()));
        let id = generate_event_id();
        assert!(id.starts_with("evt_") && id.len() == 4 + 32);
        assert_ne!(id, generate_event_id());
    }

    #[test]
    fn signatures_verify_and_refuse_tampering() {
        let body = br#"{"id":"evt_1","type":"link.created"}"#;
        let header = sign(SECRET, 1_700_000_000, body);
        assert!(header.starts_with("t=1700000000,v1="));
        // A known answer, so receivers in other languages can check theirs:
        // HMAC-SHA256(key = the secret string, "1700000000." || body).
        let expected = {
            let mut m = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
            m.update(b"1700000000.");
            m.update(body);
            hex_encode(&m.finalize().into_bytes())
        };
        assert_eq!(header, format!("t=1700000000,v1={expected}"));
        let tol = Duration::from_secs(300);
        assert_eq!(verify(SECRET, &header, body, 1_700_000_100, tol), Ok(()));
        assert_eq!(verify(SECRET, &header, body, 1_699_999_800, tol), Ok(()));
        assert_eq!(
            verify(SECRET, &header, body, 1_700_000_301, tol),
            Err(VerifyError::Stale)
        );
        assert_eq!(
            verify(SECRET, &header, b"{}", 1_700_000_000, tol),
            Err(VerifyError::Mismatch)
        );
        let other = generate_secret();
        assert_eq!(
            verify(&other, &header, body, 1_700_000_000, tol),
            Err(VerifyError::Mismatch)
        );
        // A second v1 (a receiver mid-rotation) is accepted if either matches.
        let both = format!("{header},v1={}", "00".repeat(32));
        assert_eq!(verify(SECRET, &both, body, 1_700_000_000, tol), Ok(()));
        let reversed = format!("v1={}, {}", "ab".repeat(32), header);
        assert_eq!(verify(SECRET, &reversed, body, 1_700_000_000, tol), Ok(()));
        for bad in ["", "t=1", "v1=00", "t=x,v1=00", "t=1,v1=zz", "garbage"] {
            assert_eq!(
                verify(SECRET, bad, body, 1, tol),
                Err(VerifyError::Malformed),
                "{bad:?}"
            );
        }
        // Unknown schemes are ignored, as long as a v1 is there.
        let extra = format!("{header},v2=whatever");
        assert_eq!(verify(SECRET, &extra, body, 1_700_000_000, tol), Ok(()));
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_with_jitter() {
        let base = Duration::from_secs(30);
        let max = Duration::from_secs(6 * 3600);
        // random = 0 is the low end (half the full delay), u64::MAX the top.
        assert_eq!(backoff(1, base, max, 0), Duration::from_secs(15));
        assert_eq!(backoff(2, base, max, 0), Duration::from_secs(30));
        assert_eq!(backoff(5, base, max, 0), Duration::from_secs(240));
        let top = backoff(1, base, max, u64::MAX);
        assert!(top < base && top > Duration::from_millis(29_999), "{top:?}");
        assert_eq!(backoff(11, base, max, 0), max / 2);
        assert_eq!(backoff(40, base, max, 0), max / 2);
        assert_eq!(backoff(u32::MAX, base, max, 0), max / 2);
        // failures = 0 is treated as the first.
        assert_eq!(backoff(0, base, max, 0), Duration::from_secs(15));
        let mut prev = Duration::ZERO;
        for n in 1..20 {
            let d = backoff(n, base, max, 1 << 62);
            assert!(d >= prev, "{n}");
            prev = d;
        }
    }

    #[test]
    fn urls_follow_destination_rules_and_need_https() {
        let strict = Policy {
            allow_ip_literals: false,
            allow_private: false,
        };
        let dev = Policy {
            allow_ip_literals: true,
            allow_private: true,
        };
        assert_eq!(
            parse_webhook_url(" https://Hooks.Example.com/in?x=1 ", strict).unwrap(),
            "https://hooks.example.com/in?x=1"
        );
        assert!(
            parse_webhook_url("http://hooks.example.com/", strict)
                .unwrap_err()
                .contains("https")
        );
        assert!(parse_webhook_url("https://localhost/", strict).is_err());
        assert!(parse_webhook_url("https://u:p@example.com/", strict).is_err());
        assert!(parse_webhook_url("ftp://example.com/", strict).is_err());
        assert!(parse_webhook_url("http://127.0.0.1:9/hook", dev).is_ok());
    }

    #[test]
    fn outcomes_succeed_only_on_2xx() {
        let o = |status, error: Option<&str>| Outcome {
            status,
            duration: Duration::ZERO,
            error: error.map(str::to_owned),
            response: None,
        };
        assert!(o(Some(200), None).succeeded());
        assert!(o(Some(204), None).succeeded());
        assert!(!o(Some(301), None).succeeded());
        assert!(!o(Some(500), None).succeeded());
        assert!(!o(None, Some("refused")).succeeded());
    }

    #[test]
    fn clipping_counts_characters() {
        assert_eq!(clip("héllo", 2), "hé");
        assert_eq!(clip("ok", 10), "ok");
    }
}

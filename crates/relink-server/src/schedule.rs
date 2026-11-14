//! Link version history, rollback and scheduled changes.
//!
//! Every change to what a link does is kept as a numbered version
//! (migration 0018): the link's settings as one JSON object, a [`LinkSpec`],
//! built in SQL by `relink_link_spec` from the row itself, so a snapshot
//! cannot drift from the link it describes. [`record_version`] runs inside
//! the transaction of every change, after the row is written: if the row
//! now differs from its current version, the link's version number goes up
//! by one and the new snapshot is kept; if not (a `PATCH` that sets what was
//! already set), nothing is recorded. The newest [`MAX_VERSIONS`] versions
//! of each link are kept.
//!
//! A rollback ([`Tenant::rollback_link`]) writes an old version's settings
//! back through the same path as a `PATCH`, so it becomes a new version and
//! history only grows.
//!
//! A schedule ([`ScheduledChange`]) is new destinations, or enabling or
//! disabling the link, at a given time. The [`run`] task on every instance
//! looks for due schedules every `RELINK_SCHEDULE_POLL_MS`, and applies each
//! in one tenant transaction that takes the schedule's row lock with
//! `SKIP LOCKED`, applies the change and marks the schedule applied. So a
//! change is applied exactly once however many instances run, and a crash
//! before the commit leaves it pending for the next tick.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{Postgres, Row, Transaction};
use tokio::sync::watch;

use crate::api::{
    self, ApiError, DomainQuery, LinkView, StrictJson, StrictQuery, decode_cursor, encode_cursor,
    json,
};
use crate::audit::{self, Action, Actor, Change};
use crate::metrics::DbOp;
use crate::model::{Destination, GeoRule};
use crate::server::App;
use crate::store::{Db, DbError, LinkPatch, StoredLink, columns, link_key};
use crate::tenant::{Allowed, Edit, LinksRead, LinksWrite, Tenant, by_code, lock_by_code};
use crate::util::stopped;
use relink_core::deeplink::AppLink;
use relink_core::rules_v2::RuleSet;

/// Versions kept per link; older ones are deleted as new ones are written.
pub const MAX_VERSIONS: i32 = 100;

/// Pending schedules one link may have.
pub const MAX_PENDING: i64 = 20;

/// How far ahead a change may be scheduled.
pub const MAX_SCHEDULE_DAYS: i64 = 3650;

/// Due schedules claimed per query; a full batch is followed at once by
/// another.
const BATCH: i64 = 100;

const DEFAULT_PAGE: u32 = 20;
const MAX_PAGE: u32 = 100;

/// What wrote a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Create,
    Update,
    /// A rollback to this version.
    Rollback(i32),
    /// The schedule with this ID.
    Schedule(i64),
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Create => "create",
            Source::Update => "update",
            Source::Rollback(_) => "rollback",
            Source::Schedule(_) => "schedule",
        }
    }
}

/// A link's settings as one version keeps them: what `PATCH` can change.
/// Written by `relink_link_spec` in SQL (migration 0018), read here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSpec {
    pub destinations: Vec<Destination>,
    pub redirect_type: u16,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_clicks: Option<i64>,
    pub geo: Option<GeoRule>,
    pub fallback_url: Option<String>,
    pub enabled: bool,
    pub health_check: bool,
    #[serde(default)]
    pub rules: RuleSet,
    #[serde(default)]
    pub app: Option<AppLink>,
}

impl LinkSpec {
    /// The patch that gives a link exactly these settings.
    pub fn into_patch(self) -> LinkPatch {
        LinkPatch {
            destinations: Some(self.destinations),
            redirect_status: Some(self.redirect_type),
            expires_at: Some(self.expires_at),
            max_clicks: Some(self.max_clicks),
            geo: Some(self.geo),
            fallback_url: Some(self.fallback_url),
            enabled: Some(self.enabled),
            health_check: Some(self.health_check),
            rules: Some(self.rules),
            app: Some(self.app),
        }
    }
}

/// Records the settings of link `link_id`, as `tx` has just written them,
/// as a new version if they differ from its current one, and returns the
/// link's version number. A link with no version yet (just created) gets
/// its current number. Prunes versions beyond [`MAX_VERSIONS`].
pub(crate) async fn record_version(
    tx: &mut Transaction<'static, Postgres>,
    link_id: i64,
    actor: &Actor,
    source: Source,
) -> Result<i32, sqlx::Error> {
    let (current, same): (i32, Option<bool>) = sqlx::query_as(
        "SELECT l.version, v.spec = relink_link_spec(l) FROM links l \
         LEFT JOIN link_versions v ON v.link_id = l.id AND v.version = l.version \
         WHERE l.id = $1",
    )
    .bind(link_id)
    .fetch_one(&mut **tx)
    .await?;
    let version = match same {
        Some(true) => return Ok(current),
        None => current,
        Some(false) => {
            sqlx::query_scalar(
                "UPDATE links SET version = version + 1 WHERE id = $1 RETURNING version",
            )
            .bind(link_id)
            .fetch_one(&mut **tx)
            .await?
        }
    };
    let (restored_from, schedule_id) = match source {
        Source::Rollback(v) => (Some(v), None),
        Source::Schedule(id) => (None, Some(id)),
        Source::Create | Source::Update => (None, None),
    };
    sqlx::query(
        "INSERT INTO link_versions (link_id, version, member, via, source, restored_from, \
         schedule_id, spec) SELECT l.id, $2, $3, $4, $5, $6, $7, relink_link_spec(l) \
         FROM links l WHERE l.id = $1",
    )
    .bind(link_id)
    .bind(version)
    .bind(&actor.member)
    .bind(actor.via.to_string())
    .bind(source.as_str())
    .bind(restored_from)
    .bind(schedule_id)
    .execute(&mut **tx)
    .await?;
    if version > MAX_VERSIONS {
        sqlx::query("DELETE FROM link_versions WHERE link_id = $1 AND version <= $2")
            .bind(link_id)
            .bind(version - MAX_VERSIONS)
            .execute(&mut **tx)
            .await?;
    }
    Ok(version)
}

/// One version of a link, as the API returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Version {
    pub version: i32,
    pub created_at: DateTime<Utc>,
    /// The member who made the change; `null` for the server or an operator.
    pub member: Option<String>,
    /// How they acted: `key:<id>`, `session:<id>`, `cli` or `system`.
    pub via: String,
    /// `create`, `update`, `rollback`, `schedule` or `migration` (a link
    /// from before version history).
    pub source: String,
    /// For a rollback, the version whose settings it restored.
    pub restored_from: Option<i32>,
    /// For a scheduled change, the schedule's ID.
    pub schedule_id: Option<i64>,
    pub settings: LinkSpec,
}

fn row_to_version(r: &PgRow) -> Result<Version, sqlx::Error> {
    let Json(settings): Json<LinkSpec> = r.try_get("spec")?;
    Ok(Version {
        version: r.try_get("version")?,
        created_at: r.try_get("created_at")?,
        member: r.try_get("member")?,
        via: r.try_get("via")?,
        source: r.try_get("source")?,
        restored_from: r.try_get("restored_from")?,
        schedule_id: r.try_get("schedule_id")?,
        settings,
    })
}

/// A change to apply to a link later. At least one field is set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledChange {
    /// New destinations, already validated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<Destination>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl ScheduledChange {
    pub fn is_empty(&self) -> bool {
        self.destinations.is_none() && self.enabled.is_none()
    }

    fn to_patch(&self) -> LinkPatch {
        LinkPatch {
            destinations: self.destinations.clone(),
            enabled: self.enabled,
            ..LinkPatch::default()
        }
    }
}

/// A schedule as the API returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Schedule {
    pub id: i64,
    pub run_at: DateTime<Utc>,
    /// The [`ScheduledChange`] as stored, so a row the server cannot apply
    /// (it is then marked failed) still lists.
    pub change: Value,
    /// `pending`, `applied`, `failed` or `canceled`.
    pub state: String,
    pub member: Option<String>,
    pub via: String,
    pub created_at: DateTime<Utc>,
    /// When it was applied, failed or was cancelled.
    pub finished_at: Option<DateTime<Utc>>,
    /// The link version it produced (or the one already current, when the
    /// change changed nothing).
    pub applied_version: Option<i32>,
    /// Why it could not be applied.
    pub error: Option<String>,
}

/// Columns read into a [`Schedule`], as a literal so queries stay static.
macro_rules! schedule_columns {
    () => {
        "id, run_at, change, state, member, via, created_at, finished_at, applied_version, error"
    };
}

fn row_to_schedule(r: &PgRow) -> Result<Schedule, sqlx::Error> {
    let change: Value = r.try_get("change")?;
    Ok(Schedule {
        id: r.try_get("id")?,
        run_at: r.try_get("run_at")?,
        change,
        state: r.try_get("state")?,
        member: r.try_get("member")?,
        via: r.try_get("via")?,
        created_at: r.try_get("created_at")?,
        finished_at: r.try_get("finished_at")?,
        applied_version: r.try_get("applied_version")?,
        error: r.try_get("error")?,
    })
}

fn schedule_state(s: &Schedule) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

/// The ID of the link with `code` on `domain`, or `RowNotFound`.
async fn link_id(
    tx: &mut Transaction<'static, Postgres>,
    code: &str,
    domain: Option<&str>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(concat!("SELECT id FROM links", by_code!()))
        .bind(code)
        .bind(domain)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

impl Tenant<'_> {
    /// Versions of the link with `code` on `domain`, newest first, older
    /// than `before` when given.
    pub async fn versions(
        &self,
        code: &str,
        domain: Option<&str>,
        before: Option<i32>,
        limit: i64,
    ) -> Result<Vec<Version>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let id = link_id(&mut tx, code, domain).await?;
                let rows = sqlx::query(
                    "SELECT version, created_at, member, via, source, restored_from, schedule_id, \
                     spec FROM link_versions WHERE link_id = $1 \
                     AND ($2::integer IS NULL OR version < $2) ORDER BY version DESC LIMIT $3",
                )
                .bind(id)
                .bind(before)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_version)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Gives the link with `code` on `domain` the settings of its version
    /// `version` again, as a new version. `Missing` if the link has no such
    /// version (any more).
    pub async fn rollback_link(
        &self,
        code: &str,
        domain: Option<&str>,
        version: i32,
    ) -> Result<StoredLink, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = lock_by_code(&mut tx, code, domain).await?;
                let id: i64 = row.try_get("id")?;
                let spec: Option<Json<LinkSpec>> = sqlx::query_scalar(
                    "SELECT spec FROM link_versions WHERE link_id = $1 AND version = $2",
                )
                .bind(id)
                .bind(version)
                .fetch_optional(&mut *tx)
                .await?;
                let Some(Json(spec)) = spec else {
                    return Ok(Err(DbError::Missing(format!(
                        "this link has no version {version}; it keeps its last {MAX_VERSIONS}"
                    ))));
                };
                let edit = Edit {
                    action: Action::LinkRollback,
                    source: Source::Rollback(version),
                };
                let link = self
                    .apply_patch(&mut tx, &row, &spec.into_patch(), edit)
                    .await?;
                tx.commit().await?;
                Ok(Ok(link))
            })
            .await?
    }

    /// Schedules `change` for the link with `code` on `domain` at `run_at`.
    /// `Precondition` if the link already has [`MAX_PENDING`] pending.
    pub async fn create_schedule(
        &self,
        code: &str,
        domain: Option<&str>,
        run_at: DateTime<Utc>,
        change: &ScheduledChange,
    ) -> Result<Schedule, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                // The link's row lock serialises the pending count.
                let row = lock_by_code(&mut tx, code, domain).await?;
                let id: i64 = row.try_get("id")?;
                let pending: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM link_schedules WHERE link_id = $1 AND state = 'pending'",
                )
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
                if pending >= MAX_PENDING {
                    return Ok(Err(DbError::Precondition(format!(
                        "a link can have at most {MAX_PENDING} pending schedules"
                    ))));
                }
                let row = sqlx::query(concat!(
                    "INSERT INTO link_schedules (link_id, run_at, change, member, via) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING ",
                    schedule_columns!()
                ))
                .bind(id)
                .bind(run_at)
                .bind(Json(change))
                .bind(&self.actor().member)
                .bind(self.actor().via.to_string())
                .fetch_one(&mut *tx)
                .await?;
                let schedule = row_to_schedule(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::ScheduleCreate,
                    target: format!("link:{id}"),
                    before: None,
                    after: Some(schedule_state(&schedule)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(schedule))
            })
            .await?
    }

    /// Schedules of the link with `code` on `domain`, newest first, with
    /// IDs below `before` when given.
    pub async fn schedules(
        &self,
        code: &str,
        domain: Option<&str>,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Schedule>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let id = link_id(&mut tx, code, domain).await?;
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    schedule_columns!(),
                    " FROM link_schedules WHERE link_id = $1 \
                     AND ($2::bigint IS NULL OR id < $2) ORDER BY id DESC LIMIT $3"
                ))
                .bind(id)
                .bind(before)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_schedule)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Cancels pending schedule `schedule_id` of the link with `code` on
    /// `domain`. `Precondition` if it already finished.
    pub async fn cancel_schedule(
        &self,
        code: &str,
        domain: Option<&str>,
        schedule_id: i64,
    ) -> Result<Schedule, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let id = link_id(&mut tx, code, domain).await?;
                // Waits for a scheduler applying it right now, then sees
                // the outcome.
                let state: Option<String> = sqlx::query_scalar(
                    "SELECT state FROM link_schedules WHERE id = $1 AND link_id = $2 FOR UPDATE",
                )
                .bind(schedule_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
                match state.as_deref() {
                    None => return Err(sqlx::Error::RowNotFound),
                    Some("pending") => {}
                    Some(other) => {
                        return Ok(Err(DbError::Precondition(format!(
                            "schedule {schedule_id} is already {other}"
                        ))));
                    }
                }
                let before = sqlx::query(concat!(
                    "SELECT ",
                    schedule_columns!(),
                    " FROM link_schedules WHERE id = $1"
                ))
                .bind(schedule_id)
                .fetch_one(&mut *tx)
                .await?;
                let before = row_to_schedule(&before)?;
                let row = sqlx::query(concat!(
                    "UPDATE link_schedules SET state = 'canceled', finished_at = now() \
                     WHERE id = $1 RETURNING ",
                    schedule_columns!()
                ))
                .bind(schedule_id)
                .fetch_one(&mut *tx)
                .await?;
                let schedule = row_to_schedule(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::ScheduleCancel,
                    target: format!("link:{id}"),
                    before: Some(schedule_state(&before)),
                    after: Some(schedule_state(&schedule)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(schedule))
            })
            .await?
    }

    /// Applies schedule `schedule_id` if it is pending and due and no other
    /// instance is applying it, returning the changed link. `None` if there
    /// was nothing to do. A change that can no longer be read is marked
    /// failed instead.
    pub async fn apply_schedule(&self, schedule_id: i64) -> Result<Option<StoredLink>, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row: Option<(i64, Value)> = sqlx::query_as(
                    "SELECT link_id, change FROM link_schedules \
                     WHERE id = $1 AND state = 'pending' AND run_at <= now() \
                     FOR UPDATE SKIP LOCKED",
                )
                .bind(schedule_id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some((link_id, change)) = row else {
                    return Ok(None);
                };
                let change: ScheduledChange = match serde_json::from_value(change) {
                    Ok(c) => c,
                    Err(e) => {
                        mark_failed(&mut tx, schedule_id, &format!("unreadable change: {e}"))
                            .await?;
                        tx.commit().await?;
                        return Ok(None);
                    }
                };
                let row = sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE id = $1 FOR NO KEY UPDATE"
                ))
                .bind(link_id)
                .fetch_one(&mut *tx)
                .await?;
                let edit = Edit {
                    action: Action::ScheduleApply,
                    source: Source::Schedule(schedule_id),
                };
                let link = self
                    .apply_patch(&mut tx, &row, &change.to_patch(), edit)
                    .await?;
                sqlx::query(
                    "UPDATE link_schedules SET state = 'applied', finished_at = now(), \
                     applied_version = $2 WHERE id = $1",
                )
                .bind(schedule_id)
                .bind(link.version)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(Some(link))
            })
            .await
    }

    /// Marks pending schedule `schedule_id` failed with `error`.
    pub async fn fail_schedule(&self, schedule_id: i64, error: &str) -> Result<(), DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                mark_failed(&mut tx, schedule_id, error).await?;
                tx.commit().await
            })
            .await
    }
}

async fn mark_failed(
    tx: &mut Transaction<'static, Postgres>,
    schedule_id: i64,
    error: &str,
) -> Result<(), sqlx::Error> {
    let error: String = error.chars().take(256).collect();
    sqlx::query(
        "UPDATE link_schedules SET state = 'failed', finished_at = now(), error = $2 \
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(schedule_id)
    .bind(error)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl Db {
    /// Up to `limit` pending schedules that are due, oldest first, with
    /// their link's workspace. Crosses workspaces, so runs as the connecting
    /// role; each is then applied in its own workspace's transaction.
    pub async fn due_schedules(&self, limit: i64) -> Result<Vec<(i64, i64)>, DbError> {
        self.timed(
            sqlx::query_as(
                "SELECT s.id, l.workspace_id FROM link_schedules s \
                 JOIN links l ON l.id = s.link_id \
                 WHERE s.state = 'pending' AND s.run_at <= now() \
                 ORDER BY s.run_at, s.id LIMIT $1",
            )
            .bind(limit)
            .fetch_all(self.pool()),
        )
        .await
    }
}

/// Applies every due schedule once, returning how many changed a link.
/// Stops early, leaving the rest pending, when the database is unavailable.
pub async fn tick(app: &App) -> usize {
    let mut applied = 0;
    loop {
        let due = match app.db.due_schedules(BATCH).await {
            Ok(due) => due,
            Err(e) => {
                app.metrics.db_error(DbOp::Schedule);
                tracing::warn!(error = %e, "could not look for due schedules");
                return applied;
            }
        };
        for &(id, workspace_id) in &due {
            let tenant = Tenant::new(&app.db, workspace_id);
            match tenant.apply_schedule(id).await {
                Ok(Some(link)) => {
                    app.resolver
                        .invalidate(&link_key(link.domain_id, &link.code));
                    app.limiter.invalidate(link.id).await;
                    app.metrics.schedules_applied.inc();
                    applied += 1;
                    tracing::info!(schedule = id, code = %link.code, version = link.version,
                        "scheduled change applied");
                }
                Ok(None) => {}
                Err(DbError::Unavailable(e)) => {
                    app.metrics.db_error(DbOp::Schedule);
                    tracing::warn!(schedule = id, error = %e, "could not apply a scheduled change");
                    return applied;
                }
                Err(e) => {
                    // Not transient: retrying would fail the same way.
                    app.metrics.schedules_failed.inc();
                    tracing::error!(schedule = id, error = %e, "scheduled change failed");
                    if let Err(e) = tenant.fail_schedule(id, &e.to_string()).await {
                        app.metrics.db_error(DbOp::Schedule);
                        tracing::warn!(schedule = id, error = %e, "could not mark a schedule failed");
                        return applied;
                    }
                }
            }
        }
        if (due.len() as i64) < BATCH {
            return applied;
        }
    }
}

/// The scheduler: [`tick`] every `poll` until `stop`.
pub async fn run(app: Arc<App>, poll: Duration, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(poll);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = stopped(&mut stop) => return,
        }
        tick(&app).await;
    }
}

// The API.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    pub domain: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

impl PageQuery {
    fn limit(&self) -> Result<u32, ApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE);
        if (1..=MAX_PAGE).contains(&limit) {
            Ok(limit)
        } else {
            Err(ApiError::invalid(format!("limit must be 1 to {MAX_PAGE}")))
        }
    }

    fn before(&self) -> Result<Option<i64>, ApiError> {
        self.cursor
            .as_deref()
            .map(|c| decode_cursor(c).ok_or_else(|| ApiError::invalid("cursor is not valid")))
            .transpose()
    }
}

#[derive(Debug, Serialize)]
struct VersionList {
    versions: Vec<Version>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScheduleList {
    schedules: Vec<Schedule>,
    next_cursor: Option<String>,
}

/// `GET /v1/links/{code}/versions`
pub async fn list_versions(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(code): Path<String>,
    StrictQuery(q): StrictQuery<PageQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit()?;
    let before = q
        .before()?
        .map(|v| i32::try_from(v).map_err(|_| ApiError::invalid("cursor is not valid")))
        .transpose()?;
    let domain = api::domain_param(q.domain);
    let mut versions = app
        .db
        .tenant(ws.id)
        .versions(&code, domain.as_deref(), before, i64::from(limit) + 1)
        .await?;
    let next_cursor = if versions.len() > limit as usize {
        versions.truncate(limit as usize);
        versions.last().map(|v| encode_cursor(i64::from(v.version)))
    } else {
        None
    };
    Ok(json(
        StatusCode::OK,
        &VersionList {
            versions,
            next_cursor,
        },
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub version: i32,
}

/// `POST /v1/links/{code}/rollback`
pub async fn rollback(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(code): Path<String>,
    StrictQuery(q): StrictQuery<DomainQuery>,
    StrictJson(req): StrictJson<RollbackRequest>,
) -> Result<Response, ApiError> {
    if req.version < 1 {
        return Err(ApiError::invalid("version must be a positive integer"));
    }
    let domain = api::domain_param(q.domain);
    let link = ws
        .tenant(&app.db)
        .rollback_link(&code, domain.as_deref(), req.version)
        .await?;
    app.resolver
        .invalidate(&link_key(link.domain_id, &link.code));
    app.limiter.invalidate(link.id).await;
    tracing::info!(code = %link.code, restored = req.version, version = link.version,
        "link rolled back");
    Ok(json(
        StatusCode::OK,
        &LinkView::new(&link, &app.cfg.public_base_url),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSchedule {
    pub run_at: DateTime<Utc>,
    pub url: Option<String>,
    pub destinations: Option<Vec<Destination>>,
    pub enabled: Option<bool>,
}

/// `GET /v1/links/{code}/schedules`
pub async fn list_schedules(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(code): Path<String>,
    StrictQuery(q): StrictQuery<PageQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit()?;
    let before = q.before()?;
    let domain = api::domain_param(q.domain);
    let mut schedules = app
        .db
        .tenant(ws.id)
        .schedules(&code, domain.as_deref(), before, i64::from(limit) + 1)
        .await?;
    let next_cursor = if schedules.len() > limit as usize {
        schedules.truncate(limit as usize);
        schedules.last().map(|s| encode_cursor(s.id))
    } else {
        None
    };
    Ok(json(
        StatusCode::OK,
        &ScheduleList {
            schedules,
            next_cursor,
        },
    ))
}

/// `POST /v1/links/{code}/schedules`
pub async fn create_schedule(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(code): Path<String>,
    StrictQuery(q): StrictQuery<DomainQuery>,
    StrictJson(req): StrictJson<CreateSchedule>,
) -> Result<Response, ApiError> {
    let now = Utc::now();
    if req.run_at <= now {
        return Err(ApiError::invalid("run_at must be in the future"));
    }
    if req.run_at > now + ChronoDuration::days(MAX_SCHEDULE_DAYS) {
        return Err(ApiError::invalid("run_at must be within 10 years"));
    }
    let change = ScheduledChange {
        destinations: api::validate_destinations(&app, req.url, req.destinations, false)?,
        enabled: req.enabled,
    };
    if change.is_empty() {
        return Err(ApiError::invalid(
            "a schedule must change url, destinations or enabled",
        ));
    }
    let domain = api::domain_param(q.domain);
    let schedule = ws
        .tenant(&app.db)
        .create_schedule(&code, domain.as_deref(), req.run_at, &change)
        .await?;
    tracing::info!(code = %code, schedule = schedule.id, run_at = %schedule.run_at,
        "change scheduled");
    Ok(json(StatusCode::CREATED, &schedule))
}

/// `DELETE /v1/links/{code}/schedules/{id}`: cancels a pending schedule.
pub async fn cancel_schedule(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path((code, id)): Path<(String, String)>,
    StrictQuery(q): StrictQuery<DomainQuery>,
) -> Result<Response, ApiError> {
    // Anything but a positive decimal ID is a schedule that does not exist.
    let id = id
        .parse::<i64>()
        .ok()
        .filter(|&id| id > 0)
        .ok_or_else(ApiError::not_found)?;
    let domain = api::domain_param(q.domain);
    let schedule = ws
        .tenant(&app.db)
        .cancel_schedule(&code, domain.as_deref(), id)
        .await?;
    tracing::info!(code = %code, schedule = id, "schedule cancelled");
    Ok(json(StatusCode::OK, &schedule))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_spec_reads_what_relink_link_spec_writes() {
        // The shape of migration 0018's relink_link_spec, timestamps in UTC
        // with microseconds.
        let written = json!({
            "destinations": [{"url": "https://a.example/", "weight": 3},
                             {"url": "https://b.example/", "weight": 1}],
            "redirect_type": 307,
            "expires_at": "2027-01-02T03:04:05.123456Z",
            "max_clicks": 10,
            "geo": {"mode": "deny", "countries": ["DE", "FR"]},
            "fallback_url": "https://fallback.example/",
            "enabled": false,
            "health_check": true,
            "rules": [],
            "app": null,
        });
        let spec: LinkSpec = serde_json::from_value(written).unwrap();
        assert_eq!(spec.destinations.len(), 2);
        assert_eq!(spec.redirect_type, 307);
        assert_eq!(
            spec.expires_at.unwrap().to_rfc3339(),
            "2027-01-02T03:04:05.123456+00:00"
        );
        assert_eq!(spec.geo.as_ref().unwrap().countries, vec![*b"DE", *b"FR"]);
        let patch = spec.clone().into_patch();
        assert_eq!(patch.destinations.as_ref(), Some(&spec.destinations));
        assert_eq!(patch.redirect_status, Some(307));
        assert_eq!(patch.expires_at, Some(spec.expires_at));
        assert_eq!(patch.max_clicks, Some(Some(10)));
        assert_eq!(patch.geo, Some(spec.geo.clone()));
        assert_eq!(patch.enabled, Some(false));
        assert_eq!(patch.health_check, Some(true));
        assert_eq!(patch.app, Some(None));
        // Every field is set, so a rollback restores all of them.
        assert!(patch.rules.is_some() && patch.fallback_url.is_some());
    }

    #[test]
    fn scheduled_changes_round_trip_and_refuse_unknown_fields() {
        let c = ScheduledChange {
            destinations: None,
            enabled: Some(false),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v, json!({"enabled": false}));
        assert_eq!(serde_json::from_value::<ScheduledChange>(v).unwrap(), c);
        assert!(serde_json::from_value::<ScheduledChange>(json!({"rules": []})).is_err());
        assert!(ScheduledChange::default().is_empty());
        let patch = c.to_patch();
        assert_eq!(patch.enabled, Some(false));
        assert!(patch.destinations.is_none() && patch.rules.is_none());
    }

    #[test]
    fn sources_name_themselves() {
        assert_eq!(Source::Create.as_str(), "create");
        assert_eq!(Source::Update.as_str(), "update");
        assert_eq!(Source::Rollback(3).as_str(), "rollback");
        assert_eq!(Source::Schedule(9).as_str(), "schedule");
    }
}

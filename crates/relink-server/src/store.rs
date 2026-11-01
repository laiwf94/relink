//! Postgres access. Every query is a static string with bound parameters.
//!
//! Each call is bounded by a deadline so a database that stops answering
//! (rather than refusing connections) cannot pin request tasks.
//!
//! This module runs the work that crosses workspaces by design: redirect
//! lookups (as [`REDIRECT_ROLE`], through their own pool), click flushes,
//! health checks, the KV outbox and key lookups. Everything done for one
//! tenant goes through [`crate::tenant::Tenant`] instead, inside a
//! transaction that row-level security limits to that tenant's workspace.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::auth::{Role, Scopes};
use crate::limiter::{LeaseStore, StoreUnavailable};
use crate::model::{Destination, GeoMode, GeoRule, Link};
use crate::util::BoxFuture;

/// Columns read into a [`Link`], as a literal so queries stay `&'static str`.
macro_rules! columns {
    () => {
        "id, code, owner, workspace_id, destinations, destinations_version, redirect_status, \
         expires_at, max_clicks, geo_mode, geo_countries, fallback_url, enabled, health_check, \
         health_failures, health_checked_at, created_at, updated_at"
    };
}
pub(crate) use columns;

/// Embedded migrations from `migrations/`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The role a tenant transaction runs as. Row-level security policies
/// (migration 0003) apply to it; the connecting role, which runs system work
/// such as the click flusher, the health worker and key lookups, owns the
/// tables and is not subject to them.
pub const TENANT_ROLE: &str = "relink_tenant";

/// The role the redirect lookup pool runs as: it may only call
/// `relink_link_by_code` (migration 0004) and has no table privileges.
pub const REDIRECT_ROLE: &str = "relink_redirect";

/// The transaction-local setting naming the workspace a tenant transaction
/// acts for. Unset, a tenant transaction sees no rows.
pub const WORKSPACE_SETTING: &str = "relink.workspace_id";

/// Channel for link change notifications. Payload: `<id>:<code>`.
pub const CHANGES_CHANNEL: &str = "relink_link_changes";

/// Database errors as the rest of the service sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The row does not exist (or belongs to another workspace).
    NotFound,
    /// A unique constraint was violated.
    Conflict,
    /// The database could not be reached or did not answer in time.
    Unavailable(String),
    /// Anything else: a bug or a constraint the API should have caught.
    Other(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::NotFound => f.write_str("not found"),
            DbError::Conflict => f.write_str("conflict"),
            DbError::Unavailable(m) => write!(f, "database unavailable: {m}"),
            DbError::Other(m) => write!(f, "database error: {m}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => DbError::NotFound,
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => DbError::Conflict,
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::Protocol(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => DbError::Unavailable(e.to_string()),
            // 57P01..57P03: admin shutdown, crash shutdown, cannot connect now.
            sqlx::Error::Database(db) if db.code().is_some_and(|c| c.starts_with("57P")) => {
                DbError::Unavailable(e.to_string())
            }
            _ => DbError::Other(e.to_string()),
        }
    }
}

impl DbError {
    fn is_fk_violation(e: &sqlx::Error) -> bool {
        matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23503"))
    }
}

/// A link with the bookkeeping the redirect path does not need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredLink {
    pub link: Link,
    pub owner: String,
    pub workspace_id: i64,
    pub health_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::ops::Deref for StoredLink {
    type Target = Link;
    fn deref(&self) -> &Link {
        &self.link
    }
}

impl std::ops::DerefMut for StoredLink {
    fn deref_mut(&mut self) -> &mut Link {
        &mut self.link
    }
}

/// Fields for a new link, already validated by the API layer.
#[derive(Clone, Debug)]
pub struct NewLink {
    pub owner: String,
    /// A custom alias, or `None` to generate a random code.
    pub alias: Option<String>,
    pub destinations: Vec<Destination>,
    pub redirect_status: u16,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_clicks: Option<i64>,
    pub geo: Option<GeoRule>,
    pub fallback_url: Option<String>,
    pub enabled: bool,
    pub health_check: bool,
}

/// A partial update, already validated. The outer `Option` is "change this
/// field", the inner one (where present) is "set or clear".
#[derive(Clone, Debug, Default)]
pub struct LinkPatch {
    pub destinations: Option<Vec<Destination>>,
    pub redirect_status: Option<u16>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub max_clicks: Option<Option<i64>>,
    pub geo: Option<Option<GeoRule>>,
    pub fallback_url: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub health_check: Option<bool>,
}

/// An active API key as stored, with its owner's role in its workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    pub id: i64,
    pub owner: String,
    pub workspace_id: i64,
    pub hash: Vec<u8>,
    pub scopes: Scopes,
    pub expires_at: Option<DateTime<Utc>>,
    /// None when the owner is no longer a member of the workspace.
    pub role: Option<Role>,
}

impl KeyRow {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|e| e <= now)
    }
}

/// A key to create with [`Db::create_api_key`].
#[derive(Clone, Debug)]
pub struct NewApiKey<'a> {
    pub owner: &'a str,
    pub name: &'a str,
    pub hash: [u8; 32],
    /// The workspace; None means the owner's personal workspace, created on
    /// first use.
    pub workspace_id: Option<i64>,
    pub scopes: Scopes,
    /// Time to live from creation; None never expires.
    pub lifetime: Option<Duration>,
}

/// A key as created or rotated (never its secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: i64,
    pub owner: String,
    pub workspace_id: i64,
    pub role: Role,
    pub scopes: Scopes,
    pub expires_at: Option<DateTime<Utc>>,
}

/// The result of [`Db::rotate_api_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub new: KeyInfo,
    pub old_id: i64,
    /// When the old key stops working: the end of the overlap, or its own
    /// expiry if that comes first.
    pub old_expires_at: DateTime<Utc>,
}

/// Why a key could not be created or rotated.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The owner is not a member of the workspace (or it does not exist).
    NotMember {
        owner: String,
        workspace_id: i64,
    },
    /// The scopes asked for are more than the owner's role grants.
    ScopesExceedRole {
        role: Role,
        scopes: Scopes,
    },
    /// No active (unrevoked, unexpired) key has that ID.
    NoSuchKey(i64),
    /// The key was already rotated; rotate its successor instead.
    AlreadyRotated {
        id: i64,
        successor: i64,
    },
    Db(DbError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NotMember {
                owner,
                workspace_id,
            } => write!(
                f,
                "{owner} is not a member of workspace {workspace_id}, or it does not exist"
            ),
            KeyError::ScopesExceedRole { role, scopes } => write!(
                f,
                "the {role} role grants only {}, not {scopes}",
                role.grants()
            ),
            KeyError::NoSuchKey(id) => write!(f, "no active key with id {id}"),
            KeyError::AlreadyRotated { id, successor } => write!(
                f,
                "key {id} was already rotated to key {successor}; rotate that one instead"
            ),
            KeyError::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<DbError> for KeyError {
    fn from(e: DbError) -> KeyError {
        KeyError::Db(e)
    }
}

impl From<sqlx::Error> for KeyError {
    fn from(e: sqlx::Error) -> KeyError {
        KeyError::Db(e.into())
    }
}

fn row_role(row: &PgRow) -> Result<Option<Role>, sqlx::Error> {
    let role: Option<String> = row.try_get("role")?;
    role.map(|r| {
        Role::parse(&r).ok_or_else(|| sqlx::Error::Decode(format!("unknown role {r:?}").into()))
    })
    .transpose()
}

fn row_scopes(row: &PgRow) -> Result<Scopes, sqlx::Error> {
    let names: Vec<String> = row.try_get("scopes")?;
    Scopes::from_names(&names).map_err(|e| sqlx::Error::Decode(e.into()))
}

/// One aggregated click row for [`Db::flush_clicks`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClickRow {
    pub link_id: i64,
    pub day: i32,
    pub country: [u8; 2],
    pub device: &'static str,
    pub referrer: Option<Box<str>>,
}

/// A link claimed by the health worker.
#[derive(Clone, Debug)]
pub struct HealthTarget {
    pub id: i64,
    pub code: String,
    pub destinations: Vec<Destination>,
    pub version: i32,
    pub failures: Vec<i16>,
}

/// Count per value of one dimension.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Bucket {
    pub value: String,
    pub clicks: i64,
}

/// Per-day totals.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DayStats {
    pub day: NaiveDate,
    pub clicks: i64,
    pub unique_visitors: i64,
}

/// Statistics for one link over a date range.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub total_clicks: i64,
    pub days: Vec<DayStats>,
    pub countries: Vec<Bucket>,
    pub devices: Vec<Bucket>,
    pub referrers: Vec<Bucket>,
}

/// Rows returned per dimension in stats.
pub(crate) const STATS_TOP_N: i64 = 50;

/// Stored value for clicks without a referrer. Parentheses never occur in a
/// parsed referrer host, so this cannot collide with a real one.
pub const DIRECT: &str = "(direct)";

/// Converts days since the Unix epoch to a date.
pub fn day_to_date(day: i32) -> NaiveDate {
    DateTime::from_timestamp(i64::from(day) * 86_400, 0)
        .expect("day within chrono's range")
        .date_naive()
}

/// Connection settings for [`Db::connect`].
#[derive(Clone, Debug)]
pub struct DbConfig {
    pub max_connections: u32,
    /// Size of the separate pool for redirect lookups by code.
    pub lookup_connections: u32,
    /// Bound on every query, including waiting for a pooled connection.
    pub timeout: Duration,
    /// Consecutive failed health probes before a destination is unhealthy.
    pub health_threshold: i16,
    /// Record link changes in the KV outbox (edge publishing is on).
    pub kv_outbox: bool,
}

/// The database handle.
#[derive(Clone)]
pub struct Db {
    pool: PgPool,
    /// Connections that run as [`REDIRECT_ROLE`] for the whole session.
    lookup: PgPool,
    timeout: Duration,
    health_threshold: i16,
    outbox: bool,
}

impl Db {
    /// Builds a pool. Connections are opened lazily, so this succeeds even if
    /// the database is down; [`Db::migrate`] is the first real round trip.
    pub fn connect(options: PgConnectOptions, cfg: &DbConfig) -> Db {
        let options = options
            .application_name("relink")
            .options([("statement_timeout", cfg.timeout.as_millis().to_string())]);
        let pool_options = |size| {
            PgPoolOptions::new()
                .max_connections(size)
                .acquire_timeout(cfg.timeout)
                // A ping before every query would double miss-path latency; a
                // dead connection instead fails one query and is dropped.
                .test_before_acquire(false)
        };
        let pool = pool_options(cfg.max_connections).connect_lazy_with(options.clone());
        // Session-level SET ROLE, once per connection: the lookup itself
        // stays one round trip. Nothing else runs on these connections, so
        // the role is never reset.
        let lookup = pool_options(cfg.lookup_connections)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SELECT set_config('role', $1, false)")
                        .bind(REDIRECT_ROLE)
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect_lazy_with(options);
        Db {
            pool,
            lookup,
            timeout: cfg.timeout,
            health_threshold: cfg.health_threshold,
            outbox: cfg.kv_outbox,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Open and idle connections across both pools, for metrics.
    pub fn pool_stats(&self) -> (u32, usize) {
        (
            self.pool.size() + self.lookup.size(),
            self.pool.num_idle() + self.lookup.num_idle(),
        )
    }

    /// Closes both pools, waiting for checked-out connections to return.
    pub async fn close(&self) {
        tokio::join!(self.pool.close(), self.lookup.close());
    }

    pub(crate) async fn timed<T>(
        &self,
        f: impl Future<Output = Result<T, sqlx::Error>>,
    ) -> Result<T, DbError> {
        match tokio::time::timeout(self.timeout, f).await {
            Ok(r) => r.map_err(DbError::from),
            Err(_) => Err(DbError::Unavailable("query timed out".into())),
        }
    }

    /// Applies pending migrations.
    pub async fn migrate(&self) -> Result<(), DbError> {
        MIGRATOR.run(&self.pool).await.map_err(|e| match e {
            sqlx::migrate::MigrateError::Execute(inner) => DbError::from(inner),
            other => DbError::Other(other.to_string()),
        })
    }

    /// Cheap liveness query for readiness checks.
    pub async fn ping(&self) -> Result<(), DbError> {
        self.timed(sqlx::query("SELECT 1").execute(&self.pool))
            .await
            .map(|_| ())
    }

    pub(crate) fn row_to_link(&self, row: &PgRow) -> Result<StoredLink, sqlx::Error> {
        let Json(destinations): Json<Vec<Destination>> = row.try_get("destinations")?;
        // The redirect path relies on these; a row edited by hand into
        // another shape is reported as an error, not served.
        if destinations.is_empty() || destinations.iter().any(|d| d.weight == 0) {
            return Err(sqlx::Error::Decode(
                "link has no destinations or a zero weight".into(),
            ));
        }
        let geo_mode: Option<String> = row.try_get("geo_mode")?;
        let countries: Vec<String> = row.try_get("geo_countries")?;
        let geo = geo_mode
            .and_then(|m| GeoMode::parse(&m))
            .map(|mode| GeoRule {
                mode,
                countries: countries
                    .iter()
                    .filter_map(|c| <[u8; 2]>::try_from(c.as_bytes()).ok())
                    .collect(),
            });
        let failures: Vec<i16> = row.try_get("health_failures")?;
        let unhealthy = (0..destinations.len())
            .map(|i| failures.get(i).copied().unwrap_or(0) >= self.health_threshold)
            .collect();
        let status: i16 = row.try_get("redirect_status")?;
        let link = Link {
            id: row.try_get("id")?,
            code: row.try_get("code")?,
            destinations,
            destinations_version: row.try_get("destinations_version")?,
            redirect_status: status as u16,
            expires_at: row.try_get("expires_at")?,
            max_clicks: row.try_get("max_clicks")?,
            geo,
            fallback_url: row.try_get("fallback_url")?,
            enabled: row.try_get("enabled")?,
            health_check: row.try_get("health_check")?,
            unhealthy,
        };
        Ok(StoredLink {
            link,
            owner: row.try_get("owner")?,
            workspace_id: row.try_get("workspace_id")?,
            health_checked_at: row.try_get("health_checked_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    /// The link for a code, in any workspace (redirect path and edge
    /// publishing). Runs on the lookup pool as [`REDIRECT_ROLE`], through
    /// the one function that role may call. Retried once on an I/O error
    /// from a pooled connection that died while idle (the pool does not ping
    /// before use, and a read is safe to repeat). Both attempts share one
    /// deadline.
    pub async fn link_by_code(&self, code: &str) -> Result<Option<StoredLink>, DbError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut retried = false;
        loop {
            let query = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM relink_link_by_code($1)"
            ))
            .bind(code)
            .fetch_optional(&self.lookup);
            match tokio::time::timeout_at(deadline, query).await {
                Ok(Ok(row)) => {
                    return row
                        .map(|r| self.row_to_link(&r))
                        .transpose()
                        .map_err(DbError::from);
                }
                Ok(Err(sqlx::Error::Io(_))) if !retried => retried = true,
                Ok(Err(e)) => return Err(DbError::from(e)),
                Err(_) => return Err(DbError::Unavailable("query timed out".into())),
            }
        }
    }

    /// Records that link `code` changed, inside the caller's transaction:
    /// other instances are told to drop their cached copy, and, when edge
    /// publishing is on, the code joins the KV outbox.
    pub(crate) async fn changed(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: i64,
        code: &str,
    ) -> Result<(), sqlx::Error> {
        notify(tx, id, code).await?;
        if self.outbox {
            enqueue(tx, code).await?;
        }
        Ok(())
    }

    /// Claims up to `limit` outbox entries that are due and pushes their next
    /// attempt back with exponential backoff (1 s doubling to 10 min), so a
    /// failed or crashed sync is retried later without coordination.
    /// Returns `(code, enqueued_at)` pairs.
    pub async fn claim_outbox(&self, limit: i64) -> Result<Vec<(String, DateTime<Utc>)>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "UPDATE kv_outbox o
                        SET attempts = o.attempts + 1,
                            next_attempt_at = now() + LEAST(interval '10 minutes',
                                interval '1 second' * power(2, LEAST(o.attempts, 20)))
                      WHERE o.code IN (SELECT code FROM kv_outbox WHERE next_attempt_at <= now()
                                       ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
                  RETURNING o.code, o.enqueued_at",
                )
                .bind(limit)
                .fetch_all(&self.pool),
            )
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("code")?, r.try_get("enqueued_at")?)))
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Removes an outbox entry after a successful sync, unless the link
    /// changed again meanwhile (then the newer entry stays).
    pub async fn finish_outbox(
        &self,
        code: &str,
        enqueued_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        self.timed(
            sqlx::query("DELETE FROM kv_outbox WHERE code = $1 AND enqueued_at = $2")
                .bind(code)
                .bind(enqueued_at)
                .execute(&self.pool),
        )
        .await
        .map(|_| ())
    }

    /// Adds codes to the outbox outside any change (reconciliation).
    pub async fn enqueue_outbox(&self, codes: &[String]) -> Result<(), DbError> {
        if codes.is_empty() {
            return Ok(());
        }
        self.timed(
            sqlx::query(
                "INSERT INTO kv_outbox (code) SELECT * FROM UNNEST($1::text[])
                 ON CONFLICT (code) DO UPDATE SET enqueued_at = clock_timestamp(), attempts = 0,
                                                  next_attempt_at = now()",
            )
            .bind(codes)
            .execute(&self.pool),
        )
        .await
        .map(|_| ())
    }

    /// Entries waiting in the outbox.
    pub async fn outbox_len(&self) -> Result<i64, DbError> {
        self.timed(sqlx::query_scalar("SELECT count(*) FROM kv_outbox").fetch_one(&self.pool))
            .await
    }

    /// Link codes after `after`, in code order, `limit` at a time
    /// (reconciliation walks every link this way).
    pub async fn codes_after(&self, after: &str, limit: i64) -> Result<Vec<String>, DbError> {
        self.timed(
            sqlx::query_scalar("SELECT code FROM links WHERE code > $1 ORDER BY code LIMIT $2")
                .bind(after)
                .bind(limit)
                .fetch_all(&self.pool),
        )
        .await
    }

    /// Reserves a click lease (see [`crate::limiter`]). The row lock taken by
    /// The row lock serialises concurrent reservations for the same link.
    /// `NO KEY UPDATE` rather than `UPDATE`: click flushes hold key-share
    /// locks on links through their foreign keys, and a plain `FOR UPDATE`
    /// would queue behind every flush of a busy link.
    pub async fn reserve_clicks(&self, link_id: i64, max_lease: i64) -> Result<i64, DbError> {
        let granted: Option<i64> = self
            .timed(
                sqlx::query_scalar(
                    "UPDATE links l
                        SET clicks_reserved = l.clicks_reserved + LEAST($2,
                            GREATEST(1, (l.max_clicks - l.clicks_reserved) / 8),
                            l.max_clicks - l.clicks_reserved)
                       FROM (SELECT id, clicks_reserved AS before FROM links
                              WHERE id = $1 FOR NO KEY UPDATE) o
                      WHERE l.id = o.id
                        AND l.max_clicks IS NOT NULL
                        AND l.clicks_reserved < l.max_clicks
                  RETURNING l.clicks_reserved - o.before",
                )
                .bind(link_id)
                .bind(max_lease)
                .fetch_optional(&self.pool),
            )
            .await?;
        Ok(granted.unwrap_or(0))
    }

    /// Returns unspent clicks from a lease.
    pub async fn release_clicks(&self, link_id: i64, n: i64) -> Result<(), DbError> {
        self.timed(
            sqlx::query(
                "UPDATE links SET clicks_reserved = GREATEST(0, clicks_reserved - $2) WHERE id = $1",
            )
            .bind(link_id)
            .bind(n)
            .execute(&self.pool),
        )
        .await
        .map(|_| ())
    }

    /// Clicks reserved so far (for tests and the stats endpoint).
    pub async fn clicks_reserved(&self, link_id: i64) -> Result<i64, DbError> {
        self.timed(
            sqlx::query_scalar("SELECT clicks_reserved FROM links WHERE id = $1")
                .bind(link_id)
                .fetch_one(&self.pool),
        )
        .await
    }

    /// The salt for `day`, created on first use. Concurrent instances agree
    /// because the insert is `ON CONFLICT DO NOTHING` followed by a read.
    ///
    /// Salts exist only for `today` and the day before (see
    /// [`Db::maintain_visitors`]); for an older day this returns whatever is
    /// left and never creates one, because a fresh salt for a day whose
    /// hashes were already rolled up would count those visitors twice.
    pub async fn salt_for_day(&self, day: i32, today: i32) -> Result<Option<[u8; 32]>, DbError> {
        let mut fresh = [0u8; 32];
        crate::util::secure_random(&mut fresh);
        let date = day_to_date(day);
        let may_create = day >= today - 1;
        let salt: Option<Vec<u8>> = self
            .timed(async {
                if may_create {
                    sqlx::query(
                        "INSERT INTO visitor_salts (day, salt) VALUES ($1, $2) ON CONFLICT (day) DO NOTHING",
                    )
                    .bind(date)
                    .bind(&fresh[..])
                    .execute(&self.pool)
                    .await?;
                }
                sqlx::query_scalar("SELECT salt FROM visitor_salts WHERE day = $1")
                    .bind(date)
                    .fetch_optional(&self.pool)
                    .await
            })
            .await?;
        salt.map(|s| {
            <[u8; 32]>::try_from(s.as_slice())
                .map_err(|_| DbError::Other("stored salt has the wrong length".into()))
        })
        .transpose()
    }

    /// Adds aggregated click counts and visitor hashes in one transaction, so
    /// a failed flush can be retried without double counting. Rows for links
    /// deleted in the meantime are skipped.
    pub async fn flush_clicks(
        &self,
        rows: &[(ClickRow, i64)],
        visitors: &[(i64, i32, [u8; 16])],
    ) -> Result<(), DbError> {
        // One input row per stored key: ON CONFLICT DO UPDATE refuses to
        // touch the same row twice in one statement.
        let mut merged: HashMap<(i64, i32, String, &'static str, String), i64> =
            HashMap::with_capacity(rows.len());
        for (row, n) in rows {
            let key = (
                row.link_id,
                row.day,
                String::from_utf8_lossy(&row.country).into_owned(),
                row.device,
                row.referrer.as_deref().unwrap_or(DIRECT).to_owned(),
            );
            *merged.entry(key).or_insert(0) += *n;
        }
        let mut ids = Vec::with_capacity(merged.len());
        let mut days = Vec::with_capacity(merged.len());
        let mut countries = Vec::with_capacity(merged.len());
        let mut devices = Vec::with_capacity(merged.len());
        let mut referrers = Vec::with_capacity(merged.len());
        let mut counts = Vec::with_capacity(merged.len());
        for ((id, day, country, device, referrer), n) in merged {
            ids.push(id);
            days.push(day_to_date(day));
            countries.push(country);
            devices.push(device);
            referrers.push(referrer);
            counts.push(n);
        }
        let v_ids: Vec<i64> = visitors.iter().map(|v| v.0).collect();
        let v_days: Vec<NaiveDate> = visitors.iter().map(|v| day_to_date(v.1)).collect();
        let v_hashes: Vec<Vec<u8>> = visitors.iter().map(|v| v.2.to_vec()).collect();

        let run = || async {
            let mut tx = self.pool.begin().await?;
            if !ids.is_empty() {
                sqlx::query(
                    "INSERT INTO click_daily (link_id, day, country, device, referrer_host, clicks)
                     SELECT u.link_id, u.day, u.country, u.device, u.referrer_host, u.clicks
                       FROM UNNEST($1::bigint[], $2::date[], $3::text[], $4::text[], $5::text[], $6::bigint[])
                            AS u(link_id, day, country, device, referrer_host, clicks)
                       JOIN links l ON l.id = u.link_id
                     ON CONFLICT (link_id, day, country, device, referrer_host)
                     DO UPDATE SET clicks = click_daily.clicks + EXCLUDED.clicks",
                )
                .bind(&ids)
                .bind(&days)
                .bind(&countries)
                .bind(&devices)
                .bind(&referrers)
                .bind(&counts)
                .execute(&mut *tx)
                .await?;
            }
            if !v_ids.is_empty() {
                sqlx::query(
                    "INSERT INTO visitor_daily (link_id, day, visitor)
                     SELECT u.link_id, u.day, u.visitor
                       FROM UNNEST($1::bigint[], $2::date[], $3::bytea[]) AS u(link_id, day, visitor)
                       JOIN links l ON l.id = u.link_id
                     ON CONFLICT DO NOTHING",
                )
                .bind(&v_ids)
                .bind(&v_days)
                .bind(&v_hashes)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await
        };
        // A link deleted between the JOIN and the foreign-key check makes the
        // batch fail once; the retry's JOIN no longer sees it.
        match tokio::time::timeout(self.timeout, run()).await {
            Ok(Err(e)) if DbError::is_fk_violation(&e) => self.timed(run()).await,
            Ok(r) => r.map_err(DbError::from),
            Err(_) => Err(DbError::Unavailable("query timed out".into())),
        }
    }

    /// Claims up to `limit` links due for a health check (not checked within
    /// `interval`), marking them checked now. `SKIP LOCKED` lets several
    /// instances share the work without checking a link twice. The lock is
    /// `NO KEY UPDATE` because click flushes hold key-share locks on busy
    /// links (foreign keys from `click_daily`), and `FOR UPDATE` would skip
    /// exactly the links that get the most traffic.
    pub async fn claim_health_targets(
        &self,
        interval: Duration,
        limit: i64,
    ) -> Result<Vec<HealthTarget>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "UPDATE links SET health_checked_at = now()
                      WHERE id IN (
                            SELECT id FROM links
                             WHERE health_check AND enabled
                               AND (health_checked_at IS NULL
                                    OR health_checked_at < now() - make_interval(secs => $1))
                             ORDER BY health_checked_at NULLS FIRST
                             LIMIT $2
                               FOR NO KEY UPDATE SKIP LOCKED)
                  RETURNING id, code, destinations, destinations_version, health_failures",
                )
                .bind(interval.as_secs_f64())
                .bind(limit)
                .fetch_all(&self.pool),
            )
            .await?;
        rows.iter()
            .map(|r| {
                let Json(destinations): Json<Vec<Destination>> = r.try_get("destinations")?;
                Ok(HealthTarget {
                    id: r.try_get("id")?,
                    code: r.try_get("code")?,
                    destinations,
                    version: r.try_get("destinations_version")?,
                    failures: r.try_get("health_failures")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Stores new failure counts unless the destinations changed since the
    /// claim. Notifies other instances when health flipped for any
    /// destination. Returns whether the row was updated.
    pub async fn record_health(
        &self,
        target: &HealthTarget,
        failures: &[i16],
    ) -> Result<bool, DbError> {
        let flipped = (0..target.destinations.len()).any(|i| {
            let before = target.failures.get(i).copied().unwrap_or(0) >= self.health_threshold;
            let after = failures.get(i).copied().unwrap_or(0) >= self.health_threshold;
            before != after
        });
        self.timed(async {
            let mut tx = self.pool.begin().await?;
            let updated = sqlx::query(
                "UPDATE links SET health_failures = $3 WHERE id = $1 AND destinations_version = $2",
            )
            .bind(target.id)
            .bind(target.version)
            .bind(failures)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            if updated && flipped {
                self.changed(&mut tx, target.id, &target.code).await?;
            }
            tx.commit().await?;
            Ok(updated)
        })
        .await
    }

    /// Housekeeping: rolls up visitor hashes for days whose salt is about to
    /// be destroyed, then destroys old salts. `today` is days since epoch.
    pub async fn maintain_visitors(&self, today: i32) -> Result<(), DbError> {
        // Hashes and salts are kept for today and yesterday (late flushes).
        let cutoff = day_to_date(today - 1);
        self.timed(async {
            let mut tx = self.pool.begin().await?;
            sqlx::query(
                "WITH moved AS (
                    DELETE FROM visitor_daily WHERE day < $1 RETURNING link_id, day)
                 INSERT INTO visitor_rollup (link_id, day, visitors)
                 SELECT link_id, day, count(*) FROM moved GROUP BY link_id, day
                 ON CONFLICT (link_id, day)
                 DO UPDATE SET visitors = visitor_rollup.visitors + EXCLUDED.visitors",
            )
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM visitor_salts WHERE day < $1")
                .bind(cutoff)
                .execute(&mut *tx)
                .await?;
            tx.commit().await
        })
        .await
    }

    /// Stores a new API key hash in the owner's personal workspace (created
    /// on first use), with every scope and no expiry. Returns the key's ID.
    pub async fn insert_api_key(
        &self,
        owner: &str,
        name: &str,
        hash: &[u8; 32],
    ) -> Result<i64, DbError> {
        let key = NewApiKey {
            owner,
            name,
            hash: *hash,
            workspace_id: None,
            scopes: Scopes::ALL,
            lifetime: None,
        };
        match self.create_api_key(&key).await {
            Ok(info) => Ok(info.id),
            Err(KeyError::Db(e)) => Err(e),
            Err(e) => Err(DbError::Other(e.to_string())),
        }
    }

    /// Creates a key for `key.owner` in a workspace they are a member of,
    /// with scopes their role grants. System work: it runs before any
    /// workspace is acting.
    pub async fn create_api_key(&self, key: &NewApiKey<'_>) -> Result<KeyInfo, KeyError> {
        let work = async {
            let mut tx = self.pool.begin().await?;
            let workspace_id = match key.workspace_id {
                Some(id) => id,
                None => personal_workspace(&mut tx, key.owner).await?,
            };
            let row = sqlx::query(
                "SELECT role FROM workspace_members WHERE workspace_id = $1 AND member = $2",
            )
            .bind(workspace_id)
            .bind(key.owner)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(role) = row.as_ref().map(row_role).transpose()?.flatten() else {
                return Err(KeyError::NotMember {
                    owner: key.owner.to_owned(),
                    workspace_id,
                });
            };
            if key.scopes.is_empty() || !key.scopes.is_subset(role.grants()) {
                return Err(KeyError::ScopesExceedRole {
                    role,
                    scopes: key.scopes,
                });
            }
            let row = sqlx::query(
                "INSERT INTO api_keys (owner, name, key_hash, workspace_id, scopes, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, \
                         CASE WHEN $6::float8 IS NULL THEN NULL \
                              ELSE now() + make_interval(secs => $6::float8) END) \
                 RETURNING id, expires_at",
            )
            .bind(key.owner)
            .bind(key.name)
            .bind(&key.hash[..])
            .bind(workspace_id)
            .bind(key.scopes.names())
            .bind(key.lifetime.map(|d| d.as_secs_f64()))
            .fetch_one(&mut *tx)
            .await?;
            let info = KeyInfo {
                id: row.try_get("id")?,
                owner: key.owner.to_owned(),
                workspace_id,
                role,
                scopes: key.scopes,
                expires_at: row.try_get("expires_at")?,
            };
            tx.commit().await?;
            Ok(info)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(KeyError::Db(DbError::Unavailable("query timed out".into()))),
        }
    }

    /// Rotates an active key: inserts a successor with a new hash and the
    /// same owner, workspace, name and lifetime, with its scopes narrowed to
    /// what the owner's role grants today, and ends the old key at
    /// `now + overlap` (or its own expiry, if sooner). Both keys work during
    /// the overlap. A key can be rotated once; its successor carries on.
    pub async fn rotate_api_key(
        &self,
        id: i64,
        new_hash: &[u8; 32],
        overlap: Duration,
    ) -> Result<Rotation, KeyError> {
        let work = async {
            let mut tx = self.pool.begin().await?;
            let row = sqlx::query(
                "SELECT k.owner, k.name, k.workspace_id, k.scopes, k.rotated_to, m.role,
                        k.expires_at - k.created_at AS lifetime
                   FROM api_keys k
                   LEFT JOIN workspace_members m
                          ON m.workspace_id = k.workspace_id AND m.member = k.owner
                  WHERE k.id = $1 AND k.revoked_at IS NULL
                    AND (k.expires_at IS NULL OR k.expires_at > now())
                    FOR UPDATE OF k",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(KeyError::NoSuchKey(id))?;
            let owner: String = row.try_get("owner")?;
            let workspace_id: i64 = row.try_get("workspace_id")?;
            if let Some(successor) = row.try_get::<Option<i64>, _>("rotated_to")? {
                return Err(KeyError::AlreadyRotated { id, successor });
            }
            let Some(role) = row_role(&row)? else {
                return Err(KeyError::NotMember {
                    owner,
                    workspace_id,
                });
            };
            let old_scopes = row_scopes(&row)?;
            let scopes = old_scopes.intersect(role.grants());
            if scopes.is_empty() {
                return Err(KeyError::ScopesExceedRole {
                    role,
                    scopes: old_scopes,
                });
            }
            let lifetime: Option<sqlx::postgres::types::PgInterval> = row.try_get("lifetime")?;
            let name: String = row.try_get("name")?;
            let new = sqlx::query(
                "INSERT INTO api_keys (owner, name, key_hash, workspace_id, scopes, expires_at)
                 VALUES ($1, $2, $3, $4, $5, now() + $6::interval)
                 RETURNING id, expires_at",
            )
            .bind(&owner)
            .bind(&name)
            .bind(&new_hash[..])
            .bind(workspace_id)
            .bind(scopes.names())
            .bind(lifetime)
            .fetch_one(&mut *tx)
            .await?;
            let new_id: i64 = new.try_get("id")?;
            let old_expires_at: DateTime<Utc> = sqlx::query_scalar(
                "UPDATE api_keys
                    SET rotated_to = $2,
                        expires_at = LEAST(expires_at, now() + make_interval(secs => $3::float8))
                  WHERE id = $1
              RETURNING expires_at",
            )
            .bind(id)
            .bind(new_id)
            .bind(overlap.as_secs_f64())
            .fetch_one(&mut *tx)
            .await?;
            let rotation = Rotation {
                new: KeyInfo {
                    id: new_id,
                    owner,
                    workspace_id,
                    role,
                    scopes,
                    expires_at: new.try_get("expires_at")?,
                },
                old_id: id,
                old_expires_at,
            };
            tx.commit().await?;
            Ok(rotation)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(KeyError::Db(DbError::Unavailable("query timed out".into()))),
        }
    }

    /// The ID of `owner`'s personal workspace, created (with `owner` as its
    /// owner member) if it does not exist yet.
    pub async fn personal_workspace(&self, owner: &str) -> Result<i64, DbError> {
        self.timed(async {
            let mut tx = self.pool.begin().await?;
            let id = personal_workspace(&mut tx, owner).await?;
            tx.commit().await?;
            Ok(id)
        })
        .await
    }

    /// Starts a transaction that acts for one workspace: it runs as
    /// [`TENANT_ROLE`] with [`WORKSPACE_SETTING`] set, both local to the
    /// transaction, so row-level security limits every statement in it to
    /// that workspace's rows. Both are reset at commit or rollback, so the
    /// pooled connection goes back to the pool unscoped.
    ///
    /// The scoping travels with `BEGIN` in one simple-query message, so a
    /// tenant transaction costs no extra round trip. The values are a
    /// constant and an integer, so formatting them into the text is safe.
    pub async fn begin_tenant(
        &self,
        workspace_id: i64,
    ) -> Result<Transaction<'static, Postgres>, DbError> {
        self.timed(self.begin_tenant_untimed(workspace_id)).await
    }

    /// [`Db::begin_tenant`] without its own deadline, for callers that bound
    /// the whole transaction with one.
    pub(crate) async fn begin_tenant_untimed(
        &self,
        workspace_id: i64,
    ) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        let begin = format!(
            "BEGIN; SET LOCAL ROLE {TENANT_ROLE}; SET LOCAL {WORKSPACE_SETTING} = '{workspace_id}'"
        );
        self.pool.begin_with(sqlx::AssertSqlSafe(begin)).await
    }

    /// The tenant-scoped queries for one workspace.
    pub fn tenant(&self, workspace_id: i64) -> crate::tenant::Tenant<'_> {
        crate::tenant::Tenant::new(self, workspace_id)
    }

    /// Finds an active (unrevoked, unexpired) key by hash, with its owner's
    /// role in its workspace. Runs before the caller's workspace is known, so
    /// it is system work, not a tenant query. One round trip: the role comes
    /// from a primary-key probe of `workspace_members` in the same query.
    pub async fn api_key_by_hash(&self, hash: &[u8; 32]) -> Result<Option<KeyRow>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT k.id, k.owner, k.workspace_id, k.key_hash, k.scopes, k.expires_at, m.role \
                       FROM api_keys k \
                       LEFT JOIN workspace_members m \
                              ON m.workspace_id = k.workspace_id AND m.member = k.owner \
                      WHERE k.key_hash = $1 AND k.revoked_at IS NULL \
                        AND (k.expires_at IS NULL OR k.expires_at > now())",
                )
                .bind(&hash[..])
                .fetch_optional(&self.pool),
            )
            .await?;
        row.map(|r| {
            Ok(KeyRow {
                id: r.try_get("id")?,
                owner: r.try_get("owner")?,
                workspace_id: r.try_get("workspace_id")?,
                hash: r.try_get("key_hash")?,
                scopes: row_scopes(&r)?,
                expires_at: r.try_get("expires_at")?,
                role: row_role(&r)?,
            })
        })
        .transpose()
        .map_err(|e: sqlx::Error| DbError::from(e))
    }

    /// Revokes a key. Returns false if no active key has that ID.
    pub async fn revoke_api_key(&self, id: i64) -> Result<bool, DbError> {
        self.timed(
            sqlx::query(
                "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(id)
            .execute(&self.pool),
        )
        .await
        .map(|r| r.rows_affected() == 1)
    }
}

/// Scopes an open transaction to `workspace_id` (see [`Db::begin_tenant`]).
/// One round trip: `set_config('role', ..)` is `SET LOCAL ROLE`, and unlike
/// `SET` it takes the workspace as a bound parameter.
pub async fn scope_to_workspace(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('role', $1, true), set_config($2, $3, true)")
        .bind(TENANT_ROLE)
        .bind(WORKSPACE_SETTING)
        .bind(workspace_id.to_string())
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Finds or creates `owner`'s personal workspace inside the caller's
/// transaction. The common case is one indexed read. A concurrent creator
/// makes our insert do nothing and its row invisible to that statement's
/// snapshot, so the read is repeated as a new statement, which sees it.
async fn personal_workspace(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
) -> Result<i64, sqlx::Error> {
    const FIND: &str = "SELECT id FROM workspaces WHERE personal_owner = $1";
    if let Some(id) = sqlx::query_scalar(FIND)
        .bind(owner)
        .fetch_optional(&mut **tx)
        .await?
    {
        return Ok(id);
    }
    let created: Option<i64> = sqlx::query_scalar(
        "WITH w AS (INSERT INTO workspaces (name, personal_owner) VALUES ($1, $1)
                    ON CONFLICT (personal_owner) DO NOTHING RETURNING id),
              m AS (INSERT INTO workspace_members (workspace_id, member, role)
                    SELECT id, $1, 'owner' FROM w)
         SELECT id FROM w",
    )
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await?;
    match created {
        Some(id) => Ok(id),
        None => {
            sqlx::query_scalar(FIND)
                .bind(owner)
                .fetch_one(&mut **tx)
                .await
        }
    }
}

async fn enqueue(tx: &mut Transaction<'_, Postgres>, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO kv_outbox (code) VALUES ($1)
         ON CONFLICT (code) DO UPDATE SET enqueued_at = clock_timestamp(), attempts = 0,
                                          next_attempt_at = now()",
    )
    .bind(code)
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

async fn notify(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    code: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANGES_CHANNEL)
        .bind(format!("{id}:{code}"))
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

pub(crate) fn geo_columns(geo: Option<&GeoRule>) -> (Option<&'static str>, Vec<String>) {
    match geo {
        Some(g) => (Some(g.mode.as_str()), g.country_strings()),
        None => (None, Vec::new()),
    }
}

/// Parses a change notification payload `<id>:<code>`.
pub fn parse_change(payload: &str) -> Option<(i64, &str)> {
    let (id, code) = payload.split_once(':')?;
    let id: i64 = id.parse().ok()?;
    if id <= 0 || !crate::code::is_plausible_code(code) {
        return None;
    }
    Some((id, code))
}

impl LeaseStore for Db {
    fn reserve(
        &self,
        link_id: i64,
        max_lease: i64,
    ) -> BoxFuture<'_, Result<i64, StoreUnavailable>> {
        Box::pin(async move {
            self.reserve_clicks(link_id, max_lease)
                .await
                .map_err(|_| StoreUnavailable)
        })
    }
    fn release(&self, link_id: i64, n: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>> {
        Box::pin(async move {
            self.release_clicks(link_id, n)
                .await
                .map_err(|_| StoreUnavailable)
        })
    }
}

pub(crate) const STATS_COUNTRY: &str = "SELECT country AS value, sum(clicks)::bigint AS clicks FROM click_daily \
     WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY country ORDER BY clicks DESC, value LIMIT $4";
pub(crate) const STATS_DEVICE: &str = "SELECT device AS value, sum(clicks)::bigint AS clicks FROM click_daily \
     WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY device ORDER BY clicks DESC, value LIMIT $4";
pub(crate) const STATS_REFERRER: &str = "SELECT referrer_host AS value, sum(clicks)::bigint AS clicks FROM click_daily \
     WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY referrer_host ORDER BY clicks DESC, value LIMIT $4";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limiter::grant_size;

    #[test]
    fn change_payloads() {
        assert_eq!(parse_change("12:abc"), Some((12, "abc")));
        assert_eq!(parse_change("12:a:b"), None);
        assert_eq!(parse_change("x:abc"), None);
        assert_eq!(parse_change("0:abc"), None);
        assert_eq!(parse_change("-1:abc"), None);
        assert_eq!(parse_change("12"), None);
        assert_eq!(parse_change("12:"), None);
    }

    #[test]
    fn days_convert() {
        assert_eq!(day_to_date(0).to_string(), "1970-01-01");
        assert_eq!(day_to_date(19_000).to_string(), "2022-01-08");
    }

    #[test]
    fn grant_rule_matches_sql_comment() {
        // The SQL in reserve_clicks implements limiter::grant_size.
        assert_eq!(grant_size(100, 0, 1000), 12);
    }

    #[test]
    fn errors_classify() {
        assert_eq!(DbError::from(sqlx::Error::RowNotFound), DbError::NotFound);
        assert!(matches!(
            DbError::from(sqlx::Error::PoolTimedOut),
            DbError::Unavailable(_)
        ));
        assert!(matches!(
            DbError::from(sqlx::Error::ColumnNotFound("x".into())),
            DbError::Other(_)
        ));
        for e in [
            DbError::NotFound,
            DbError::Conflict,
            DbError::Unavailable("x".into()),
            DbError::Other("y".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}

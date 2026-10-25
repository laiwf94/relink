//! Postgres access. Every query is a static string with bound parameters.
//!
//! Each call is bounded by a deadline so a database that stops answering
//! (rather than refusing connections) cannot pin request tasks.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::limiter::{LeaseStore, StoreUnavailable};
use crate::model::{Destination, GeoMode, GeoRule, Link};
use crate::util::BoxFuture;

/// Columns read into a [`Link`], as a literal so queries stay `&'static str`.
macro_rules! columns {
    () => {
        "id, code, owner, destinations, destinations_version, redirect_status, \
         expires_at, max_clicks, geo_mode, geo_countries, fallback_url, enabled, health_check, \
         health_failures, health_checked_at, created_at, updated_at"
    };
}

/// Embedded migrations from `migrations/`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Channel for link change notifications. Payload: `<id>:<code>`.
pub const CHANGES_CHANNEL: &str = "relink_link_changes";

/// Database errors as the rest of the service sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The row does not exist (or belongs to another owner).
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
const STATS_TOP_N: i64 = 50;

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
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(cfg.timeout)
            // A ping before every query would double miss-path latency; a dead
            // connection instead fails one query and is dropped.
            .test_before_acquire(false)
            .connect_lazy_with(options);
        Db {
            pool,
            timeout: cfg.timeout,
            health_threshold: cfg.health_threshold,
            outbox: cfg.kv_outbox,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn timed<T>(
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

    fn row_to_link(&self, row: &PgRow) -> Result<StoredLink, sqlx::Error> {
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
            health_checked_at: row.try_get("health_checked_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    /// The link for a code, regardless of owner (redirect path). Retried
    /// once on an I/O error from a pooled connection that died while idle
    /// (the pool does not ping before use, and a read is safe to repeat).
    /// Both attempts share one deadline.
    pub async fn link_by_code(&self, code: &str) -> Result<Option<StoredLink>, DbError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut retried = false;
        loop {
            let query = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM links WHERE code = $1"
            ))
            .bind(code)
            .fetch_optional(&self.pool);
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

    /// A link owned by `owner`.
    pub async fn owned_link(&self, owner: &str, code: &str) -> Result<StoredLink, DbError> {
        let row = self
            .timed(
                sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE owner = $1 AND code = $2"
                ))
                .bind(owner)
                .bind(code)
                .fetch_optional(&self.pool),
            )
            .await?
            .ok_or(DbError::NotFound)?;
        self.row_to_link(&row).map_err(DbError::from)
    }

    /// Inserts a link. With an alias, a taken code is `Conflict`; with a
    /// random code, collisions are retried with a fresh code up to five times.
    pub async fn insert_link(&self, new: &NewLink, code_len: usize) -> Result<StoredLink, DbError> {
        let attempts = if new.alias.is_some() { 1 } else { 5 };
        for _ in 0..attempts {
            let code = new
                .alias
                .clone()
                .unwrap_or_else(|| crate::code::random_code(code_len));
            let (geo_mode, geo_countries) = geo_columns(new.geo.as_ref());
            let res = self
                .timed(async {
                    let mut tx = self.pool.begin().await?;
                    let row = sqlx::query(concat!(
                        "INSERT INTO links (code, owner, destinations, redirect_status, expires_at, \
                         max_clicks, geo_mode, geo_countries, fallback_url, enabled, health_check) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING ",
                        columns!()
                    ))
                    .bind(&code)
                    .bind(&new.owner)
                    .bind(Json(&new.destinations))
                    .bind(new.redirect_status as i16)
                    .bind(new.expires_at)
                    .bind(new.max_clicks)
                    .bind(geo_mode)
                    .bind(geo_countries)
                    .bind(&new.fallback_url)
                    .bind(new.enabled)
                    .bind(new.health_check)
                    .fetch_one(&mut *tx)
                    .await?;
                    let id: i64 = row.try_get("id")?;
                    // Instances may hold a negative cache entry for this code.
                    self.changed(&mut tx, id, &code).await?;
                    tx.commit().await?;
                    Ok(row)
                })
                .await;
            match res {
                Ok(row) => return self.row_to_link(&row).map_err(DbError::from),
                Err(DbError::Conflict) if new.alias.is_none() => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Other(
            "could not allocate a unique code after 5 attempts".into(),
        ))
    }

    /// Lists an owner's links, newest first, after the cursor (a link ID).
    pub async fn list_links(
        &self,
        owner: &str,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<StoredLink>, DbError> {
        let rows = self
            .timed(
                sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE owner = $1 AND ($2::bigint IS NULL OR id < $2) \
                     ORDER BY id DESC LIMIT $3"
                ))
                .bind(owner)
                .bind(before_id)
                .bind(limit)
                .fetch_all(&self.pool),
            )
            .await?;
        rows.iter()
            .map(|r| self.row_to_link(r))
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Applies `patch` to an owned link in one transaction and notifies other
    /// instances.
    pub async fn update_link(
        &self,
        owner: &str,
        code: &str,
        patch: &LinkPatch,
    ) -> Result<StoredLink, DbError> {
        self.timed(async {
            let mut tx = self.pool.begin().await?;
            let row = sqlx::query(concat!(
                "SELECT ",
                columns!(),
                " FROM links WHERE owner = $1 AND code = $2 FOR NO KEY UPDATE"
            ))
            .bind(owner)
            .bind(code)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
            let mut link = self.row_to_link(&row)?;
            let destinations_changed = match &patch.destinations {
                Some(d) if *d != link.destinations => {
                    link.destinations = d.clone();
                    true
                }
                _ => false,
            };
            if let Some(s) = patch.redirect_status {
                link.redirect_status = s;
            }
            if let Some(e) = patch.expires_at {
                link.expires_at = e;
            }
            if let Some(m) = patch.max_clicks {
                link.max_clicks = m;
            }
            if let Some(g) = &patch.geo {
                link.geo = g.clone();
            }
            if let Some(f) = &patch.fallback_url {
                link.fallback_url = f.clone();
            }
            if let Some(e) = patch.enabled {
                link.enabled = e;
            }
            if let Some(h) = patch.health_check {
                link.health_check = h;
            }
            let (geo_mode, geo_countries) = geo_columns(link.geo.as_ref());
            let row = sqlx::query(concat!(
                "UPDATE links SET destinations = $2, \
                 destinations_version = destinations_version + CASE WHEN $3 THEN 1 ELSE 0 END, \
                 health_failures = CASE WHEN $3 THEN '{}'::smallint[] ELSE health_failures END, \
                 redirect_status = $4, expires_at = $5, max_clicks = $6, geo_mode = $7, \
                 geo_countries = $8, fallback_url = $9, enabled = $10, health_check = $11, \
                 updated_at = now() WHERE id = $1 RETURNING ",
                columns!()
            ))
            .bind(link.id)
            .bind(Json(&link.destinations))
            .bind(destinations_changed)
            .bind(link.redirect_status as i16)
            .bind(link.expires_at)
            .bind(link.max_clicks)
            .bind(geo_mode)
            .bind(geo_countries)
            .bind(&link.fallback_url)
            .bind(link.enabled)
            .bind(link.health_check)
            .fetch_one(&mut *tx)
            .await?;
            let updated = self.row_to_link(&row)?;
            self.changed(&mut tx, updated.id, &updated.code).await?;
            tx.commit().await?;
            Ok(updated)
        })
        .await
    }

    /// Deletes an owned link and its statistics, and notifies other instances.
    /// Returns the deleted link's ID.
    pub async fn delete_link(&self, owner: &str, code: &str) -> Result<i64, DbError> {
        self.timed(async {
            let mut tx = self.pool.begin().await?;
            let id: i64 =
                sqlx::query_scalar("DELETE FROM links WHERE owner = $1 AND code = $2 RETURNING id")
                    .bind(owner)
                    .bind(code)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)?;
            self.changed(&mut tx, id, code).await?;
            tx.commit().await?;
            Ok(id)
        })
        .await
    }

    /// Records that link `code` changed, inside the caller's transaction:
    /// other instances are told to drop their cached copy, and, when edge
    /// publishing is on, the code joins the KV outbox.
    async fn changed(
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

    /// Statistics for an owned link between two dates, inclusive.
    pub async fn stats(
        &self,
        owner: &str,
        code: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Stats, DbError> {
        let link = self.owned_link(owner, code).await?;
        self.timed(async {
            let day_rows = sqlx::query(
                "SELECT d.day, d.clicks, COALESCE(v.visitors, 0)::bigint AS visitors
                   FROM (SELECT day, sum(clicks)::bigint AS clicks FROM click_daily
                          WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY day) d
                   LEFT JOIN (
                        SELECT day, count(*) AS visitors FROM visitor_daily
                         WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY day
                        UNION ALL
                        SELECT day, visitors FROM visitor_rollup
                         WHERE link_id = $1 AND day BETWEEN $2 AND $3) v ON v.day = d.day
                  ORDER BY d.day",
            )
            .bind(link.id)
            .bind(from)
            .bind(to)
            .fetch_all(&self.pool)
            .await?;
            let mut days: Vec<DayStats> = Vec::with_capacity(day_rows.len());
            for r in &day_rows {
                let day: NaiveDate = r.try_get("day")?;
                let clicks: i64 = r.try_get("clicks")?;
                let visitors: i64 = r.try_get("visitors")?;
                // A day can have both live hashes and a rollup during the
                // hand-over; the JOIN then yields two rows to merge.
                match days.last_mut() {
                    Some(last) if last.day == day => last.unique_visitors += visitors,
                    _ => days.push(DayStats {
                        day,
                        clicks,
                        unique_visitors: visitors,
                    }),
                }
            }
            let total_clicks = days.iter().map(|d| d.clicks).sum();
            let countries = self.top(STATS_COUNTRY, link.id, from, to).await?;
            let devices = self.top(STATS_DEVICE, link.id, from, to).await?;
            let referrers = self.top(STATS_REFERRER, link.id, from, to).await?;
            Ok(Stats {
                total_clicks,
                days,
                countries,
                devices,
                referrers,
            })
        })
        .await
    }

    async fn top(
        &self,
        query: &'static str,
        link_id: i64,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<Bucket>, sqlx::Error> {
        let rows = sqlx::query(query)
            .bind(link_id)
            .bind(from)
            .bind(to)
            .bind(STATS_TOP_N)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(Bucket {
                    value: r.try_get("value")?,
                    clicks: r.try_get("clicks")?,
                })
            })
            .collect()
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

    /// Stores a new API key hash. Returns the key's ID.
    pub async fn insert_api_key(
        &self,
        owner: &str,
        name: &str,
        hash: &[u8; 32],
    ) -> Result<i64, DbError> {
        self.timed(
            sqlx::query_scalar(
                "INSERT INTO api_keys (owner, name, key_hash) VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(owner)
            .bind(name)
            .bind(&hash[..])
            .fetch_one(&self.pool),
        )
        .await
    }

    /// Finds an active key by hash: `(id, owner, stored hash)`.
    pub async fn api_key_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(i64, String, Vec<u8>)>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT id, owner, key_hash FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
                )
                .bind(&hash[..])
                .fetch_optional(&self.pool),
            )
            .await?;
        row.map(|r| {
            Ok((
                r.try_get("id")?,
                r.try_get("owner")?,
                r.try_get("key_hash")?,
            ))
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

fn geo_columns(geo: Option<&GeoRule>) -> (Option<&'static str>, Vec<String>) {
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

const STATS_COUNTRY: &str = "SELECT country AS value, sum(clicks)::bigint AS clicks FROM click_daily \
     WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY country ORDER BY clicks DESC, value LIMIT $4";
const STATS_DEVICE: &str = "SELECT device AS value, sum(clicks)::bigint AS clicks FROM click_daily \
     WHERE link_id = $1 AND day BETWEEN $2 AND $3 GROUP BY device ORDER BY clicks DESC, value LIMIT $4";
const STATS_REFERRER: &str = "SELECT referrer_host AS value, sum(clicks)::bigint AS clicks FROM click_daily \
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

//! Tenancy on the request path: which workspace a request acts for, and the
//! queries it may run there.
//!
//! [`Workspace`] is the extractor every management handler takes. It
//! authenticates the caller and settles the workspace: an API key belongs to
//! exactly one, and a request that names a different one in the
//! `Relink-Workspace` header is refused rather than silently served from the
//! key's own.
//!
//! [`Tenant`] holds every query the API runs. Each one runs in its own
//! transaction opened by [`Db::begin_tenant`], so it executes as the tenant
//! role with the workspace set and row-level security (migration 0003) keeps
//! it inside that workspace. The queries carry no `owner` or `workspace_id`
//! filter of their own: a link in another workspace is invisible, so it is
//! "not found" exactly like a code that does not exist.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::NaiveDate;
use sqlx::types::Json;
use sqlx::{Postgres, Row, Transaction};

use crate::api::{ApiError, Authed};
use crate::auth::Principal;
use crate::server::App;
use crate::store::{
    Bucket, DayStats, Db, DbError, LinkPatch, NewLink, STATS_COUNTRY, STATS_DEVICE, STATS_REFERRER,
    STATS_TOP_N, Stats, StoredLink, columns, geo_columns,
};

/// Request header naming the workspace a request is meant for. Optional:
/// without it, a request acts in its key's workspace.
pub const WORKSPACE_HEADER: &str = "relink-workspace";

/// The workspace an authenticated request acts for, and who is acting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    pub id: i64,
    pub principal: Principal,
}

/// Why a `Relink-Workspace` header was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceError {
    /// Not a positive decimal integer.
    Malformed,
    /// A real workspace ID, but not the one this key belongs to.
    Mismatch,
}

/// Settles the workspace for `principal` given the header, if any.
pub fn select_workspace(
    principal: &Principal,
    header: Option<&[u8]>,
) -> Result<i64, WorkspaceError> {
    let Some(raw) = header else {
        return Ok(principal.workspace_id);
    };
    let id = std::str::from_utf8(raw)
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&id| id > 0)
        .ok_or(WorkspaceError::Malformed)?;
    if id == principal.workspace_id {
        Ok(id)
    } else {
        Err(WorkspaceError::Mismatch)
    }
}

impl FromRequestParts<Arc<App>> for Workspace {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let Authed(principal) = Authed::from_request_parts(parts, app).await?;
        let header = parts.headers.get(WORKSPACE_HEADER).map(|v| v.as_bytes());
        match select_workspace(&principal, header) {
            Ok(id) => Ok(Workspace { id, principal }),
            Err(WorkspaceError::Malformed) => Err(ApiError::invalid(
                "Relink-Workspace must be a workspace ID (a positive integer)",
            )),
            Err(WorkspaceError::Mismatch) => Err(ApiError::permission_denied(
                "this API key does not belong to the workspace named in Relink-Workspace",
            )),
        }
    }
}

/// The queries for one workspace. Cheap to make: [`Db::tenant`].
#[derive(Clone, Copy)]
pub struct Tenant<'a> {
    db: &'a Db,
    workspace_id: i64,
}

impl<'a> Tenant<'a> {
    pub fn new(db: &'a Db, workspace_id: i64) -> Tenant<'a> {
        Tenant { db, workspace_id }
    }

    pub fn workspace_id(&self) -> i64 {
        self.workspace_id
    }

    async fn begin(&self) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        self.db.begin_tenant_untimed(self.workspace_id).await
    }

    /// The link with `code` in this workspace.
    pub async fn link(&self, code: &str) -> Result<StoredLink, DbError> {
        let row = self
            .db
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE code = $1"
                ))
                .bind(code)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(row)
            })
            .await?
            .ok_or(DbError::NotFound)?;
        self.db.row_to_link(&row).map_err(DbError::from)
    }

    /// Inserts a link into this workspace, with `new.owner` recorded as its
    /// creator. With an alias, a taken code (in any workspace: codes are
    /// global) is `Conflict`; with a random code, collisions are retried with
    /// a fresh code up to five times.
    pub async fn insert_link(&self, new: &NewLink, code_len: usize) -> Result<StoredLink, DbError> {
        let attempts = if new.alias.is_some() { 1 } else { 5 };
        for _ in 0..attempts {
            let code = new
                .alias
                .clone()
                .unwrap_or_else(|| crate::code::random_code(code_len));
            let (geo_mode, geo_countries) = geo_columns(new.geo.as_ref());
            let res = self
                .db
                .timed(async {
                    let mut tx = self.begin().await?;
                    // workspace_id defaults to the transaction's workspace.
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
                    self.db.changed(&mut tx, id, &code).await?;
                    tx.commit().await?;
                    Ok(row)
                })
                .await;
            match res {
                Ok(row) => return self.db.row_to_link(&row).map_err(DbError::from),
                Err(DbError::Conflict) if new.alias.is_none() => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DbError::Other(
            "could not allocate a unique code after 5 attempts".into(),
        ))
    }

    /// This workspace's links, newest first, after the cursor (a link ID).
    pub async fn list_links(
        &self,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<StoredLink>, DbError> {
        let rows = self
            .db
            .timed(async {
                let mut tx = self.begin().await?;
                // The policy's own predicate on workspace_id, together with
                // this order, walks the (workspace_id, id DESC) index.
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE ($1::bigint IS NULL OR id < $1) ORDER BY id DESC LIMIT $2"
                ))
                .bind(before_id)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(|r| self.db.row_to_link(r))
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Applies `patch` to a link in one transaction and notifies other
    /// instances.
    pub async fn update_link(&self, code: &str, patch: &LinkPatch) -> Result<StoredLink, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links WHERE code = $1 FOR NO KEY UPDATE"
                ))
                .bind(code)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let mut link = self.db.row_to_link(&row)?;
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
                let updated = self.db.row_to_link(&row)?;
                self.db.changed(&mut tx, updated.id, &updated.code).await?;
                tx.commit().await?;
                Ok(updated)
            })
            .await
    }

    /// Deletes a link and its statistics, and notifies other instances.
    /// Returns the deleted link's ID.
    pub async fn delete_link(&self, code: &str) -> Result<i64, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let id: i64 = sqlx::query_scalar("DELETE FROM links WHERE code = $1 RETURNING id")
                    .bind(code)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)?;
                self.db.changed(&mut tx, id, code).await?;
                tx.commit().await?;
                Ok(id)
            })
            .await
    }

    /// Statistics for a link between two dates, inclusive. One transaction,
    /// so every part of the answer comes from the same snapshot.
    pub async fn stats(
        &self,
        code: &str,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Stats, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let id: i64 = sqlx::query_scalar("SELECT id FROM links WHERE code = $1")
                    .bind(code)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)?;
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
                .bind(id)
                .bind(from)
                .bind(to)
                .fetch_all(&mut *tx)
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
                let countries = top(&mut tx, STATS_COUNTRY, id, from, to).await?;
                let devices = top(&mut tx, STATS_DEVICE, id, from, to).await?;
                let referrers = top(&mut tx, STATS_REFERRER, id, from, to).await?;
                tx.commit().await?;
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
}

async fn top(
    tx: &mut Transaction<'_, Postgres>,
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
        .fetch_all(&mut **tx)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Principal {
        Principal {
            key_id: 1,
            owner: "alice".into(),
            workspace_id: 42,
        }
    }

    #[test]
    fn the_key_decides_the_workspace() {
        assert_eq!(select_workspace(&alice(), None), Ok(42));
        assert_eq!(select_workspace(&alice(), Some(b"42")), Ok(42));
        assert_eq!(
            select_workspace(&alice(), Some(b"43")),
            Err(WorkspaceError::Mismatch)
        );
    }

    #[test]
    fn malformed_headers_are_refused() {
        for bad in [
            &b""[..],
            b"0",
            b"-1",
            b"+42",
            b" 42",
            b"42 ",
            b"4x",
            b"\xff",
            b"99999999999999999999",
            b"9223372036854775808",
        ] {
            assert_eq!(
                select_workspace(&alice(), Some(bad)),
                Err(WorkspaceError::Malformed),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // Leading zeros are still the same number.
        assert_eq!(select_workspace(&alice(), Some(b"042")), Ok(42));
    }
}

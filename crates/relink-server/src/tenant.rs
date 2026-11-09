//! Tenancy on the request path: which workspace a request acts for, and the
//! queries it may run there.
//!
//! [`Workspace`] is the extractor every management handler takes. It
//! authenticates the caller and settles the workspace: an API key belongs to
//! exactly one, and a request that names a different one in the
//! `Relink-Workspace` header is refused rather than silently served from the
//! key's own.
//!
//! [`Allowed`] wraps it with the scope a handler needs: the key must carry
//! the scope and its owner's role must grant it, or the request is refused
//! with `permission_denied` before its body is read.
//!
//! [`Tenant`] holds every query the API runs. Each one runs in its own
//! transaction opened by [`Db::begin_tenant`], so it executes as the tenant
//! role with the workspace set and row-level security (migration 0003) keeps
//! it inside that workspace. The queries carry no `owner` or `workspace_id`
//! filter of their own: a link in another workspace is invisible, so it is
//! "not found" exactly like a code that does not exist. Each change also
//! appends to the workspace's audit chain in the same transaction, as the
//! [`Actor`] the `Tenant` was made for.

use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{NaiveDate, Utc};
use sqlx::types::Json;
use sqlx::{Postgres, Row, Transaction};

use crate::api::{ApiError, Authed};
use crate::audit::{self, Action, Actor, Change};
use crate::auth::{Principal, Scope};
use crate::quota::{self, Usage};
use crate::server::App;
use crate::store::{
    Bucket, DayStats, Db, DbError, LinkPatch, NewLink, STATS_COUNTRY, STATS_DEVICE, STATS_REFERRER,
    STATS_TOP_N, Stats, StoredLink, api_columns, columns, geo_columns,
};

/// `WHERE` clause finding a link by code (`$1`) on a domain named by its
/// hostname (`$2`, NULL for the default domain) in the tenant's workspace.
/// A hostname the workspace does not have matches no link (-1 is no
/// domain's ID), rather than falling back to the default domain. Served by
/// the `links_domain_code` index.
macro_rules! by_code {
    () => {
        " WHERE COALESCE(domain_id, 0) = (CASE WHEN $2::text IS NULL THEN 0 ELSE \
         COALESCE((SELECT d.id FROM domains d WHERE d.hostname = $2), -1) END) AND code = $1"
    };
}

/// Request header naming the workspace a request is meant for. Optional:
/// without it, a request acts in its key's workspace.
pub const WORKSPACE_HEADER: &str = "relink-workspace";

/// The workspace an authenticated request acts for, and who is acting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    pub id: i64,
    pub principal: Principal,
}

impl Workspace {
    /// The queries for this workspace, acting as this request's caller.
    pub fn tenant<'a>(&self, db: &'a Db) -> Tenant<'a> {
        Tenant::new(db, self.id).acting_as(Actor::from(&self.principal))
    }
}

/// Why a `Relink-Workspace` header was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceError {
    /// Not a positive decimal integer.
    Malformed,
    /// A real workspace ID, but not the one this key belongs to.
    Mismatch,
}

/// Parses a `Relink-Workspace` value: a positive decimal integer.
pub fn parse_workspace_header(raw: &[u8]) -> Result<i64, WorkspaceError> {
    std::str::from_utf8(raw)
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&id| id > 0)
        .ok_or(WorkspaceError::Malformed)
}

/// The error for a malformed `Relink-Workspace` header.
pub fn malformed_workspace() -> ApiError {
    ApiError::invalid("Relink-Workspace must be a workspace ID (a positive integer)")
}

/// Settles the workspace for `principal` given the header, if any. A
/// session principal already acts in the workspace its header named.
pub fn select_workspace(
    principal: &Principal,
    header: Option<&[u8]>,
) -> Result<i64, WorkspaceError> {
    let Some(raw) = header else {
        return Ok(principal.workspace_id);
    };
    let id = parse_workspace_header(raw)?;
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
            Err(WorkspaceError::Malformed) => Err(malformed_workspace()),
            Err(WorkspaceError::Mismatch) => Err(ApiError::permission_denied(
                "this API key does not belong to the workspace named in Relink-Workspace",
            )),
        }
    }
}

/// A scope a handler requires, as a type so the route declares it.
pub trait RequiredScope: Send + Sync + 'static {
    const SCOPE: Scope;
}

/// Requires `links:read`.
pub struct LinksRead;
/// Requires `links:write`.
pub struct LinksWrite;
/// Requires `stats:read`.
pub struct StatsRead;

impl RequiredScope for LinksRead {
    const SCOPE: Scope = Scope::LinksRead;
}
impl RequiredScope for LinksWrite {
    const SCOPE: Scope = Scope::LinksWrite;
}
impl RequiredScope for StatsRead {
    const SCOPE: Scope = Scope::StatsRead;
}

/// A [`Workspace`] whose caller may use the scope `S` there.
pub struct Allowed<S>(pub Workspace, PhantomData<S>);

impl<S> Deref for Allowed<S> {
    type Target = Workspace;
    fn deref(&self) -> &Workspace {
        &self.0
    }
}

impl<S: RequiredScope> FromRequestParts<Arc<App>> for Allowed<S> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let ws = Workspace::from_request_parts(parts, app).await?;
        match ws.principal.require(S::SCOPE) {
            Ok(()) => Ok(Allowed(ws, PhantomData)),
            Err(denied) => {
                app.metrics.permission_denied.inc();
                Err(ApiError::permission_denied(denied.to_string()))
            }
        }
    }
}

/// The queries for one workspace, and who runs them. Cheap to make:
/// [`Db::tenant`] or [`Workspace::tenant`].
#[derive(Clone)]
pub struct Tenant<'a> {
    db: &'a Db,
    workspace_id: i64,
    actor: Actor,
}

impl<'a> Tenant<'a> {
    /// Changes are recorded as made by the server ([`Actor::system`]) until
    /// [`Tenant::acting_as`] names someone.
    pub fn new(db: &'a Db, workspace_id: i64) -> Tenant<'a> {
        Tenant {
            db,
            workspace_id,
            actor: Actor::system(),
        }
    }

    /// The same queries, with changes recorded as made by `actor`.
    pub fn acting_as(self, actor: Actor) -> Tenant<'a> {
        Tenant { actor, ..self }
    }

    fn change(&self, action: Action, link_id: i64) -> Change {
        Change {
            workspace_id: self.workspace_id,
            action,
            target: format!("link:{link_id}"),
            before: None,
            after: None,
        }
    }

    pub fn workspace_id(&self) -> i64 {
        self.workspace_id
    }

    pub(crate) fn db(&self) -> &'a Db {
        self.db
    }

    /// Who changes made through this `Tenant` are recorded as made by.
    pub(crate) fn actor(&self) -> &Actor {
        &self.actor
    }

    pub(crate) async fn begin(&self) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        self.db.begin_tenant_untimed(self.workspace_id).await
    }

    /// The link with `code` on `domain` (a hostname; `None` for the
    /// default domain) in this workspace.
    pub async fn link(&self, code: &str, domain: Option<&str>) -> Result<StoredLink, DbError> {
        let row = self
            .db
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    api_columns!(),
                    " FROM links",
                    by_code!()
                ))
                .bind(code)
                .bind(domain)
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
    /// creator, if the workspace's plan admits one more (`DbError::Quota`
    /// otherwise; see src/quota.rs). A link on a custom domain needs a
    /// domain this workspace has verified (`DbError::Invalid` otherwise).
    /// With an alias, a code taken on the same domain (by any workspace, for
    /// the default domain) is `Conflict`; with a random code, collisions are
    /// retried with a fresh code up to five times.
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
                    if let Err(q) = quota::admit_new_link(&mut tx, Utc::now().date_naive()).await? {
                        return Ok(Err(DbError::Quota(q)));
                    }
                    let (domain_id, code): (Option<i64>, Cow<'_, str>) = match &new.domain {
                        None => (None, Cow::Borrowed(&code)),
                        Some(host) => {
                            // FOR KEY SHARE: the domain cannot be deleted,
                            // nor its case rule changed, before this link
                            // commits.
                            let row: Option<(i64, bool)> = sqlx::query_as(
                                "SELECT id, COALESCE((settings->>'case_insensitive')::boolean, \
                                 false) FROM domains WHERE hostname = $1 \
                                 AND verified_at IS NOT NULL FOR KEY SHARE",
                            )
                            .bind(host)
                            .fetch_optional(&mut *tx)
                            .await?;
                            match row {
                                // A case-insensitive domain stores its
                                // codes in lowercase, the form visitors'
                                // paths are folded to.
                                Some((id, true)) => {
                                    (Some(id), Cow::Owned(code.to_ascii_lowercase()))
                                }
                                Some((id, false)) => (Some(id), Cow::Borrowed(&code)),
                                None => {
                                    return Ok(Err(DbError::Invalid(format!(
                                        "domain: {host} is not a verified domain of this workspace"
                                    ))));
                                }
                            }
                        }
                    };
                    // workspace_id defaults to the transaction's workspace.
                    let row = sqlx::query(concat!(
                        "INSERT INTO links (code, owner, destinations, redirect_status, expires_at, \
                         max_clicks, geo_mode, geo_countries, fallback_url, enabled, health_check, \
                         domain_id) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING ",
                        api_columns!()
                    ))
                    .bind(&*code)
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
                    .bind(domain_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    let link = self.db.row_to_link(&row)?;
                    // Instances may hold a negative cache entry for this code.
                    self.db.changed(&mut tx, link.id, domain_id, &code).await?;
                    let change = Change {
                        after: Some(audit::link_state(&link)),
                        ..self.change(Action::LinkCreate, link.id)
                    };
                    audit::record(&mut tx, &self.actor, change).await?;
                    tx.commit().await?;
                    Ok(Ok(link))
                })
                .await;
            match res {
                Ok(Ok(link)) => return Ok(link),
                Ok(Err(e)) => return Err(e),
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
                    api_columns!(),
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

    /// Applies `patch` to the link with `code` on `domain` in one
    /// transaction and notifies other instances.
    pub async fn update_link(
        &self,
        code: &str,
        domain: Option<&str>,
        patch: &LinkPatch,
    ) -> Result<StoredLink, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM links",
                    by_code!(),
                    " FOR NO KEY UPDATE"
                ))
                .bind(code)
                .bind(domain)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let mut link = self.db.row_to_link(&row)?;
                let before = audit::link_state(&link);
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
                    api_columns!()
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
                self.db
                    .changed(&mut tx, updated.id, updated.domain_id, &updated.code)
                    .await?;
                let change = Change {
                    before: Some(before),
                    after: Some(audit::link_state(&updated)),
                    ..self.change(Action::LinkUpdate, updated.id)
                };
                audit::record(&mut tx, &self.actor, change).await?;
                tx.commit().await?;
                Ok(updated)
            })
            .await
    }

    /// Deletes the link with `code` on `domain` and its statistics, and
    /// notifies other instances. Returns the deleted link.
    pub async fn delete_link(
        &self,
        code: &str,
        domain: Option<&str>,
    ) -> Result<StoredLink, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "DELETE FROM links",
                    by_code!(),
                    " RETURNING ",
                    columns!()
                ))
                .bind(code)
                .bind(domain)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let deleted = self.db.row_to_link(&row)?;
                let id = deleted.id;
                self.db
                    .changed(&mut tx, id, deleted.domain_id, code)
                    .await?;
                let change = Change {
                    before: Some(audit::link_state(&deleted)),
                    ..self.change(Action::LinkDelete, id)
                };
                audit::record(&mut tx, &self.actor, change).await?;
                tx.commit().await?;
                Ok(deleted)
            })
            .await
    }

    /// The workspace's plan, link count and clicks in the month of the UTC
    /// day `today`.
    pub async fn usage(&self, today: NaiveDate) -> Result<Usage, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let usage = quota::read_usage(&mut tx, today).await?;
                tx.commit().await?;
                Ok(usage)
            })
            .await
    }

    /// Statistics for a link between two dates, inclusive. One transaction,
    /// so every part of the answer comes from the same snapshot.
    pub async fn stats(
        &self,
        code: &str,
        domain: Option<&str>,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Stats, DbError> {
        self.db
            .timed(async {
                let mut tx = self.begin().await?;
                let id: i64 = sqlx::query_scalar(concat!("SELECT id FROM links", by_code!()))
                    .bind(code)
                    .bind(domain)
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
            credential: crate::auth::Credential::ApiKey(1),
            owner: "alice".into(),
            workspace_id: 42,
            role: crate::auth::Role::Owner,
            scopes: crate::auth::Scopes::ALL,
            expires_at: None,
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

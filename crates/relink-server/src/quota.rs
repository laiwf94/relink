//! Plans and quotas: how many links a workspace may hold and how many clicks
//! it may receive in a calendar month (UTC), what it has used, and the
//! operator commands that define plans and move workspaces between them.
//!
//! A plan is a named set of limits in the `plans` table (migration 0008);
//! `None` means no limit, and every workspace starts on `unlimited`.
//!
//! Clicks are metered from the click pipeline: [`Db::flush_clicks`] adds
//! each flushed batch to `workspace_usage` in the transaction that writes it
//! to `click_daily`, keyed by the month of the click's own day. The meter
//! therefore costs nothing on the redirect path and counts exactly the clicks
//! the statistics show.
//!
//! Limits are checked when a link is created, inside the creating
//! transaction ([`admit_new_link`]). A workspace at its link limit, or one
//! that has used its month's clicks, gets [`QuotaExceeded`], which the API
//! answers with the stable code `quota_exceeded`. Redirects are never
//! refused for quota: links already handed out keep working, and their
//! clicks keep being counted.
//!
//! Under a link limit, creating transactions lock the workspace row before
//! counting, so concurrent requests cannot both take the last slot. The
//! count stops at the limit, so the check costs at most `max_links` index
//! entries however large the workspace; workspaces without a link limit
//! take no lock and count nothing.
//!
//! [`Db::flush_clicks`]: crate::store::Db::flush_clicks

use std::fmt;

use chrono::{Datelike, Months, NaiveDate};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};

use crate::audit::{self, Action, Actor, Change};
use crate::auth::is_valid_owner;
use crate::store::{Db, DbError};

/// The plan every workspace starts on: no limits.
pub const DEFAULT_PLAN: &str = "unlimited";

/// A plan's limits. `None` is "no limit".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Limits {
    pub max_links: Option<i64>,
    pub monthly_clicks: Option<i64>,
}

/// A named plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub name: String,
    #[serde(flatten)]
    pub limits: Limits,
}

/// Which limit a request ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaKind {
    Links,
    MonthlyClicks,
}

impl QuotaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            QuotaKind::Links => "links",
            QuotaKind::MonthlyClicks => "monthly_clicks",
        }
    }
}

/// A request refused because the workspace is at one of its plan's limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaExceeded {
    pub kind: QuotaKind,
    pub limit: i64,
    /// When the limit stops applying by itself: the next month, for clicks.
    pub resets_on: Option<NaiveDate>,
}

impl fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, self.resets_on) {
            (QuotaKind::MonthlyClicks, Some(day)) => write!(
                f,
                "the workspace has used the {} clicks its plan allows this month; \
                 new links can be created again on {day}",
                self.limit
            ),
            (QuotaKind::MonthlyClicks, None) => write!(
                f,
                "the workspace has used the {} clicks its plan allows this month",
                self.limit
            ),
            (QuotaKind::Links, _) => write!(
                f,
                "the workspace holds the {} links its plan allows; delete links or move \
                 the workspace to a larger plan",
                self.limit
            ),
        }
    }
}

impl std::error::Error for QuotaExceeded {}

/// The first day of the month `day` falls in.
pub fn month_start(day: NaiveDate) -> NaiveDate {
    day.with_day(1).expect("every month has a first day")
}

/// The first day of the month after the one starting on `start`.
pub fn next_month(start: NaiveDate) -> NaiveDate {
    month_start(start)
        .checked_add_months(Months::new(1))
        .expect("dates stay far inside chrono's range")
}

/// Whether a workspace with `links` links that has had `clicks` clicks this
/// month (starting on `month`) may create one more link under `limits`.
pub fn check_new_link(
    limits: &Limits,
    links: i64,
    clicks: i64,
    month: NaiveDate,
) -> Result<(), QuotaExceeded> {
    if let Some(limit) = limits.max_links
        && links >= limit
    {
        return Err(QuotaExceeded {
            kind: QuotaKind::Links,
            limit,
            resets_on: None,
        });
    }
    if let Some(limit) = limits.monthly_clicks
        && clicks >= limit
    {
        return Err(QuotaExceeded {
            kind: QuotaKind::MonthlyClicks,
            limit,
            resets_on: Some(next_month(month)),
        });
    }
    Ok(())
}

/// Admits one new link in the tenant transaction `tx`, whose workspace is
/// the one being checked, on the UTC day `today`. Under a link limit this
/// locks the workspace row until `tx` ends, so the caller must insert the
/// link in the same transaction.
pub(crate) async fn admit_new_link(
    tx: &mut Transaction<'_, Postgres>,
    today: NaiveDate,
) -> Result<Result<(), QuotaExceeded>, sqlx::Error> {
    let month = month_start(today);
    // Row-level security leaves exactly the transaction's own workspace.
    let row = sqlx::query(
        "SELECT p.max_links, p.monthly_clicks,
                COALESCE((SELECT u.clicks FROM workspace_usage u
                           WHERE u.workspace_id = w.id AND u.month = $1), 0) AS clicks
           FROM workspaces w JOIN plans p ON p.name = w.plan",
    )
    .bind(month)
    .fetch_one(&mut **tx)
    .await?;
    let limits = Limits {
        max_links: row.try_get("max_links")?,
        monthly_clicks: row.try_get("monthly_clicks")?,
    };
    let clicks: i64 = row.try_get("clicks")?;
    let links = match limits.max_links {
        None => 0,
        Some(limit) => {
            // Serialise link creation in this workspace, then count with a
            // fresh snapshot (READ COMMITTED), which includes every link
            // committed by whoever held the lock before.
            sqlx::query("SELECT 1 FROM workspaces FOR NO KEY UPDATE")
                .execute(&mut **tx)
                .await?;
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM (SELECT 1 FROM links LIMIT $1) l")
                .bind(limit)
                .fetch_one(&mut **tx)
                .await?
        }
    };
    Ok(check_new_link(&limits, links, clicks, month))
}

/// One metered quantity and its limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Meter {
    pub used: i64,
    /// `None`: the plan sets no limit.
    pub limit: Option<i64>,
}

/// A workspace's plan and what it has used, as `GET /v1/usage` returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub workspace_id: i64,
    pub plan: String,
    /// The current month, as the first day it includes and the first day it
    /// does not (UTC).
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub links: Meter,
    pub clicks: Meter,
}

/// Reads the usage of the tenant transaction's workspace on the UTC day
/// `today`. One snapshot: the link count and the click meter agree.
pub(crate) async fn read_usage(
    tx: &mut Transaction<'_, Postgres>,
    today: NaiveDate,
) -> Result<Usage, sqlx::Error> {
    let month = month_start(today);
    let row = sqlx::query(
        "SELECT w.id, w.plan, p.max_links, p.monthly_clicks,
                (SELECT count(*) FROM links) AS links,
                COALESCE((SELECT u.clicks FROM workspace_usage u
                           WHERE u.workspace_id = w.id AND u.month = $1), 0) AS clicks
           FROM workspaces w JOIN plans p ON p.name = w.plan",
    )
    .bind(month)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Usage {
        workspace_id: row.try_get("id")?,
        plan: row.try_get("plan")?,
        period_start: month,
        period_end: next_month(month),
        links: Meter {
            used: row.try_get("links")?,
            limit: row.try_get("max_links")?,
        },
        clicks: Meter {
            used: row.try_get("clicks")?,
            limit: row.try_get("monthly_clicks")?,
        },
    })
}

/// A change to a plan's limits: `None` leaves a limit as it is (or, for a
/// new plan, without a limit), `Some(None)` removes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlanChange {
    pub max_links: Option<Option<i64>>,
    pub monthly_clicks: Option<Option<i64>>,
}

/// Why a plan could not be assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    NoSuchWorkspace(i64),
    NoSuchPlan(String),
    Db(DbError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::NoSuchWorkspace(id) => write!(f, "workspace {id} does not exist"),
            PlanError::NoSuchPlan(name) => {
                write!(f, "plan {name:?} does not exist; create it with plan-set")
            }
            PlanError::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PlanError {}

impl From<DbError> for PlanError {
    fn from(e: DbError) -> Self {
        PlanError::Db(e)
    }
}

/// A plan's limits as JSON for the audit log.
fn plan_state(plan: &Plan) -> serde_json::Value {
    serde_json::json!({
        "plan": plan.name,
        "max_links": plan.limits.max_links,
        "monthly_clicks": plan.limits.monthly_clicks,
    })
}

fn row_to_plan(row: &sqlx::postgres::PgRow) -> Result<Plan, sqlx::Error> {
    Ok(Plan {
        name: row.try_get("name")?,
        limits: Limits {
            max_links: row.try_get("max_links")?,
            monthly_clicks: row.try_get("monthly_clicks")?,
        },
    })
}

impl Db {
    /// Creates the plan `name` or changes its limits, and returns it. Plans
    /// belong to no workspace, so this is operator work, not a tenant query.
    pub async fn set_plan(&self, name: &str, change: PlanChange) -> Result<Plan, DbError> {
        if !is_valid_owner(name) {
            return Err(DbError::Other(format!("invalid plan name {name:?}")));
        }
        let row = self
            .timed(
                sqlx::query(
                    "INSERT INTO plans (name, max_links, monthly_clicks) VALUES ($1, $3, $5)
                     ON CONFLICT (name) DO UPDATE SET
                         max_links = CASE WHEN $2 THEN EXCLUDED.max_links ELSE plans.max_links END,
                         monthly_clicks = CASE WHEN $4 THEN EXCLUDED.monthly_clicks
                                               ELSE plans.monthly_clicks END,
                         updated_at = now()
                     RETURNING name, max_links, monthly_clicks",
                )
                .bind(name)
                .bind(change.max_links.is_some())
                .bind(change.max_links.flatten())
                .bind(change.monthly_clicks.is_some())
                .bind(change.monthly_clicks.flatten())
                .fetch_one(self.pool()),
            )
            .await?;
        row_to_plan(&row).map_err(DbError::from)
    }

    /// Every plan, by name.
    pub async fn plans(&self) -> Result<Vec<Plan>, DbError> {
        let rows = self
            .timed(
                sqlx::query("SELECT name, max_links, monthly_clicks FROM plans ORDER BY name")
                    .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(row_to_plan)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Moves a workspace to the plan `name`, recording the move in the
    /// workspace's audit chain as made by `actor`. Returns the plans before
    /// and after. Limits apply from the next request: links over a new,
    /// lower link limit are kept, and only new ones are refused.
    pub async fn assign_plan(
        &self,
        workspace_id: i64,
        name: &str,
        actor: &Actor,
    ) -> Result<(Plan, Plan), PlanError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            let Some(old) = sqlx::query(
                "SELECT p.name, p.max_links, p.monthly_clicks
                       FROM workspaces w JOIN plans p ON p.name = w.plan
                      WHERE w.id = $1 FOR NO KEY UPDATE OF w",
            )
            .bind(workspace_id)
            .fetch_optional(&mut *tx)
            .await?
            else {
                return Ok(Err(PlanError::NoSuchWorkspace(workspace_id)));
            };
            let old = row_to_plan(&old)?;
            // Locks the plan against deletion until the move commits.
            let Some(new) = sqlx::query(
                "SELECT name, max_links, monthly_clicks FROM plans WHERE name = $1 FOR KEY SHARE",
            )
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
            else {
                return Ok(Err(PlanError::NoSuchPlan(name.to_owned())));
            };
            let new = row_to_plan(&new)?;
            sqlx::query("UPDATE workspaces SET plan = $2 WHERE id = $1")
                .bind(workspace_id)
                .bind(&new.name)
                .execute(&mut *tx)
                .await?;
            let change = Change {
                workspace_id,
                action: Action::WorkspacePlan,
                target: format!("workspace:{workspace_id}"),
                before: Some(plan_state(&old)),
                after: Some(plan_state(&new)),
            };
            audit::record(&mut tx, actor, change).await?;
            tx.commit().await?;
            Ok(Ok((old, new)))
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn months_run_from_the_first_to_the_first() {
        assert_eq!(month_start(d(2026, 11, 4)), d(2026, 11, 1));
        assert_eq!(month_start(d(2026, 11, 1)), d(2026, 11, 1));
        assert_eq!(month_start(d(2024, 2, 29)), d(2024, 2, 1));
        assert_eq!(next_month(d(2026, 11, 1)), d(2026, 12, 1));
        assert_eq!(next_month(d(2026, 12, 1)), d(2027, 1, 1));
        // Any day of the month gives the same next month.
        assert_eq!(next_month(d(2026, 1, 31)), d(2026, 2, 1));
    }

    #[test]
    fn limits_admit_up_to_and_not_beyond() {
        let month = d(2026, 11, 1);
        let none = Limits::default();
        assert_eq!(check_new_link(&none, i64::MAX, i64::MAX, month), Ok(()));

        let links = Limits {
            max_links: Some(3),
            monthly_clicks: None,
        };
        assert_eq!(check_new_link(&links, 2, 1_000_000, month), Ok(()));
        let err = check_new_link(&links, 3, 0, month).unwrap_err();
        assert_eq!(err.kind, QuotaKind::Links);
        assert_eq!(err.limit, 3);
        assert_eq!(err.resets_on, None);
        assert!(err.to_string().contains("3 links"), "{err}");

        let clicks = Limits {
            max_links: None,
            monthly_clicks: Some(100),
        };
        assert_eq!(check_new_link(&clicks, 10, 99, month), Ok(()));
        let err = check_new_link(&clicks, 10, 100, month).unwrap_err();
        assert_eq!(err.kind, QuotaKind::MonthlyClicks);
        assert_eq!(err.resets_on, Some(d(2026, 12, 1)));
        assert!(err.to_string().contains("on 2026-12-01"), "{err}");

        // A zero limit refuses everything; the link limit is reported first.
        let zero = Limits {
            max_links: Some(0),
            monthly_clicks: Some(0),
        };
        assert_eq!(
            check_new_link(&zero, 0, 0, month).unwrap_err().kind,
            QuotaKind::Links
        );
    }

    #[test]
    fn messages_name_the_limit() {
        assert_eq!(QuotaKind::Links.as_str(), "links");
        assert_eq!(QuotaKind::MonthlyClicks.as_str(), "monthly_clicks");
        let e = QuotaExceeded {
            kind: QuotaKind::MonthlyClicks,
            limit: 5,
            resets_on: None,
        };
        assert!(e.to_string().contains("5 clicks"));
        assert_eq!(
            PlanError::NoSuchWorkspace(9).to_string(),
            "workspace 9 does not exist"
        );
        assert!(
            PlanError::NoSuchPlan("pro".into())
                .to_string()
                .contains("\"pro\"")
        );
        assert!(
            PlanError::from(DbError::NotFound)
                .to_string()
                .contains("not found")
        );
    }

    #[test]
    fn plans_serialise_flat() {
        let plan = Plan {
            name: "free".into(),
            limits: Limits {
                max_links: Some(10),
                monthly_clicks: None,
            },
        };
        assert_eq!(
            serde_json::to_value(&plan).unwrap(),
            serde_json::json!({"name": "free", "max_links": 10, "monthly_clicks": null})
        );
        assert_eq!(
            plan_state(&plan),
            serde_json::json!({"plan": "free", "max_links": 10, "monthly_clicks": null})
        );
    }
}

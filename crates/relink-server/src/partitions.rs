//! The partition manager for raw click events.
//!
//! `click_events` (migration 0020) is partitioned by calendar month, UTC,
//! one table per month named `click_events_pYYYYMM`. Every instance runs
//! [`maintain`] from its housekeeping loop once a minute; it
//!
//! - creates the partitions for the current month and the [`AHEAD`] months
//!   after it, so an insert never finds its month missing, even after the
//!   server was down across a month boundary; and
//! - drops partitions older than the retention, which is a number of whole
//!   months counting the current one. Dropping a partition frees its space
//!   at once, without a `DELETE`, dead tuples or vacuum.
//!
//! Only one instance does the work at a time: each run takes a transaction
//! advisory lock with `pg_try_advisory_xact_lock` and returns
//! [`Outcome::Busy`] when another instance holds it. Creating or dropping a
//! partition locks the parent table, so the transaction sets a short
//! `lock_timeout`: behind a long query it gives up and tries again on the
//! next tick instead of queueing every insert behind its own lock request.
//!
//! Tables under `click_events` whose name is not exactly
//! `click_events_pYYYYMM` are never dropped; they are reported in
//! [`Report::unknown`] so an operator's own partition is left alone.

use chrono::{Datelike, NaiveDate};
use sqlx::Row;

use crate::store::{Db, DbError, day_to_date};

/// Months after the current one whose partitions are kept ready.
pub const AHEAD: u32 = 2;

/// Upper bound on `RELINK_CLICK_EVENTS_RETENTION_MONTHS` (ten years).
pub const MAX_RETENTION_MONTHS: u32 = 120;

/// Advisory lock key held while partitions are created or dropped
/// ("relink" in ASCII, then 1).
pub const LOCK_KEY: i64 = 0x7265_6c69_6e6b_0001;

const PREFIX: &str = "click_events_p";

/// A calendar month, UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Month(i32);

impl Month {
    /// The month `month` (1 to 12) of `year` (0 to 9999).
    pub fn new(year: i32, month: u32) -> Option<Month> {
        if !(0..=9999).contains(&year) || !(1..=12).contains(&month) {
            return None;
        }
        Some(Month(year * 12 + month as i32 - 1))
    }

    /// The month containing `day`, in days since the Unix epoch.
    pub fn of_day(day: i32) -> Month {
        let d = day_to_date(day);
        Month(d.year() * 12 + d.month0() as i32)
    }

    pub fn year(self) -> i32 {
        self.0.div_euclid(12)
    }

    /// 1 to 12.
    pub fn month(self) -> u32 {
        self.0.rem_euclid(12) as u32 + 1
    }

    /// The month `n` months later (earlier when `n` is negative).
    pub fn plus(self, n: i32) -> Month {
        Month(self.0 + n)
    }

    /// Its first day.
    pub fn first_day(self) -> NaiveDate {
        NaiveDate::from_ymd_opt(self.year(), self.month(), 1).expect("a valid month")
    }

    /// The name of its partition.
    pub fn table(self) -> String {
        format!("{PREFIX}{:04}{:02}", self.year(), self.month())
    }

    /// The month of a partition named by [`Month::table`], or `None` for
    /// any other name.
    pub fn parse_table(name: &str) -> Option<Month> {
        let digits = name.strip_prefix(PREFIX)?;
        if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Month::new(digits[..4].parse().ok()?, digits[4..].parse().ok()?)
    }
}

/// What a run should change, given the partitions that exist.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Missing months from the current one to [`AHEAD`] months later, oldest
    /// first.
    pub create: Vec<Month>,
    /// Existing months older than the retention, oldest first.
    pub drop: Vec<Month>,
}

/// The months to create and drop so that partitions exist from `current`
/// to `current + AHEAD` and none is older than `retention` months counting
/// `current` (so `retention = 1` keeps only the current month and later).
pub fn plan(existing: &[Month], current: Month, retention: u32) -> Plan {
    let retention = retention.clamp(1, MAX_RETENTION_MONTHS) as i32;
    let oldest_kept = current.plus(1 - retention);
    let create = (0..=AHEAD as i32)
        .map(|n| current.plus(n))
        .filter(|m| !existing.contains(m))
        .collect();
    let mut drop: Vec<Month> = existing
        .iter()
        .copied()
        .filter(|&m| m < oldest_kept)
        .collect();
    drop.sort_unstable();
    drop.dedup();
    Plan { create, drop }
}

/// What a run changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub created: Vec<Month>,
    pub dropped: Vec<Month>,
    /// Partitions of `click_events` with names the manager does not own.
    pub unknown: Vec<String>,
}

/// The result of [`maintain`].
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done(Report),
    /// Another instance is maintaining the partitions right now.
    Busy,
}

/// Brings the partitions in line with [`plan`] for the month of `today`
/// (days since the epoch), in one transaction.
pub async fn maintain(db: &Db, today: i32, retention: u32) -> Result<Outcome, DbError> {
    let current = Month::of_day(today);
    db.timed(async {
        let mut tx = db.pool().begin().await?;
        // How long creating or dropping a partition waits for its lock.
        sqlx::query("SET LOCAL lock_timeout = '1s'")
            .execute(&mut *tx)
            .await?;
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(LOCK_KEY)
            .fetch_one(&mut *tx)
            .await?;
        if !locked {
            return Ok(Outcome::Busy);
        }
        let rows = sqlx::query(
            "SELECT c.relname::text AS name
               FROM pg_inherits i
               JOIN pg_class c ON c.oid = i.inhrelid
              WHERE i.inhparent = 'click_events'::regclass
              ORDER BY 1",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut report = Report::default();
        let mut existing = Vec::with_capacity(rows.len());
        for row in rows {
            let name: String = row.get("name");
            match Month::parse_table(&name) {
                Some(m) => existing.push(m),
                None => report.unknown.push(name),
            }
        }
        let todo = plan(&existing, current, retention);
        for m in todo.create {
            let created: bool = sqlx::query_scalar("SELECT relink_click_events_partition($1)")
                .bind(m.first_day())
                .fetch_one(&mut *tx)
                .await?;
            if created {
                report.created.push(m);
            }
        }
        for m in todo.drop {
            // The name comes from Month::table: "click_events_p" and six
            // digits, so it needs no quoting.
            sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {}", m.table())))
                .execute(&mut *tx)
                .await?;
            report.dropped.push(m);
        }
        tx.commit().await?;
        Ok(Outcome::Done(report))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn m(year: i32, month: u32) -> Month {
        Month::new(year, month).unwrap()
    }

    fn day(y: i32, mo: u32, d: u32) -> i32 {
        let date = NaiveDate::from_ymd_opt(y, mo, d).unwrap();
        (date - NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()).num_days() as i32
    }

    #[test]
    fn months_from_days() {
        assert_eq!(Month::of_day(0), m(1970, 1));
        assert_eq!(Month::of_day(day(2026, 11, 30)), m(2026, 11));
        assert_eq!(Month::of_day(day(2026, 12, 1)), m(2026, 12));
        assert_eq!(Month::of_day(day(2028, 2, 29)), m(2028, 2));
        assert_eq!(Month::of_day(-1), m(1969, 12));
    }

    #[test]
    fn arithmetic_crosses_years() {
        assert_eq!(m(2026, 11).plus(2), m(2027, 1));
        assert_eq!(m(2027, 1).plus(-13), m(2025, 12));
        assert_eq!(
            m(2026, 12).first_day(),
            NaiveDate::from_ymd_opt(2026, 12, 1).unwrap()
        );
        assert!(m(2026, 12) < m(2027, 1));
    }

    #[test]
    fn rejects_out_of_range_months() {
        assert_eq!(Month::new(2026, 0), None);
        assert_eq!(Month::new(2026, 13), None);
        assert_eq!(Month::new(-1, 1), None);
        assert_eq!(Month::new(10_000, 1), None);
    }

    #[test]
    fn table_names_round_trip_and_nothing_else_parses() {
        assert_eq!(m(2026, 11).table(), "click_events_p202611");
        assert_eq!(m(812, 3).table(), "click_events_p081203");
        assert_eq!(
            Month::parse_table("click_events_p202611"),
            Some(m(2026, 11))
        );
        for bad in [
            "click_events_p20261",
            "click_events_p2026111",
            "click_events_p202613",
            "click_events_p202600",
            "click_events_p2026-1",
            "click_events_p+20261",
            "click_events_default",
            "click_events_p２０２６１１",
            "x_click_events_p202611",
            "",
        ] {
            assert_eq!(Month::parse_table(bad), None, "{bad}");
        }
    }

    #[test]
    fn plan_from_nothing_creates_the_current_month_and_two_ahead() {
        let p = plan(&[], m(2026, 11), 13);
        assert_eq!(p.create, vec![m(2026, 11), m(2026, 12), m(2027, 1)]);
        assert!(p.drop.is_empty());
    }

    #[test]
    fn plan_drops_months_past_retention_and_keeps_the_rest() {
        let existing: Vec<Month> = (0..20).map(|n| m(2025, 1).plus(n)).collect();
        // Current is 2026-06; 13 months keeps 2025-06 to 2026-06.
        let p = plan(&existing, m(2026, 6), 13);
        assert_eq!(
            p.drop,
            (0..5).map(|n| m(2025, 1).plus(n)).collect::<Vec<_>>()
        );
        assert!(p.create.is_empty(), "2026-07 and 2026-08 exist: {p:?}");
        // One month keeps only the current month and later.
        let p = plan(&existing, m(2026, 6), 1);
        assert_eq!(p.drop.len(), 17);
        assert_eq!(*p.drop.last().unwrap(), m(2026, 5));
    }

    #[test]
    fn plan_never_drops_future_months_and_fills_gaps() {
        // The server was off from 2026-02 to 2026-09; months ahead of the
        // clock (a clock that went backwards) are left alone.
        let existing = [m(2026, 1), m(2026, 2), m(2026, 3), m(2027, 6)];
        let p = plan(&existing, m(2026, 9), 3);
        assert_eq!(p.create, vec![m(2026, 9), m(2026, 10), m(2026, 11)]);
        assert_eq!(p.drop, vec![m(2026, 1), m(2026, 2), m(2026, 3)]);
    }

    #[test]
    fn retention_is_clamped() {
        let existing = [m(2026, 10)];
        assert_eq!(plan(&existing, m(2026, 11), 0).drop, vec![m(2026, 10)]);
        let old = [m(2010, 1)];
        assert!(plan(&old, m(2019, 12), u32::MAX).drop.is_empty());
        assert_eq!(plan(&old, m(2020, 1), u32::MAX).drop, vec![m(2010, 1)]);
    }

    proptest! {
        #[test]
        fn plan_holds_its_invariants(
            existing in proptest::collection::vec(0i32..400, 0..40),
            current in 0i32..400,
            retention in 1u32..=MAX_RETENTION_MONTHS,
        ) {
            let base = m(2000, 1);
            let existing: Vec<Month> = existing.into_iter().map(|n| base.plus(n)).collect();
            let current = base.plus(current);
            let p = plan(&existing, current, retention);
            let after: Vec<Month> = existing
                .iter()
                .copied()
                .filter(|x| !p.drop.contains(x))
                .chain(p.create.iter().copied())
                .collect();
            // Every month from current to current + AHEAD exists afterwards.
            for n in 0..=AHEAD as i32 {
                prop_assert!(after.contains(&current.plus(n)));
            }
            // Nothing older than the retention survives, everything within
            // it does, and only existing months are dropped.
            let oldest = current.plus(1 - retention as i32);
            for x in &after {
                prop_assert!(*x >= oldest);
            }
            for x in &existing {
                prop_assert_eq!(p.drop.contains(x), *x < oldest);
            }
            // Running the plan again changes nothing.
            prop_assert_eq!(plan(&after, current, retention), Plan::default());
        }
    }
}

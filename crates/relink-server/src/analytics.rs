//! The analytics query API, `GET /v1/analytics` (docs/DESIGN.md, "Querying
//! analytics").
//!
//! A query names a period, a granularity, up to three dimensions to group
//! by, filters on any dimension, how many groups to return and optionally
//! a period to compare with. [`parse`] turns the query string into a
//! [`Query`] and checks every limit before the database is touched; [`run`]
//! answers it from the rollups in one read-only snapshot:
//!
//! - clicks from `click_daily` when the period is whole UTC days and the
//!   granularity is a day or longer, otherwise from `click_hourly`;
//! - unique visitors by merging the HyperLogLog++ sketches of the same
//!   resolution (`visitor_sketch_daily` or `visitor_sketch_hourly`). The
//!   sketches are per link and period, so visitors are reported only when
//!   the query groups and filters by link alone; otherwise `visitors` is
//!   null rather than a number that would be wrong.
//!
//! Every query has a cost limit: the rollup rows and sketches it reads,
//! together, may not exceed `RELINK_ANALYTICS_MAX_ROWS`. The scan is a
//! `LIMIT`ed, materialised CTE, so the database never reads more than one
//! row past the limit before the query is refused, however broad it was.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chrono::{DateTime, Datelike, Duration, Months, NaiveDate, NaiveTime, Utc};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder, Row, Transaction};

use crate::classify::Device;
use crate::hll::Hll;
use crate::store::{DIRECT, Db, DbError};

/// Longest period, in days (a compared period is extra).
pub const MAX_RANGE_DAYS: i64 = 366;
/// Most points in one time series.
pub const MAX_POINTS: usize = 1_000;
/// Most dimensions to group by.
pub const MAX_GROUP_BY: usize = 3;
/// Most values in one filter.
pub const MAX_FILTER_VALUES: usize = 50;
/// Groups returned when `limit` is not given.
pub const DEFAULT_LIMIT: u32 = 10;
/// Most groups returned.
pub const MAX_LIMIT: u32 = 100;
/// Default and bounds of `RELINK_ANALYTICS_MAX_ROWS`.
pub const DEFAULT_MAX_ROWS: u64 = 1_000_000;
pub const MIN_MAX_ROWS: u64 = 1_000;
pub const MAX_MAX_ROWS: u64 = 100_000_000;

const HOUR_SECS: i64 = 3_600;
const DAY_SECS: i64 = 86_400;

/// The resolution of the returned time series.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    Hour,
    Day,
    /// ISO weeks, starting on Monday.
    Week,
    Month,
    /// One point for the whole period.
    All,
}

impl Granularity {
    fn parse(s: &str) -> Option<Granularity> {
        Some(match s {
            "hour" => Granularity::Hour,
            "day" => Granularity::Day,
            "week" => Granularity::Week,
            "month" => Granularity::Month,
            "all" => Granularity::All,
            _ => return None,
        })
    }

    /// The `date_trunc` unit, for the granularities that truncate.
    fn unit(self) -> Option<&'static str> {
        match self {
            Granularity::Day => Some("day"),
            Granularity::Week => Some("week"),
            Granularity::Month => Some("month"),
            Granularity::Hour | Granularity::All => None,
        }
    }
}

/// Something clicks can be grouped and filtered by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dimension {
    Link,
    Country,
    Device,
    Referrer,
}

impl Dimension {
    const ALL: [Dimension; 4] = [
        Dimension::Link,
        Dimension::Country,
        Dimension::Device,
        Dimension::Referrer,
    ];

    fn parse(s: &str) -> Option<Dimension> {
        Some(match s {
            "link" => Dimension::Link,
            "country" => Dimension::Country,
            "device" => Dimension::Device,
            "referrer" => Dimension::Referrer,
            _ => return None,
        })
    }

    /// The column in the rollup tables.
    fn column(self) -> &'static str {
        match self {
            Dimension::Link => "link_id",
            Dimension::Country => "country",
            Dimension::Device => "device",
            Dimension::Referrer => "referrer_host",
        }
    }

    /// The column in the query's output, NULL when not grouped by.
    fn null(self) -> &'static str {
        match self {
            Dimension::Link => "NULL::bigint",
            _ => "NULL::text",
        }
    }

    /// The column as the tie-break when ranking groups: byte order, so the
    /// database and this module agree on which of two equal groups is first.
    fn order(self) -> String {
        match self {
            Dimension::Link => "link_id".into(),
            d => format!("{} COLLATE \"C\"", d.column()),
        }
    }
}

/// The period to compare with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Compare {
    /// The period of the same length just before.
    Previous,
    /// The same period a year earlier.
    Year,
}

/// Which rollups answer a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Hourly,
    Daily,
}

/// A link named in a filter: its code, on a custom domain or (no host) on
/// the default domain. Written `code` or `host/code`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkRef {
    pub host: Option<String>,
    pub code: String,
}

impl fmt::Display for LinkRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Some(h) => write!(f, "{h}/{}", self.code),
            None => f.write_str(&self.code),
        }
    }
}

/// The query string of `GET /v1/analytics`. Lists are comma-separated.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    pub from: Option<String>,
    pub to: Option<String>,
    pub granularity: Option<String>,
    pub group_by: Option<String>,
    pub link: Option<String>,
    pub country: Option<String>,
    pub device: Option<String>,
    pub referrer: Option<String>,
    pub limit: Option<u32>,
    pub compare: Option<String>,
}

/// A checked query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The period, `[from, to)`, on whole hours.
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub granularity: Granularity,
    pub group_by: Vec<Dimension>,
    pub links: Vec<LinkRef>,
    pub countries: Vec<String>,
    pub devices: Vec<String>,
    pub referrers: Vec<String>,
    pub limit: u32,
    pub compare: Option<Compare>,
    /// The compared period, `[from, to)`, when there is one.
    pub previous: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub source: Source,
}

impl Query {
    /// Whether unique visitors can be answered: sketches exist per link and
    /// period only.
    pub fn has_visitors(&self) -> bool {
        self.group_by.iter().all(|d| *d == Dimension::Link)
            && self.countries.is_empty()
            && self.devices.is_empty()
            && self.referrers.is_empty()
    }

    /// The start of every point of the series, in order.
    pub fn buckets(&self) -> Vec<DateTime<Utc>> {
        buckets(self.from, self.to, self.granularity)
    }
}

fn floor_to(t: DateTime<Utc>, secs: i64) -> DateTime<Utc> {
    let s = t.timestamp().div_euclid(secs) * secs;
    DateTime::from_timestamp(s, 0).expect("within range")
}

fn ceil_to(t: DateTime<Utc>, secs: i64) -> DateTime<Utc> {
    let floor = floor_to(t, secs);
    if floor == t && t.timestamp_subsec_nanos() == 0 {
        t
    } else {
        floor + Duration::seconds(secs)
    }
}

fn midnight(d: NaiveDate) -> DateTime<Utc> {
    d.and_time(NaiveTime::MIN).and_utc()
}

fn is_whole(t: DateTime<Utc>, secs: i64) -> bool {
    t.timestamp().rem_euclid(secs) == 0 && t.timestamp_subsec_nanos() == 0
}

/// The start of every point between `from` and `to`: the first is the
/// start of the unit that contains `from`, as `date_trunc` computes it.
pub fn buckets(from: DateTime<Utc>, to: DateTime<Utc>, g: Granularity) -> Vec<DateTime<Utc>> {
    let mut out = Vec::new();
    let step = |t: DateTime<Utc>| -> Option<DateTime<Utc>> {
        match g {
            Granularity::Hour => Some(t + Duration::hours(1)),
            Granularity::Day => Some(t + Duration::days(1)),
            Granularity::Week => Some(t + Duration::days(7)),
            Granularity::Month => t.checked_add_months(Months::new(1)),
            Granularity::All => None,
        }
    };
    let mut t = match g {
        Granularity::All => from,
        Granularity::Hour => floor_to(from, HOUR_SECS),
        Granularity::Day => floor_to(from, DAY_SECS),
        Granularity::Week => {
            let day = from.date_naive();
            midnight(day - Duration::days(i64::from(day.weekday().num_days_from_monday())))
        }
        Granularity::Month => midnight(from.date_naive().with_day(1).expect("day 1 exists")),
    };
    while t < to {
        out.push(t);
        // Never more than the limit plus one: enough to refuse the query.
        if out.len() > MAX_POINTS {
            break;
        }
        match step(t) {
            Some(next) => t = next,
            None => break,
        }
    }
    out
}

/// `from` or `to`: an RFC 3339 instant on a whole hour, or a date. A date
/// as `from` is its first moment; as `to` it is included, so the period
/// ends at the next midnight.
fn parse_time(name: &str, raw: &str, is_to: bool) -> Result<DateTime<Utc>, String> {
    let raw = raw.trim();
    if let Ok(d) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let start = midnight(d);
        return Ok(if is_to {
            start + Duration::days(1)
        } else {
            start
        });
    }
    let t = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| format!("{name} must be a date (YYYY-MM-DD) or an RFC 3339 time"))?
        .with_timezone(&Utc);
    if !is_whole(t, HOUR_SECS) {
        return Err(format!("{name} must be on a whole hour"));
    }
    Ok(t)
}

fn list(raw: &Option<String>) -> Vec<&str> {
    let mut out: Vec<&str> = raw
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn filter<T: Ord>(
    name: &str,
    raw: &Option<String>,
    each: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, String> {
    let values = list(raw);
    if values.len() > MAX_FILTER_VALUES {
        return Err(format!("{name} takes at most {MAX_FILTER_VALUES} values"));
    }
    let mut out = values
        .into_iter()
        .map(|v| each(v).ok_or_else(|| format!("{name}: {v:?} is not valid")))
        .collect::<Result<Vec<T>, String>>()?;
    // Values that differ only before normalisation are one value.
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn link_ref(v: &str) -> Option<LinkRef> {
    let (host, code) = match v.rsplit_once('/') {
        Some((h, c)) => {
            let h = h.trim_end_matches('.').to_ascii_lowercase();
            if h.is_empty() || h.len() > 253 {
                return None;
            }
            (Some(h), c)
        }
        None => (None, v),
    };
    (!code.is_empty() && code.len() <= 128).then(|| LinkRef {
        host,
        code: code.to_owned(),
    })
}

fn country(v: &str) -> Option<String> {
    (v.len() == 2 && v.bytes().all(|b| b.is_ascii_alphabetic())).then(|| v.to_ascii_uppercase())
}

fn device(v: &str) -> Option<String> {
    Device::parse(&v.to_ascii_lowercase()).map(|d| d.as_str().to_owned())
}

fn referrer(v: &str) -> Option<String> {
    if v == DIRECT {
        return Some(DIRECT.to_owned());
    }
    let v = v.trim_end_matches('.').to_ascii_lowercase();
    (!v.is_empty()
        && v.len() <= 253
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.:_[]".contains(&b)))
    .then_some(v)
}

/// Checks a query string. `now` sets the default period;
/// `hourly_retention_days` is how far back hourly rollups go.
pub fn parse(p: &Params, now: DateTime<Utc>, hourly_retention_days: u32) -> Result<Query, String> {
    let granularity = match p.granularity.as_deref() {
        None => Granularity::Day,
        Some(g) => Granularity::parse(g.trim())
            .ok_or_else(|| "granularity must be one of hour, day, week, month or all".to_owned())?,
    };
    let to = match &p.to {
        Some(raw) => parse_time("to", raw, true)?,
        None if granularity == Granularity::Hour => ceil_to(now, HOUR_SECS),
        None => ceil_to(now, DAY_SECS),
    };
    let from = match &p.from {
        Some(raw) => parse_time("from", raw, false)?,
        None => {
            to - match granularity {
                Granularity::Hour => Duration::hours(24),
                Granularity::Week => Duration::weeks(12),
                Granularity::Month => Duration::days(365),
                Granularity::Day | Granularity::All => Duration::days(30),
            }
        }
    };
    if from >= to {
        return Err("from must be before to".into());
    }
    if to - from > Duration::days(MAX_RANGE_DAYS) {
        return Err(format!("the period must be at most {MAX_RANGE_DAYS} days"));
    }
    if buckets(from, to, granularity).len() > MAX_POINTS {
        return Err(format!(
            "the series would have more than {MAX_POINTS} points; use a longer granularity or a shorter period"
        ));
    }

    let mut group_by = Vec::new();
    for raw in p
        .group_by
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
    {
        if raw.is_empty() {
            continue;
        }
        let d = Dimension::parse(raw).ok_or_else(|| {
            format!("group_by: {raw:?} is not one of link, country, device or referrer")
        })?;
        if group_by.contains(&d) {
            return Err(format!("group_by names {raw} twice"));
        }
        group_by.push(d);
    }
    if group_by.len() > MAX_GROUP_BY {
        return Err(format!("group_by takes at most {MAX_GROUP_BY} dimensions"));
    }

    let limit = p.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }

    let compare = match p.compare.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("previous") => Some(Compare::Previous),
        Some("year") => Some(Compare::Year),
        Some(_) => return Err("compare must be previous or year".into()),
    };
    let previous = match compare {
        None => None,
        Some(Compare::Previous) => Some((from - (to - from), from)),
        Some(Compare::Year) => {
            let back = |t: DateTime<Utc>| t.checked_sub_months(Months::new(12));
            match (back(from), back(to)) {
                (Some(f), Some(t)) => Some((f, t)),
                _ => return Err("the compared period is out of range".into()),
            }
        }
    };

    let day_aligned = [
        Some(from),
        Some(to),
        previous.map(|p| p.0),
        previous.map(|p| p.1),
    ]
    .into_iter()
    .flatten()
    .all(|t| is_whole(t, DAY_SECS));
    let source = if granularity == Granularity::Hour || !day_aligned {
        Source::Hourly
    } else {
        Source::Daily
    };
    if source == Source::Hourly {
        let earliest = previous.map_or(from, |p| p.0);
        let kept = floor_to(now, HOUR_SECS) - Duration::days(i64::from(hourly_retention_days));
        if earliest < kept {
            return Err(format!(
                "hourly analytics are kept for {hourly_retention_days} days; \
                 for older periods use whole days (UTC) and a granularity of a day or longer"
            ));
        }
    }

    Ok(Query {
        from,
        to,
        granularity,
        group_by,
        links: filter("link", &p.link, link_ref)?,
        countries: filter("country", &p.country, country)?,
        devices: filter("device", &p.device, device)?,
        referrers: filter("referrer", &p.referrer, referrer)?,
        limit,
        compare,
        previous,
        source,
    })
}

/// Clicks and, where they can be counted, unique visitors.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Counts {
    pub clicks: i64,
    /// Estimated from HyperLogLog++ sketches; `None` when the query groups
    /// or filters by something other than links.
    pub visitors: Option<u64>,
}

/// One point of a series.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Point {
    pub t: DateTime<Utc>,
    pub clicks: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitors: Option<u64>,
}

/// One of the top groups.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Group {
    /// The dimension values, by dimension name; a link as `code` or
    /// `host/code`.
    pub key: BTreeMap<Dimension, String>,
    pub clicks: i64,
    pub visitors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<Counts>,
    /// The group's points, those with clicks only; absent for
    /// `granularity=all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<Vec<Point>>,
}

/// The totals over the period.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Total {
    pub clicks: i64,
    pub visitors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<Counts>,
}

/// The answer to a [`Query`].
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    /// Rollup rows and sketches read, counted against the cost limit.
    pub rows_scanned: u64,
    pub total: Total,
    /// Every point of the period, including those without clicks.
    pub series: Vec<Point>,
    /// The top groups by clicks, most first (ties in byte order of the
    /// key); empty without `group_by`.
    pub groups: Vec<Group>,
}

/// Why a query was not answered.
#[derive(Debug)]
pub enum QueryError {
    Db(DbError),
    /// The query would read more rows than the cost limit allows.
    TooExpensive {
        max_rows: u64,
    },
}

impl From<DbError> for QueryError {
    fn from(e: DbError) -> QueryError {
        QueryError::Db(e)
    }
}

impl From<sqlx::Error> for QueryError {
    fn from(e: sqlx::Error) -> QueryError {
        QueryError::Db(DbError::from(e))
    }
}

/// A group's dimension values, as the query returns them.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key {
    link: Option<i64>,
    country: Option<String>,
    device: Option<String>,
    referrer: Option<String>,
}

impl Key {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Key, sqlx::Error> {
        Ok(Key {
            link: row.try_get("link_id")?,
            country: row.try_get("country")?,
            device: row.try_get("device")?,
            referrer: row.try_get("referrer")?,
        })
    }

    /// The tuple the database ranks ties by: the grouped values in
    /// `group_by` order.
    fn rank(&self, group_by: &[Dimension]) -> Vec<Vec<u8>> {
        group_by
            .iter()
            .map(|d| match d {
                // Sign flipped so byte order is numeric order.
                Dimension::Link => (self.link.unwrap_or(0) as u64 ^ (1 << 63))
                    .to_be_bytes()
                    .to_vec(),
                Dimension::Country => self.country.clone().unwrap_or_default().into_bytes(),
                Dimension::Device => self.device.clone().unwrap_or_default().into_bytes(),
                Dimension::Referrer => self.referrer.clone().unwrap_or_default().into_bytes(),
            })
            .collect()
    }
}

/// A period's time column, for binding it in the right type.
#[derive(Clone, Copy)]
enum Bound {
    At(DateTime<Utc>),
    Day(NaiveDate),
}

fn bound(source: Source, t: DateTime<Utc>) -> Bound {
    match source {
        Source::Hourly => Bound::At(t),
        Source::Daily => Bound::Day(t.date_naive()),
    }
}

fn push_bound(qb: &mut QueryBuilder<Postgres>, b: Bound) {
    match b {
        Bound::At(t) => qb.push_bind(t),
        Bound::Day(d) => qb.push_bind(d),
    };
}

/// The table, its time column, and the expression for a row's point.
fn table(q: &Query, kind: Table) -> (&'static str, &'static str, String) {
    let (table, col) = match (q.source, kind) {
        (Source::Hourly, Table::Clicks) => ("click_hourly", "hour"),
        (Source::Daily, Table::Clicks) => ("click_daily", "day"),
        (Source::Hourly, Table::Sketches) => ("visitor_sketch_hourly", "hour"),
        (Source::Daily, Table::Sketches) => ("visitor_sketch_daily", "day"),
    };
    let bucket = match (q.source, q.granularity.unit()) {
        (_, None) if q.granularity == Granularity::All => "NULL::timestamptz".to_owned(),
        (Source::Hourly, None) => "x.hour".to_owned(),
        (Source::Hourly, Some(unit)) => format!("date_trunc('{unit}', x.hour, 'UTC')"),
        (Source::Daily, Some("day")) => "(x.day::timestamp AT TIME ZONE 'UTC')".to_owned(),
        (Source::Daily, Some(unit)) => {
            format!("(date_trunc('{unit}', x.day::timestamp) AT TIME ZONE 'UTC')")
        }
        (Source::Daily, None) => unreachable!("hourly granularity is answered from hours"),
    };
    (table, col, bucket)
}

#[derive(Clone, Copy)]
enum Table {
    Clicks,
    Sketches,
}

/// The `WHERE` clause both scans share: the periods, the links and the
/// filters. `cur` is a predicate true for rows of the period itself.
fn push_where(qb: &mut QueryBuilder<Postgres>, q: &Query, col: &str, link_ids: &Option<Vec<i64>>) {
    let range = |qb: &mut QueryBuilder<Postgres>, f: DateTime<Utc>, t: DateTime<Utc>| {
        qb.push(format_args!("(x.{col} >= "));
        push_bound(qb, bound(q.source, f));
        qb.push(format_args!(" AND x.{col} < "));
        push_bound(qb, bound(q.source, t));
        qb.push(")");
    };
    qb.push(" WHERE (");
    range(qb, q.from, q.to);
    if let Some((f, t)) = q.previous {
        qb.push(" OR ");
        range(qb, f, t);
    }
    qb.push(")");
    match link_ids {
        Some(ids) => {
            qb.push(" AND x.link_id = ANY(");
            qb.push_bind(ids.clone());
            qb.push(")");
        }
        // Through the workspace's links, so the primary keys (which start
        // with link_id) serve the scan; row-level security limits `links`
        // to the workspace.
        None => {
            qb.push(" AND x.link_id IN (SELECT id FROM links)");
        }
    }
    for (column, values) in [
        ("country", &q.countries),
        ("device", &q.devices),
        ("referrer_host", &q.referrers),
    ] {
        if !values.is_empty() {
            qb.push(format_args!(" AND x.{column} = ANY("));
            qb.push_bind(values.clone());
            qb.push(")");
        }
    }
}

/// The four key columns of an output row: the grouped ones read from the
/// scan (with `prefix`), NULL otherwise, and all NULL without a prefix.
fn key_columns(q: &Query, prefix: Option<&str>) -> String {
    Dimension::ALL
        .iter()
        .map(|d| {
            let out = match d {
                Dimension::Referrer => "referrer",
                other => other.column(),
            };
            match prefix {
                Some(p) if q.group_by.contains(d) => format!("{p}{} AS {out}", d.column()),
                _ => format!("{} AS {out}", d.null()),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The clicks query: one statement over one materialised, `LIMIT`ed scan.
/// Output rows by `kind`: 0 is the rows scanned, 1 the total per point,
/// 2 the compared period's total, 3 a top group's clicks per point and 4 a
/// top group's clicks in the compared period.
fn clicks_sql(q: &Query, link_ids: &Option<Vec<i64>>, scan_limit: i64) -> QueryBuilder<Postgres> {
    let (table, col, bucket) = table(q, Table::Clicks);
    let mut qb = QueryBuilder::new("WITH scan AS MATERIALIZED (SELECT ");
    qb.push(format_args!("x.{col} >= "));
    push_bound(&mut qb, bound(q.source, q.from));
    qb.push(format_args!(" AS cur, {bucket} AS t"));
    for d in &q.group_by {
        qb.push(format_args!(", x.{}", d.column()));
    }
    qb.push(format_args!(", x.clicks FROM {table} x"));
    push_where(&mut qb, q, col, link_ids);
    qb.push(" LIMIT ");
    qb.push_bind(scan_limit);
    qb.push(")");

    let grouped: Vec<&str> = q.group_by.iter().map(|d| d.column()).collect();
    let g = grouped.join(", ");
    if !q.group_by.is_empty() {
        let order: Vec<String> = q.group_by.iter().map(|d| d.order()).collect();
        qb.push(format_args!(
            ", grp AS (SELECT {g} FROM scan WHERE cur GROUP BY {g} \
             ORDER BY sum(clicks) DESC, {} LIMIT ",
            order.join(", ")
        ));
        qb.push_bind(i64::from(q.limit));
        qb.push(")");
    }
    let none = key_columns(q, None);
    qb.push(format_args!(
        " SELECT 0 AS kind, NULL::timestamptz AS t, {none}, count(*)::bigint AS clicks FROM scan \
         UNION ALL SELECT 1, t, {none}, sum(clicks)::bigint FROM scan WHERE cur GROUP BY t"
    ));
    if q.previous.is_some() {
        qb.push(format_args!(
            " UNION ALL SELECT 2, NULL, {none}, COALESCE(sum(clicks), 0)::bigint FROM scan WHERE NOT cur"
        ));
    }
    if !q.group_by.is_empty() {
        let k = key_columns(q, Some("s."));
        let sg: Vec<String> = grouped.iter().map(|c| format!("s.{c}")).collect();
        let sg = sg.join(", ");
        qb.push(format_args!(
            " UNION ALL SELECT 3, s.t, {k}, sum(s.clicks)::bigint FROM scan s JOIN grp USING ({g}) \
             WHERE s.cur GROUP BY s.t, {sg}"
        ));
        if q.previous.is_some() {
            qb.push(format_args!(
                " UNION ALL SELECT 4, NULL, {k}, sum(s.clicks)::bigint FROM scan s JOIN grp USING ({g}) \
                 WHERE NOT s.cur GROUP BY {sg}"
            ));
        }
    }
    qb
}

/// The sketches query, in point order so one point is merged at a time.
fn sketches_sql(q: &Query, link_ids: &Option<Vec<i64>>, scan_limit: i64) -> QueryBuilder<Postgres> {
    let (table, col, bucket) = table(q, Table::Sketches);
    let mut qb = QueryBuilder::new("SELECT x.link_id, ");
    qb.push(format_args!("x.{col} >= "));
    push_bound(&mut qb, bound(q.source, q.from));
    qb.push(format_args!(
        " AS cur, {bucket} AS t, x.sketch FROM {table} x"
    ));
    push_where(&mut qb, q, col, link_ids);
    qb.push(format_args!(" ORDER BY x.{col} LIMIT "));
    qb.push_bind(scan_limit);
    qb
}

/// Finds the links a filter names; a name that matches none is an error.
async fn resolve_links(
    tx: &mut Transaction<'_, Postgres>,
    links: &[LinkRef],
) -> Result<Vec<i64>, QueryError> {
    let hosts: Vec<String> = links
        .iter()
        .map(|l| l.host.clone().unwrap_or_default())
        .collect();
    let codes: Vec<String> = links.iter().map(|l| l.code.clone()).collect();
    let rows = sqlx::query(
        "SELECT f.ord, l.id
           FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS f(host, code, ord)
           JOIN links l ON l.code = f.code
                       AND COALESCE(l.domain_id, 0) = CASE WHEN f.host = '' THEN 0 ELSE
                           COALESCE((SELECT d.id FROM domains d WHERE d.hostname = f.host), -1) END",
    )
    .bind(&hosts)
    .bind(&codes)
    .fetch_all(&mut **tx)
    .await?;
    let mut found: HashMap<i64, i64> = HashMap::new();
    for r in &rows {
        found.insert(r.try_get("ord")?, r.try_get("id")?);
    }
    let mut ids = Vec::with_capacity(links.len());
    for (i, l) in links.iter().enumerate() {
        match found.get(&(i as i64 + 1)) {
            Some(id) => ids.push(*id),
            None => return Err(DbError::Missing(format!("no link {l} in this workspace")).into()),
        }
    }
    Ok(ids)
}

/// The names of links, as `code` or `host/code`.
async fn link_names(
    tx: &mut Transaction<'_, Postgres>,
    ids: Vec<i64>,
) -> Result<HashMap<i64, String>, QueryError> {
    let rows = sqlx::query(
        "SELECT l.id, l.code, d.hostname FROM links l LEFT JOIN domains d ON d.id = l.domain_id
          WHERE l.id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for r in &rows {
        let name = LinkRef {
            host: r.try_get("hostname")?,
            code: r.try_get("code")?,
        };
        out.insert(r.try_get::<i64, _>("id")?, name.to_string());
    }
    Ok(out)
}

fn estimate(h: &Hll) -> u64 {
    h.count()
}

/// A top group's clicks: in the period, in the compared period, and per
/// point (`None` for `granularity=all`).
#[derive(Default)]
struct GroupClicks {
    clicks: i64,
    previous: i64,
    points: Vec<(Option<DateTime<Utc>>, i64)>,
}

/// What the sketch scan adds to a report.
#[derive(Default)]
struct Visitors {
    total: Hll,
    previous: Hll,
    points: HashMap<DateTime<Utc>, u64>,
    groups: HashMap<i64, (Hll, Hll)>,
}

/// Answers `q` for `workspace_id` in one read-only snapshot, reading at most
/// `max_rows` rollup rows and sketches.
pub async fn run(
    db: &Db,
    workspace_id: i64,
    q: &Query,
    max_rows: u64,
) -> Result<Report, QueryError> {
    let work = async {
        let mut tx = db.begin_tenant_snapshot_untimed(workspace_id).await?;
        let link_ids = if q.links.is_empty() {
            None
        } else {
            Some(resolve_links(&mut tx, &q.links).await?)
        };
        let limit = i64::try_from(max_rows).unwrap_or(i64::MAX - 1) + 1;
        let rows = clicks_sql(q, &link_ids, limit)
            .build()
            .fetch_all(&mut *tx)
            .await?;

        let mut scanned = 0u64;
        let mut per_point: HashMap<Option<DateTime<Utc>>, i64> = HashMap::new();
        let mut previous_clicks = 0i64;
        let mut groups: HashMap<Key, GroupClicks> = HashMap::new();
        for r in &rows {
            let kind: i32 = r.try_get("kind")?;
            let clicks: i64 = r.try_get("clicks")?;
            let t: Option<DateTime<Utc>> = r.try_get("t")?;
            match kind {
                0 => scanned = clicks as u64,
                1 => {
                    per_point.insert(t, clicks);
                }
                2 => previous_clicks = clicks,
                3 => {
                    let g = groups.entry(Key::from_row(r)?).or_default();
                    g.clicks += clicks;
                    g.points.push((t, clicks));
                }
                4 => groups.entry(Key::from_row(r)?).or_default().previous = clicks,
                _ => unreachable!("the query returns kinds 0 to 4"),
            }
        }
        if scanned > max_rows {
            return Err(QueryError::TooExpensive { max_rows });
        }
        let mut ranked: Vec<(Key, GroupClicks)> = groups.into_iter().collect();
        ranked.sort_by(|a, b| {
            b.1.clicks
                .cmp(&a.1.clicks)
                .then_with(|| a.0.rank(&q.group_by).cmp(&b.0.rank(&q.group_by)))
        });

        let visitors = if q.has_visitors() {
            let by_link = q.group_by == [Dimension::Link];
            let mut v = Visitors::default();
            if by_link {
                for (k, _) in &ranked {
                    if let Some(id) = k.link {
                        v.groups.insert(id, Default::default());
                    }
                }
            }
            let remaining = max_rows - scanned;
            let limit = i64::try_from(remaining).unwrap_or(i64::MAX - 1) + 1;
            let mut qb = sketches_sql(q, &link_ids, limit);
            let mut stream = qb.build().fetch(&mut *tx);
            let mut point: Option<(Option<DateTime<Utc>>, Hll)> = None;
            let mut read = 0u64;
            let per_point = q.granularity != Granularity::All;
            while let Some(r) = stream.try_next().await? {
                read += 1;
                if read > remaining {
                    return Err(QueryError::TooExpensive { max_rows });
                }
                let link: i64 = r.try_get("link_id")?;
                let cur: bool = r.try_get("cur")?;
                let t: Option<DateTime<Utc>> = r.try_get("t")?;
                let bytes: Vec<u8> = r.try_get("sketch")?;
                let sketch = Hll::from_bytes(&bytes)
                    .map_err(|e| DbError::Other(format!("stored sketch of link {link}: {e}")))?;
                if let Some((cur_g, prev_g)) = v.groups.get_mut(&link) {
                    if cur { cur_g } else { prev_g }.merge(&sketch);
                }
                if !cur {
                    v.previous.merge(&sketch);
                    continue;
                }
                v.total.merge(&sketch);
                if per_point {
                    // Rows come in time order, so a point is complete when
                    // the next one starts.
                    match &mut point {
                        Some((pt, acc)) if *pt == t => acc.merge(&sketch),
                        _ => {
                            if let Some((Some(pt), acc)) = point.take() {
                                v.points.insert(pt, estimate(&acc));
                            }
                            point = Some((t, sketch));
                        }
                    }
                }
            }
            drop(stream);
            if let Some((Some(pt), acc)) = point.take() {
                v.points.insert(pt, estimate(&acc));
            }
            scanned += read;
            Some(v)
        } else {
            None
        };

        let names = if q.group_by.contains(&Dimension::Link) {
            link_names(&mut tx, ranked.iter().filter_map(|(k, _)| k.link).collect()).await?
        } else {
            HashMap::new()
        };
        tx.commit().await?;

        let total_visitors = visitors.as_ref().map(|v| estimate(&v.total));
        let series = q
            .buckets()
            .into_iter()
            .map(|b| {
                let key = (q.granularity != Granularity::All).then_some(b);
                Point {
                    t: b,
                    clicks: per_point.get(&key).copied().unwrap_or(0),
                    visitors: visitors.as_ref().map(|v| {
                        if q.granularity == Granularity::All {
                            estimate(&v.total)
                        } else {
                            v.points.get(&b).copied().unwrap_or(0)
                        }
                    }),
                }
            })
            .collect();
        let total_clicks = per_point.values().sum();
        let groups = ranked
            .into_iter()
            .map(|(k, g)| {
                let GroupClicks {
                    clicks,
                    previous: prev,
                    mut points,
                } = g;
                let gv = visitors
                    .as_ref()
                    .and_then(|v| k.link.and_then(|id| v.groups.get(&id)));
                let mut key = BTreeMap::new();
                for d in &q.group_by {
                    let value = match d {
                        Dimension::Link => k
                            .link
                            .and_then(|id| names.get(&id).cloned())
                            .unwrap_or_default(),
                        Dimension::Country => k.country.clone().unwrap_or_default(),
                        Dimension::Device => k.device.clone().unwrap_or_default(),
                        Dimension::Referrer => k.referrer.clone().unwrap_or_default(),
                    };
                    key.insert(*d, value);
                }
                points.sort_by_key(|p| p.0);
                Group {
                    key,
                    clicks,
                    visitors: gv.map(|g| estimate(&g.0)),
                    previous: q.previous.map(|_| Counts {
                        clicks: prev,
                        visitors: gv.map(|g| estimate(&g.1)),
                    }),
                    series: (q.granularity != Granularity::All).then(|| {
                        points
                            .into_iter()
                            .filter_map(|(t, clicks)| {
                                t.map(|t| Point {
                                    t,
                                    clicks,
                                    visitors: None,
                                })
                            })
                            .collect()
                    }),
                }
            })
            .collect();
        Ok(Report {
            rows_scanned: scanned,
            total: Total {
                clicks: total_clicks,
                visitors: total_visitors,
                previous: q.previous.map(|_| Counts {
                    clicks: previous_clicks,
                    visitors: visitors.as_ref().map(|v| estimate(&v.previous)),
                }),
            },
            series,
            groups,
        })
    };
    match db.timed(async { Ok::<_, sqlx::Error>(work.await) }).await {
        Ok(r) => r,
        Err(e) => Err(QueryError::Db(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn now() -> DateTime<Utc> {
        at("2026-11-20T10:17:42Z")
    }

    fn params(pairs: &[(&str, &str)]) -> Params {
        let qs: String = pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", v.replace(' ', "%20")))
            .collect::<Vec<_>>()
            .join("&");
        serde_urlencoded_like(&qs)
    }

    /// Parses a query string the way axum's `Query` does.
    fn serde_urlencoded_like(qs: &str) -> Params {
        let uri: axum::http::Uri = format!("/?{qs}").parse().unwrap();
        axum::extract::Query::<Params>::try_from_uri(&uri)
            .unwrap()
            .0
    }

    fn ok(pairs: &[(&str, &str)]) -> Query {
        parse(&params(pairs), now(), 92).unwrap()
    }

    fn err(pairs: &[(&str, &str)]) -> String {
        parse(&params(pairs), now(), 92).unwrap_err()
    }

    #[test]
    fn defaults_are_the_last_30_days_by_day_from_daily_rollups() {
        let q = ok(&[]);
        assert_eq!(q.to, at("2026-11-21T00:00:00Z"));
        assert_eq!(q.from, at("2026-10-22T00:00:00Z"));
        assert_eq!(q.granularity, Granularity::Day);
        assert_eq!(q.source, Source::Daily);
        assert_eq!(q.limit, DEFAULT_LIMIT);
        assert!(q.group_by.is_empty() && q.compare.is_none() && q.previous.is_none());
        assert_eq!(q.buckets().len(), 30);
        assert!(q.has_visitors());
    }

    #[test]
    fn default_periods_per_granularity() {
        let q = ok(&[("granularity", "hour")]);
        assert_eq!(q.to, at("2026-11-20T11:00:00Z"));
        assert_eq!(q.from, at("2026-11-19T11:00:00Z"));
        assert_eq!(q.source, Source::Hourly);
        assert_eq!(q.buckets().len(), 24);
        let q = ok(&[("granularity", "week")]);
        assert_eq!(q.to - q.from, Duration::weeks(12));
        let q = ok(&[("granularity", "month")]);
        assert_eq!(q.to - q.from, Duration::days(365));
        assert_eq!(q.buckets().len(), 13);
        let q = ok(&[("granularity", "all")]);
        assert_eq!(q.buckets(), vec![q.from]);
        // Exactly midnight is its own ceiling.
        let midnight = at("2026-11-20T00:00:00Z");
        let q = parse(&Params::default(), midnight, 92).unwrap();
        assert_eq!(q.to, midnight);
    }

    #[test]
    fn dates_include_their_last_day_and_instants_are_half_open() {
        let q = ok(&[("from", "2026-11-01"), ("to", "2026-11-03")]);
        assert_eq!(q.from, at("2026-11-01T00:00:00Z"));
        assert_eq!(q.to, at("2026-11-04T00:00:00Z"));
        assert_eq!(q.buckets().len(), 3);
        let q = ok(&[
            ("from", "2026-11-19T06:00:00Z"),
            ("to", "2026-11-19T09:00:00%2B01:00"),
        ]);
        assert_eq!(q.to, at("2026-11-19T08:00:00Z"));
        assert_eq!(q.source, Source::Hourly, "not whole days");
        assert_eq!(
            q.buckets(),
            vec![at("2026-11-19T00:00:00Z")],
            "one day point, starting where date_trunc puts it"
        );
    }

    #[test]
    fn source_is_daily_only_for_whole_days_and_daily_or_longer_points() {
        for g in ["day", "week", "month", "all"] {
            let q = ok(&[
                ("from", "2026-11-01"),
                ("to", "2026-11-10"),
                ("granularity", g),
            ]);
            assert_eq!(q.source, Source::Daily, "{g}");
        }
        let q = ok(&[
            ("from", "2026-11-18"),
            ("to", "2026-11-19"),
            ("granularity", "hour"),
        ]);
        assert_eq!(q.source, Source::Hourly);
        assert_eq!(q.buckets().len(), 48);
    }

    #[test]
    fn hourly_data_is_refused_past_its_retention() {
        // 92 days before 10:00 on 20 November is 10:00 on 20 August.
        let e = err(&[
            ("from", "2026-08-20T09:00:00Z"),
            ("to", "2026-08-21T00:00:00Z"),
        ]);
        assert!(e.contains("kept for 92 days"), "{e}");
        ok(&[
            ("from", "2026-08-20T10:00:00Z"),
            ("to", "2026-08-21T00:00:00Z"),
        ]);
        // Whole days go to the daily rollups, which are kept with the link.
        let q = ok(&[("from", "2026-01-01"), ("to", "2026-01-31")]);
        assert_eq!(q.source, Source::Daily);
        // A compared period counts too.
        let e = err(&[
            ("from", "2026-11-19T00:00:00Z"),
            ("to", "2026-11-19T05:00:00Z"),
            ("compare", "year"),
        ]);
        assert!(e.contains("kept for"), "{e}");
    }

    #[test]
    fn periods_are_bounded() {
        assert!(err(&[("from", "2026-11-02"), ("to", "2026-11-01")]).contains("before"));
        assert!(err(&[("from", "2025-01-01"), ("to", "2026-01-02")]).contains("366"));
        ok(&[("from", "2025-01-01"), ("to", "2026-01-01")]);
        let e = err(&[
            ("from", "2026-10-01"),
            ("to", "2026-11-20"),
            ("granularity", "hour"),
        ]);
        assert!(e.contains("points"), "{e}");
        assert!(err(&[("from", "2026-11-01T10:30:00Z")]).contains("whole hour"));
        assert!(err(&[("to", "yesterday")]).contains("RFC 3339"));
        assert!(err(&[("granularity", "minute")]).contains("granularity"));
    }

    #[test]
    fn group_by_filters_limit_and_compare() {
        let q = ok(&[
            ("group_by", "country, link"),
            ("country", "de,US,de"),
            ("device", "Mobile"),
            ("referrer", "News.Example.org.,(direct)"),
            ("link", "abc,go.example.com/xyz,Go.Example.COM./xyz"),
            ("limit", "100"),
            ("compare", "previous"),
        ]);
        assert_eq!(q.group_by, [Dimension::Country, Dimension::Link]);
        assert_eq!(q.countries, ["DE", "US"]);
        assert_eq!(q.devices, ["mobile"]);
        assert_eq!(q.referrers, ["(direct)", "news.example.org"]);
        assert_eq!(
            q.links,
            [
                LinkRef {
                    host: None,
                    code: "abc".into()
                },
                LinkRef {
                    host: Some("go.example.com".into()),
                    code: "xyz".into()
                },
            ]
        );
        assert!(!q.has_visitors());
        assert_eq!(q.limit, 100);
        assert_eq!(q.compare, Some(Compare::Previous));
        assert_eq!(q.previous, Some((q.from - (q.to - q.from), q.from)));

        let q = ok(&[("group_by", "link"), ("compare", "year"), ("link", "a")]);
        assert!(q.has_visitors());
        assert_eq!(
            q.previous.unwrap().0,
            q.from.checked_sub_months(Months::new(12)).unwrap()
        );

        assert!(err(&[("group_by", "city")]).contains("group_by"));
        assert!(err(&[("group_by", "link,link")]).contains("twice"));
        assert!(err(&[("limit", "0")]).contains("limit"));
        assert!(err(&[("limit", "101")]).contains("limit"));
        assert!(err(&[("compare", "last")]).contains("compare"));
        assert!(err(&[("country", "DEU")]).contains("country"));
        assert!(err(&[("device", "fridge")]).contains("device"));
        assert!(err(&[("referrer", "a b")]).contains("referrer"));
        assert!(err(&[("link", "/abc")]).contains("link"));
        assert!(err(&[("link", "host/")]).contains("link"));
        let many: Vec<String> = (0..=MAX_FILTER_VALUES).map(|i| format!("c{i}")).collect();
        assert!(err(&[("link", &many.join(","))]).contains("at most"));
    }

    #[test]
    fn group_by_takes_at_most_three_dimensions() {
        let q = ok(&[("group_by", "link,country,device")]);
        assert_eq!(q.group_by.len(), 3);
        assert!(err(&[("group_by", "link,country,device,referrer")]).contains("at most 3"));
    }

    #[test]
    fn buckets_match_date_trunc() {
        // Wednesday 18 November: its week starts on Monday the 16th.
        let b = buckets(
            at("2026-11-18T05:00:00Z"),
            at("2026-12-02T00:00:00Z"),
            Granularity::Week,
        );
        assert_eq!(
            b,
            vec![
                at("2026-11-16T00:00:00Z"),
                at("2026-11-23T00:00:00Z"),
                at("2026-11-30T00:00:00Z")
            ]
        );
        let b = buckets(
            at("2026-01-31T00:00:00Z"),
            at("2026-04-01T00:00:00Z"),
            Granularity::Month,
        );
        assert_eq!(
            b,
            vec![
                at("2026-01-01T00:00:00Z"),
                at("2026-02-01T00:00:00Z"),
                at("2026-03-01T00:00:00Z")
            ]
        );
        // Stops one past the limit, enough to refuse.
        let b = buckets(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            Granularity::Hour,
        );
        assert_eq!(b.len(), MAX_POINTS + 1);
    }

    #[test]
    fn clicks_sql_names_only_whitelisted_columns_and_binds_values() {
        let q = ok(&[
            ("group_by", "referrer,link"),
            ("country", "NZ"),
            ("compare", "previous"),
            ("granularity", "week"),
        ]);
        let qb = clicks_sql(&q, &Some(vec![1, 2]), 11);
        let sql = qb.sql().as_str().to_owned();
        assert!(sql.contains("FROM click_daily x"), "{sql}");
        assert!(
            sql.contains("date_trunc('week', x.day::timestamp)"),
            "{sql}"
        );
        assert!(sql.contains("x.country = ANY($"), "{sql}");
        assert!(sql.contains("x.link_id = ANY($"), "{sql}");
        assert!(
            sql.contains("ORDER BY sum(clicks) DESC, referrer_host COLLATE \"C\", link_id LIMIT $")
        );
        assert!(sql.contains("SELECT 4,"), "{sql}");
        assert!(!sql.contains("NZ"), "values are bound, never inlined");

        let q = ok(&[("granularity", "hour")]);
        let qb = clicks_sql(&q, &None, 11);
        let sql = qb.sql().as_str().to_owned();
        assert!(sql.contains("FROM click_hourly x"), "{sql}");
        assert!(sql.contains("x.link_id IN (SELECT id FROM links)"), "{sql}");
        assert!(!sql.contains("grp AS"), "{sql}");
        assert!(!sql.contains("SELECT 2,"), "{sql}");

        let q = ok(&[("granularity", "all"), ("from", "2026-11-19T03:00:00Z")]);
        let qb = sketches_sql(&q, &None, 5);
        let sql = qb.sql().as_str().to_owned();
        assert!(sql.contains("FROM visitor_sketch_hourly x"), "{sql}");
        assert!(sql.contains("NULL::timestamptz AS t"), "{sql}");
        assert!(sql.contains("ORDER BY x.hour LIMIT $"), "{sql}");
    }

    #[test]
    fn ties_rank_in_byte_order_of_the_grouped_values() {
        let k = |link: i64, country: &str| Key {
            link: Some(link),
            country: Some(country.into()),
            ..Key::default()
        };
        let by = [Dimension::Country, Dimension::Link];
        assert!(k(9, "DE").rank(&by) < k(1, "US").rank(&by));
        assert!(k(-1, "DE").rank(&by) < k(1, "DE").rank(&by));
        assert!(k(2, "DE").rank(&by) < k(10, "DE").rank(&by));
    }

    #[test]
    fn links_print_as_they_are_written() {
        assert_eq!(link_ref("abc").unwrap().to_string(), "abc");
        assert_eq!(
            link_ref("Go.Example.com/AbC").unwrap().to_string(),
            "go.example.com/AbC"
        );
    }
}

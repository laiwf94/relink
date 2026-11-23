//! Conversion tracking (docs/DESIGN.md, "Conversions").
//!
//! A link with `conversion_window_days` set sends each click on with a
//! signed click id in `rl_cid` (`relink_core::conversion`, minted alike at
//! the origin and the edge). The destination keeps it; its server posts it
//! back with the event, `POST /v1/conversions`, using a key with the
//! `conversions:write` scope. The id names the link, the click time and
//! what chose the URL, so nothing is written per click: this module checks
//! the signature, the workspace and the attribution window, names the
//! destination and A/B variant, and stores one row per conversion, counted
//! once per event by the poster's `external_id` or else per click.
//! `GET /v1/links/{code}/conversions` adds them up per destination.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::api::{ApiError, MAX_STATS_DAYS, StrictJson, StrictQuery, domain_param, json};
use crate::model::Destination;
use crate::schedule::LinkSpec;
use crate::server::App;
use crate::store::{DbError, StoredLink, api_columns, columns};
use crate::tenant::{Allowed, ConversionsWrite, StatsRead, Tenant, by_code};
use relink_core::conversion::{ClickId, Target};
use relink_core::deeplink::AppTargets;
use relink_core::rules_v2::RuleSet;

/// Longest event name.
pub const MAX_EVENT_LEN: usize = 64;
/// Longest `external_id`, in characters.
pub const MAX_EXTERNAL_ID_LEN: usize = 128;
/// Largest value, in minor units: ten trillion in a currency with cents.
pub const MAX_VALUE: i64 = 1_000_000_000_000_000;
/// How far clocks may disagree: a conversion may say it happened this long
/// before its click, or this long after now.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// `POST /v1/conversions` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostConversion {
    /// The `rl_cid` the destination received.
    pub click_id: String,
    /// What happened: `signup`, `purchase`, ...
    pub event: String,
    /// In minor units of `currency` (cents), or a plain number without one.
    pub value: Option<i64>,
    pub currency: Option<String>,
    /// The poster's own id, such as an order number: a conversion with the
    /// same event and id is counted once, whichever click it names.
    pub external_id: Option<String>,
    /// When it happened; now when absent.
    pub occurred_at: Option<DateTime<Utc>>,
}

/// A conversion as validated, before attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewConversion {
    pub click_id: String,
    pub event: String,
    pub value: Option<i64>,
    pub currency: Option<String>,
    pub external_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

/// Checks a posted conversion. Errors name the field at fault.
pub fn validate(req: PostConversion, now: DateTime<Utc>) -> Result<NewConversion, String> {
    let event = req.event;
    if event.is_empty()
        || event.len() > MAX_EVENT_LEN
        || !event
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(format!(
            "event must be 1 to {MAX_EVENT_LEN} letters, digits or _ . : -"
        ));
    }
    if let Some(v) = req.value
        && !(0..=MAX_VALUE).contains(&v)
    {
        return Err(format!("value must be 0 to {MAX_VALUE}"));
    }
    if let Some(c) = &req.currency {
        if c.len() != 3 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err("currency must be an ISO 4217 code such as EUR".into());
        }
        if req.value.is_none() {
            return Err("currency needs a value".into());
        }
    }
    if let Some(x) = &req.external_id {
        let n = x.chars().count();
        if n == 0 || n > MAX_EXTERNAL_ID_LEN || x.chars().any(char::is_control) {
            return Err(format!(
                "external_id must be 1 to {MAX_EXTERNAL_ID_LEN} characters, without control characters"
            ));
        }
    }
    let occurred_at = req.occurred_at.unwrap_or(now);
    if occurred_at > now + ChronoDuration::seconds(CLOCK_SKEW_SECS) {
        return Err("occurred_at is in the future".into());
    }
    Ok(NewConversion {
        click_id: req.click_id,
        event,
        value: req.value,
        currency: req.currency,
        external_id: req.external_id,
        occurred_at,
    })
}

/// The click time of `click`.
pub fn clicked_at(click: &ClickId) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(click.at_ms())
        .single()
        .unwrap_or_default()
}

/// Whether a conversion at `occurred_at` is attributed to `click` under a
/// window of `days`: from the click (less the clock skew) to `days` after.
pub fn within_window(click: &ClickId, occurred_at: DateTime<Utc>, days: u16) -> Result<(), String> {
    let at = clicked_at(click);
    if occurred_at < at - ChronoDuration::seconds(CLOCK_SKEW_SECS) {
        return Err("occurred_at is before the click".into());
    }
    if occurred_at > at + ChronoDuration::days(i64::from(days)) {
        return Err(format!(
            "the conversion is outside the link's attribution window of {days} days \
             after the click at {}",
            at.to_rfc3339()
        ));
    }
    Ok(())
}

/// The URLs `target` could have named for a link with these settings.
fn urls_for<'a>(
    target: Target,
    destinations: &'a [Destination],
    rules: &'a RuleSet,
    app: &'a AppTargets,
    fallback: Option<&'a str>,
) -> Vec<&'a str> {
    match target {
        Target::Destination(i) => destinations
            .get(usize::from(i))
            .map(|d| d.url.as_str())
            .into_iter()
            .collect(),
        Target::Rule(i) => rules
            .compiled()
            .urls()
            .get(usize::from(i))
            .map(String::as_str)
            .into_iter()
            .collect(),
        Target::App => [app.ios.as_deref(), app.android.as_deref()]
            .into_iter()
            .flatten()
            .collect(),
        Target::Fallback => fallback.into_iter().collect(),
    }
}

/// The URL among `urls` that `click` was sent to, by its hash.
fn matching(click: &ClickId, urls: Vec<&str>) -> Option<String> {
    urls.into_iter()
        .find(|u| relink_core::conversion::url_hash(u) == click.url_hash)
        .map(str::to_owned)
}

/// The URL `click` went to, if `link` still has it.
pub fn current_url(click: &ClickId, link: &StoredLink) -> Option<String> {
    matching(
        click,
        urls_for(
            click.target,
            &link.destinations,
            &link.rules,
            &link.link.app,
            link.fallback_url.as_deref(),
        ),
    )
}

/// The URL `click` went to if a kept version of the link had it.
pub fn version_url(click: &ClickId, spec: &LinkSpec) -> Option<String> {
    let app = spec.app.as_ref().map(|a| a.compile()).unwrap_or_default();
    matching(
        click,
        urls_for(
            click.target,
            &spec.destinations,
            &spec.rules,
            &app,
            spec.fallback_url.as_deref(),
        ),
    )
}

/// A stored conversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conversion {
    pub id: i64,
    pub click_id: String,
    pub event: String,
    pub value: Option<i64>,
    pub currency: Option<String>,
    pub external_id: Option<String>,
    /// The link's code and its custom domain (`null` for the default).
    pub link: String,
    pub domain: Option<String>,
    /// `destination`, `rule`, `app` or `fallback`: what chose the URL.
    pub target: String,
    /// The A/B variant, the destination's index, when `target` is
    /// `destination`.
    pub variant: Option<i16>,
    /// The targeting rule's index, when `target` is `rule`.
    pub rule: Option<i16>,
    /// The URL the click went to; `null` once neither the link nor its kept
    /// versions have it.
    pub destination: Option<String>,
    pub clicked_at: DateTime<Utc>,
    pub occurred_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// The answer to a post: the conversion, and whether it was already there.
#[derive(Debug, Serialize)]
pub struct Recorded {
    #[serde(flatten)]
    pub conversion: Conversion,
    pub duplicate: bool,
}

macro_rules! conversion_columns {
    () => {
        "id, link_id, click_id, event, value, currency, external_id, target, target_index, destination, \
         clicked_at, occurred_at, created_at"
    };
}

fn row_to_conversion(r: &PgRow, link: &StoredLink) -> Result<Conversion, sqlx::Error> {
    let target: String = r.try_get("target")?;
    let index: i16 = r.try_get("target_index")?;
    Ok(Conversion {
        id: r.try_get("id")?,
        click_id: r.try_get("click_id")?,
        event: r.try_get("event")?,
        value: r.try_get("value")?,
        currency: r.try_get("currency")?,
        external_id: r.try_get("external_id")?,
        link: link.code.clone(),
        domain: link.domain.clone(),
        variant: (target == "destination").then_some(index),
        rule: (target == "rule").then_some(index),
        target,
        destination: r.try_get("destination")?,
        clicked_at: r.try_get("clicked_at")?,
        occurred_at: r.try_get("occurred_at")?,
        created_at: r.try_get("created_at")?,
    })
}

/// A sum of values in one currency (`null` for plain numbers).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ValueSum {
    pub currency: Option<String>,
    pub total: i64,
    pub conversions: i64,
}

/// Conversions to one URL from one target, or to all of a link's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub conversions: i64,
    /// Distinct clicks with at least one conversion.
    pub converted_clicks: i64,
    /// Per event name.
    pub events: BTreeMap<String, i64>,
    pub values: Vec<ValueSum>,
}

impl Tally {
    fn add(&mut self, event: &str, currency: Option<&str>, n: i64, total: Option<i64>) {
        self.conversions += n;
        *self.events.entry(event.to_owned()).or_default() += n;
        if let Some(total) = total {
            match self
                .values
                .iter_mut()
                .find(|v| v.currency.as_deref() == currency)
            {
                Some(v) => {
                    v.total = v.total.saturating_add(total);
                    v.conversions += n;
                }
                None => {
                    self.values.push(ValueSum {
                        currency: currency.map(str::to_owned),
                        total,
                        conversions: n,
                    });
                    self.values.sort_by(|a, b| a.currency.cmp(&b.currency));
                }
            }
        }
    }
}

/// One destination's conversions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DestinationTally {
    pub target: String,
    pub variant: Option<i16>,
    pub rule: Option<i16>,
    pub destination: Option<String>,
    /// The link sends visitors here now: one of its destinations as they
    /// are, so a variant without conversions still shows.
    pub current: bool,
    #[serde(flatten)]
    pub tally: Tally,
}

/// `GET /v1/links/{code}/conversions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConversionStats {
    pub code: String,
    pub domain: Option<String>,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub event: Option<String>,
    pub conversion_window_days: Option<u16>,
    #[serde(flatten)]
    pub total: Tally,
    pub destinations: Vec<DestinationTally>,
}

type Key = (String, i16, Option<String>);

impl Tenant<'_> {
    /// Attributes `new`, whose click id reads as `click`, to its click and
    /// stores it, unless the same conversion is already stored (then that
    /// one comes back, marked duplicate). `NotFound` when the click's link
    /// is not in this workspace, `Precondition` when it does not track
    /// conversions or the conversion is outside its window.
    pub async fn record_conversion(
        &self,
        click: &ClickId,
        new: &NewConversion,
    ) -> Result<Recorded, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                // KEY SHARE: the link cannot be deleted under the insert.
                let Some(row) = sqlx::query(concat!(
                    "SELECT ",
                    api_columns!(),
                    " FROM links WHERE id = $1 FOR KEY SHARE"
                ))
                .bind(click.link_id)
                .fetch_optional(&mut *tx)
                .await?
                else {
                    return Ok(Err(DbError::NotFound));
                };
                let link = self.db().row_to_link(&row)?;
                let Some(days) = link.conversion_window_days else {
                    return Ok(Err(DbError::Precondition(format!(
                        "link {} does not track conversions",
                        link.code
                    ))));
                };
                if let Err(e) = within_window(click, new.occurred_at, days) {
                    return Ok(Err(DbError::Precondition(e)));
                }
                let mut destination = current_url(click, &link);
                if destination.is_none() {
                    let specs: Vec<serde_json::Value> = sqlx::query_scalar(
                        "SELECT spec FROM link_versions WHERE link_id = $1 ORDER BY version DESC",
                    )
                    .bind(link.id)
                    .fetch_all(&mut *tx)
                    .await?;
                    destination = specs
                        .into_iter()
                        .filter_map(|s| serde_json::from_value::<LinkSpec>(s).ok())
                        .find_map(|s| version_url(click, &s));
                }
                let inserted = sqlx::query(concat!(
                    "INSERT INTO conversions (link_id, click_id, event, value, currency, \
                     external_id, target, target_index, destination, clicked_at, occurred_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                     ON CONFLICT (workspace_id, event, dedup) DO NOTHING RETURNING ",
                    conversion_columns!()
                ))
                .bind(link.id)
                .bind(&new.click_id)
                .bind(&new.event)
                .bind(new.value)
                .bind(&new.currency)
                .bind(&new.external_id)
                .bind(click.target.kind())
                .bind(i16::from(click.target.index()))
                .bind(&destination)
                .bind(clicked_at(click))
                .bind(new.occurred_at)
                .fetch_optional(&mut *tx)
                .await?;
                let recorded = match inserted {
                    Some(r) => Recorded {
                        conversion: row_to_conversion(&r, &link)?,
                        duplicate: false,
                    },
                    None => {
                        // Committed by someone else first; ON CONFLICT
                        // waited for it, so it is visible now.
                        let r = sqlx::query(concat!(
                            "SELECT ",
                            conversion_columns!(),
                            " FROM conversions WHERE event = $1 \
                             AND dedup = COALESCE('x:' || $2, 'c:' || $3)"
                        ))
                        .bind(&new.event)
                        .bind(&new.external_id)
                        .bind(&new.click_id)
                        .fetch_one(&mut *tx)
                        .await?;
                        // The stored one may belong to another link of the
                        // workspace (the same external_id from another
                        // click), so it names its own.
                        let owner: i64 = r.try_get("link_id")?;
                        let owner_link = if owner == link.id {
                            link.clone()
                        } else {
                            let row = sqlx::query(concat!(
                                "SELECT ",
                                api_columns!(),
                                " FROM links WHERE id = $1"
                            ))
                            .bind(owner)
                            .fetch_one(&mut *tx)
                            .await?;
                            self.db().row_to_link(&row)?
                        };
                        Recorded {
                            conversion: row_to_conversion(&r, &owner_link)?,
                            duplicate: true,
                        }
                    }
                };
                tx.commit().await?;
                Ok(Ok(recorded))
            })
            .await?
    }

    /// The conversions of the link with `code` on `domain` that happened
    /// from the start of `from` to the end of `to` (UTC), per destination,
    /// optionally of one event only.
    pub async fn conversion_stats(
        &self,
        code: &str,
        domain: Option<&str>,
        from: NaiveDate,
        to: NaiveDate,
        event: Option<&str>,
    ) -> Result<ConversionStats, DbError> {
        let start = from
            .and_hms_opt(0, 0, 0)
            .expect("midnight exists")
            .and_utc();
        let end = (to + ChronoDuration::days(1))
            .and_hms_opt(0, 0, 0)
            .expect("midnight exists")
            .and_utc();
        let (link, sums, clicks) = self
            .db()
            .timed(async {
                // One snapshot, so the counts and the clicks agree.
                let mut tx = self.begin().await?;
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    .execute(&mut *tx)
                    .await?;
                let Some(row) = sqlx::query(concat!(
                    "SELECT ",
                    api_columns!(),
                    " FROM links",
                    by_code!()
                ))
                .bind(code)
                .bind(domain)
                .fetch_optional(&mut *tx)
                .await?
                else {
                    return Ok(Err(DbError::NotFound));
                };
                let link = self.db().row_to_link(&row)?;
                let sums = sqlx::query(
                    "SELECT target, target_index, destination, event, currency, \
                            count(*) AS n, count(value) AS valued, \
                            LEAST(sum(value), 9223372036854775807)::bigint AS total \
                       FROM conversions \
                      WHERE link_id = $1 AND occurred_at >= $2 AND occurred_at < $3 \
                        AND ($4::text IS NULL OR event = $4) \
                      GROUP BY target, target_index, destination, event, currency",
                )
                .bind(link.id)
                .bind(start)
                .bind(end)
                .bind(event)
                .fetch_all(&mut *tx)
                .await?;
                let clicks = sqlx::query(
                    "SELECT target, target_index, destination, \
                            GROUPING(target, target_index, destination) <> 0 AS overall, \
                            count(DISTINCT click_id) AS clicks \
                       FROM conversions \
                      WHERE link_id = $1 AND occurred_at >= $2 AND occurred_at < $3 \
                        AND ($4::text IS NULL OR event = $4) \
                      GROUP BY GROUPING SETS ((target, target_index, destination), ())",
                )
                .bind(link.id)
                .bind(start)
                .bind(end)
                .bind(event)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(Ok((link, sums, clicks)))
            })
            .await??;
        let mut total = Tally::default();
        let mut by: BTreeMap<Key, Tally> = BTreeMap::new();
        for r in &sums {
            let key: Key = (
                r.try_get("target")?,
                r.try_get("target_index")?,
                r.try_get("destination")?,
            );
            let ev: String = r.try_get("event")?;
            let currency: Option<String> = r.try_get("currency")?;
            let n: i64 = r.try_get("n")?;
            let valued: i64 = r.try_get("valued")?;
            let sum: Option<i64> = r.try_get("total")?;
            // Rows without a value add to the counts only; a group mixes
            // the two only for plain numbers, which have no currency.
            let (plain, with_value) = (n - valued, valued);
            for t in [&mut total, by.entry(key).or_default()] {
                if plain > 0 {
                    t.add(&ev, None, plain, None);
                }
                if with_value > 0 {
                    t.add(&ev, currency.as_deref(), with_value, sum);
                }
            }
        }
        for r in &clicks {
            let n: i64 = r.try_get("clicks")?;
            if r.try_get::<bool, _>("overall")? {
                total.converted_clicks = n;
            } else {
                let key: Key = (
                    r.try_get("target")?,
                    r.try_get("target_index")?,
                    r.try_get("destination")?,
                );
                by.entry(key).or_default().converted_clicks = n;
            }
        }
        Ok(ConversionStats {
            destinations: arrange(&link, by),
            code: link.code.clone(),
            domain: link.domain.clone(),
            from,
            to,
            event: event.map(str::to_owned),
            conversion_window_days: link.conversion_window_days,
            total,
        })
    }
}

/// The link's current destinations first, in their order and whether or
/// not they converted, then everything else by conversions.
fn arrange(link: &StoredLink, mut by: BTreeMap<Key, Tally>) -> Vec<DestinationTally> {
    let entry = |key: Key, tally: Tally, current: bool| {
        let (target, index, destination) = key;
        DestinationTally {
            variant: (target == "destination").then_some(index),
            rule: (target == "rule").then_some(index),
            target,
            destination,
            current,
            tally,
        }
    };
    let mut out = Vec::with_capacity(by.len() + link.destinations.len());
    for (i, d) in link.destinations.iter().enumerate() {
        let key: Key = (
            "destination".into(),
            i16::try_from(i).unwrap_or(i16::MAX),
            Some(d.url.clone()),
        );
        let tally = by.remove(&key).unwrap_or_default();
        out.push(entry(key, tally, true));
    }
    let mut rest: Vec<_> = by.into_iter().collect();
    rest.sort_by(|a, b| b.1.conversions.cmp(&a.1.conversions).then(a.0.cmp(&b.0)));
    out.extend(rest.into_iter().map(|(k, t)| entry(k, t, false)));
    out
}

/// `GET /v1/links/{code}/conversions` query.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsQuery {
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
    pub domain: Option<String>,
    pub event: Option<String>,
}

/// `POST /v1/conversions`: attributes a conversion to its click. 201 with
/// the attribution, or 200 with the stored one when it was posted before.
pub async fn post_conversion(
    State(app): State<Arc<App>>,
    ws: Allowed<ConversionsWrite>,
    StrictJson(req): StrictJson<PostConversion>,
) -> Result<Response, ApiError> {
    let rejected = |e: ApiError| {
        app.metrics.conversions_rejected.inc();
        e
    };
    let new = validate(req, Utc::now()).map_err(|e| rejected(ApiError::invalid(e)))?;
    let click = ClickId::decode(&app.signer, &new.click_id).ok_or_else(|| {
        rejected(ApiError::invalid(
            "click_id is not a click id issued by this deployment",
        ))
    })?;
    let recorded = ws
        .tenant(&app.db)
        .record_conversion(&click, &new)
        .await
        .map_err(|e| {
            rejected(match e {
                DbError::NotFound => {
                    ApiError::not_found_msg("click_id names a link that is not in this workspace")
                }
                other => ApiError::from(other),
            })
        })?;
    let status = if recorded.duplicate {
        app.metrics.conversions_duplicate.inc();
        StatusCode::OK
    } else {
        app.metrics.conversions_recorded.inc();
        tracing::info!(
            link = %recorded.conversion.link,
            event = %recorded.conversion.event,
            "conversion recorded"
        );
        StatusCode::CREATED
    };
    Ok(json(status, &recorded))
}

/// `GET /v1/links/{code}/conversions`: a link's conversions per
/// destination, over the last 30 days unless `from` and `to` say otherwise.
pub async fn link_conversions(
    State(app): State<Arc<App>>,
    ws: Allowed<StatsRead>,
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
    if let Some(e) = &q.event
        && (e.is_empty() || e.len() > MAX_EVENT_LEN)
    {
        return Err(ApiError::invalid(format!(
            "event must be 1 to {MAX_EVENT_LEN} characters"
        )));
    }
    let domain = domain_param(q.domain);
    let stats = ws
        .tenant(&app.db)
        .conversion_stats(&code, domain.as_deref(), from, to, q.event.as_deref())
        .await?;
    Ok(json(StatusCode::OK, &stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(event: &str) -> PostConversion {
        PostConversion {
            click_id: "x".repeat(48),
            event: event.into(),
            value: None,
            currency: None,
            external_id: None,
            occurred_at: None,
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_764_000_000, 0).unwrap()
    }

    #[test]
    fn validates_posts() {
        let ok = validate(req("purchase.completed:v2-x_y"), now()).unwrap();
        assert_eq!(ok.occurred_at, now());
        assert_eq!(ok.event, "purchase.completed:v2-x_y");
        for bad in ["", "sign up", "é", &"a".repeat(65)] {
            assert!(
                validate(req(bad), now())
                    .unwrap_err()
                    .starts_with("event must")
            );
        }
        assert!(validate(req(&"a".repeat(64)), now()).is_ok());

        let with = |f: fn(&mut PostConversion)| {
            let mut r = req("sale");
            f(&mut r);
            validate(r, now())
        };
        assert!(
            with(|r| r.value = Some(-1))
                .unwrap_err()
                .starts_with("value")
        );
        assert!(
            with(|r| r.value = Some(MAX_VALUE + 1))
                .unwrap_err()
                .starts_with("value")
        );
        assert_eq!(
            with(|r| r.value = Some(MAX_VALUE)).unwrap().value,
            Some(MAX_VALUE)
        );
        assert_eq!(
            with(|r| r.currency = Some("EUR".into())).unwrap_err(),
            "currency needs a value"
        );
        for c in ["eur", "EU", "EURO", "E1R"] {
            let mut r = req("sale");
            r.value = Some(1);
            r.currency = Some(c.into());
            assert!(
                validate(r, now()).unwrap_err().starts_with("currency"),
                "{c}"
            );
        }
        let ok = with(|r| {
            r.value = Some(1999);
            r.currency = Some("EUR".into());
        })
        .unwrap();
        assert_eq!(
            (ok.value, ok.currency.as_deref()),
            (Some(1999), Some("EUR"))
        );
        for x in ["", "a\nb"] {
            let mut r = req("sale");
            r.external_id = Some(x.into());
            assert!(validate(r, now()).unwrap_err().starts_with("external_id"));
        }
        let mut r = req("sale");
        r.external_id = Some("ø".repeat(128));
        assert!(validate(r, now()).is_ok());
        let mut r = req("sale");
        r.external_id = Some("ø".repeat(129));
        assert!(validate(r, now()).is_err());

        let mut r = req("sale");
        r.occurred_at = Some(now() + ChronoDuration::seconds(CLOCK_SKEW_SECS));
        assert!(validate(r, now()).is_ok());
        let mut r = req("sale");
        r.occurred_at = Some(now() + ChronoDuration::seconds(CLOCK_SKEW_SECS + 1));
        assert_eq!(
            validate(r, now()).unwrap_err(),
            "occurred_at is in the future"
        );
    }

    #[test]
    fn attribution_window() {
        let click = ClickId::new(1, now().timestamp_millis(), Target::App, "x:", 0);
        assert_eq!(clicked_at(&click), now());
        let at = |secs: i64| now() + ChronoDuration::seconds(secs);
        assert!(within_window(&click, at(0), 1).is_ok());
        assert!(within_window(&click, at(-CLOCK_SKEW_SECS), 1).is_ok());
        assert_eq!(
            within_window(&click, at(-CLOCK_SKEW_SECS - 1), 1).unwrap_err(),
            "occurred_at is before the click"
        );
        assert!(within_window(&click, at(86_400), 1).is_ok());
        let late = within_window(&click, at(86_401), 1).unwrap_err();
        assert!(late.contains("attribution window of 1 days"), "{late}");
        assert!(within_window(&click, at(30 * 86_400), 30).is_ok());
    }

    #[test]
    fn names_the_url_by_its_hash() {
        let destinations = vec![
            Destination {
                url: "https://a.example/".into(),
                weight: 1,
            },
            Destination {
                url: "https://b.example/".into(),
                weight: 1,
            },
        ];
        let rules = RuleSet::default();
        let app = AppTargets {
            ios: Some("https://apps.example/ios".into()),
            android: Some("intent://x#Intent;end".into()),
        };
        let fallback = Some("https://fallback.example/");
        let find = |target, url: &str| {
            let click = ClickId::new(1, 0, target, url, 0);
            matching(
                &click,
                urls_for(target, &destinations, &rules, &app, fallback),
            )
        };
        assert_eq!(
            find(Target::Destination(1), "https://b.example/").as_deref(),
            Some("https://b.example/")
        );
        // The index now holds another URL: not that one.
        assert_eq!(find(Target::Destination(0), "https://b.example/"), None);
        assert_eq!(find(Target::Destination(5), "https://a.example/"), None);
        assert_eq!(find(Target::Rule(0), "https://a.example/"), None);
        assert_eq!(
            find(Target::App, "intent://x#Intent;end").as_deref(),
            Some("intent://x#Intent;end")
        );
        assert_eq!(
            find(Target::Fallback, "https://fallback.example/").as_deref(),
            fallback
        );
    }

    #[test]
    fn tallies_add_up_per_currency() {
        let mut t = Tally::default();
        t.add("sale", Some("USD"), 2, Some(500));
        t.add("sale", Some("EUR"), 1, Some(100));
        t.add("sale", Some("USD"), 1, Some(i64::MAX));
        t.add("signup", None, 3, None);
        t.add("points", None, 1, Some(7));
        assert_eq!(t.conversions, 8);
        assert_eq!(t.events["sale"], 4);
        assert_eq!(t.events["signup"], 3);
        let v: Vec<_> = t
            .values
            .iter()
            .map(|v| (v.currency.as_deref(), v.total, v.conversions))
            .collect();
        assert_eq!(
            v,
            [
                (None, 7, 1),
                (Some("EUR"), 100, 1),
                (Some("USD"), i64::MAX, 3)
            ]
        );
    }
}

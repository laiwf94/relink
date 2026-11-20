//! The analytics query API (`GET /v1/analytics`, src/analytics.rs) over
//! real HTTP against a real Postgres: series, group-bys, filters, top-N
//! and period comparison agree with the rows they are computed from, from
//! the daily and the hourly rollups alike; unique visitors are the merged
//! sketches; the cost limit refuses broad queries; and a workspace sees
//! only its own links.

mod common;

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use relink_server::hll::Hll;
use reqwest::Method;
use serde_json::{Value, json};

use common::{Harness, admin_url, eventually, metric};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

const COUNTRIES: [&str; 3] = ["DE", "NZ", "US"];
const DEVICES: [&str; 2] = ["desktop", "mobile"];
const REFERRERS: [&str; 2] = ["(direct)", "news.example.org"];

/// One rollup row as the tests generate it.
#[derive(Clone, Debug)]
struct Row {
    link: usize,
    hour: DateTime<Utc>,
    country: &'static str,
    device: &'static str,
    referrer: &'static str,
    clicks: i64,
}

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn midnight(d: NaiveDate) -> DateTime<Utc> {
    d.and_hms_opt(0, 0, 0).unwrap().and_utc()
}

/// The first of the three days the data covers: three days ago, UTC.
fn first_day() -> NaiveDate {
    Utc::now().date_naive() - ChronoDuration::days(3)
}

/// Deterministic rows for `links` links over three days, every fifth
/// hour, in every dimension combination.
fn rows(links: usize) -> Vec<Row> {
    let mut out = Vec::new();
    for link in 0..links {
        for d in 0..3 {
            let day = midnight(first_day() + ChronoDuration::days(d));
            for h in (0..24).step_by(5) {
                for (c, country) in COUNTRIES.iter().enumerate() {
                    for (v, device) in DEVICES.iter().enumerate() {
                        for (r, referrer) in REFERRERS.iter().enumerate() {
                            let seed = (link * 7 + d as usize * 5 + h + c * 3 + v * 2 + r) as u64;
                            out.push(Row {
                                link,
                                hour: day + ChronoDuration::hours(h as i64),
                                country,
                                device,
                                referrer,
                                clicks: 1 + (mix(seed) % 20) as i64,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

/// The IDs and workspace of links by code.
async fn link_ids(h: &Harness, codes: &[&str]) -> Vec<(i64, i64)> {
    let mut out = Vec::new();
    for code in codes {
        let row: (i64, i64) = sqlx::query_as("SELECT id, workspace_id FROM links WHERE code = $1")
            .bind(code)
            .fetch_one(h.store.pool())
            .await
            .unwrap();
        out.push(row);
    }
    out
}

/// Writes `rows` to click_hourly, and their sums per day to click_daily.
async fn insert_rows(h: &Harness, links: &[(i64, i64)], rows: &[Row]) {
    let mut ids = Vec::new();
    let mut ws = Vec::new();
    let mut hours = Vec::new();
    let mut countries = Vec::new();
    let mut devices = Vec::new();
    let mut referrers = Vec::new();
    let mut clicks = Vec::new();
    for r in rows {
        ids.push(links[r.link].0);
        ws.push(links[r.link].1);
        hours.push(r.hour);
        countries.push(r.country.to_owned());
        devices.push(r.device.to_owned());
        referrers.push(r.referrer.to_owned());
        clicks.push(r.clicks);
    }
    sqlx::query(
        "INSERT INTO click_hourly (link_id, workspace_id, hour, country, device, referrer_host, clicks)
         SELECT * FROM unnest($1::bigint[], $2::bigint[], $3::timestamptz[], $4::text[], $5::text[], $6::text[], $7::bigint[])",
    )
    .bind(&ids)
    .bind(&ws)
    .bind(&hours)
    .bind(&countries)
    .bind(&devices)
    .bind(&referrers)
    .bind(&clicks)
    .execute(h.store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO click_daily (link_id, day, country, device, referrer_host, clicks)
         SELECT link_id, (hour AT TIME ZONE 'UTC')::date, country, device, referrer_host, sum(clicks)
           FROM click_hourly WHERE link_id = ANY($1) GROUP BY 1, 2, 3, 4, 5",
    )
    .bind(links.iter().map(|l| l.0).collect::<Vec<_>>())
    .execute(h.store.pool())
    .await
    .unwrap();
}

async fn get(h: &Harness, key: &str, query: &str) -> (u16, Value) {
    h.api(Method::GET, &format!("/v1/analytics?{query}"), key, None)
        .await
}

async fn ok(h: &Harness, query: &str) -> Value {
    let (status, body) = get(h, &h.alice, query).await;
    assert_eq!(status, 200, "{query}: {body}");
    body
}

fn day(d: i64) -> String {
    (first_day() + ChronoDuration::days(d)).to_string()
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[tokio::test]
async fn series_groups_filters_and_comparison_match_the_rollups() {
    let mut h = harness!();
    let mut codes = Vec::new();
    for alias in ["an-a", "an-b", "an-c"] {
        let l = h
            .create(json!({"url": "https://example.com/", "alias": alias}))
            .await;
        codes.push(l["code"].as_str().unwrap().to_owned());
    }
    let code_refs: Vec<&str> = codes.iter().map(String::as_str).collect();
    let links = link_ids(&h, &code_refs).await;
    let data = rows(3);
    insert_rows(&h, &links, &data).await;
    let sum =
        |f: &dyn Fn(&Row) -> bool| -> i64 { data.iter().filter(|r| f(r)).map(|r| r.clicks).sum() };
    let total = sum(&|_| true);

    // Whole days: the daily rollups, one point per day, empty days as 0.
    let q = format!("from={}&to={}", day(-1), day(2));
    let r = ok(&h, &q).await;
    assert_eq!(r["granularity"], "day");
    assert_eq!(r["total"]["clicks"], total, "{r}");
    let series = r["series"].as_array().unwrap();
    assert_eq!(series.len(), 4);
    assert_eq!(series[0]["clicks"], 0);
    for d in 0..3 {
        let start = midnight(first_day() + ChronoDuration::days(d));
        assert_eq!(series[d as usize + 1]["t"], ts(start));
        assert_eq!(
            series[d as usize + 1]["clicks"],
            sum(&|r| r.hour >= start && r.hour < start + ChronoDuration::days(1))
        );
    }
    assert_eq!(r["groups"], json!([]));
    assert_eq!(r["compare"], Value::Null);
    let daily_scanned = r["rows_scanned"].as_u64().unwrap();
    assert!(daily_scanned > 0);

    // The same period by hour, from the hourly rollups, adds up the same.
    let q = format!(
        "from={}&to={}&granularity=hour",
        ts(midnight(first_day())),
        ts(midnight(first_day()) + ChronoDuration::days(3))
    );
    let r = ok(&h, &q).await;
    assert_eq!(r["total"]["clicks"], total);
    let series = r["series"].as_array().unwrap();
    assert_eq!(series.len(), 72);
    assert_eq!(
        series[5]["clicks"],
        sum(&|r| r.hour == midnight(first_day()) + ChronoDuration::hours(5))
    );
    assert_eq!(series[6]["clicks"], 0);
    assert_eq!(
        series
            .iter()
            .map(|p| p["clicks"].as_i64().unwrap())
            .sum::<i64>(),
        total
    );

    // Group by country, top 2, with filters on device and referrer. Ranked
    // by clicks, then by the value.
    let q = format!(
        "from={}&to={}&group_by=country&limit=2&device=mobile&referrer=news.example.org",
        day(0),
        day(2)
    );
    let r = ok(&h, &q).await;
    let filtered = |c: &str| {
        sum(&|r| r.country == c && r.device == "mobile" && r.referrer == "news.example.org")
    };
    let mut expected: Vec<(i64, &str)> = COUNTRIES.iter().map(|c| (filtered(c), *c)).collect();
    expected.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let groups = r["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2, "{r}");
    for (g, (clicks, country)) in groups.iter().zip(&expected) {
        assert_eq!(g["key"], json!({"country": country}));
        assert_eq!(g["clicks"], *clicks);
        assert_eq!(g["visitors"], Value::Null, "no sketches per country");
        let points: i64 = g["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["clicks"].as_i64().unwrap())
            .sum();
        assert_eq!(points, *clicks);
    }
    assert_eq!(
        r["total"]["clicks"],
        expected.iter().map(|e| e.0).sum::<i64>(),
        "the total covers every group, not only the top ones"
    );
    assert_eq!(r["total"]["visitors"], Value::Null);

    // Two dimensions and a link filter, as code and as a list.
    let q = format!(
        "from={}&to={}&group_by=link,device&link={},{}&granularity=all&limit=100",
        day(0),
        day(2),
        codes[0],
        codes[2]
    );
    let r = ok(&h, &q).await;
    let groups = r["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 4);
    for g in groups {
        let link = codes.iter().position(|c| g["key"]["link"] == *c).unwrap();
        assert_ne!(link, 1, "filtered out");
        let device = g["key"]["device"].as_str().unwrap();
        assert_eq!(g["clicks"], sum(&|r| r.link == link && r.device == device));
        assert!(g.get("series").is_none(), "no series for granularity=all");
    }
    assert_eq!(r["series"].as_array().unwrap().len(), 1);

    // Compare the last day with the one before, overall and per group.
    let q = format!(
        "from={}&to={}&group_by=referrer&compare=previous",
        day(2),
        day(2)
    );
    let r = ok(&h, &q).await;
    let on = |d: i64| {
        let s = midnight(first_day() + ChronoDuration::days(d));
        move |r: &Row| r.hour >= s && r.hour < s + ChronoDuration::days(1)
    };
    assert_eq!(
        r["compare"]["from"],
        ts(midnight(first_day() + ChronoDuration::days(1)))
    );
    assert_eq!(r["total"]["clicks"], sum(&on(2)));
    assert_eq!(r["total"]["previous"]["clicks"], sum(&on(1)));
    for g in r["groups"].as_array().unwrap() {
        let referrer = g["key"]["referrer"].as_str().unwrap();
        assert_eq!(g["clicks"], sum(&|r| on(2)(r) && r.referrer == referrer));
        assert_eq!(
            g["previous"]["clicks"],
            sum(&|r| on(1)(r) && r.referrer == referrer)
        );
    }
    // A year back there is nothing.
    let r = ok(&h, &format!("from={}&to={}&compare=year", day(0), day(2))).await;
    assert_eq!(r["total"]["previous"]["clicks"], 0);
    assert_eq!(r["total"]["clicks"], total);

    // Weeks and months add up to the same total.
    for g in ["week", "month"] {
        let r = ok(
            &h,
            &format!("from={}&to={}&granularity={g}", day(0), day(2)),
        )
        .await;
        let points: i64 = r["series"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["clicks"].as_i64().unwrap())
            .sum();
        assert_eq!(points, total, "{g}");
    }

    let m = h.metrics().await;
    assert!(metric(&m, "relink_analytics_queries_total") >= 8.0);
    assert!(metric(&m, "relink_analytics_rows_scanned_total") >= daily_scanned as f64);
    h.shutdown().await;
}

/// The sketches of `visitors` (hashes) of one link and hour.
fn sketch_of(hashes: impl Iterator<Item = u64>) -> Hll {
    let mut s = Hll::new();
    for x in hashes {
        s.insert_hash(x);
    }
    s
}

#[tokio::test]
async fn unique_visitors_are_the_merged_sketches_of_links_and_periods() {
    let mut h = harness!();
    let mut codes = Vec::new();
    for alias in ["uv-a", "uv-b"] {
        let l = h
            .create(json!({"url": "https://example.com/", "alias": alias}))
            .await;
        codes.push(l["code"].as_str().unwrap().to_owned());
    }
    let links = link_ids(&h, &[&codes[0], &codes[1]]).await;
    // Link a: visitors d*3000 .. d*3000+6000 on day d; link b: an
    // overlapping 3000 of them. A day's salt differs, so a visitor's hash
    // differs between days, as it does in production. Within a day each
    // visitor comes in the hour v % 24.
    let visitors = |link: usize, d: u64| -> std::ops::Range<u64> {
        if link == 0 {
            d * 3_000..d * 3_000 + 6_000
        } else {
            d * 3_000 + 4_500..d * 3_000 + 7_500
        }
    };
    let hash = |d: u64, v: u64| mix((d << 40) ^ v);
    let mut exact_by_day: Vec<HashSet<u64>> = vec![HashSet::new(); 3];
    let mut exact_by_link: Vec<HashSet<u64>> = vec![HashSet::new(); 2];
    let mut local_by_link = [Hll::new(), Hll::new()];
    let mut local_total = Hll::new();
    let mut click_rows = Vec::new();
    for (link, (id, _)) in links.iter().enumerate() {
        for d in 0..3u64 {
            let start = midnight(first_day() + ChronoDuration::days(d as i64));
            let daily = sketch_of(visitors(link, d).map(|v| hash(d, v)));
            sqlx::query(
                "INSERT INTO visitor_sketch_daily (link_id, day, sketch) VALUES ($1, $2, $3)",
            )
            .bind(id)
            .bind(start.date_naive())
            .bind(daily.to_bytes())
            .execute(h.store.pool())
            .await
            .unwrap();
            for hr in 0..24u64 {
                let s = sketch_of(
                    visitors(link, d)
                        .filter(|v| v % 24 == hr)
                        .map(|v| hash(d, v)),
                );
                sqlx::query(
                    "INSERT INTO visitor_sketch_hourly (link_id, hour, sketch) VALUES ($1, $2, $3)",
                )
                .bind(id)
                .bind(start + ChronoDuration::hours(hr as i64))
                .bind(s.to_bytes())
                .execute(h.store.pool())
                .await
                .unwrap();
            }
            local_by_link[link].merge(&daily);
            local_total.merge(&daily);
            for v in visitors(link, d) {
                exact_by_day[d as usize].insert(hash(d, v));
                exact_by_link[link].insert(hash(d, v));
            }
            click_rows.push(Row {
                link,
                hour: start,
                country: "DE",
                device: "desktop",
                referrer: "(direct)",
                clicks: visitors(link, d).count() as i64,
            });
        }
    }
    insert_rows(&h, &links, &click_rows).await;
    let exact_total: usize = exact_by_day.iter().map(HashSet::len).sum();

    let r = ok(&h, &format!("from={}&to={}&group_by=link", day(0), day(2))).await;
    let est = r["total"]["visitors"].as_u64().unwrap();
    assert_eq!(est, local_total.count(), "the merge of every daily sketch");
    let err = (est as f64 - exact_total as f64).abs() / exact_total as f64;
    assert!(err < 0.025, "{est} against {exact_total}");
    for g in r["groups"].as_array().unwrap() {
        let link = codes.iter().position(|c| g["key"]["link"] == *c).unwrap();
        assert_eq!(g["visitors"], local_by_link[link].count());
        let exact = exact_by_link[link].len() as f64;
        let err = (g["visitors"].as_f64().unwrap() - exact).abs() / exact;
        assert!(err < 0.025, "link {link}: {g} against {exact}");
    }
    // Each day's point is that day's visitors across both links.
    let series = r["series"].as_array().unwrap();
    for d in 0..3 {
        let exact = exact_by_day[d].len() as f64;
        let err = (series[d]["visitors"].as_f64().unwrap() - exact).abs() / exact;
        assert!(err < 0.025, "day {d}: {} against {exact}", series[d]);
    }

    // A period that is not whole days merges the hourly sketches. From
    // 06:00 on the second day to the end of the third, hours 6 to 23 of
    // day 1 and all of day 2.
    let from = midnight(first_day() + ChronoDuration::days(1)) + ChronoDuration::hours(6);
    let r = ok(
        &h,
        &format!(
            "from={}&to={}&granularity=all",
            ts(from),
            ts(midnight(first_day() + ChronoDuration::days(3)))
        ),
    )
    .await;
    let exact: usize = exact_by_day[2].len()
        + (0..2u64)
            .flat_map(|link| visitors(link as usize, 1))
            .filter(|v| v % 24 >= 6)
            .collect::<HashSet<_>>()
            .len();
    let est = r["total"]["visitors"].as_f64().unwrap();
    assert!(
        (est - exact as f64).abs() / (exact as f64) < 0.025,
        "{est} against {exact}"
    );
    assert_eq!(r["series"][0]["visitors"], r["total"]["visitors"]);

    // Compared periods merge their own sketches.
    let r = ok(
        &h,
        &format!(
            "from={}&to={}&compare=previous&link={}",
            day(2),
            day(2),
            codes[0]
        ),
    )
    .await;
    let prev = sketch_of(visitors(0, 1).map(|v| hash(1, v))).count();
    assert_eq!(r["total"]["previous"]["visitors"], prev);
    h.shutdown().await;
}

#[tokio::test]
async fn broad_queries_are_refused_by_the_cost_limit() {
    let mut h = harness!(("RELINK_ANALYTICS_MAX_ROWS", "1000"));
    let mut codes = Vec::new();
    for alias in ["cost-a", "cost-b"] {
        let l = h
            .create(json!({"url": "https://example.com/", "alias": alias}))
            .await;
        codes.push(l["code"].as_str().unwrap().to_owned());
    }
    let links = link_ids(&h, &[&codes[0], &codes[1]]).await;
    // 1,080 hourly rows for link a (72 hours, 3 countries, 5 devices), one
    // for link b.
    let mut data = Vec::new();
    for hr in 0..72 {
        for country in COUNTRIES {
            for device in ["desktop", "mobile", "tablet", "bot", "other"] {
                data.push(Row {
                    link: 0,
                    hour: midnight(first_day()) + ChronoDuration::hours(hr),
                    country,
                    device,
                    referrer: "(direct)",
                    clicks: 1,
                });
            }
        }
    }
    data.push(Row {
        link: 1,
        clicks: 7,
        ..data[0].clone()
    });
    insert_rows(&h, &links, &data).await;

    let hourly = format!(
        "from={}&to={}&granularity=hour",
        ts(midnight(first_day())),
        ts(midnight(first_day()) + ChronoDuration::days(3))
    );
    let (status, body) = get(&h, &h.alice, &hourly).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"]["code"], "query_too_expensive", "{body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("1000"));

    // Filtered to link b, the same period is cheap.
    let r = ok(&h, &format!("{hourly}&link={}", codes[1])).await;
    assert_eq!(r["total"]["clicks"], 7);
    assert_eq!(r["rows_scanned"], 1, "one click row and no sketches");
    // So are whole days, which read the daily rollups.
    let r = ok(&h, &format!("from={}&to={}", day(0), day(2))).await;
    assert!(r["rows_scanned"].as_u64().unwrap() <= 1_000, "{r}");

    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_analytics_queries_refused_total"), 1.0);
    h.shutdown().await;
}

#[tokio::test]
async fn workspaces_see_only_their_own_links() {
    let mut h = harness!();
    let a = h
        .create(json!({"url": "https://example.com/", "alias": "mine-a"}))
        .await;
    let (status, b) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.com/", "alias": "bobs-b"})),
        )
        .await;
    assert_eq!(status, 201, "{b}");
    let links = link_ids(&h, &["mine-a", "bobs-b"]).await;
    let data = rows(2);
    insert_rows(&h, &links, &data).await;
    let of = |link: usize| -> i64 {
        data.iter()
            .filter(|r| r.link == link)
            .map(|r| r.clicks)
            .sum()
    };

    let q = format!("from={}&to={}&group_by=link", day(0), day(2));
    let r = ok(&h, &q).await;
    assert_eq!(r["total"]["clicks"], of(0));
    assert_eq!(r["groups"].as_array().unwrap().len(), 1);
    assert_eq!(r["groups"][0]["key"]["link"], a["code"]);
    let (status, r) = get(&h, &h.bob, &q).await;
    assert_eq!(status, 200);
    assert_eq!(r["total"]["clicks"], of(1));
    assert_eq!(r["groups"][0]["key"]["link"], "bobs-b");

    // Naming another workspace's link is "not found", as for every other
    // endpoint; so is a link on a domain the workspace does not have.
    for link in ["mine-a", "nope", "go.example.com/bobs-b"] {
        let (status, body) = get(&h, &h.bob, &format!("{q}&link={link}")).await;
        assert_eq!(status, 404, "{link}: {body}");
        assert!(body["error"]["message"].as_str().unwrap().contains(link));
    }
    h.shutdown().await;
}

#[tokio::test]
async fn real_clicks_reach_the_query_api() {
    let mut h = harness!(("RELINK_CLIENT_IP_HEADER", "x-client-ip"));
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap().to_owned();
    for ip in ["203.0.113.1", "203.0.113.1", "203.0.113.2"] {
        let resp = h
            .visit(&code, &[("cf-ipcountry", "DE"), ("x-client-ip", ip)])
            .await;
        assert_eq!(resp.status(), 302);
    }
    let q = format!("granularity=hour&link={code}&group_by=link");
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, r) = get(&h, &h.alice, &q).await;
            r["total"]["clicks"] == 3
        })
        .await,
        "clicks were not flushed"
    );
    let r = ok(&h, &q).await;
    assert_eq!(r["total"]["visitors"], 2, "{r}");
    assert_eq!(r["groups"][0]["key"]["link"], code.as_str());
    assert_eq!(r["groups"][0]["visitors"], 2);
    let last: BTreeMap<String, Value> =
        serde_json::from_value(r["series"].as_array().unwrap().last().unwrap().clone()).unwrap();
    assert_eq!(last["clicks"], 3, "this hour is the last point: {r}");
    h.shutdown().await;
}

#[tokio::test]
async fn bad_queries_are_refused_before_the_database() {
    let mut h = harness!();
    for q in [
        "from=2026-11-02&to=2026-11-01",
        "granularity=minute",
        "group_by=city",
        "limit=0",
        "compare=sometime",
        "country=Germany",
        "unknown=1",
        "from=2026-11-01T10:30:00Z",
    ] {
        let (status, body) = get(&h, &h.alice, q).await;
        assert_eq!(status, 400, "{q}: {body}");
        assert_eq!(body["error"]["code"], "invalid_argument");
    }
    let resp = h
        .http
        .get(format!("{}/v1/analytics", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    h.shutdown().await;
}

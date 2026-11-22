//! Week 4 end to end (#25): clicks from people, crawlers and link-preview
//! fetchers, at two instances and from the edge, over two days, followed
//! through every part of the analytics engine:
//!
//! - live streams on one instance get each click within a second, from
//!   either instance and from edge batches, and bots only when asked for
//! - raw events land in their month's partition, with no client address in
//!   any column, and bots have no visitor hash
//! - the query API answers the same at both instances: series by day and
//!   by hour, group-bys, filters, top N and a compared period, bots left
//!   out by default
//! - unique visitors are the merged sketches of links and days, within 1%
//!   of the exact count of people
//! - retention drops a whole old month and leaves the rollups alone
//! - another workspace sees none of it

mod common;

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, NaiveDate};
use relink_server::partitions::{self, Month, Outcome};
use relink_server::util::{now_ms, utc_day};
use reqwest::Method;
use serde_json::{Value, json};

use common::{Harness, admin_url, eventually, metric};

const EDGE_TOKEN: &str = "edge-token-for-the-week-4-walk-0123456789";
const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1";
const MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15";
const CRAWLER: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const PREVIEW: &str = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)";
const COUNTRIES: [&str; 3] = ["DE", "NZ", "US"];

/// An open event stream and the bytes read from it not yet parsed.
struct Sse {
    resp: reqwest::Response,
    buf: String,
}

impl Sse {
    async fn open(base: &str, path: &str, key: &str) -> Result<Sse, u16> {
        let resp = common::client()
            .get(format!("{base}{path}"))
            .bearer_auth(key)
            .send()
            .await
            .unwrap();
        if resp.status() != 200 {
            return Err(resp.status().as_u16());
        }
        let mut s = Sse {
            resp,
            buf: String::new(),
        };
        let (event, _) = s.next(Duration::from_secs(5)).await.expect("open event");
        assert_eq!(event, "open");
        Ok(s)
    }

    /// The next event, or `None` if none arrives within `wait`.
    async fn next(&mut self, wait: Duration) -> Option<(String, Value)> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            while let Some(end) = self.buf.find("\n\n") {
                let frame: String = self.buf.drain(..end + 2).collect();
                let mut event = None;
                let mut data = None;
                for line in frame.lines() {
                    if let Some(e) = line.strip_prefix("event: ") {
                        event = Some(e.to_owned());
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        data = Some(serde_json::from_str(d).unwrap());
                    }
                }
                if let (Some(e), Some(d)) = (event, data) {
                    return Some((e, d));
                }
            }
            match tokio::time::timeout_at(deadline, self.resp.chunk()).await {
                Ok(Ok(Some(bytes))) => self.buf.push_str(std::str::from_utf8(&bytes).unwrap()),
                _ => return None,
            }
        }
    }

    /// The next click, which must arrive within a second.
    async fn click(&mut self, what: &str) -> Value {
        let sent = Instant::now();
        let (event, data) = self
            .next(Duration::from_secs(1))
            .await
            .unwrap_or_else(|| panic!("{what}: no click within a second"));
        assert!(sent.elapsed() < Duration::from_secs(1));
        assert_eq!(event, "click", "{what}: {data}");
        data
    }
}

/// The edge's fingerprint of person `i` (any 16 bytes will do).
fn fingerprint(i: usize) -> String {
    format!(
        "{:032x}",
        0x5eed_0000_0000_0000_0000_0000_0000_0000_u128 + i as u128
    )
}

/// One expected click: which link, which day, what it was.
#[derive(Clone, Debug)]
struct Expected {
    link: &'static str,
    day: i32,
    country: &'static str,
    device: &'static str,
    referrer: &'static str,
    /// Who it was, for counting visitors; `None` for bots.
    person: Option<String>,
}

#[derive(Default)]
struct Ledger(Vec<Expected>);

impl Ledger {
    fn clicks(&self, f: impl Fn(&Expected) -> bool) -> i64 {
        self.0.iter().filter(|e| f(e)).count() as i64
    }

    /// People counted once per day, as the visitor rules have it.
    fn visitors(&self, f: impl Fn(&Expected) -> bool) -> f64 {
        let set: HashSet<(i32, &str)> = self
            .0
            .iter()
            .filter(|e| f(e))
            .filter_map(|e| e.person.as_deref().map(|p| (e.day, p)))
            .collect();
        set.len() as f64
    }
}

fn near(got: &Value, exact: f64, what: &str) {
    let got = got
        .as_f64()
        .unwrap_or_else(|| panic!("{what}: no visitors in {got}"));
    let err = (got - exact).abs() / exact;
    assert!(
        err <= 0.01,
        "{what}: {got} visitors against {exact} exactly"
    );
}

/// One edge click on the wire.
fn wire(link_id: i64, day: i32, e: &Expected, fp: &str) -> Value {
    let referrer = match e.referrer {
        "(direct)" => Value::Null,
        r => json!(r),
    };
    json!({"link_id": link_id, "day": day, "country": e.country, "device": e.device,
           "referrer": referrer, "fingerprint": fp})
}

#[tokio::test]
async fn a_week_of_clicks_through_the_analytics_engine() {
    let Some(admin) = admin_url() else { return };
    // Leave a minute's margin before midnight UTC, so every click of the
    // walk lands on the day it is counted for.
    let to_midnight = 86_400_000 - now_ms().rem_euclid(86_400_000);
    if to_midnight < 60_000 {
        tokio::time::sleep(Duration::from_millis(to_midnight as u64 + 1_000)).await;
    }
    let settings = [
        ("RELINK_CLIENT_IP_HEADER", "x-client-ip"),
        ("RELINK_EDGE_TOKEN", EDGE_TOKEN),
        ("RELINK_LIVE_ANNOUNCE_MS", "200"),
    ];
    let mut h = Harness::start(&admin, &settings).await;
    let b = h.second_instance(&settings).await;
    let base_b = format!("http://{}", b.addr);
    let today = utc_day(now_ms());
    let yesterday = today - 1;
    let date =
        |d: i32| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap() + ChronoDuration::days(d as i64);

    for alias in ["launch", "guide", "probe"] {
        h.create(json!({"url": format!("https://example.com/{alias}"), "alias": alias}))
            .await;
    }
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.org/", "alias": "bobs"})),
        )
        .await;
    assert_eq!(status, 201);
    let ids: BTreeMap<String, i64> = sqlx::query_as("SELECT code, id FROM links")
        .fetch_all(h.store.pool())
        .await
        .unwrap()
        .into_iter()
        .collect();
    let mut ledger = Ledger::default();

    // 1. History from the edge: yesterday through instance A, today so far
    // through instance B. People 0..900 clicked launch yesterday and
    // 600..1100 guide, so 300 clicked both; 50 crawler hits went with them.
    // Today 0..400 came back to launch and 300..500 to guide.
    let mut batches: Vec<(&str, Vec<Value>)> = vec![("a", vec![]), ("b", vec![])];
    let plan: [(&'static str, i32, std::ops::Range<usize>, usize); 4] = [
        ("launch", yesterday, 0..900, 0),
        ("guide", yesterday, 600..1100, 0),
        ("launch", today, 0..400, 1),
        ("guide", today, 300..500, 1),
    ];
    for (link, day, people, to) in plan {
        for i in people {
            let e = Expected {
                link,
                day,
                country: COUNTRIES[i % 3],
                device: if i % 4 == 0 { "desktop" } else { "mobile" },
                referrer: if i % 5 == 0 {
                    "news.example.org"
                } else {
                    "(direct)"
                },
                person: Some(fingerprint(i)),
            };
            batches[to]
                .1
                .push(wire(ids[link], day, &e, &fingerprint(i)));
            ledger.0.push(e);
        }
    }
    for i in 0..50 {
        let e = Expected {
            link: "launch",
            day: yesterday,
            country: "US",
            device: "bot",
            referrer: "(direct)",
            person: None,
        };
        batches[0]
            .1
            .push(wire(ids["launch"], yesterday, &e, &fingerprint(5_000 + i)));
        ledger.0.push(e);
    }
    let edge = |base: String, clicks: &[Value]| {
        let req = common::client()
            .post(format!("{base}/v1/edge/clicks"))
            .bearer_auth(EDGE_TOKEN)
            .header("content-type", "application/json")
            .body(json!({ "clicks": clicks }).to_string());
        async move {
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status(), 202);
        }
    };
    for (to, clicks) in &batches {
        let base = if *to == "a" {
            h.base.clone()
        } else {
            base_b.clone()
        };
        for chunk in clicks.chunks(1_000) {
            edge(base.clone(), chunk).await;
        }
    }
    let both_days = format!("from={}&to={}", date(yesterday), date(today));
    let history = ledger.clicks(|_| true);
    assert!(
        eventually(Duration::from_secs(10), || async {
            let (_, r) = h
                .api(
                    Method::GET,
                    &format!("/v1/analytics?{both_days}&include_bots=true"),
                    &h.alice,
                    None,
                )
                .await;
            r["total"]["clicks"] == history
        })
        .await,
        "the edge history was not flushed"
    );

    // 2. Live streams at instance B on launch: one for people, one with
    // bots. The probe stream opens last; once a probe click made at A
    // arrives, A has heard B announce launch too.
    let launch_live = "/v1/links/launch/live";
    let mut people = Sse::open(&base_b, launch_live, &h.alice).await.unwrap();
    let mut everyone = Sse::open(
        &base_b,
        &format!("{launch_live}?include_bots=true"),
        &h.alice,
    )
    .await
    .unwrap();
    let mut probe = Sse::open(&base_b, "/v1/links/probe/live", &h.alice)
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        h.visit("probe", &[("user-agent", IPHONE)]).await;
        if probe.next(Duration::from_millis(100)).await.is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "B's streams were never announced"
        );
    }
    assert_eq!(
        Sse::open(&base_b, launch_live, &h.bob).await.err(),
        Some(404),
        "another workspace cannot watch the link"
    );

    // 3. Twenty people visit launch, alternately at A and at B; the first
    // five also open guide. Each launch click reaches both streams within a
    // second, with no address in it.
    let http = common::client();
    let visit =
        |base: &str, code: &str, ua: &str, ip: &str, country: &str, referer: Option<&str>| {
            let mut req = http
                .get(format!("{base}/{code}"))
                .header("user-agent", ua)
                .header("x-client-ip", ip)
                .header("cf-ipcountry", country);
            if let Some(r) = referer {
                req = req.header("referer", r);
            }
            async move {
                let resp = req.send().await.unwrap();
                assert_eq!(resp.status(), 302);
            }
        };
    for i in 0..20usize {
        let base = if i % 2 == 0 { &h.base } else { &base_b };
        let ip = format!("203.0.113.{}", i + 1);
        let (ua, device) = if i % 3 == 0 {
            (MAC, "desktop")
        } else {
            (IPHONE, "mobile")
        };
        let country = COUNTRIES[i % 3];
        let referer = (i % 4 == 0).then_some("https://social.example.net/post/1");
        let referrer = if referer.is_some() {
            "social.example.net"
        } else {
            "(direct)"
        };
        let person = Some(format!("{ip} {ua}"));
        visit(base, "launch", ua, &ip, country, referer).await;
        ledger.0.push(Expected {
            link: "launch",
            day: today,
            country,
            device,
            referrer,
            person: person.clone(),
        });
        let seen = people.click(&format!("visit {i}")).await;
        assert_eq!(seen["code"], "launch");
        assert_eq!(seen["country"], country);
        assert_eq!(seen["device"], device);
        assert_eq!(seen["bot"], false);
        let referrer_seen = seen["referrer"].as_str().unwrap_or("(direct)");
        assert_eq!(referrer_seen, referrer, "{seen}");
        assert!(!seen.to_string().contains("203.0.113"));
        assert_eq!(everyone.click(&format!("visit {i}, all")).await, seen);
        if i < 5 {
            visit(base, "guide", ua, &ip, country, referer).await;
            ledger.0.push(Expected {
                link: "guide",
                day: today,
                country,
                device,
                referrer,
                person,
            });
        }
    }

    // A crawler and two link previews: clicks, never people.
    for (i, ua) in [CRAWLER, PREVIEW, PREVIEW].into_iter().enumerate() {
        let base = if i == 0 { &h.base } else { &base_b };
        visit(base, "launch", ua, "198.51.100.7", "US", None).await;
        ledger.0.push(Expected {
            link: "launch",
            day: today,
            country: "US",
            device: "bot",
            referrer: "(direct)",
            person: None,
        });
        let seen = everyone.click(&format!("bot {i}")).await;
        assert_eq!(
            (seen["device"].as_str(), seen["bot"].as_bool()),
            (Some("bot"), Some(true))
        );
    }
    assert!(
        people.next(Duration::from_millis(300)).await.is_none(),
        "bots reached the people stream"
    );

    // Two edge clicks reach the streams too.
    let mut live_batch = Vec::new();
    for i in 0..2 {
        let e = Expected {
            link: "launch",
            day: today,
            country: "NZ",
            device: "tablet",
            referrer: "(direct)",
            person: Some(fingerprint(9_000 + i)),
        };
        live_batch.push(wire(ids["launch"], today, &e, &fingerprint(9_000 + i)));
        ledger.0.push(e);
    }
    edge(h.base.clone(), &live_batch).await;
    for i in 0..2 {
        assert_eq!(people.click(&format!("edge {i}")).await["device"], "tablet");
        assert_eq!(
            everyone.click(&format!("edge {i}, all")).await["device"],
            "tablet"
        );
    }
    let m = h.metrics().await;
    assert!(metric(&m, "relink_live_clicks_relayed_total") >= 13.0);
    let m = common::client()
        .get(format!("http://{}/metrics", b.admin_addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(metric(&m, "relink_live_clicks_lagged_total"), 0.0);
    drop((people, everyone, probe));

    // 4. Everything is flushed: the query API, at either instance.
    let not_probe = |e: &Expected| e.link != "probe";
    let all_clicks = ledger.clicks(not_probe);
    let filter = "link=launch,guide";
    let q = format!("{both_days}&{filter}&include_bots=true");
    assert!(
        eventually(Duration::from_secs(10), || async {
            let (_, r) = h
                .api(Method::GET, &format!("/v1/analytics?{q}"), &h.alice, None)
                .await;
            r["total"]["clicks"] == all_clicks
        })
        .await,
        "the live clicks were not flushed: {}",
        h.api(Method::GET, &format!("/v1/analytics?{q}"), &h.alice, None)
            .await
            .1
    );
    let ask = |base: String, q: String| {
        let req = common::client()
            .get(format!("{base}/v1/analytics?{q}"))
            .bearer_auth(&h.alice);
        async move {
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status(), 200, "{q}");
            serde_json::from_str::<Value>(&resp.text().await.unwrap()).unwrap()
        }
    };
    let people_only = |e: &Expected| e.person.is_some();

    // By day, people only (the default): two points and visitors per link,
    // merged across links and days.
    let q = format!("{both_days}&{filter}&group_by=link");
    let r = ask(h.base.clone(), q.clone()).await;
    let mut same = ask(base_b.clone(), q.clone()).await;
    same["rows_scanned"] = r["rows_scanned"].clone();
    assert_eq!(same, r, "the instances disagree");
    assert_eq!(r["include_bots"], false);
    assert_eq!(r["granularity"], "day");
    assert_eq!(r["total"]["clicks"], ledger.clicks(people_only));
    near(
        &r["total"]["visitors"],
        ledger.visitors(|_| true),
        "both links, both days",
    );
    let series = r["series"].as_array().unwrap();
    assert_eq!(series.len(), 2);
    for (point, day) in series.iter().zip([yesterday, today]) {
        assert_eq!(
            point["clicks"],
            ledger.clicks(|e| e.day == day && people_only(e))
        );
        near(
            &point["visitors"],
            ledger.visitors(|e| e.day == day),
            "one day",
        );
    }
    let groups = r["groups"].as_array().unwrap();
    let keys: Vec<&str> = groups
        .iter()
        .map(|g| g["key"]["link"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["launch", "guide"], "ranked by clicks");
    for g in groups {
        let link = g["key"]["link"].as_str().unwrap();
        assert_eq!(
            g["clicks"],
            ledger.clicks(|e| e.link == link && people_only(e))
        );
        near(&g["visitors"], ledger.visitors(|e| e.link == link), link);
    }
    // 300 people opened both links yesterday and 105 today: the merge
    // counts them once.
    let sum: f64 = groups.iter().map(|g| g["visitors"].as_f64().unwrap()).sum();
    assert!(
        sum - r["total"]["visitors"].as_f64().unwrap() > 380.0,
        "{r}"
    );

    // By hour, the hourly rollups add up the same.
    let start = date(yesterday).and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end = start + ChronoDuration::days(2);
    let hours = format!(
        "from={}&to={}&granularity=hour&{filter}",
        start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let r = ask(base_b.clone(), hours.clone()).await;
    assert_eq!(r["series"].as_array().unwrap().len(), 48);
    assert_eq!(r["total"]["clicks"], ledger.clicks(people_only));
    let by_hour: i64 = r["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["clicks"].as_i64().unwrap())
        .sum();
    assert_eq!(by_hour, ledger.clicks(people_only));
    let r = ask(base_b.clone(), format!("{hours}&include_bots=true")).await;
    assert_eq!(r["total"]["clicks"], all_clicks);

    // Group-bys and filters, with and without bots.
    for (dimension, field) in [("country", 0), ("device", 1), ("referrer", 2)] {
        let value = |e: &Expected| [e.country, e.device, e.referrer][field];
        for bots in [false, true] {
            let r = ask(
                h.base.clone(),
                format!("{both_days}&{filter}&group_by={dimension}&limit=100&include_bots={bots}"),
            )
            .await;
            let got: BTreeMap<String, i64> = r["groups"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| {
                    (
                        g["key"][dimension].as_str().unwrap().to_owned(),
                        g["clicks"].as_i64().unwrap(),
                    )
                })
                .collect();
            let mut want = BTreeMap::new();
            for e in ledger
                .0
                .iter()
                .filter(|e| not_probe(e) && (bots || people_only(e)))
            {
                *want.entry(value(e).to_owned()).or_insert(0) += 1;
            }
            assert_eq!(got, want, "{dimension}, bots {bots}");
            // Without a link grouping or filter alone, there are no visitors.
            assert_eq!(r["total"]["visitors"], Value::Null);
        }
    }
    let r = ask(
        h.base.clone(),
        format!("{both_days}&{filter}&group_by=link,country&country=NZ&device=tablet&limit=1"),
    )
    .await;
    let groups = r["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["key"], json!({"link": "launch", "country": "NZ"}));
    assert_eq!(groups[0]["clicks"], 2, "the two edge clicks from step 3");

    // Today against yesterday.
    let r = ask(
        h.base.clone(),
        format!(
            "from={}&to={}&{filter}&compare=previous",
            date(today),
            date(today)
        ),
    )
    .await;
    assert_eq!(
        r["total"]["clicks"],
        ledger.clicks(|e| e.day == today && people_only(e))
    );
    assert_eq!(
        r["total"]["previous"]["clicks"],
        ledger.clicks(|e| e.day == yesterday && people_only(e)),
        "{r}"
    );
    near(
        &r["total"]["previous"]["visitors"],
        ledger.visitors(|e| e.day == yesterday),
        "yesterday",
    );

    // 5. The raw events: one per click, each in its month's partition, bots
    // without a visitor hash, and no client address or User-Agent anywhere.
    let rows: Vec<(bool, bool, bool, i64)> = sqlx::query_as(
        "SELECT e.tableoid::regclass::text = 'click_events_p' || to_char(e.at AT TIME ZONE 'UTC', 'YYYYMM'),
                e.bot, e.visitor IS NOT NULL, count(*)
           FROM click_events e JOIN links l ON l.id = e.link_id
          WHERE l.code IN ('launch', 'guide')
          GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    let bots = ledger.clicks(|e| not_probe(e) && e.person.is_none());
    assert_eq!(
        rows,
        [
            (true, false, true, ledger.clicks(people_only)),
            (true, true, false, bots)
        ]
    );
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM click_events e
          WHERE row_to_json(e)::text ~ '203\\.0\\.113|198\\.51\\.100|Mozilla|Slackbot'",
    )
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
          WHERE table_name = 'click_events' ORDER BY 1",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(
        columns,
        [
            "at",
            "bot",
            "country",
            "device",
            "domain_id",
            "link_id",
            "referrer_host",
            "visitor",
            "workspace_id"
        ],
        "no column for an address or a User-Agent"
    );

    // 6. Retention: a month past the 13 kept is dropped whole, at once.
    let current = Month::of_day(today);
    let old = current.plus(-14);
    sqlx::query("SELECT relink_click_events_partition($1)")
        .bind(old.first_day())
        .execute(h.store.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO click_events (at, workspace_id, link_id, domain_id, country, device, referrer_host, visitor, bot)
         SELECT $1, workspace_id, link_id, domain_id, country, device, referrer_host, visitor, bot
           FROM click_events LIMIT 1",
    )
    .bind(old.first_day().and_hms_opt(12, 0, 0).unwrap().and_utc())
    .execute(h.store.pool())
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM click_events")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let Outcome::Done(report) = partitions::maintain(&h.store, today, 13).await.unwrap() else {
        panic!("the partition manager was busy");
    };
    assert_eq!(report.dropped, [old]);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM click_events")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(after, before - 1);
    let r = ask(
        h.base.clone(),
        format!("{both_days}&{filter}&include_bots=true"),
    )
    .await;
    assert_eq!(
        r["total"]["clicks"], all_clicks,
        "rollups outlive raw events"
    );

    // 7. Bob's workspace sees none of it, and cannot name alice's links.
    let resp = common::client()
        .get(format!(
            "{}/v1/analytics?{both_days}&include_bots=true",
            h.base
        ))
        .bearer_auth(&h.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        serde_json::from_str::<Value>(&resp.text().await.unwrap()).unwrap()["total"]["clicks"],
        0
    );
    let resp = common::client()
        .get(format!("{}/v1/analytics?{both_days}&link=launch", h.base))
        .bearer_auth(&h.bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    b.shutdown().await;
    h.shutdown().await;
}

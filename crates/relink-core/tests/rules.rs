//! Targeting rules checked against a naive interpreter.
//!
//! [`rules_v2::compile`] flattens a rule list into a jump table that keeps
//! no stack, gathers request facts lazily and decodes query strings in
//! place. The interpreter here does none of that: it walks the condition
//! tree as written, recursively, computing every fact up front and each
//! leaf the obvious way (chrono for the time of day, an allocating decoder
//! for query strings). The two must pick the same rule for every request
//! and test the same leaves: the decision list is short-circuit evaluation
//! of the tree, so it must stop exactly where the tree walk stops.
//!
//! [`CASES`] rule lists, each against [`REQUESTS_PER_CASE`] requests, give
//! 100,000 generated requests per run. The vocabularies are small on
//! purpose so that requests match rules often, with a share of random
//! headers mixed in.

use chrono::{DateTime, Datelike, FixedOffset, Timelike, Utc};
use proptest::prelude::*;
use relink_core::classify::{
    Browser, Device, Os, browser_family, device_class, os_family, preferred_language, referrer_host,
};
use relink_core::destination::Policy;
use relink_core::rules_v2::{
    self, Condition, MAX_CONDITIONS, MAX_QUERY_BYTES, MAX_QUERY_PARAMS, QueryMatch, Request, Rule,
    RuleSet, Rules, TimeWindow,
};

const CASES: u32 = 1_000;
const REQUESTS_PER_CASE: usize = 100;

const POLICY: Policy = Policy {
    allow_ip_literals: false,
    allow_private: false,
};

/// 2026-11-16 12:30:00 UTC, a Monday. Generated times cluster around it.
const BASE_MS: i64 = 1_794_832_200_000;
const HOUR_MS: i64 = 3_600_000;

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

// ------------------------------------------------------------ interpreter

/// Every fact a rule can read, computed up front.
struct Facts {
    now_ms: i64,
    country: Option<[u8; 2]>,
    region: Option<Vec<u8>>,
    device: Device,
    os: Os,
    browser: Browser,
    language: Option<String>,
    referrer: Option<String>,
    query: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Facts {
    fn of(req: &Request<'_>) -> Facts {
        Facts {
            now_ms: req.now_ms,
            country: req.country,
            region: req.region.map(<[u8]>::to_vec),
            device: device_class(req.user_agent),
            os: os_family(req.user_agent),
            browser: browser_family(req.user_agent),
            language: preferred_language(req.accept_language).map(str::to_owned),
            referrer: referrer_host(req.referer),
            query: req.query.map(naive_query).unwrap_or_default(),
        }
    }
}

/// The first rule that holds and how many leaves were tested to find it.
fn interpret(rules: &[Rule], facts: &Facts) -> (Option<usize>, usize) {
    let mut tested = 0;
    for (i, rule) in rules.iter().enumerate() {
        if holds(&rule.condition, facts, &mut tested) {
            return (Some(i), tested);
        }
    }
    (None, tested)
}

fn holds(c: &Condition, f: &Facts, tested: &mut usize) -> bool {
    match c {
        Condition::All(children) => children.iter().all(|c| holds(c, f, tested)),
        Condition::Any(children) => children.iter().any(|c| holds(c, f, tested)),
        Condition::Not(child) => !holds(child, f, tested),
        leaf => {
            *tested += 1;
            leaf_holds(leaf, f)
        }
    }
}

fn leaf_holds(c: &Condition, f: &Facts) -> bool {
    match c {
        Condition::Country(list) => f.country.is_some_and(|have| {
            list.iter()
                .any(|v| v.to_ascii_uppercase().as_bytes() == have)
        }),
        Condition::Region(list) => {
            let (Some(country), Some(sub)) = (f.country, f.region.as_deref()) else {
                return false;
            };
            let valid = (1..=3).contains(&sub.len()) && sub.iter().all(u8::is_ascii_alphanumeric);
            valid
                && list.iter().any(|v| {
                    let (c, s) = v.split_once('-').expect("generated regions have a dash");
                    c.to_ascii_uppercase().as_bytes() == country
                        && s.to_ascii_uppercase().as_bytes() == sub.to_ascii_uppercase()
                })
        }
        Condition::Device(list) => list.iter().any(|v| v == f.device.as_str()),
        Condition::Os(list) => list.iter().any(|v| v == f.os.as_str()),
        Condition::Browser(list) => list.iter().any(|v| v == f.browser.as_str()),
        Condition::Language(list) => f.language.as_deref().is_some_and(|tag| {
            let tag = tag.to_ascii_lowercase();
            list.iter().any(|v| {
                let want = v.to_ascii_lowercase();
                tag == want || tag.starts_with(&format!("{want}-"))
            })
        }),
        Condition::Referrer(list) => f.referrer.as_deref().is_some_and(|host| {
            list.iter().any(|v| {
                let want = v.strip_suffix('.').unwrap_or(v).to_ascii_lowercase();
                host == want || host.ends_with(&format!(".{want}"))
            })
        }),
        Condition::Time(w) => time_holds(w, f.now_ms),
        Condition::Query(q) => f.query.iter().any(|(name, value)| {
            name.as_slice() == q.name.as_bytes()
                && q.values
                    .as_ref()
                    .is_none_or(|vals| vals.iter().any(|v| value.as_slice() == v.as_bytes()))
        }),
        Condition::All(_) | Condition::Any(_) | Condition::Not(_) => unreachable!("not a leaf"),
    }
}

fn time_holds(w: &TimeWindow, now_ms: i64) -> bool {
    if w.after.is_some_and(|a| now_ms < a.timestamp_millis())
        || w.before.is_some_and(|b| now_ms >= b.timestamp_millis())
    {
        return false;
    }
    let zone = FixedOffset::east_opt(w.utc_offset_minutes * 60).expect("offset in range");
    let local = DateTime::from_timestamp_millis(now_ms)
        .expect("time in range")
        .with_timezone(&zone);
    if let Some(days) = &w.days {
        let today = DAYS[local.weekday().num_days_from_monday() as usize];
        if !days.iter().any(|d| d == today) {
            return false;
        }
    }
    let Some([from, to]) = &w.hours else {
        return true;
    };
    let minute = local.hour() * 60 + local.minute();
    let (start, end) = (clock(from), clock(to));
    if start < end {
        start <= minute && minute < end
    } else {
        minute >= start || minute < end
    }
}

fn clock(s: &str) -> u32 {
    let (h, m) = s.split_once(':').expect("HH:MM");
    h.parse::<u32>().unwrap() * 60 + m.parse::<u32>().unwrap()
}

/// The query parameters rules see, decoded: split at every `&`, keeping
/// only parameters that end within [`MAX_QUERY_BYTES`], dropping empty
/// ones, and then the first [`MAX_QUERY_PARAMS`].
fn naive_query(q: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut ends: Vec<usize> = (0..q.len()).filter(|&i| q[i] == b'&').collect();
    ends.push(q.len());
    let mut start = 0;
    let mut segments = Vec::new();
    for end in ends {
        segments.push((start, end));
        start = end + 1;
    }
    segments
        .into_iter()
        .take_while(|&(_, end)| end <= MAX_QUERY_BYTES)
        .filter(|&(s, e)| s < e)
        .take(MAX_QUERY_PARAMS)
        .map(|(s, e)| {
            let part = &q[s..e];
            let (name, value) = match part.iter().position(|&b| b == b'=') {
                Some(i) => (&part[..i], &part[i + 1..]),
                None => (part, &[][..]),
            };
            (form_decode(name), form_decode(value))
        })
        .collect()
}

/// `application/x-www-form-urlencoded` decoding: `+` is a space, `%XX` with
/// two hex digits is that byte, and any other `%` stands for itself.
fn form_decode(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if raw
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                let hex = std::str::from_utf8(&raw[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn leaves(c: &Condition) -> usize {
    match c {
        Condition::All(cs) | Condition::Any(cs) => cs.iter().map(leaves).sum(),
        Condition::Not(c) => leaves(c),
        _ => 1,
    }
}

// ------------------------------------------------------------ rule lists

fn names<const N: usize>(all: [&'static str; N]) -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(prop::sample::select(all.to_vec()), 1..4)
        .prop_map(|v| v.into_iter().map(str::to_owned).collect())
}

fn instant() -> impl Strategy<Value = DateTime<Utc>> {
    (-72i64..72).prop_map(|h| DateTime::from_timestamp_millis(BASE_MS + h * HOUR_MS).unwrap())
}

fn hhmm(m: u32) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

fn time_window() -> impl Strategy<Value = TimeWindow> {
    let hours = (0u32..1440, 0u32..=1440)
        .prop_filter("start and end differ", |(s, e)| s != &(e % 1440))
        .prop_map(|(s, e)| [hhmm(s), hhmm(e)]);
    (
        prop::option::of(instant()),
        prop::option::of(instant()),
        prop::option::of(names(DAYS)),
        prop::option::of(hours),
        prop_oneof![Just(0), Just(-300), Just(330), Just(840), -840i32..=840],
    )
        .prop_map(|(after, before, days, hours, utc_offset_minutes)| {
            let (after, before) = match (after, before) {
                (Some(a), Some(b)) if a == b => (Some(a), Some(b + chrono::Duration::hours(1))),
                (Some(a), Some(b)) => (Some(a.min(b)), Some(a.max(b))),
                other => other,
            };
            let mut w = TimeWindow {
                after,
                before,
                days,
                hours,
                utc_offset_minutes,
            };
            if w.after.is_none() && w.before.is_none() && w.hours.is_none() && w.days.is_none() {
                w.days = Some(vec!["mon".to_owned(), "sat".to_owned()]);
            }
            w
        })
}

fn query_match() -> impl Strategy<Value = QueryMatch> {
    (
        prop::sample::select(vec!["utm_source", "q", "a b", "é", "x", "%"]),
        prop::option::of(prop::collection::vec(
            prop::sample::select(vec!["news", "a b", "100%", "é", "", "N"]),
            1..4,
        )),
    )
        .prop_map(|(name, values)| QueryMatch {
            name: name.to_owned(),
            values: values.map(|v| v.into_iter().map(str::to_owned).collect()),
        })
}

fn leaf() -> impl Strategy<Value = Condition> {
    prop_oneof![
        names(["US", "us", "CA", "DE", "gb", "FR"]).prop_map(Condition::Country),
        names(["US-CA", "us-ny", "DE-BY", "CA-ON", "GB-ENG", "FR-75"]).prop_map(Condition::Region),
        names(Device::ALL.map(Device::as_str)).prop_map(Condition::Device),
        names(Os::ALL.map(Os::as_str)).prop_map(Condition::Os),
        names(Browser::ALL.map(Browser::as_str)).prop_map(Condition::Browser),
        names(["en", "EN-gb", "de", "pt-BR", "pt", "fr-CA", "zh-Hant"])
            .prop_map(Condition::Language),
        names([
            "example.com",
            "news.example.com",
            "t.co",
            "Social.Example.",
            "x.org"
        ])
        .prop_map(Condition::Referrer),
        time_window().prop_map(Condition::Time),
        query_match().prop_map(Condition::Query),
    ]
}

fn condition() -> impl Strategy<Value = Condition> {
    leaf().prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..4).prop_map(Condition::All),
            prop::collection::vec(inner.clone(), 1..4).prop_map(Condition::Any),
            inner.prop_map(|c| Condition::Not(Box::new(c))),
        ]
    })
}

fn rule_at(i: usize, condition: Condition) -> Rule {
    Rule {
        condition,
        url: format!("https://r{i}.example.com/"),
    }
}

/// Up to 8 rules of random trees, cut to the 64-leaf limit.
fn mixed_rules() -> impl Strategy<Value = Vec<Rule>> {
    prop::collection::vec(condition(), 0..8).prop_map(|conditions| {
        let mut total = 0;
        conditions
            .into_iter()
            .take_while(|c| {
                total += leaves(c);
                total <= MAX_CONDITIONS
            })
            .enumerate()
            .map(|(i, c)| rule_at(i, c))
            .collect()
    })
}

/// Exactly 64 leaves split over 1 to 32 rules, each rule a `not`, `all` or
/// `any` of its share: the worst case the bound allows.
fn full_rules() -> impl Strategy<Value = Vec<Rule>> {
    (
        prop::collection::vec(leaf(), MAX_CONDITIONS),
        1usize..=32,
        prop::collection::vec(0u8..3, 32),
    )
        .prop_map(|(leaves, rules, shapes)| {
            let per = MAX_CONDITIONS.div_ceil(rules);
            leaves
                .chunks(per)
                .zip(shapes)
                .enumerate()
                .map(|(i, (chunk, shape))| {
                    let chunk = chunk.to_vec();
                    let c = match shape {
                        0 => Condition::Not(Box::new(Condition::Any(chunk))),
                        1 => Condition::All(chunk),
                        _ => Condition::Any(chunk),
                    };
                    rule_at(i, c)
                })
                .collect()
        })
}

// ------------------------------------------------------------ requests

#[derive(Clone, Debug)]
struct OwnedRequest {
    now_ms: i64,
    country: Option<[u8; 2]>,
    region: Option<String>,
    user_agent: Option<String>,
    accept_language: Option<String>,
    referer: Option<String>,
    query: Option<String>,
}

impl OwnedRequest {
    fn borrow(&self) -> Request<'_> {
        Request {
            now_ms: self.now_ms,
            country: self.country,
            region: self.region.as_deref().map(str::as_bytes),
            user_agent: self.user_agent.as_deref().map(str::as_bytes),
            accept_language: self.accept_language.as_deref().map(str::as_bytes),
            referer: self.referer.as_deref().map(str::as_bytes),
            query: self.query.as_deref().map(str::as_bytes),
        }
    }
}

fn pick(pool: &[&'static str]) -> BoxedStrategy<String> {
    prop::sample::select(pool.to_vec())
        .prop_map(str::to_owned)
        .boxed()
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/118.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36 Edg/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36 OPR/105.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
    "",
];

const LANGUAGES: &[&str] = &[
    "en-GB,en;q=0.9",
    "en",
    "EN-us",
    "de;q=0.5, pt-BR",
    "pt",
    "fr-CA;q=0, fr;q=0.4",
    "zh-Hant-TW,zh;q=0.8",
    "*",
    "*;q=1, de-CH",
    "en-;q=1",
    "",
];

const REFERERS: &[&str] = &[
    "https://news.example.com/story?id=1",
    "http://EXAMPLE.com:8080/",
    "https://notexample.com/",
    "https://deep.news.example.com./",
    "https://t.co/abc",
    "https://user@social.example/x",
    "android-app://com.example",
    "https://x.org",
    "https://[2001:db8::1]/",
    "",
];

const QUERY_NAMES: &[&str] = &[
    "utm_source",
    "UTM_SOURCE",
    "q",
    "a+b",
    "a%20b",
    "a%2",
    "%C3%A9",
    "%c3%a9",
    "é",
    "x",
    "%",
    "%25",
    "",
];

const QUERY_VALUES: &[&str] = &[
    "news", "a+b", "a%20b", "100%", "100%25", "%C3%A9", "", "%zz", "%4", "%+1", "N", "n",
];

fn query_string() -> impl Strategy<Value = String> {
    let param =
        (pick(QUERY_NAMES), prop::option::of(pick(QUERY_VALUES))).prop_map(|(n, v)| match v {
            Some(v) => format!("{n}={v}"),
            None => n,
        });
    let segment = prop_oneof![
        6 => param,
        1 => Just(String::new()),
        1 => "[a-z]{1,4}=[a-z0-9]{0,6}",
    ];
    // Something in front, so the generated parameters land around the
    // parameter and byte limits.
    let prefix = prop_oneof![
        4 => Just(String::new()),
        1 => (55usize..70).prop_map(|n| "f=1&".repeat(n)),
        1 => (MAX_QUERY_BYTES - 40..MAX_QUERY_BYTES + 10)
            .prop_map(|n| format!("pad={}&", "y".repeat(n - 4))),
    ];
    (prefix, prop::collection::vec(segment, 0..8)).prop_map(|(p, s)| p + &s.join("&"))
}

fn request() -> impl Strategy<Value = OwnedRequest> {
    let now = prop_oneof![
        4 => (-96 * 60i64..96 * 60).prop_map(|m| BASE_MS + m * 60_000),
        1 => -2_208_988_800_000i64..4_102_444_800_000,
    ];
    let country = prop::option::of(prop::sample::select(vec![
        *b"US", *b"CA", *b"DE", *b"GB", *b"FR", *b"JP",
    ]));
    let region = prop::option::of(prop_oneof![
        4 => pick(&["CA", "ny", "NY", "BY", "ON", "ENG", "75", "TX"]),
        1 => "[A-Za-z0-9-]{0,5}",
    ]);
    let user_agent = prop::option::of(prop_oneof![
        6 => pick(USER_AGENTS),
        1 => "[ -~]{0,40}",
        1 => pick(USER_AGENTS).prop_map(|ua| format!("{}{ua}", "x".repeat(500))),
    ]);
    let accept_language = prop::option::of(prop_oneof![
        6 => pick(LANGUAGES),
        1 => "[a-zA-Z0-9,;=. *-]{0,30}",
    ]);
    let referer = prop::option::of(prop_oneof![
        6 => pick(REFERERS),
        1 => "[ -~]{0,30}",
    ]);
    let query = prop::option::of(query_string());
    (
        now,
        country,
        region,
        user_agent,
        accept_language,
        referer,
        query,
    )
        .prop_map(
            |(now_ms, country, region, user_agent, accept_language, referer, query)| OwnedRequest {
                now_ms,
                country,
                region,
                user_agent,
                accept_language,
                referer,
                query,
            },
        )
}

// ------------------------------------------------------------ the property

/// The rule list compiled the three ways it is loaded: by the API (with
/// destinations normalised), by the origin from a stored row, and by the
/// edge from the published decision list.
fn loaded(rules: &[Rule]) -> [Rules; 3] {
    let api = rules_v2::compile(rules, POLICY).expect("generated rules are valid");
    let origin = RuleSet::new(rules.to_vec())
        .expect("generated rules are valid")
        .compiled()
        .clone();
    let published = serde_json::to_string(&origin).unwrap();
    let edge: Rules = serde_json::from_str(&published).expect("published lists load");
    [api, origin, edge]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn compiled_rules_agree_with_the_tree_walk(
        rules in prop_oneof![4 => mixed_rules(), 1 => full_rules()],
        requests in prop::collection::vec(request(), REQUESTS_PER_CASE),
    ) {
        let compiled = loaded(&rules);
        for owned in &requests {
            let req = owned.borrow();
            let (want, want_tested) = interpret(&rules, &Facts::of(&req));
            prop_assert!(want_tested <= MAX_CONDITIONS);
            for (form, r) in ["api", "origin", "edge"].iter().zip(&compiled) {
                let (got, tested) = r.evaluate_counted(&req);
                prop_assert_eq!(got, want, "{} chose another rule for {:?}", form, owned);
                prop_assert_eq!(
                    tested, want_tested,
                    "{} tested another number of leaves for {:?}", form, owned
                );
                prop_assert_eq!(
                    r.destination(&req),
                    want.map(|i| rules[i].url.as_str())
                );
            }
        }
    }
}

// ------------------------------------------------------------ the model

// The interpreter is only as good as its own reading of the grammar, so a
// few of its answers are pinned by hand.

fn req_at(now_ms: i64) -> Request<'static> {
    Request {
        now_ms,
        ..Request::default()
    }
}

#[test]
fn model_decodes_like_a_form() {
    assert_eq!(form_decode(b"a+b%20c"), b"a b c");
    assert_eq!(form_decode(b"%C3%a9"), "é".as_bytes());
    assert_eq!(form_decode(b"100%"), b"100%");
    assert_eq!(form_decode(b"%4"), b"%4");
    assert_eq!(form_decode(b"%+1"), b"% 1");
    assert_eq!(form_decode(b"%zz"), b"%zz");
}

#[test]
fn model_reads_queries_within_the_limits() {
    let q = naive_query(b"a=1&&b&c=2=3");
    assert_eq!(
        q,
        [
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), Vec::new()),
            (b"c".to_vec(), b"2=3".to_vec()),
        ]
    );
    let many = "f=1&".repeat(MAX_QUERY_PARAMS) + "x=1";
    assert_eq!(naive_query(many.as_bytes()).len(), MAX_QUERY_PARAMS);
    let fits = format!("p={}&x", "y".repeat(MAX_QUERY_BYTES - 2));
    assert_eq!(naive_query(fits.as_bytes()).len(), 1);
    let crosses = format!("p={}", "y".repeat(MAX_QUERY_BYTES - 1));
    assert!(naive_query(crosses.as_bytes()).is_empty());
}

#[test]
fn model_reads_local_time() {
    // Monday 12:30 UTC is Monday 07:30 at UTC-5 and Tuesday 02:30 at +14.
    let window = |days: &[&str], hours: [&str; 2], offset: i32| TimeWindow {
        days: Some(days.iter().map(|d| d.to_string()).collect()),
        hours: Some(hours.map(str::to_owned)),
        utc_offset_minutes: offset,
        ..TimeWindow::default()
    };
    assert!(time_holds(
        &window(&["mon"], ["07:30", "08:00"], -300),
        BASE_MS
    ));
    assert!(!time_holds(
        &window(&["mon"], ["07:31", "08:00"], -300),
        BASE_MS
    ));
    assert!(time_holds(
        &window(&["tue"], ["22:00", "03:00"], 840),
        BASE_MS
    ));
    assert!(!time_holds(
        &window(&["mon"], ["22:00", "03:00"], 840),
        BASE_MS
    ));
    assert!(time_holds(
        &window(&["mon"], ["12:00", "24:00"], 0),
        BASE_MS
    ));
    let bounded = TimeWindow {
        after: DateTime::from_timestamp_millis(BASE_MS),
        before: DateTime::from_timestamp_millis(BASE_MS + HOUR_MS),
        ..TimeWindow::default()
    };
    assert!(time_holds(&bounded, BASE_MS));
    assert!(!time_holds(&bounded, BASE_MS + HOUR_MS));
    assert!(!time_holds(&bounded, BASE_MS - 1));
}

#[test]
fn model_short_circuits_and_counts_like_the_tree() {
    let us = || Condition::Country(vec!["US".into()]);
    let de = || Condition::Country(vec!["DE".into()]);
    let rules = vec![
        rule_at(0, Condition::All(vec![de(), us(), us()])),
        rule_at(1, Condition::Any(vec![us(), de()])),
        rule_at(2, Condition::Not(Box::new(us()))),
    ];
    let facts = |c: &[u8; 2]| {
        Facts::of(&Request {
            country: Some(*c),
            ..req_at(BASE_MS)
        })
    };
    // US: rule 0 stops after its first leaf, rule 1 after its first.
    assert_eq!(interpret(&rules, &facts(b"US")), (Some(1), 2));
    // DE: rule 0 tests DE then US, rule 1 tests US then DE.
    assert_eq!(interpret(&rules, &facts(b"DE")), (Some(1), 4));
    // FR: rule 0 one leaf, rule 1 two, rule 2 one.
    assert_eq!(interpret(&rules, &facts(b"FR")), (Some(2), 4));
    let [api, ..] = loaded(&rules);
    for c in [b"US", b"DE", b"FR"] {
        let req = Request {
            country: Some(*c),
            ..req_at(BASE_MS)
        };
        assert_eq!(
            api.evaluate_counted(&req),
            interpret(&rules, &Facts::of(&req))
        );
    }
}

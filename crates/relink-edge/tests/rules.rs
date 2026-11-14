//! Targeting rules decide the same at the origin and at the edge.
//!
//! Each case generates links with random rule lists (every leaf type, under
//! `all`, `any` and `not`) and publishes them twice: to the origin's link
//! source and, as the origin syncs them, to KV. Random visitors (country
//! and region from the CDN, User-Agent, Accept-Language, Referer and query
//! string) are then answered by both: by the origin directly, behind the
//! CDN as a trusted proxy, and by the edge, which forwards what it cannot
//! answer to that same origin with the headers the Worker sends. The two
//! answers must be the same response, and neither may let a cache keep an
//! answer from a link with rules.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::response::Response;
use proptest::prelude::*;
use relink_core::abtest::Signer;
use relink_core::deeplink::AppLink;
use relink_core::model::{Destination, Link};
use relink_core::rules::Settings;
use relink_core::rules_v2::{Condition, QueryMatch, Rule, RuleSet, TimeWindow};
use relink_core::wire::kv_key;
use relink_edge::logic::{
    EDGE_MAX_AGE, EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, REGION_HEADER, Served, handle,
    origin_path,
};
use relink_server::config::Config;
use relink_server::limiter::{LeaseStore, StoreUnavailable};
use relink_server::metrics::{Metrics, Outcome};
use relink_server::resolver::LinkSource;
use relink_server::server::{App, open_db};
use relink_server::store::DbError;
use relink_server::util::{BoxFuture, now_ms};

const KEY_HEX: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
const DEFAULT_HOST: &str = "relink.example";
/// The CDN in front of the origin, and the edge as the origin sees it.
const PROXY: &str = "10.0.0.7";
const COUNTRY_HEADER: &str = "cf-ipcountry";

const UAS: [&str; 7] = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
];

const LANGUAGES: [&str; 6] = [
    "en-US,en;q=0.9",
    "de-DE,de;q=0.8,en;q=0.5",
    "fr-CA",
    "fr;q=0.2, de",
    "*",
    "pt-BR, pt;q=0.9",
];

const REFERERS: [&str; 5] = [
    "https://news.example/story",
    "https://www.news.example/a?b=c",
    "https://example.com/",
    "android-app://com.example.app/",
    "not a url",
];

const QUERIES: [&str; 7] = [
    "src=mail",
    "src=ma%69l&x=1",
    "utm_source=ads&src",
    "x=1&utm_source=news+letter",
    "src=",
    "",
    "a=%zz&src=MAIL",
];

fn pick<T: Clone + std::fmt::Debug + 'static>(items: &'static [T]) -> impl Strategy<Value = T> {
    prop::sample::select(items)
}

fn strings(items: &'static [&'static str], max: usize) -> impl Strategy<Value = Vec<String>> {
    prop::sample::subsequence(items, 1..=max.min(items.len()))
        .prop_map(|v| v.into_iter().map(str::to_owned).collect())
}

/// A leaf condition of any type, with values visitors below can match.
fn leaf() -> impl Strategy<Value = Condition> {
    prop_oneof![
        strings(&["US", "DE", "FR", "BR"], 3).prop_map(Condition::Country),
        strings(&["US-CA", "US-NY", "DE-BY", "us-ca"], 2).prop_map(Condition::Region),
        strings(&["desktop", "mobile", "tablet", "bot", "other"], 2).prop_map(Condition::Device),
        strings(&["ios", "android", "windows", "macos", "linux", "other"], 2)
            .prop_map(Condition::Os),
        strings(&["chrome", "safari", "firefox", "edge", "other"], 2).prop_map(Condition::Browser),
        strings(&["en", "de", "fr-CA", "fr", "pt-br"], 2).prop_map(Condition::Language),
        strings(&["news.example", "example.com", "com.example.app"], 2)
            .prop_map(Condition::Referrer),
        (
            pick(&["src", "utm_source", "x"]),
            prop::option::of(strings(&["mail", "ads", "news letter", "1", ""], 2)),
        )
            .prop_map(|(name, values)| Condition::Query(QueryMatch {
                name: name.to_owned(),
                values,
            })),
        // Instants far from now, so the origin and edge clocks, a moment
        // apart, see the same side.
        prop::bool::ANY.prop_map(|past| Condition::Time(TimeWindow {
            after: past.then(|| "2001-01-01T00:00:00Z".parse().unwrap()),
            before: (!past).then(|| "2001-01-01T00:00:00Z".parse().unwrap()),
            ..TimeWindow::default()
        })),
    ]
}

fn condition() -> impl Strategy<Value = Condition> {
    leaf().prop_recursive(2, 8, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..3).prop_map(Condition::All),
            prop::collection::vec(inner.clone(), 1..3).prop_map(Condition::Any),
            inner.prop_map(|c| Condition::Not(Box::new(c))),
        ]
    })
}

fn rules() -> impl Strategy<Value = Vec<Rule>> {
    prop::collection::vec(condition(), 0..4).prop_map(|conds| {
        conds
            .into_iter()
            .enumerate()
            .map(|(i, condition)| Rule {
                condition,
                url: format!("https://rule.example/{i}"),
            })
            .collect()
    })
}

/// App targets a generated link may have.
const APPS: [Option<&str>; 4] = [
    None,
    Some(r#"{"ios": {"store_url": "https://apps.apple.com/app/id1"}}"#),
    Some(r#"{"android": {"package": "com.example.app", "url": "myapp://item/7"}}"#),
    Some(
        r#"{"ios": {"store_url": "https://apps.apple.com/app/id1"},
            "android": {"package": "com.example.app", "url": "https://dest.example/app",
                        "store_url": "https://dest.example/get?the=app"}}"#,
    ),
];

fn link(id: i64, rules: Vec<Rule>, limited: bool) -> Link {
    with_app(id, rules, limited, None)
}

fn with_app(id: i64, rules: Vec<Rule>, limited: bool, app: Option<&str>) -> Link {
    Link {
        id,
        code: format!("link{id}"),
        destinations: vec![Destination {
            url: format!("https://dest.example/{id}"),
            weight: 1,
        }],
        destinations_version: 1,
        redirect_status: 302,
        expires_at: None,
        max_clicks: limited.then_some(1_000_000),
        geo: None,
        fallback_url: None,
        enabled: true,
        health_check: false,
        unhealthy: vec![false],
        rules: RuleSet::new(rules).unwrap(),
        app: app
            .map(|a| serde_json::from_str::<AppLink>(a).unwrap().compile())
            .unwrap_or_default(),
    }
}

/// The facts one visitor brings.
#[derive(Clone, Debug, Default)]
struct Visitor {
    country: Option<&'static str>,
    region: Option<&'static str>,
    user_agent: Option<&'static str>,
    accept_language: Option<&'static str>,
    referer: Option<&'static str>,
    query: Option<&'static str>,
}

fn visitor() -> impl Strategy<Value = Visitor> {
    (
        prop::option::of(pick(&["US", "DE", "FR", "BR"])),
        prop::option::of(pick(&["CA", "NY", "BY", "by", "C!"])),
        prop::option::of(pick(&UAS)),
        prop::option::of(pick(&LANGUAGES)),
        prop::option::of(pick(&REFERERS)),
        prop::option::of(pick(&QUERIES)),
    )
        .prop_map(
            |(country, region, user_agent, accept_language, referer, query)| Visitor {
                country,
                region,
                user_agent,
                accept_language,
                referer,
                query,
            },
        )
}

struct Links(HashMap<String, Link>);

impl LinkSource for Links {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
        Box::pin(async move { Ok(self.0.get(key).cloned()) })
    }
}

/// Grants every click: limited links are answered by the origin, with
/// their rules applied there.
struct Unlimited;

impl LeaseStore for Unlimited {
    fn reserve(&self, _: i64, max: i64) -> BoxFuture<'_, Result<i64, StoreUnavailable>> {
        Box::pin(async move { Ok(max) })
    }
    fn release(&self, _: i64, _: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>> {
        Box::pin(async { Ok(()) })
    }
}

fn origin(links: &[Link]) -> Arc<App> {
    let cfg = Config::from_vars(&|k| match k {
        "RELINK_DATABASE_URL" => Some("postgres://x:x@127.0.0.1:1/x".into()),
        "RELINK_PUBLIC_BASE_URL" => Some(format!("https://{DEFAULT_HOST}")),
        "RELINK_COOKIE_KEY" => Some(KEY_HEX.into()),
        "RELINK_TRUSTED_PROXIES" => Some("10.0.0.0/8".into()),
        "RELINK_COUNTRY_HEADER" => Some(COUNTRY_HEADER.into()),
        "RELINK_REGION_HEADER" => Some(REGION_HEADER.into()),
        _ => None,
    })
    .unwrap();
    let db = open_db(&cfg).unwrap();
    let links = links.iter().map(|l| (l.code.clone(), l.clone())).collect();
    let (app, _rx) = App::new(
        cfg,
        db,
        Arc::new(Links(links)),
        Arc::new(Unlimited),
        Arc::new(Metrics::default()),
    );
    app
}

struct MemoryKv(HashMap<String, String>);

impl MemoryKv {
    fn of(links: &[Link]) -> MemoryKv {
        MemoryKv(
            links
                .iter()
                .map(|l| (kv_key(&l.code), serde_json::to_string(l).unwrap()))
                .collect(),
        )
    }
}

impl Kv for MemoryKv {
    async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
        Ok(self.0.get(key).cloned())
    }
}

fn set(headers: &mut HeaderMap, name: &str, value: Option<&[u8]>) {
    if let Some(v) = value {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(v).unwrap(),
        );
    }
}

/// The origin behind the edge, called with exactly what the Worker sends:
/// the visitor's path and query, User-Agent, Referer, Accept-Language and
/// the CDN's country and region, from a trusted address.
struct Behind(Arc<App>);

impl Origin for Behind {
    async fn redirect(&self, req: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static(DEFAULT_HOST));
        set(&mut headers, "user-agent", req.user_agent.as_deref());
        set(&mut headers, "referer", req.referer.as_deref());
        set(
            &mut headers,
            "accept-language",
            req.accept_language.as_deref(),
        );
        set(
            &mut headers,
            COUNTRY_HEADER,
            req.country.as_ref().map(|c| &c[..]),
        );
        set(&mut headers, REGION_HEADER, req.region.as_deref());
        let target = origin_path(req);
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target.as_str(), None),
        };
        let peer: IpAddr = PROXY.parse().unwrap();
        let (resp, _) = relink_server::redirect::handle(&self.0, path, query, &headers, peer).await;
        Ok(answer(resp).await)
    }
}

async fn answer(resp: Response) -> EdgeResponse {
    let status = resp.status().as_u16();
    let mut headers = Vec::new();
    for name in [
        "location",
        "set-cookie",
        "cache-control",
        "retry-after",
        "content-type",
    ] {
        if let Some(v) = resp.headers().get(name) {
            headers.push((name.to_owned(), v.to_str().unwrap().to_owned()));
        }
    }
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    EdgeResponse {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

fn settings(signer: &Signer) -> Settings<'_> {
    Settings {
        signer,
        cookie_secure: true,
    }
}

fn signer() -> Signer {
    Signer::new(
        relink_core::hex::decode(KEY_HEX)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn edge_request(code: &str, v: &Visitor) -> EdgeRequest {
    let bytes = |s: Option<&str>| s.map(|s| s.as_bytes().to_vec());
    EdgeRequest {
        code: code.to_owned(),
        host: Some(DEFAULT_HOST.as_bytes().to_vec()),
        country: v.country.map(|c| c.as_bytes().try_into().unwrap()),
        region: bytes(v.region),
        user_agent: bytes(v.user_agent),
        accept_language: bytes(v.accept_language),
        referer: bytes(v.referer),
        query: v.query.map(str::to_owned),
        now_ms: now_ms(),
        random: 7,
        ..EdgeRequest::default()
    }
}

/// Both answers to `v` asking for `code`: the origin's (reached through
/// the CDN), the edge's, where the edge got its answer, and the origin's
/// outcome.
async fn both(
    app: &Arc<App>,
    kv: &MemoryKv,
    code: &str,
    v: &Visitor,
) -> (EdgeResponse, EdgeResponse, Served, Outcome) {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static(DEFAULT_HOST));
    set(&mut headers, "user-agent", v.user_agent.map(str::as_bytes));
    set(&mut headers, "referer", v.referer.map(str::as_bytes));
    set(
        &mut headers,
        "accept-language",
        v.accept_language.map(str::as_bytes),
    );
    set(&mut headers, COUNTRY_HEADER, v.country.map(str::as_bytes));
    set(&mut headers, REGION_HEADER, v.region.map(str::as_bytes));
    let peer: IpAddr = PROXY.parse().unwrap();
    let (resp, outcome) = relink_server::redirect::handle(app, code, v.query, &headers, peer).await;
    let at_origin = answer(resp).await;

    let signer = signer();
    let req = edge_request(code, v);
    let out = handle(
        kv,
        &Behind(app.clone()),
        &settings(&signer),
        DEFAULT_HOST,
        &req,
    )
    .await;
    (at_origin, out.response, out.served, outcome)
}

/// The responses without `cache-control`, which the edge sets to its own
/// shorter time on answers that may be cached.
fn without_cache(mut r: EdgeResponse) -> EdgeResponse {
    r.headers.retain(|(k, _)| k != "cache-control");
    r.headers.sort();
    r
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn origin_and_edge_apply_rules_alike(
        lists in prop::collection::vec(
            (rules(), prop::bool::weighted(0.2), pick(&APPS)),
            1..5,
        ),
        visits in prop::collection::vec((0usize..5, visitor()), 1..16),
    ) {
        let links: Vec<Link> = lists
            .into_iter()
            .enumerate()
            .map(|(i, (r, limited, app))| with_app(i as i64, r, limited, app))
            .collect();
        let rt = runtime();
        rt.block_on(async {
            let app = origin(&links);
            let kv = MemoryKv::of(&links);
            for (i, v) in &visits {
                let l = &links[i % links.len()];
                let (o, e, served, _) = both(&app, &kv, &l.code, v).await;
                if !l.rules.is_empty() || !l.app.is_empty() {
                    for r in [&o, &e] {
                        prop_assert_eq!(
                            r.header("cache-control"),
                            Some("no-store"),
                            "a link with rules or app targets was cacheable: {:?}",
                            r
                        );
                    }
                }
                let (o, e) = (without_cache(o), without_cache(e));
                prop_assert!(
                    o == e,
                    "{} {:?} (edge {:?})\nrules:  {}\norigin: {:?}\nedge:   {:?}",
                    l.code,
                    v,
                    served,
                    serde_json::to_string(&l.rules).unwrap(),
                    o,
                    e
                );
                prop_assert_eq!(served, if l.max_clicks.is_some() {
                    Served::Origin
                } else {
                    Served::Edge
                });
            }
            Ok(())
        })?;
    }
}

/// The property above would hold if rules were ignored on both sides; these
/// visitors must each be sent where their rule says, at the edge itself and
/// at the origin behind it.
#[tokio::test]
async fn rules_route_visitors_at_both_and_are_never_cached() {
    let rules: Vec<Rule> = serde_json::from_str(
        r#"[
          {"if": {"all": [{"os": ["ios"]}, {"not": {"device": ["tablet"]}}]},
           "url": "https://apps.example/ios"},
          {"if": {"region": ["US-CA"]}, "url": "https://example.com/ca"},
          {"if": {"language": ["de"]}, "url": "https://example.com/de"},
          {"if": {"referrer": ["news.example"]}, "url": "https://example.com/news"},
          {"if": {"query": {"name": "src", "values": ["mail"]}}, "url": "https://example.com/mail"},
          {"if": {"browser": ["firefox"]}, "url": "https://example.com/firefox"}
        ]"#,
    )
    .unwrap();
    let open = link(0, rules.clone(), false);
    let limited = link(1, rules, true);
    let plain = link(2, Vec::new(), false);
    let links = [open, limited, plain];
    let app = origin(&links);
    let kv = MemoryKv::of(&links);

    let cases = [
        (
            Visitor {
                user_agent: Some(UAS[0]),
                ..Visitor::default()
            },
            "https://apps.example/ios",
        ),
        (
            Visitor {
                user_agent: Some(UAS[1]),
                country: Some("US"),
                region: Some("ca"),
                ..Visitor::default()
            },
            "https://example.com/ca",
        ),
        (
            Visitor {
                accept_language: Some(LANGUAGES[1]),
                ..Visitor::default()
            },
            "https://example.com/de",
        ),
        (
            Visitor {
                referer: Some(REFERERS[1]),
                ..Visitor::default()
            },
            "https://example.com/news",
        ),
        (
            Visitor {
                query: Some(QUERIES[1]),
                ..Visitor::default()
            },
            "https://example.com/mail",
        ),
        (
            Visitor {
                user_agent: Some(UAS[3]),
                ..Visitor::default()
            },
            "https://example.com/firefox",
        ),
        (
            Visitor {
                // A region without its country never matches.
                region: Some("CA"),
                query: Some("src=ads"),
                ..Visitor::default()
            },
            "https://dest.example/0",
        ),
    ];
    for (v, want) in &cases {
        for (code, want_served) in [("link0", Served::Edge), ("link1", Served::Origin)] {
            let (o, e, served, outcome) = both(&app, &kv, code, v).await;
            let fell_through = want.contains("dest.example");
            let want = want.replace("dest.example/0", &format!("dest.example/{}", &code[4..]));
            assert_eq!(served, want_served, "{code} {v:?}");
            let counted = if fell_through {
                Outcome::Redirect
            } else {
                Outcome::Rule
            };
            assert_eq!(outcome, counted, "{code} {v:?}");
            for r in [&o, &e] {
                assert_eq!(r.status, 302, "{code} {v:?}: {r:?}");
                assert_eq!(r.header("location"), Some(want.as_str()), "{code} {v:?}");
                assert_eq!(r.header("cache-control"), Some("no-store"), "{code} {v:?}");
            }
        }
    }
    // A link without rules is still cached as before.
    let (o, e, served, _) = both(&app, &kv, "link2", &Visitor::default()).await;
    assert_eq!(served, Served::Edge);
    assert_eq!(e.header("cache-control"), Some(EDGE_MAX_AGE));
    assert_ne!(o.header("cache-control"), Some("no-store"));
}

/// App targets send phones to the store or into the app at both, after
/// targeting rules and before the destinations; desktops and crawlers
/// follow the destinations; nothing is cached.
#[tokio::test]
async fn app_targets_send_phones_at_both() {
    let rule: Vec<Rule> =
        serde_json::from_str(r#"[{"if": {"language": ["de"]}, "url": "https://example.com/de"}]"#)
            .unwrap();
    let links = [
        with_app(0, rule.clone(), false, APPS[3]),
        with_app(1, rule, true, APPS[3]),
        with_app(2, Vec::new(), false, APPS[2]),
    ];
    let app = origin(&links);
    let kv = MemoryKv::of(&links);
    let ua = |i: usize| Visitor {
        user_agent: Some(UAS[i]),
        ..Visitor::default()
    };
    let intent = "intent://dest.example/app#Intent;scheme=https;package=com.example.app;\
                  S.browser_fallback_url=https%3A%2F%2Fdest.example%2Fget%3Fthe%3Dapp;end";
    let german_iphone = Visitor {
        accept_language: Some(LANGUAGES[1]),
        ..ua(0)
    };
    assert!(LANGUAGES[1].starts_with("de"));
    for (code, want_served) in [("link0", Served::Edge), ("link1", Served::Origin)] {
        let dest = format!("https://dest.example/{}", &code[4..]);
        for (v, want, counted) in [
            (ua(0), "https://apps.apple.com/app/id1", Outcome::App),
            (ua(1), "https://apps.apple.com/app/id1", Outcome::App),
            (ua(2), intent, Outcome::App),
            (ua(3), dest.as_str(), Outcome::Redirect),
            (ua(6), dest.as_str(), Outcome::Redirect),
            (Visitor::default(), dest.as_str(), Outcome::Redirect),
            (
                german_iphone.clone(),
                "https://example.com/de",
                Outcome::Rule,
            ),
        ] {
            let (o, e, served, outcome) = both(&app, &kv, code, &v).await;
            assert_eq!(served, want_served, "{code} {v:?}");
            assert_eq!(outcome, counted, "{code} {v:?}");
            for r in [&o, &e] {
                assert_eq!(r.status, 302, "{code} {v:?}: {r:?}");
                assert_eq!(r.header("location"), Some(want), "{code} {v:?}");
                assert_eq!(r.header("cache-control"), Some("no-store"), "{code} {v:?}");
            }
        }
    }
    // Android only: the Play Store is the fallback; iPhones get the link.
    let (_, e, _, _) = both(&app, &kv, "link2", &ua(2)).await;
    assert_eq!(
        e.header("location"),
        Some(
            "intent://item/7#Intent;scheme=myapp;package=com.example.app;S.browser_fallback_url=\
             https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dcom.example.app;end"
        )
    );
    let (_, e, _, _) = both(&app, &kv, "link2", &ua(0)).await;
    assert_eq!(e.header("location"), Some("https://dest.example/2"));
}

/// The origin believes the region header only from a trusted proxy, as it
/// does the country header.
#[tokio::test]
async fn the_region_header_is_believed_only_from_trusted_proxies() {
    let rules: Vec<Rule> =
        serde_json::from_str(r#"[{"if": {"region": ["US-CA"]}, "url": "https://example.com/ca"}]"#)
            .unwrap();
    let links = [link(0, rules, false)];
    let app = origin(&links);
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static(DEFAULT_HOST));
    set(&mut headers, COUNTRY_HEADER, Some(b"US"));
    set(&mut headers, REGION_HEADER, Some(b"CA"));
    let location = |resp: &Response| {
        resp.headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let trusted: IpAddr = PROXY.parse().unwrap();
    let (resp, _) = relink_server::redirect::handle(&app, "link0", None, &headers, trusted).await;
    assert_eq!(location(&resp).as_deref(), Some("https://example.com/ca"));
    let visitor: IpAddr = "203.0.113.9".parse().unwrap();
    let (resp, _) = relink_server::redirect::handle(&app, "link0", None, &headers, visitor).await;
    assert_eq!(location(&resp).as_deref(), Some("https://dest.example/0"));
}

#[test]
fn the_origin_is_asked_for_the_visitors_query() {
    let mut req = EdgeRequest {
        code: "abc".into(),
        ..EdgeRequest::default()
    };
    assert_eq!(origin_path(&req), "abc");
    req.query = Some(String::new());
    assert_eq!(origin_path(&req), "abc");
    req.query = Some("src=mail&x=%20".into());
    assert_eq!(origin_path(&req), "abc?src=mail&x=%20");
}

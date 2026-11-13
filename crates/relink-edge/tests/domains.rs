//! Every domain decision is the same at the origin and at the edge.
//!
//! Each case generates a world (verified custom domains with random
//! settings, and links on them and on the default domain, live, expired,
//! disabled or click-limited) and publishes it twice: into the origin's
//! domain map and link source, and into the KV records the origin syncs to
//! the edge. Random requests (any `Host`, including ports, final dots,
//! mixed case, IP addresses, unknown and malformed hosts, and any path,
//! including prefixes, mixed-case codes, percent-encoding and junk) are
//! then answered by both: by the origin directly, and by the edge, which
//! forwards what it cannot answer to that same origin the way the Worker
//! does (`x-forwarded-host` from a trusted proxy). The two answers must be
//! the same response.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;
use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use relink_core::abtest::Signer;
use relink_core::destination::Policy;
use relink_core::model::{Destination, Link};
use relink_core::rules::Settings;
use relink_core::site::{DomainSettings, NOT_FOUND_TEXT};
use relink_core::wire::{EdgeDomain, domain_kv_key, host_kv_key, kv_key};
use relink_edge::logic::{
    EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, Served, forwarded_host, handle,
};
use relink_server::config::Config;
use relink_server::domains::VerifiedDomain;
use relink_server::limiter::{LeaseStore, StoreUnavailable};
use relink_server::metrics::Metrics;
use relink_server::resolver::LinkSource;
use relink_server::server::{App, open_db};
use relink_server::store::{DbError, link_key};
use relink_server::util::{BoxFuture, now_ms};

const KEY_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// The origin's own host, from `RELINK_PUBLIC_BASE_URL`.
const DEFAULT_HOST: &str = "relink.example";

/// The edge, as the origin sees it: a trusted proxy.
const EDGE_PEER: &str = "10.0.0.7";

/// A visitor talking to the origin directly: not trusted.
const VISITOR: &str = "203.0.113.9";

const HOSTNAMES: [&str; 3] = [
    "go.example.com",
    "links.example.org",
    "xn--bcher-kva.example",
];

const CODES: [&str; 7] = [
    "abc",
    "Pricing",
    "promo",
    "summer-sale",
    "x_y_z",
    "campaign",
    "ABC",
];

const PREFIXES: [&str; 3] = ["campaign", "promo", "x1"];

#[derive(Clone, Copy, Debug)]
enum State {
    Live,
    Expired,
    Disabled,
    Limited,
}

#[derive(Clone, Debug)]
struct World {
    domains: Vec<VerifiedDomain>,
    links: Vec<(Option<usize>, Link)>,
}

fn settings() -> impl Strategy<Value = DomainSettings> {
    (
        prop::option::of(prop::sample::select(vec![
            "https://example.com/home",
            "https://shop.example.net/?from=root",
        ])),
        prop::option::of(Just("<h1>{{code}} is not on {{host}}</h1>")),
        prop::option::of(Just("<p>{{code}} has gone</p>")),
        prop::sample::subsequence(PREFIXES.to_vec(), 0..=PREFIXES.len()),
        any::<bool>(),
    )
        .prop_map(|(root, nf, gone, prefixes, ci)| {
            DomainSettings {
                root_url: root.map(str::to_owned),
                not_found_page: nf.map(str::to_owned),
                gone_page: gone.map(str::to_owned),
                prefixes: prefixes.into_iter().map(str::to_owned).collect(),
                case_insensitive: ci,
            }
            .validated(Policy {
                allow_ip_literals: false,
                allow_private: false,
            })
            .expect("generated settings are valid")
        })
}

fn state() -> impl Strategy<Value = State> {
    prop_oneof![
        4 => Just(State::Live),
        1 => Just(State::Expired),
        1 => Just(State::Disabled),
        1 => Just(State::Limited),
    ]
}

fn world() -> impl Strategy<Value = World> {
    (
        prop::sample::subsequence(HOSTNAMES.to_vec(), 0..=HOSTNAMES.len()),
        prop::collection::vec(settings(), HOSTNAMES.len()),
        prop::collection::vec(
            (
                any::<prop::sample::Index>(),
                any::<prop::sample::Index>(),
                state(),
            ),
            0..12,
        ),
    )
        .prop_map(|(hosts, settings, links)| {
            let domains: Vec<VerifiedDomain> = hosts
                .into_iter()
                .zip(settings)
                .enumerate()
                .map(|(i, (h, s))| VerifiedDomain {
                    hostname: h.to_owned(),
                    id: 100 + i as i64,
                    settings: s,
                })
                .collect();
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for (i, (domain, code, state)) in links.into_iter().enumerate() {
                // Index `domains.len()` is the default domain.
                let d = domain.index(domains.len() + 1);
                let d = (d < domains.len()).then_some(d);
                let mut code = CODES[code.index(CODES.len())].to_owned();
                // Codes on a case-insensitive domain are stored lowercase.
                if d.is_some_and(|d| domains[d].settings.case_insensitive) {
                    code.make_ascii_lowercase();
                }
                if !seen.insert((d, code.clone())) {
                    continue;
                }
                out.push((d, link(i as i64 + 1, code, state)));
            }
            World {
                domains,
                links: out,
            }
        })
}

fn link(id: i64, code: String, state: State) -> Link {
    Link {
        id,
        destinations: vec![Destination {
            url: format!("https://dest.example/{code}/{id}"),
            weight: 1,
        }],
        code,
        destinations_version: 1,
        redirect_status: 302,
        expires_at: matches!(state, State::Expired)
            .then(|| Utc.timestamp_opt(1_000_000, 0).unwrap()),
        max_clicks: matches!(state, State::Limited).then_some(10),
        geo: None,
        fallback_url: None,
        enabled: !matches!(state, State::Disabled),
        health_check: false,
        unhealthy: vec![false],
        rules: Default::default(),
    }
}

/// A `Host` header: one of the world's domains written any way a client
/// may write it, the default host, hosts nobody verified, IP addresses and
/// malformed values.
fn host() -> impl Strategy<Value = Option<String>> {
    let spelled = (
        prop::sample::select(HOSTNAMES.to_vec()),
        any::<u64>(),
        prop::option::of(prop::sample::select(vec!["80", "443", "8443"])),
        any::<bool>(),
    )
        .prop_map(|(h, case, port, dot)| {
            let mut s: String = h
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if case >> (i % 64) & 1 == 1 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            if dot {
                s.push('.');
            }
            if let Some(p) = port {
                s = format!("{s}:{p}");
            }
            s
        });
    prop_oneof![
        1 => Just(None),
        6 => spelled.prop_map(Some),
        2 => prop::sample::select(vec![
            "relink.example",
            "RELINK.example:443",
            "relink.example.",
            "other.example.net",
            "127.0.0.1:8080",
            "[::1]:443",
            "localhost",
            "go.example.com:",
            "go.example.com:99999",
            "go.example.com, links.example.org",
            "links.example.org,go.example.com",
            "go.example.com links.example.org",
            "go_example.com",
            "-go.example.com",
            "",
        ])
        .prop_map(|s| Some(s.to_owned())),
        1 => "[ -~]{0,40}".prop_map(Some),
    ]
}

/// A request path without its leading `/`, still percent-encoded.
fn path() -> impl Strategy<Value = String> {
    let code = (prop::sample::select(CODES.to_vec()), any::<u64>()).prop_map(|(c, case)| {
        c.chars()
            .enumerate()
            .map(|(i, ch)| match case >> (i % 64) & 3 {
                1 => ch.to_ascii_uppercase(),
                2 => ch.to_ascii_lowercase(),
                _ => ch,
            })
            .collect::<String>()
    });
    let prefix = prop::sample::select(vec!["campaign", "Promo", "x1", "other", "v1", ""]);
    prop_oneof![
        1 => Just(String::new()),
        5 => code.clone(),
        3 => (prefix, code).prop_map(|(p, c)| format!("{p}/{c}")),
        1 => prop::sample::select(vec![
            "a%62c", "ab", "abc.php", "campaign/", "campaign/abc/x", "/abc", "abc/",
            "%2Fabc", "pricing%20", "healthz",
        ])
        .prop_map(str::to_owned),
        1 => "[a-zA-Z0-9/%._~-]{0,24}",
    ]
}

/// The origin's link source: the world's links, by their stored key.
struct Links(HashMap<String, Link>);

impl LinkSource for Links {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
        Box::pin(async move { Ok(self.0.get(key).cloned()) })
    }
}

/// No lease store: limited links are answered 503 at the origin, which is
/// as much a decision to agree on as any other.
struct NoLeases;

impl LeaseStore for NoLeases {
    fn reserve(&self, _: i64, _: i64) -> BoxFuture<'_, Result<i64, StoreUnavailable>> {
        Box::pin(async { Err(StoreUnavailable) })
    }
    fn release(&self, _: i64, _: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>> {
        Box::pin(async { Ok(()) })
    }
}

fn origin(world: &World) -> Arc<App> {
    let cfg = Config::from_vars(&|k| match k {
        // Never contacted: links come from `Links`.
        "RELINK_DATABASE_URL" => Some("postgres://x:x@127.0.0.1:1/x".into()),
        "RELINK_PUBLIC_BASE_URL" => Some(format!("https://{DEFAULT_HOST}")),
        "RELINK_COOKIE_KEY" => Some(KEY_HEX.into()),
        "RELINK_TRUSTED_PROXIES" => Some("10.0.0.0/8".into()),
        _ => None,
    })
    .unwrap();
    let db = open_db(&cfg).unwrap();
    let links = world
        .links
        .iter()
        .map(|(d, l)| {
            let id = d.map(|d| world.domains[d].id);
            (link_key(id, &l.code), l.clone())
        })
        .collect();
    let (app, _rx) = App::new(
        cfg,
        db,
        Arc::new(Links(links)),
        Arc::new(NoLeases),
        Arc::new(Metrics::default()),
    );
    app.domains.replace(world.domains.clone());
    app
}

/// The KV namespace the origin publishes for `world`.
struct MemoryKv(HashMap<String, String>);

impl MemoryKv {
    fn of(world: &World) -> MemoryKv {
        let mut kv = HashMap::new();
        for d in &world.domains {
            let record = EdgeDomain {
                id: d.id,
                settings: d.settings.clone(),
            };
            kv.insert(
                host_kv_key(&d.hostname),
                serde_json::to_string(&record).unwrap(),
            );
        }
        for (d, l) in &world.links {
            let key = match d {
                None => kv_key(&l.code),
                Some(d) => domain_kv_key(&world.domains[*d].hostname, &l.code),
            };
            kv.insert(key, serde_json::to_string(l).unwrap());
        }
        MemoryKv(kv)
    }
}

impl Kv for MemoryKv {
    async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
        Ok(self.0.get(key).cloned())
    }
}

/// The origin behind the edge, called the way the Worker calls it: from a
/// trusted address, the visitor's host in `x-forwarded-host`, and `Host`
/// the origin's own.
struct Behind(Arc<App>);

impl Origin for Behind {
    async fn redirect(&self, req: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static(DEFAULT_HOST));
        if let Some(h) = forwarded_host(req) {
            headers.insert(
                relink_server::redirect::FORWARDED_HOST,
                HeaderValue::from_str(&h).map_err(|e| EdgeError(e.to_string()))?,
            );
        }
        let peer: IpAddr = EDGE_PEER.parse().unwrap();
        let (resp, _) =
            relink_server::redirect::handle(&self.0, &req.code, None, &headers, peer).await;
        Ok(answer(resp).await)
    }
}

/// The parts of a response both sides must agree on. `cache-control` is
/// left out: the edge caches redirects for its own, shorter time.
async fn answer(resp: Response) -> EdgeResponse {
    let status = resp.status().as_u16();
    let mut headers = Vec::new();
    for name in [
        "location",
        "set-cookie",
        "retry-after",
        "content-type",
        "content-security-policy",
        "x-content-type-options",
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

fn agreed(mut r: EdgeResponse) -> EdgeResponse {
    r.headers.retain(|(k, _)| k != "cache-control");
    r.headers.sort();
    r
}

/// Both sides' answers to `host` and `path` in `world`, and where the edge
/// got its answer.
async fn both(
    app: &Arc<App>,
    kv: &MemoryKv,
    host: Option<&str>,
    path: &str,
) -> (EdgeResponse, EdgeResponse, Served) {
    let mut headers = HeaderMap::new();
    if let Some(h) = host {
        headers.insert(header::HOST, HeaderValue::from_str(h).unwrap());
    }
    let visitor: IpAddr = VISITOR.parse().unwrap();
    let (resp, _) = relink_server::redirect::handle(app, path, None, &headers, visitor).await;
    let at_origin = agreed(answer(resp).await);

    let signer = Signer::new(
        relink_core::hex::decode(KEY_HEX)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let settings = Settings {
        signer: &signer,
        cookie_secure: true,
    };
    let req = EdgeRequest {
        code: path.to_owned(),
        host: host.map(|h| h.as_bytes().to_vec()),
        now_ms: now_ms(),
        random: 7,
        ..EdgeRequest::default()
    };
    let out = handle(kv, &Behind(app.clone()), &settings, DEFAULT_HOST, &req).await;
    (at_origin, agreed(out.response), out.served)
}

/// The one difference allowed: on the default domain, `/` and paths with
/// a `/` are unknown API paths at the origin (an API 404, whose JSON body
/// the API's error layer adds later, as before custom domains), while the
/// edge, which serves no API, answers its plain 404.
fn same(origin: &EdgeResponse, edge: &EdgeResponse) -> bool {
    let api_404 = origin.status == 404
        && origin.headers.is_empty()
        && origin.body.is_empty()
        && edge.status == 404
        && edge.body == NOT_FOUND_TEXT;
    origin == edge || api_404
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
    fn origin_and_edge_answer_every_request_alike(
        world in world(),
        requests in prop::collection::vec((host(), path()), 1..16),
    ) {
        let rt = runtime();
        rt.block_on(async {
            let app = origin(&world);
            let kv = MemoryKv::of(&world);
            for (host, path) in &requests {
                if host
                    .as_deref()
                    .is_some_and(|h| HeaderValue::from_str(h).is_err())
                {
                    continue;
                }
                let (o, e, served) = both(&app, &kv, host.as_deref(), path).await;
                prop_assert!(
                    same(&o, &e),
                    "Host {host:?} path {path:?} (edge {served:?})\norigin: {o:?}\nedge:   {e:?}"
                );
            }
            Ok(())
        })?;
    }
}

/// The property above would pass vacuously if the edge forwarded
/// everything; these requests must each be answered at the edge itself,
/// with the answer the origin gives.
#[tokio::test]
async fn the_edge_answers_domain_decisions_itself() {
    let world = World {
        domains: vec![VerifiedDomain {
            hostname: "go.example.com".into(),
            id: 100,
            settings: DomainSettings {
                root_url: Some("https://example.com/home".into()),
                not_found_page: Some("<h1>{{code}} is not on {{host}}</h1>".into()),
                gone_page: Some("<p>{{code}} has gone</p>".into()),
                prefixes: vec!["campaign".into()],
                case_insensitive: true,
            },
        }],
        links: vec![
            (Some(0), link(1, "pricing".into(), State::Live)),
            (Some(0), link(2, "old".into(), State::Expired)),
            (None, link(3, "Pricing".into(), State::Live)),
        ],
    };
    let app = origin(&world);
    let kv = MemoryKv::of(&world);
    for (host, path, status) in [
        ("go.example.com", "", 302),
        ("Go.Example.com.:443", "pricing", 302),
        ("go.example.com", "PRICING", 302),
        ("go.example.com", "Campaign/Pricing", 302),
        ("go.example.com", "old", 410),
        ("go.example.com", "campaign/a/b", 404),
        ("go.example.com", "a%62c", 404),
        ("relink.example", "Pricing", 302),
        ("other.example.net", "Pricing", 302),
        ("127.0.0.1", "Pricing", 302),
        ("relink.example", "ab", 404),
    ] {
        let (o, e, served) = both(&app, &kv, Some(host), path).await;
        assert_eq!(served, Served::Edge, "{host} {path}");
        assert_eq!(o, e, "{host} {path}");
        assert_eq!(e.status, status, "{host} {path}");
    }
    // Unknown codes on a verified domain and limited links go to the
    // origin, which still answers what it would directly.
    for (host, path) in [("go.example.com", "nothere"), ("links.example.org", "x")] {
        let (o, e, _) = both(&app, &kv, Some(host), path).await;
        assert!(same(&o, &e), "{host} {path}");
    }
    let (o, e, served) = both(&app, &kv, Some("go.example.com"), "nothere").await;
    assert_eq!(served, Served::Origin);
    assert_eq!((o.status, e.status), (404, 404));
}

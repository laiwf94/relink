//! Week 3 end to end: a launch link on a branded domain used the way a
//! customer would use it, through the HTTP API, two instances, the KV sync
//! and the edge's own request logic.
//!
//! A verified domain names its iOS and Android apps and serves their
//! association files. A link on it has targeting rules over every kind of
//! fact (country, region, device, OS, browser, language, referrer, time and
//! query) and app targets for phones; each visitor gets the same answer
//! from either instance and from the edge, which answers from KV without
//! the origin and never lets a cache keep it. The link's destination is
//! changed, swapped by a schedule that both instances' schedulers race to
//! apply, and rolled back, and the edge follows each version. A second link
//! is protected by a password and a consent page: the edge never holds it,
//! wrong guesses are limited across instances, and the grant cookie lets the
//! visitor through at the origin and at the edge alike. Previews at
//! `/{code}+` show where a link goes, and every change is in the
//! workspace's audit chain, which the binary verifies.

mod common;
#[path = "common/kv.rs"]
mod kv;

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;
use common::{FakeDns, Harness, admin_url, eventually, metric};
use kv::{TOKEN, fake_kv};
use relink_core::abtest::Signer;
use relink_core::rules::Settings;
use relink_core::wire::domain_kv_key;
use relink_edge::logic::{
    EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, REGION_HEADER, Served, forwarded_host,
    handle, origin_path,
};
use relink_server::util::now_ms;
use reqwest::Method;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_relink");

const HOST: &str = "go.launch-docs.net";

/// The origin's own host (the test servers' public base URL).
const DEFAULT_HOST: &str = "localhost";

/// The headers the origin and the edge must send alike.
const COMPARED: [&str; 6] = [
    "location",
    "cache-control",
    "content-type",
    "content-security-policy",
    "x-content-type-options",
    "retry-after",
];

const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";
const PIXEL: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like \
                     Gecko) Chrome/124.0 Mobile Safari/537.36";
const IPAD: &str = "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
                    like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
const FIREFOX: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0";
const EDGE_ON_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                           (KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0";
const LINUX_CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like \
                            Gecko) Chrome/124.0 Safari/537.36";
const GOOGLEBOT: &str = "Googlebot/2.1 (+http://www.google.com/bot.html)";

/// Runs the binary against `db_url` and returns its stdout; panics with its
/// stderr if it fails.
fn relink(db_url: &str, args: &[&str]) -> String {
    let mut c = Command::new(BIN);
    c.env_clear();
    if let Ok(v) = std::env::var("LLVM_PROFILE_FILE") {
        c.env("LLVM_PROFILE_FILE", v);
    }
    let out = c
        .args(args)
        .env("RELINK_DATABASE_URL", db_url)
        .env("RELINK_LOG", "warn")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "relink {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A visitor: what the CDN and the browser tell relink about them.
#[derive(Clone, Debug, Default)]
struct Visitor<'a> {
    country: Option<&'a str>,
    /// The subdivision part of the region, as the CDN sends it (`CA`).
    region: Option<&'a str>,
    user_agent: Option<&'a str>,
    language: Option<&'a str>,
    referer: Option<&'a str>,
    cookie: Option<&'a str>,
}

impl<'a> Visitor<'a> {
    fn ua(user_agent: &'a str) -> Self {
        Visitor {
            user_agent: Some(user_agent),
            ..Visitor::default()
        }
    }

    /// The request headers a browser behind the CDN sends.
    fn headers(&self) -> Vec<(&'static str, &'a str)> {
        [
            ("cf-ipcountry", self.country),
            (REGION_HEADER, self.region),
            ("user-agent", self.user_agent),
            ("accept-language", self.language),
            ("referer", self.referer),
            ("cookie", self.cookie),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect()
    }
}

/// A response reduced to what a visitor sees: status, the compared headers
/// and the body, and whether it set a cookie.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
    sets_cookie: bool,
}

impl Seen {
    fn of(status: u16, headers: Vec<(String, String)>, body: String) -> Seen {
        let sets_cookie = headers.iter().any(|(k, _)| k == "set-cookie");
        Seen {
            status,
            headers: headers
                .into_iter()
                .filter(|(k, _)| COMPARED.contains(&k.as_str()))
                .collect(),
            body,
            sets_cookie,
        }
    }

    fn location(&self) -> Option<&str> {
        self.headers.get("location").map(String::as_str)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

async fn seen(resp: reqwest::Response) -> (Seen, Option<String>) {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    let grant = headers
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned());
    let body = resp.text().await.unwrap();
    (Seen::of(status, headers, body), grant)
}

/// `GET` (or, with a form, `POST`) `/{path}` on `HOST` straight at an
/// origin instance, from loopback, which the test servers trust as the CDN.
async fn at_origin(
    http: &reqwest::Client,
    base: &str,
    path: &str,
    who: &Visitor<'_>,
    form: Option<&str>,
) -> (Seen, Option<String>) {
    let url = format!("{base}/{path}");
    let mut req = match form {
        Some(body) => http
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.to_owned()),
        None => http.get(url),
    };
    req = req.header("host", HOST);
    for (k, v) in who.headers() {
        req = req.header(k, v);
    }
    seen(req.send().await.unwrap()).await
}

/// The edge's KV namespace: what the origins' KV sync published.
struct PublishedKv(kv::Shared);

impl Kv for PublishedKv {
    async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
        Ok(self.0.values.lock().unwrap().get(key).cloned())
    }
}

/// The origin behind the edge, called over HTTP with the headers the
/// Worker sends: the visitor's query, facts, cookies and form, the host in
/// `x-forwarded-host`, from a trusted address.
struct Behind {
    base: String,
    http: reqwest::Client,
}

impl Origin for Behind {
    async fn redirect(&self, req: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
        let url = format!("{}/{}", self.base, origin_path(req));
        let mut r = match &req.form {
            Some(body) => self
                .http
                .post(url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body.clone()),
            None => self.http.get(url),
        };
        r = r.header("host", DEFAULT_HOST);
        if let Some(h) = forwarded_host(req) {
            r = r.header("x-forwarded-host", h);
        }
        let text = |b: &Option<Vec<u8>>| b.as_ref().map(|v| String::from_utf8(v.clone()).unwrap());
        let cookie = req
            .cookies
            .iter()
            .map(|c| String::from_utf8(c.clone()).unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let country = req.country.map(|c| String::from_utf8(c.to_vec()).unwrap());
        for (k, v) in [
            ("user-agent", text(&req.user_agent)),
            ("referer", text(&req.referer)),
            ("accept-language", text(&req.accept_language)),
            ("cf-ipcountry", country),
            (REGION_HEADER, text(&req.region)),
            ("cookie", (!cookie.is_empty()).then_some(cookie)),
        ] {
            if let Some(v) = v {
                r = r.header(k, v);
            }
        }
        let resp = r.send().await.map_err(|e| EdgeError(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        let body = resp.text().await.map_err(|e| EdgeError(e.to_string()))?;
        Ok(EdgeResponse {
            status,
            headers,
            body,
        })
    }
}

/// What the edge answers for `path` on `HOST`, and whether it asked the
/// origin.
async fn at_edge(
    kv: &PublishedKv,
    origin: &Behind,
    path: &str,
    who: &Visitor<'_>,
    form: Option<&str>,
) -> (Seen, Served) {
    let signer = Signer::new([0x5a; 32]);
    let settings = Settings {
        signer: &signer,
        cookie_secure: true,
    };
    let (code, query) = match path.split_once('?') {
        Some((c, q)) => (c, Some(q.to_owned())),
        None => (path, None),
    };
    let bytes = |v: Option<&str>| v.map(|v| v.as_bytes().to_vec());
    let req = EdgeRequest {
        code: code.to_owned(),
        host: Some(HOST.as_bytes().to_vec()),
        cookies: who
            .cookie
            .map(|c| vec![c.as_bytes().to_vec()])
            .unwrap_or_default(),
        country: who.country.map(|c| c.as_bytes().try_into().unwrap()),
        user_agent: bytes(who.user_agent),
        referer: bytes(who.referer),
        region: bytes(who.region),
        accept_language: bytes(who.language),
        query,
        form: form.map(str::to_owned),
        now_ms: now_ms(),
        random: 7,
        ..EdgeRequest::default()
    };
    let out = handle(kv, origin, &settings, DEFAULT_HOST, &req).await;
    let seen = Seen::of(out.response.status, out.response.headers, out.response.body);
    (seen, out.served)
}

async fn api(h: &Harness, method: Method, path: &str, body: Option<Value>) -> Value {
    // Creating answers 201; verifying and rolling back change what exists.
    let changes = path.ends_with("/verify") || path.contains("/rollback");
    let want = if method == Method::POST && !changes {
        201
    } else {
        200
    };
    let (status, v) = h.api(method.clone(), path, &h.alice, body).await;
    assert_eq!(status, want, "{method} {path}: {v}");
    v
}

fn at(offset: chrono::Duration) -> String {
    (Utc::now() + offset).to_rfc3339()
}

#[tokio::test]
async fn a_launch_link_routed_versioned_and_protected_at_origin_and_edge() {
    let Some(admin) = admin_url() else {
        return;
    };
    let dns = FakeDns::start().await;
    let (kv_addr, kv) = fake_kv().await;
    let kv_base = format!("http://{kv_addr}/client/v4");
    let dns_addr = dns.addr.to_string();
    let vars = [
        ("RELINK_DNS_SERVERS", dns_addr.as_str()),
        ("RELINK_REGION_HEADER", REGION_HEADER),
        ("RELINK_SCHEDULE_POLL_MS", "50"),
        ("RELINK_KV_ACCOUNT_ID", "acct1"),
        ("RELINK_KV_NAMESPACE_ID", "ns1"),
        ("RELINK_KV_API_TOKEN", TOKEN),
        ("RELINK_KV_API_BASE", &kv_base),
        ("RELINK_KV_POLL_MS", "50"),
    ];
    let mut h = Harness::start(&admin, &vars).await;
    let other = h.second_instance(&vars).await;
    let bases = [h.base.clone(), format!("http://{}", other.addr)];
    let http = common::client();
    let edge_kv = PublishedKv(kv.clone());
    let behind = Behind {
        base: h.base.clone(),
        http: common::client(),
    };
    let db = h.db.url.clone();
    let (_, usage) = h.api(Method::GET, "/v1/usage", &h.alice, None).await;
    let ws = usage["workspace_id"].as_i64().unwrap();

    // 1. A verified domain names its apps; it serves their association
    // files, from either instance and from the edge alike.
    let d = api(
        &h,
        Method::POST,
        "/v1/domains",
        Some(json!({"hostname": HOST})),
    )
    .await;
    let proof = d["verification"]["value"].as_str().unwrap();
    dns.set_txt(&format!("_relink-challenge.{HOST}"), &[proof]);
    let d = api(
        &h,
        Method::POST,
        &format!("/v1/domains/{HOST}/verify"),
        None,
    )
    .await;
    assert_eq!(d["verified"], true, "{d}");
    let print = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:\
                 B2:3F:CF:44:E5";
    api(
        &h,
        Method::PATCH,
        &format!("/v1/domains/{HOST}"),
        Some(json!({"apps": {
            "ios": [{"team_id": "ABCDE12345", "bundle_id": "net.launchdocs.app"}],
            "android": [{"package": "net.launchdocs.app", "sha256_cert_fingerprints": [print]}],
        }})),
    )
    .await;
    let files = [
        ".well-known/apple-app-site-association",
        "apple-app-site-association",
        ".well-known/assetlinks.json",
    ];
    for file in files {
        assert!(
            eventually(Duration::from_secs(5), || async {
                at_edge(&edge_kv, &behind, file, &Visitor::default(), None)
                    .await
                    .0
                    .status
                    == 200
            })
            .await,
            "the edge never served /{file}"
        );
        let (edge, by) = at_edge(&edge_kv, &behind, file, &Visitor::default(), None).await;
        assert_eq!(by, Served::Edge, "/{file}");
        assert_eq!(edge.header("content-type"), Some("application/json"));
        for base in &bases {
            let (origin, _) = at_origin(&http, base, file, &Visitor::default(), None).await;
            assert_eq!(origin, edge, "/{file}: the edge and the origin disagree");
        }
        let v: Value = serde_json::from_str(&edge.body).unwrap();
        if file.ends_with("assetlinks.json") {
            assert_eq!(v[0]["target"]["package_name"], "net.launchdocs.app");
            assert_eq!(v[0]["target"]["sha256_cert_fingerprints"], json!([print]));
        } else {
            assert_eq!(
                v["applinks"]["details"][0]["appIDs"],
                json!(["ABCDE12345.net.launchdocs.app"])
            );
        }
    }

    // 2. A launch link with targeting rules over every kind of fact, and
    // app targets for phones.
    let rules = json!([
        {"if": {"all": [{"country": ["DE", "AT", "CH"]}, {"language": ["de"]}]},
         "url": "https://launch.example.org/de"},
        {"if": {"region": ["US-CA"]}, "url": "https://launch.example.org/california"},
        {"if": {"all": [{"device": ["tablet"]}, {"os": ["ios"]}]},
         "url": "https://launch.example.org/ipad"},
        {"if": {"all": [{"browser": ["edge"]}, {"os": ["macos"]}]},
         "url": "https://launch.example.org/edge-mac"},
        {"if": {"referrer": ["news.example"]}, "url": "https://launch.example.org/press"},
        {"if": {"query": {"name": "utm_source", "values": ["newsletter"]}},
         "url": "https://launch.example.org/subscribers"},
        {"if": {"all": [{"query": {"name": "early"}},
                        {"time": {"before": at(chrono::Duration::days(-1))}}]},
         "url": "https://launch.example.org/too-late"},
        {"if": {"all": [{"query": {"name": "early"}},
                        {"time": {"after": at(chrono::Duration::days(-1)),
                                  "before": at(chrono::Duration::days(30))}}]},
         "url": "https://launch.example.org/early-access"},
        {"if": {"not": {"any": [{"os": ["windows", "linux", "macos", "ios", "android"]},
                                {"device": ["bot"]}]}},
         "url": "https://launch.example.org/other"},
    ]);
    let link = api(
        &h,
        Method::POST,
        "/v1/links",
        Some(json!({
            "url": "https://launch.example.org/",
            "alias": "launch",
            "domain": HOST,
            "rules": rules,
            "app": {
                "ios": {"store_url": "https://apps.apple.com/app/id6400000001"},
                "android": {"package": "net.launchdocs.app", "url": "launchdocs://launch"}
            }
        })),
    )
    .await;
    assert_eq!(link["short_url"], format!("http://{HOST}/launch"));
    assert_eq!(link["version"], 1);
    let intent = "intent://launch#Intent;scheme=launchdocs;package=net.launchdocs.app;\
                  S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails\
                  %3Fid%3Dnet.launchdocs.app;end";
    let de = Visitor {
        country: Some("DE"),
        language: Some("de-DE,de;q=0.9,en;q=0.5"),
        user_agent: Some(FIREFOX),
        ..Visitor::default()
    };
    let de_iphone = Visitor {
        user_agent: Some(IPHONE),
        ..de.clone()
    };
    let california = Visitor {
        country: Some("US"),
        region: Some("CA"),
        user_agent: Some(PIXEL),
        ..Visitor::default()
    };
    let press = Visitor {
        referer: Some("https://www.news.example/launch-day"),
        user_agent: Some(LINUX_CHROME),
        ..Visitor::default()
    };
    let english_in_de = Visitor {
        language: Some("en-GB"),
        ..de.clone()
    };
    let cases: Vec<(&str, Visitor, &str)> = vec![
        ("launch", de.clone(), "https://launch.example.org/de"),
        // A rule comes before the app targets.
        ("launch", de_iphone, "https://launch.example.org/de"),
        ("launch", english_in_de, "https://launch.example.org/"),
        (
            "launch",
            california,
            "https://launch.example.org/california",
        ),
        (
            "launch",
            Visitor::ua(IPAD),
            "https://launch.example.org/ipad",
        ),
        (
            "launch",
            Visitor::ua(EDGE_ON_MAC),
            "https://launch.example.org/edge-mac",
        ),
        ("launch", press, "https://launch.example.org/press"),
        (
            "launch?utm_source=newsletter&utm_medium=email",
            Visitor::ua(FIREFOX),
            "https://launch.example.org/subscribers",
        ),
        (
            "launch?utm_source=ads",
            Visitor::ua(FIREFOX),
            "https://launch.example.org/",
        ),
        (
            "launch?early",
            Visitor::ua(LINUX_CHROME),
            "https://launch.example.org/early-access",
        ),
        (
            "launch",
            Visitor::ua("Lynx/2.9.0"),
            "https://launch.example.org/other",
        ),
        // No rule: phones go to their app, everyone else to the link.
        (
            "launch",
            Visitor::ua(IPHONE),
            "https://apps.apple.com/app/id6400000001",
        ),
        ("launch", Visitor::ua(PIXEL), intent),
        (
            "launch",
            Visitor::ua(FIREFOX),
            "https://launch.example.org/",
        ),
        (
            "launch",
            Visitor::ua(GOOGLEBOT),
            "https://launch.example.org/",
        ),
        // No User-Agent at all is no known system either.
        (
            "launch",
            Visitor::default(),
            "https://launch.example.org/other",
        ),
    ];
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.values
                .lock()
                .unwrap()
                .contains_key(&domain_kv_key(HOST, "launch"))
        })
        .await,
        "the link never reached the edge: {:?}",
        kv.keys()
    );
    for (i, (path, who, want)) in cases.iter().enumerate() {
        let (edge, by) = at_edge(&edge_kv, &behind, path, who, None).await;
        assert_eq!(
            (edge.status, edge.location()),
            (302, Some(*want)),
            "/{path} {who:?}"
        );
        assert_eq!(edge.header("cache-control"), Some("no-store"), "/{path}");
        assert_eq!(by, Served::Edge, "/{path} {who:?}: the edge answers itself");
        let (origin, _) = at_origin(&http, &bases[i % 2], path, who, None).await;
        assert_eq!(
            origin, edge,
            "/{path} {who:?}: the edge and the origin disagree"
        );
    }
    let m = h.metrics().await;
    let routed = metric(&m, "relink_redirects_total{outcome=\"rule\"}")
        + metric(&m, "relink_redirects_total{outcome=\"app\"}");
    assert!(routed >= 5.0, "{m}");

    // 3. Versions: an edit, a scheduled swap that both instances' schedulers
    // race to apply, and a rollback. The edge follows each one.
    let path = format!("/v1/links/launch?domain={HOST}");
    let edited = api(
        &h,
        Method::PATCH,
        &path,
        Some(json!({"url": "https://launch.example.org/v2"})),
    )
    .await;
    assert_eq!(edited["version"], 2);
    let schedules = format!("/v1/links/launch/schedules?domain={HOST}");
    let swap = api(
        &h,
        Method::POST,
        &schedules,
        Some(json!({"run_at": at(chrono::Duration::seconds(1)),
                    "destinations": [{"url": "https://launch.example.org/live"}]})),
    )
    .await;
    assert_eq!(swap["state"], "pending");
    let firefox = Visitor::ua(FIREFOX);
    assert!(
        eventually(Duration::from_secs(15), || async {
            let (edge, _) = at_edge(&edge_kv, &behind, "launch", &firefox, None).await;
            edge.location() == Some("https://launch.example.org/live")
        })
        .await,
        "the edge never saw the scheduled swap"
    );
    for base in &bases {
        let (origin, _) = at_origin(&http, base, "launch", &firefox, None).await;
        assert_eq!(origin.location(), Some("https://launch.example.org/live"));
    }
    // The rules and app targets are part of every version.
    let (edge, _) = at_edge(&edge_kv, &behind, "launch", &Visitor::ua(PIXEL), None).await;
    assert_eq!(edge.location(), Some(intent));
    let (_, list) = h.api(Method::GET, &schedules, &h.alice, None).await;
    assert_eq!(list["schedules"][0]["state"], "applied", "{list}");
    assert_eq!(list["schedules"][0]["applied_version"], 3);

    let back = api(
        &h,
        Method::POST,
        &format!("/v1/links/launch/rollback?domain={HOST}"),
        Some(json!({"version": 1})),
    )
    .await;
    assert_eq!(back["version"], 4);
    assert_eq!(
        back["destinations"][0]["url"],
        "https://launch.example.org/"
    );
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (edge, _) = at_edge(&edge_kv, &behind, "launch", &firefox, None).await;
            edge.location() == Some("https://launch.example.org/")
        })
        .await,
        "the edge never saw the rollback"
    );
    for base in &bases {
        let (origin, _) = at_origin(&http, base, "launch", &firefox, None).await;
        assert_eq!(origin.location(), Some("https://launch.example.org/"));
    }
    let history = api(
        &h,
        Method::GET,
        &format!("/v1/links/launch/versions?domain={HOST}"),
        None,
    )
    .await;
    let sources: Vec<&str> = history["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["source"].as_str().unwrap())
        .collect();
    assert_eq!(sources, ["rollback", "schedule", "update", "create"]);
    assert_eq!(history["versions"][0]["restored_from"], 1);

    // 4. A protected link: a password and a consent page. The edge never
    // holds it, so the origin answers it there too.
    let vault = api(
        &h,
        Method::POST,
        "/v1/links",
        Some(json!({
            "url": "https://launch.example.org/press-kit",
            "alias": "press-kit",
            "domain": HOST,
            "protection": {"password": "embargo until 9", "max_attempts": 3,
                           "consent": "This kit is under embargo until launch."}
        })),
    )
    .await;
    assert_eq!(
        vault["protection"],
        json!({"password": true, "max_attempts": 3,
               "consent": "This kit is under embargo until launch."})
    );
    // Wait until a later link is published, so the sync has been past it.
    api(
        &h,
        Method::POST,
        "/v1/links",
        Some(json!({"url": "https://launch.example.org/faq", "alias": "faq", "domain": HOST})),
    )
    .await;
    assert!(
        eventually(Duration::from_secs(5), || async {
            kv.keys().contains(&domain_kv_key(HOST, "faq"))
        })
        .await
    );
    assert!(!kv.keys().contains(&domain_kv_key(HOST, "press-kit")));
    let nobody = Visitor::ua(FIREFOX);
    let (edge, by) = at_edge(&edge_kv, &behind, "press-kit", &nobody, None).await;
    assert_eq!(by, Served::Origin);
    assert_eq!(edge.status, 200);
    assert!(edge.body.contains("type=\"password\"") && edge.body.contains("embargo"));
    assert!(!edge.body.contains("launch.example.org/press-kit"));
    let (origin, _) = at_origin(&http, &bases[1], "press-kit", &nobody, None).await;
    assert_eq!(origin, edge);

    // A wrong guess at each instance, then the right one through the edge.
    for base in &bases {
        let (wrong, grant) = at_origin(
            &http,
            base,
            "press-kit",
            &nobody,
            Some("password=embargo+until+8&consent=yes"),
        )
        .await;
        assert_eq!((wrong.status, grant), (401, None));
    }
    let (ok, by) = at_edge(
        &edge_kv,
        &behind,
        "press-kit?ref=mail",
        &nobody,
        Some("password=embargo+until+9&consent=yes"),
    )
    .await;
    assert_eq!(by, Served::Origin);
    assert_eq!(
        (ok.status, ok.location(), ok.sets_cookie),
        (303, Some("/press-kit?ref=mail"), true)
    );
    // The grant itself, from an origin answer to the same form.
    let (_, grant) = at_origin(
        &http,
        &bases[0],
        "press-kit",
        &nobody,
        Some("password=embargo+until+9&consent=yes"),
    )
    .await;
    let grant = grant.expect("a grant cookie");
    let granted = Visitor {
        cookie: Some(&grant),
        ..nobody.clone()
    };
    let (edge, _) = at_edge(&edge_kv, &behind, "press-kit", &granted, None).await;
    assert_eq!(
        (edge.status, edge.location()),
        (302, Some("https://launch.example.org/press-kit"))
    );
    for base in &bases {
        let (origin, _) = at_origin(&http, base, "press-kit", &granted, None).await;
        assert_eq!(origin, edge);
    }
    // Right guesses gave their attempts back, so a third wrong one is
    // still a wrong guess; that makes three in the hour, which locks the
    // link on every instance, the right password included.
    let (third, _) = at_origin(
        &http,
        &bases[1],
        "press-kit",
        &nobody,
        Some("password=nope&consent=yes"),
    )
    .await;
    assert_eq!(third.status, 401);
    let (fourth, _) = at_origin(
        &http,
        &bases[0],
        "press-kit",
        &nobody,
        Some("password=nope&consent=yes"),
    )
    .await;
    assert_eq!(fourth.status, 429);
    let (locked, _) = at_edge(
        &edge_kv,
        &behind,
        "press-kit",
        &nobody,
        Some("password=embargo+until+9&consent=yes"),
    )
    .await;
    assert_eq!(locked.status, 429);
    assert!(locked.header("retry-after").is_some());
    // A visitor who already has a grant is not locked out.
    let (origin, _) = at_origin(&http, &bases[1], "press-kit", &granted, None).await;
    assert_eq!(origin.status, 302);

    // 5. Previews: where a link goes, without a click, at the origin and
    // rendered from KV at the edge; a protected link says only that.
    let (edge, by) = at_edge(&edge_kv, &behind, "launch+", &firefox, None).await;
    assert_eq!((edge.status, by), (200, Served::Edge));
    assert!(
        edge.body.contains("https://launch.example.org/"),
        "{}",
        edge.body
    );
    assert_eq!(edge.header("cache-control"), Some("no-store"));
    let (origin, _) = at_origin(&http, &bases[0], "launch+", &firefox, None).await;
    assert_eq!(origin, edge);
    let (edge, _) = at_edge(&edge_kv, &behind, "press-kit+", &firefox, None).await;
    assert!(edge.body.contains("is protected"));
    assert!(!edge.body.contains("launch.example.org/press-kit"));
    let (origin, _) = at_origin(&http, &bases[1], "press-kit+", &firefox, None).await;
    assert_eq!(origin, edge);

    // 6. Every change is in the workspace's audit chain, which verifies.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE workspace_id = $1 \
         AND (action LIKE 'link.%' OR action LIKE 'schedule.%') ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "link.create",
            "link.update",
            "schedule.create",
            "schedule.apply",
            "link.rollback",
            "link.create",
            "link.create",
        ]
    );
    let text = relink(&db, &["audit-verify", "--workspace", &ws.to_string()]);
    assert!(text.starts_with(&format!("{ws}:")), "{text}");
    assert_eq!(kv.unauthorized.load(std::sync::atomic::Ordering::SeqCst), 0);

    other.shutdown().await;
    h.shutdown().await;
}

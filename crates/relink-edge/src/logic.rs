//! The edge redirect, written against two small traits so it runs (and is
//! tested) natively as well as inside the Worker.
//!
//! A request is answered at the edge when KV has the link and the link has
//! no click limit. Everything else goes to the origin unchanged: unknown
//! codes (KV may simply not have caught up), KV errors, and max-click links,
//! whose limit only the origin's lease counter can enforce.
//!
//! Custom domains: a request whose `Host` could be a custom domain (see
//! `relink_core::host::custom_host`) looks for `link:<host>/<code>` first.
//! If that is missing, `host:<host>` says whether the host is a verified
//! domain: if it is, the code is unknown on that domain and the origin
//! answers; if it is not, the request is for the default domain, exactly as
//! the origin routes it. So a link on a custom domain costs one KV read, as
//! does a default-domain link requested on `default_host`.

use std::future::Future;
use std::net::IpAddr;

use relink_core::classify::{UNKNOWN_COUNTRY, device_class, referrer_host};
use relink_core::code::is_plausible_code;
use relink_core::hex;
use relink_core::host::custom_host;
use relink_core::model::Link;
use relink_core::rules::{Decision, Settings, Visit, evaluate};
use relink_core::visitor::fingerprint;
use relink_core::wire::{ClickBatch, WireClick, domain_kv_key, host_kv_key, kv_key};

/// A KV read failed or the origin could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeError(pub String);

/// Read access to the link records published by the origin.
pub trait Kv {
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<String>, EdgeError>>;
}

/// The origin server.
pub trait Origin {
    /// Answers the redirect for `req` at the origin, without following it.
    fn redirect(&self, req: &EdgeRequest) -> impl Future<Output = Result<EdgeResponse, EdgeError>>;
}

/// What the edge knows about a request.
#[derive(Clone, Debug, Default)]
pub struct EdgeRequest {
    /// The path without the leading slash.
    pub code: String,
    /// The `Host` the request was sent to, as received (port included). The
    /// origin is told it in `x-forwarded-host`.
    pub host: Option<Vec<u8>>,
    pub cookies: Vec<Vec<u8>>,
    /// Set by the CDN, so trusted.
    pub country: Option<[u8; 2]>,
    pub client_ip: Option<IpAddr>,
    pub user_agent: Option<Vec<u8>>,
    pub referer: Option<Vec<u8>>,
    pub now_ms: i64,
    pub random: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl EdgeResponse {
    fn text(status: u16, body: &str) -> EdgeResponse {
        EdgeResponse {
            status,
            headers: vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("cache-control".into(), "no-store".into()),
            ],
            body: body.into(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Where the answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    Edge,
    Origin,
}

#[derive(Clone, Debug)]
pub struct Outcome {
    pub response: EdgeResponse,
    pub served: Served,
    /// A click to report to the origin (only for redirects served here; the
    /// origin records the ones it serves itself).
    pub click: Option<WireClick>,
}

/// `Cache-Control` for redirects that never vary. Short: KV changes take up
/// to a minute to arrive anyway, and caching longer would add to that.
pub const EDGE_MAX_AGE: &str = "public, max-age=30";

/// Answers `req`. `default_host` is the origin's own host (the one in
/// `RELINK_PUBLIC_BASE_URL`): requests for it are on the default domain
/// without asking KV about the host.
pub async fn handle<K: Kv, O: Origin>(
    kv: &K,
    origin: &O,
    settings: &Settings<'_>,
    default_host: &str,
    req: &EdgeRequest,
) -> Outcome {
    if !is_plausible_code(&req.code) {
        return edge(EdgeResponse::text(404, "not found\n"), None);
    }
    let link = match custom_host(req.host.as_deref(), default_host) {
        None => read(kv, &kv_key(&req.code)).await,
        Some(host) => {
            let host = host.to_ascii_lowercase();
            match read(kv, &domain_kv_key(&host, &req.code)).await {
                Read::Missing => match kv.get(&host_kv_key(&host)).await {
                    // Not a custom domain: the default domain's link.
                    Ok(None) => read(kv, &kv_key(&req.code)).await,
                    // A verified domain without this code in KV (or KV
                    // failed): only the origin knows.
                    Ok(Some(_)) | Err(_) => Read::Failed,
                },
                other => other,
            }
        }
    };
    let Read::Found(link) = link else {
        return from_origin(origin, req).await;
    };
    if link.max_clicks.is_some() {
        return from_origin(origin, req).await;
    }
    let cookies: Vec<&[u8]> = req.cookies.iter().map(Vec::as_slice).collect();
    let visit = Visit {
        now_ms: req.now_ms,
        country: req.country,
        cookies: &cookies,
        random: req.random,
    };
    match evaluate(&link, &visit, settings) {
        Decision::NotFound => edge(EdgeResponse::text(404, "not found\n"), None),
        Decision::Expired => edge(EdgeResponse::text(410, "this link has expired\n"), None),
        Decision::GeoBlocked {
            fallback: Some(url),
        } => edge(redirect(302, url, None, None), None),
        Decision::GeoBlocked { fallback: None } => edge(
            EdgeResponse::text(451, "this link is not available in your region\n"),
            None,
        ),
        // Unreachable while limited links are proxied, but if one ever got
        // here the origin is the only place that can admit it.
        Decision::Redirect(r) if r.needs_admission => from_origin(origin, req).await,
        Decision::Redirect(r) => {
            let cache = r.cacheable.then_some(EDGE_MAX_AGE);
            let response = redirect(r.status, r.location, cache, r.set_cookie);
            edge(response, Some(click_for(&link, req)))
        }
    }
}

/// A link record read from KV.
enum Read {
    Found(Box<Link>),
    Missing,
    /// The read failed or the record would not parse.
    Failed,
}

async fn read<K: Kv>(kv: &K, key: &str) -> Read {
    match kv.get(key).await {
        Ok(Some(json)) => match serde_json::from_str::<Link>(&json) {
            Ok(link) => Read::Found(Box::new(link)),
            Err(_) => Read::Failed,
        },
        Ok(None) => Read::Missing,
        Err(_) => Read::Failed,
    }
}

fn edge(response: EdgeResponse, click: Option<WireClick>) -> Outcome {
    Outcome {
        response,
        served: Served::Edge,
        click,
    }
}

async fn from_origin<O: Origin>(origin: &O, req: &EdgeRequest) -> Outcome {
    let response = origin
        .redirect(req)
        .await
        .unwrap_or_else(|_| EdgeResponse::text(502, "origin unavailable, retry shortly\n"));
    Outcome {
        response,
        served: Served::Origin,
        click: None,
    }
}

fn redirect(
    status: u16,
    location: &str,
    cache: Option<&str>,
    cookie: Option<String>,
) -> EdgeResponse {
    let mut headers = vec![
        ("location".into(), location.to_owned()),
        (
            "cache-control".into(),
            cache.unwrap_or("no-store").to_owned(),
        ),
    ];
    if let Some(c) = cookie {
        headers.push(("set-cookie".into(), c));
    }
    EdgeResponse {
        status,
        headers,
        body: String::new(),
    }
}

fn click_for(link: &Link, req: &EdgeRequest) -> WireClick {
    let ua = req.user_agent.as_deref();
    // Without an address every visitor would look the same; hashing the
    // unspecified address keeps the count honest about what it knows.
    let ip = req
        .client_ip
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    WireClick {
        link_id: link.id,
        day: req.now_ms.div_euclid(86_400_000) as i32,
        country: String::from_utf8_lossy(&req.country.unwrap_or(UNKNOWN_COUNTRY)).into_owned(),
        device: device_class(ua).as_str().to_owned(),
        referrer: referrer_host(req.referer.as_deref()),
        fingerprint: hex::encode(&fingerprint(ip, ua.unwrap_or_default())),
    }
}

/// What to do after adding a click to the batch.
#[derive(Debug, PartialEq, Eq)]
pub enum Push {
    /// Send this batch now.
    Flush(ClickBatch),
    /// The batch was empty: schedule a send after [`ClickBatcher::max_age_ms`].
    Schedule,
    /// Nothing to do; a send is already due.
    Buffered,
}

/// Collects clicks within one Worker isolate. The isolate can be evicted at
/// any time, so this trades a bounded loss (at most `max` clicks per evicted
/// isolate, in practice the clicks of the last few seconds) for one origin
/// call per batch instead of one per click.
#[derive(Debug)]
pub struct ClickBatcher {
    pending: Vec<WireClick>,
    max: usize,
    pub max_age_ms: u64,
}

impl ClickBatcher {
    pub fn new(max: usize, max_age_ms: u64) -> ClickBatcher {
        assert!((1..=relink_core::wire::MAX_BATCH).contains(&max));
        ClickBatcher {
            pending: Vec::new(),
            max,
            max_age_ms,
        }
    }

    pub fn push(&mut self, click: WireClick) -> Push {
        let was_empty = self.pending.is_empty();
        self.pending.push(click);
        if self.pending.len() >= self.max {
            Push::Flush(self.take().unwrap_or_default())
        } else if was_empty {
            Push::Schedule
        } else {
            Push::Buffered
        }
    }

    /// Everything pending, if anything.
    pub fn take(&mut self) -> Option<ClickBatch> {
        if self.pending.is_empty() {
            return None;
        }
        Some(ClickBatch {
            clicks: std::mem::take(&mut self.pending),
        })
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
pub mod testing {
    //! In-memory KV and a scripted origin.

    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MemoryKv {
        pub values: RefCell<HashMap<String, String>>,
        pub fail: Cell<bool>,
    }

    impl MemoryKv {
        pub fn with(link: &Link) -> MemoryKv {
            let kv = MemoryKv::default();
            kv.values
                .borrow_mut()
                .insert(kv_key(&link.code), serde_json::to_string(link).unwrap());
            kv
        }
    }

    impl Kv for MemoryKv {
        async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
            if self.fail.get() {
                return Err(EdgeError("kv down".into()));
            }
            Ok(self.values.borrow().get(key).cloned())
        }
    }

    #[derive(Default)]
    pub struct FakeOrigin {
        pub calls: Cell<usize>,
        pub down: Cell<bool>,
        /// The `host` of every request forwarded.
        pub hosts: RefCell<Vec<Option<Vec<u8>>>>,
    }

    impl Origin for FakeOrigin {
        async fn redirect(&self, req: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
            self.calls.set(self.calls.get() + 1);
            self.hosts.borrow_mut().push(req.host.clone());
            if self.down.get() {
                return Err(EdgeError("origin down".into()));
            }
            Ok(redirect(
                302,
                &format!("https://origin.example.com/{}", req.code),
                None,
                None,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeOrigin, MemoryKv};
    use super::*;
    use relink_core::abtest::Signer;
    use relink_core::model::{Destination, GeoMode, GeoRule};

    const SIGNER: Signer = Signer::new([5; 32]);
    const SETTINGS: Settings = Settings {
        signer: &SIGNER,
        cookie_secure: true,
    };
    const DEFAULT: &str = "s.relink.example";
    const HOST: &str = "go.example.com";

    fn link(code: &str) -> Link {
        Link {
            id: 11,
            code: code.into(),
            destinations: vec![Destination {
                url: "https://example.com/landing".into(),
                weight: 1,
            }],
            destinations_version: 1,
            redirect_status: 301,
            expires_at: None,
            max_clicks: None,
            geo: None,
            fallback_url: None,
            enabled: true,
            health_check: false,
            unhealthy: vec![false],
        }
    }

    fn req(code: &str) -> EdgeRequest {
        EdgeRequest {
            code: code.into(),
            client_ip: Some("203.0.113.4".parse().unwrap()),
            user_agent: Some(b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile".to_vec()),
            referer: Some(b"https://news.example.org/x".to_vec()),
            country: Some(*b"DE"),
            now_ms: 86_400_000 * 20_000 + 5,
            ..EdgeRequest::default()
        }
    }

    fn run<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn served_from_kv_with_a_click() {
        let kv = MemoryKv::with(&link("promo"));
        let origin = FakeOrigin::default();
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &req("promo")));
        assert_eq!(out.served, Served::Edge);
        assert_eq!(out.response.status, 301);
        assert_eq!(
            out.response.header("location"),
            Some("https://example.com/landing")
        );
        assert_eq!(out.response.header("cache-control"), Some(EDGE_MAX_AGE));
        assert_eq!(origin.calls.get(), 0);
        let click = out.click.unwrap();
        assert_eq!((click.link_id, click.day), (11, 20_000));
        assert_eq!(
            (click.country.as_str(), click.device.as_str()),
            ("DE", "mobile")
        );
        assert_eq!(click.referrer.as_deref(), Some("news.example.org"));
        assert_eq!(click.fingerprint.len(), 32);
    }

    #[test]
    fn misses_errors_and_limited_links_go_to_the_origin() {
        let origin = FakeOrigin::default();
        let empty = MemoryKv::default();
        let out = run(handle(&empty, &origin, &SETTINGS, DEFAULT, &req("unknown")));
        assert_eq!(out.served, Served::Origin);
        assert_eq!(
            out.response.header("location"),
            Some("https://origin.example.com/unknown")
        );
        assert!(out.click.is_none(), "the origin records its own clicks");

        let failing = MemoryKv::with(&link("promo"));
        failing.fail.set(true);
        assert_eq!(
            run(handle(&failing, &origin, &SETTINGS, DEFAULT, &req("promo"))).served,
            Served::Origin
        );

        let mut limited = link("limited");
        limited.max_clicks = Some(10);
        let kv = MemoryKv::with(&limited);
        assert_eq!(
            run(handle(&kv, &origin, &SETTINGS, DEFAULT, &req("limited"))).served,
            Served::Origin
        );

        let garbage = MemoryKv::default();
        garbage
            .values
            .borrow_mut()
            .insert(kv_key("junk"), "{not json".into());
        assert_eq!(
            run(handle(&garbage, &origin, &SETTINGS, DEFAULT, &req("junk"))).served,
            Served::Origin
        );
        assert_eq!(origin.calls.get(), 4);

        origin.down.set(true);
        let out = run(handle(&empty, &origin, &SETTINGS, DEFAULT, &req("unknown")));
        assert_eq!(out.response.status, 502);
    }

    #[test]
    fn rules_apply_at_the_edge() {
        let origin = FakeOrigin::default();
        let mut l = link("rules");
        l.enabled = false;
        let out = run(handle(
            &MemoryKv::with(&l),
            &origin,
            &SETTINGS,
            DEFAULT,
            &req("rules"),
        ));
        assert_eq!((out.response.status, out.served), (404, Served::Edge));
        assert!(out.click.is_none());

        l.enabled = true;
        l.expires_at = Some(chrono::DateTime::from_timestamp(0, 0).unwrap());
        let out = run(handle(
            &MemoryKv::with(&l),
            &origin,
            &SETTINGS,
            DEFAULT,
            &req("rules"),
        ));
        assert_eq!(out.response.status, 410);

        l.expires_at = None;
        l.geo = Some(GeoRule {
            mode: GeoMode::Deny,
            countries: vec![*b"DE"],
        });
        let out = run(handle(
            &MemoryKv::with(&l),
            &origin,
            &SETTINGS,
            DEFAULT,
            &req("rules"),
        ));
        assert_eq!(out.response.status, 451);
        l.fallback_url = Some("https://elsewhere.example.com/".into());
        let out = run(handle(
            &MemoryKv::with(&l),
            &origin,
            &SETTINGS,
            DEFAULT,
            &req("rules"),
        ));
        assert_eq!(
            out.response.header("location"),
            Some("https://elsewhere.example.com/")
        );
        assert_eq!(out.response.header("cache-control"), Some("no-store"));
        assert_eq!(origin.calls.get(), 0);

        let bad = run(handle(
            &MemoryKv::default(),
            &origin,
            &SETTINGS,
            DEFAULT,
            &req("a/b"),
        ));
        assert_eq!((bad.response.status, bad.served), (404, Served::Edge));
        assert_eq!(
            origin.calls.get(),
            0,
            "garbage paths never reach the origin"
        );
    }

    #[test]
    fn ab_cookie_round_trip_at_the_edge() {
        let mut l = link("split");
        l.destinations.push(Destination {
            url: "https://example.com/b".into(),
            weight: 1,
        });
        l.unhealthy.push(false);
        let kv = MemoryKv::with(&l);
        let origin = FakeOrigin::default();
        let first = run(handle(
            &kv,
            &origin,
            &SETTINGS,
            DEFAULT,
            &EdgeRequest {
                random: u64::MAX,
                ..req("split")
            },
        ));
        assert_eq!(
            first.response.header("location"),
            Some("https://example.com/b")
        );
        let cookie = first.response.header("set-cookie").unwrap();
        let pair = cookie.split(';').next().unwrap().as_bytes().to_vec();
        let again = run(handle(
            &kv,
            &origin,
            &SETTINGS,
            DEFAULT,
            &EdgeRequest {
                cookies: vec![pair],
                random: 0,
                ..req("split")
            },
        ));
        assert_eq!(
            again.response.header("location"),
            Some("https://example.com/b")
        );
        assert!(again.response.header("set-cookie").is_none());
    }

    #[test]
    fn missing_client_details_still_produce_a_valid_click() {
        let kv = MemoryKv::with(&link("promo"));
        let bare = EdgeRequest {
            code: "promo".into(),
            now_ms: 1,
            ..EdgeRequest::default()
        };
        let click = run(handle(
            &kv,
            &FakeOrigin::default(),
            &SETTINGS,
            DEFAULT,
            &bare,
        ))
        .click
        .unwrap();
        assert_eq!(
            (click.country.as_str(), click.device.as_str()),
            ("XX", "other")
        );
        assert_eq!(click.referrer, None);
    }

    #[test]
    fn batching() {
        let click = run(handle(
            &MemoryKv::with(&link("promo")),
            &FakeOrigin::default(),
            &SETTINGS,
            DEFAULT,
            &req("promo"),
        ))
        .click
        .unwrap();
        let mut b = ClickBatcher::new(3, 5_000);
        assert!(b.is_empty());
        assert_eq!(b.push(click.clone()), Push::Schedule);
        assert_eq!(b.push(click.clone()), Push::Buffered);
        match b.push(click.clone()) {
            Push::Flush(batch) => assert_eq!(batch.clicks.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(b.len(), 0);
        assert_eq!(b.take(), None);
        assert_eq!(b.push(click), Push::Schedule);
        assert_eq!(b.take().unwrap().clicks.len(), 1);
    }

    fn on(host: &str, code: &str) -> EdgeRequest {
        EdgeRequest {
            host: Some(host.as_bytes().to_vec()),
            ..req(code)
        }
    }

    fn put(kv: &MemoryKv, key: String, link: &Link) {
        kv.values
            .borrow_mut()
            .insert(key, serde_json::to_string(link).unwrap());
    }

    fn mark_domain(kv: &MemoryKv, host: &str) {
        kv.values.borrow_mut().insert(
            host_kv_key(host),
            serde_json::to_string(&relink_core::wire::EdgeDomain { id: 3 }).unwrap(),
        );
    }

    /// A KV that counts reads, to hold the edge to its read budget.
    #[derive(Default)]
    struct CountingKv {
        inner: MemoryKv,
        reads: std::cell::RefCell<Vec<String>>,
    }

    impl Kv for CountingKv {
        async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
            self.reads.borrow_mut().push(key.to_owned());
            self.inner.get(key).await
        }
    }

    #[test]
    fn custom_domains_serve_their_own_codes_at_the_edge() {
        let kv = CountingKv::default();
        let mut default = link("promo");
        default.destinations[0].url = "https://default.example.org/".into();
        put(&kv.inner, kv_key("promo"), &default);
        let mut on_domain = link("promo");
        on_domain.id = 12;
        on_domain.destinations[0].url = "https://domain.example.org/".into();
        put(&kv.inner, domain_kv_key(HOST, "promo"), &on_domain);
        mark_domain(&kv.inner, HOST);
        let origin = FakeOrigin::default();

        // The same code on the custom domain and on the default one, each
        // in one read; case, port and a final dot do not matter.
        for host in ["go.example.com", "Go.Example.COM:443", "go.example.com."] {
            kv.reads.borrow_mut().clear();
            let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(host, "promo")));
            assert_eq!(out.served, Served::Edge, "{host}");
            assert_eq!(
                out.response.header("location"),
                Some("https://domain.example.org/")
            );
            assert_eq!(out.click.unwrap().link_id, 12);
            assert_eq!(*kv.reads.borrow(), ["link:go.example.com/promo"]);
        }
        for host in [
            None,
            Some("S.Relink.Example:8443"),
            Some("203.0.113.9"),
            Some("localhost"),
        ] {
            kv.reads.borrow_mut().clear();
            let r = EdgeRequest {
                host: host.map(|h| h.as_bytes().to_vec()),
                ..req("promo")
            };
            let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &r));
            assert_eq!(
                out.response.header("location"),
                Some("https://default.example.org/"),
                "{host:?}"
            );
            assert_eq!(*kv.reads.borrow(), ["link:promo"], "{host:?}");
        }
        assert_eq!(origin.calls.get(), 0);
    }

    #[test]
    fn unknown_hosts_fall_back_to_the_default_domain() {
        let kv = CountingKv::default();
        put(&kv.inner, kv_key("promo"), &link("promo"));
        let origin = FakeOrigin::default();
        // Not a verified domain: the origin would route it to the default
        // domain, and so does the edge.
        let out = run(handle(
            &kv,
            &origin,
            &SETTINGS,
            DEFAULT,
            &on("other.example.net", "promo"),
        ));
        assert_eq!(out.served, Served::Edge);
        assert_eq!(out.response.status, 301);
        assert_eq!(
            *kv.reads.borrow(),
            [
                "link:other.example.net/promo",
                "host:other.example.net",
                "link:promo"
            ]
        );
        // Without a default host configured every hostname is asked about.
        kv.reads.borrow_mut().clear();
        let out = run(handle(&kv, &origin, &SETTINGS, "", &on(DEFAULT, "promo")));
        assert_eq!(out.served, Served::Edge);
        assert_eq!(kv.reads.borrow().len(), 3);
        assert_eq!(origin.calls.get(), 0);
    }

    #[test]
    fn a_verified_domain_never_serves_default_domain_codes() {
        let kv = MemoryKv::with(&link("promo"));
        mark_domain(&kv, HOST);
        let origin = FakeOrigin::default();
        // The code exists only on the default domain. On the custom domain
        // the edge must not guess: the origin answers (404, or the link if
        // KV has not caught up).
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "promo")));
        assert_eq!(out.served, Served::Origin);
        assert!(out.click.is_none());
        assert_eq!(origin.calls.get(), 1);
        assert_eq!(
            origin.hosts.borrow().as_slice(),
            [Some(HOST.as_bytes().to_vec())]
        );

        // A host record that will not parse still marks a domain.
        kv.values
            .borrow_mut()
            .insert(host_kv_key("x.example.org"), "{bad".into());
        let out = run(handle(
            &kv,
            &origin,
            &SETTINGS,
            DEFAULT,
            &on("x.example.org", "promo"),
        ));
        assert_eq!(out.served, Served::Origin);
    }

    #[test]
    fn domain_links_follow_the_same_rules_and_failures() {
        let origin = FakeOrigin::default();
        // A limited link on a domain goes to the origin.
        let kv = MemoryKv::default();
        let mut limited = link("limited");
        limited.max_clicks = Some(5);
        put(&kv, domain_kv_key(HOST, "limited"), &limited);
        let out = run(handle(
            &kv,
            &origin,
            &SETTINGS,
            DEFAULT,
            &on(HOST, "limited"),
        ));
        assert_eq!(out.served, Served::Origin);
        // A record that will not parse goes to the origin, without
        // falling back to the default domain.
        kv.values
            .borrow_mut()
            .insert(domain_kv_key(HOST, "junk"), "{".into());
        put(&kv, kv_key("junk"), &link("junk"));
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "junk")));
        assert_eq!(out.served, Served::Origin);
        // KV down: the origin decides.
        kv.fail.set(true);
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "promo")));
        assert_eq!(out.served, Served::Origin);
        assert_eq!(origin.calls.get(), 3);
        // A disabled link on a domain is a 404 at the edge.
        kv.fail.set(false);
        let mut off = link("off");
        off.enabled = false;
        put(&kv, domain_kv_key(HOST, "off"), &off);
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "off")));
        assert_eq!((out.response.status, out.served), (404, Served::Edge));
        // Garbage paths never cost a read, whatever the host.
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "a.php")));
        assert_eq!((out.response.status, out.served), (404, Served::Edge));
        assert_eq!(origin.calls.get(), 3);
    }
}

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
//!
//! A verified domain's record carries its settings (`relink_core::site`):
//! `/` and paths that are not a plain code (`/campaign/abc`, or `/ABC` on a
//! case-insensitive domain) read it to learn where they go, then read the
//! link they name. Its 404 and 410 pages are served here, and a link found
//! by the one-read path reads the record only when it needs a page. The
//! decisions are the same functions the origin calls.

use std::cell::RefCell;
use std::future::Future;
use std::net::IpAddr;
use std::rc::Rc;

use relink_core::classify::{UNKNOWN_COUNTRY, device_class, referrer_host};
use relink_core::code::is_plausible_code;
use relink_core::hex;
use relink_core::host::{custom_host, host_part};
use relink_core::model::Link;
use relink_core::rules::{Decision, Settings, Visit, evaluate};
use relink_core::site::{
    DomainSettings, EXPIRED_TEXT, HTML, NOT_FOUND_TEXT, PAGE_CSP, PageKind, Target, page, target,
};
use relink_core::visitor::fingerprint;
use relink_core::wire::{ClickBatch, EdgeDomain, WireClick, domain_kv_key, host_kv_key, kv_key};

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
    /// Set by the CDN, so trusted: the subdivision part of the visitor's
    /// ISO 3166-2 region (`CA` for `US-CA`).
    pub region: Option<Vec<u8>>,
    pub accept_language: Option<Vec<u8>>,
    /// The query string without the `?`, as sent.
    pub query: Option<String>,
    pub now_ms: i64,
    pub random: u64,
}

/// The header the edge names the visitor's region in when it forwards a
/// request; the origin reads it when `RELINK_REGION_HEADER` names it.
pub const REGION_HEADER: &str = "cf-region-code";

/// The path and query the edge asks the origin for: the visitor's own, so
/// rules on `query` decide the same at both.
pub fn origin_path(req: &EdgeRequest) -> String {
    match req.query.as_deref() {
        Some(q) if !q.is_empty() => format!("{}?{q}", req.code),
        _ => req.code.clone(),
    }
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

/// The `x-forwarded-host` the origin is told for `req`. Workers cannot set
/// `Host` on a fetch, so this is how the origin learns which domain a
/// forwarded request is for. It is the host part the edge itself routed by
/// (`relink_core::host::host_part`), never the raw header: the origin reads
/// the first entry of a comma-separated `x-forwarded-host`, so forwarding
/// `a.example.com,b.example.com` (which the edge treats as the default
/// domain) would have the origin answer for `a.example.com` instead. With
/// no host part the header is left out and the origin, seeing its own
/// `Host`, routes to the default domain, as the edge did.
pub fn forwarded_host(req: &EdgeRequest) -> Option<String> {
    req.host.as_deref().and_then(host_part).map(str::to_owned)
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
    let Some(host) = custom_host(req.host.as_deref(), default_host) else {
        return default_domain(kv, origin, settings, req).await;
    };
    let host = host.to_ascii_lowercase();
    // A plain code is looked up as sent first: on a custom domain that is
    // the one read a redirect costs.
    let sent = is_plausible_code(&req.code).then_some(req.code.as_str());
    if let Some(code) = sent {
        match read(kv, &domain_kv_key(&host, code)).await {
            Read::Found(link) => {
                let pages = Pages::Unread(&host);
                return serve(kv, origin, settings, req, &link, pages).await;
            }
            Read::Failed => return from_origin(origin, req).await,
            Read::Missing => {}
        }
    }
    let domain = match read_domain(kv, &host).await {
        // Not a custom domain: the default domain's link.
        Ok(None) => return default_domain(kv, origin, settings, req).await,
        Ok(Some(d)) => d,
        // KV failed or the record would not parse: only the origin knows.
        Err(()) => return from_origin(origin, req).await,
    };
    let site = &domain.settings;
    match target(&req.code, Some(site)) {
        Target::Root => match &site.root_url {
            Some(url) => edge(redirect(302, url, None, None), None),
            None => edge(error_page(PageKind::NotFound, Some(site), &host, req), None),
        },
        Target::Miss => edge(error_page(PageKind::NotFound, Some(site), &host, req), None),
        // Already missing from KV: the code may not have arrived yet, so the
        // origin answers.
        Target::Code(code) if Some(&*code) == sent => from_origin(origin, req).await,
        Target::Code(code) => match read(kv, &domain_kv_key(&host, &code)).await {
            Read::Found(link) => {
                let pages = Pages::Known(&host, site);
                serve(kv, origin, settings, req, &link, pages).await
            }
            Read::Missing | Read::Failed => from_origin(origin, req).await,
        },
    }
}

/// A request for the default domain, which has no settings.
async fn default_domain<K: Kv, O: Origin>(
    kv: &K,
    origin: &O,
    settings: &Settings<'_>,
    req: &EdgeRequest,
) -> Outcome {
    if !is_plausible_code(&req.code) {
        return edge(EdgeResponse::text(404, NOT_FOUND_TEXT), None);
    }
    match read(kv, &kv_key(&req.code)).await {
        Read::Found(link) => serve(kv, origin, settings, req, &link, Pages::Default).await,
        Read::Missing | Read::Failed => from_origin(origin, req).await,
    }
}

/// Where a link's error pages come from.
enum Pages<'a> {
    /// The default domain's built-in ones.
    Default,
    /// A custom domain whose record has been read.
    Known(&'a str, &'a DomainSettings),
    /// A custom domain whose record is read only if a page is needed.
    Unread(&'a str),
}

/// The `host:` record of `host`: `Ok(None)` when it is not a verified
/// domain, `Err` when KV failed or the record would not parse.
async fn read_domain<K: Kv>(kv: &K, host: &str) -> Result<Option<EdgeDomain>, ()> {
    match kv.get(&host_kv_key(host)).await {
        Ok(None) => Ok(None),
        Ok(Some(json)) => serde_json::from_str(&json).map(Some).map_err(|_| ()),
        Err(_) => Err(()),
    }
}

/// Answers with a link found in KV.
async fn serve<K: Kv, O: Origin>(
    kv: &K,
    origin: &O,
    settings: &Settings<'_>,
    req: &EdgeRequest,
    link: &Link,
    pages: Pages<'_>,
) -> Outcome {
    if link.max_clicks.is_some() {
        return from_origin(origin, req).await;
    }
    let cookies: Vec<&[u8]> = req.cookies.iter().map(Vec::as_slice).collect();
    // Targeting rules were compiled when the record was parsed; they read
    // the same facts the origin reads.
    let visit = Visit {
        now_ms: req.now_ms,
        country: req.country,
        region: req.region.as_deref(),
        user_agent: req.user_agent.as_deref(),
        accept_language: req.accept_language.as_deref(),
        referer: req.referer.as_deref(),
        query: req.query.as_deref().map(str::as_bytes),
        cookies: &cookies,
        random: req.random,
    };
    let kind = match evaluate(link, &visit, settings) {
        Decision::NotFound => PageKind::NotFound,
        Decision::Expired => PageKind::Gone,
        Decision::GeoBlocked {
            fallback: Some(url),
        } => return edge(redirect(302, url, None, None), None),
        Decision::GeoBlocked { fallback: None } => {
            return edge(
                EdgeResponse::text(451, "this link is not available in your region\n"),
                None,
            );
        }
        // A rule's answer is no-store (`cacheable` is false), like every
        // answer from a link with rules.
        // Unreachable while limited links are proxied, but if one ever got
        // here the origin is the only place that can admit it.
        Decision::Redirect(r) if r.needs_admission => return from_origin(origin, req).await,
        Decision::Redirect(r) => {
            let cache = r.cacheable.then_some(EDGE_MAX_AGE);
            let response = redirect(r.status, r.location, cache, r.set_cookie);
            return edge(response, Some(click_for(link, req)));
        }
    };
    match pages {
        Pages::Default => edge(error_page(kind, None, "", req), None),
        Pages::Known(host, site) => edge(error_page(kind, Some(site), host, req), None),
        Pages::Unread(host) => match read_domain(kv, host).await {
            Ok(Some(d)) => edge(error_page(kind, Some(&d.settings), host, req), None),
            // A link on a domain KV no longer has: built-in pages.
            Ok(None) => edge(error_page(kind, None, host, req), None),
            Err(()) => from_origin(origin, req).await,
        },
    }
}

/// A 404 or 410 page: the domain's own when it has one.
fn error_page(
    kind: PageKind,
    site: Option<&DomainSettings>,
    host: &str,
    req: &EdgeRequest,
) -> EdgeResponse {
    let p = page(kind, site, host, &req.code, EXPIRED_TEXT);
    let mut headers = vec![
        ("content-type".to_owned(), p.content_type.to_owned()),
        ("cache-control".to_owned(), "no-store".to_owned()),
    ];
    if p.content_type == HTML {
        headers.push(("content-security-policy".into(), PAGE_CSP.into()));
        headers.push(("x-content-type-options".into(), "nosniff".into()));
    }
    EdgeResponse {
        status: p.status,
        headers,
        body: p.body,
    }
}

/// A link record read from KV.
enum Read {
    Found(Rc<Link>),
    Missing,
    /// The read failed or the record would not parse.
    Failed,
}

async fn read<K: Kv>(kv: &K, key: &str) -> Read {
    match kv.get(key).await {
        Ok(Some(json)) => match PARSED.with(|p| p.borrow_mut().parse(key, json)) {
            Some(link) => Read::Found(link),
            None => Read::Failed,
        },
        Ok(None) => Read::Missing,
        Err(_) => Read::Failed,
    }
}

thread_local! {
    // One per isolate (and per test thread natively); Workers run one
    // request at a time per isolate thread.
    static PARSED: RefCell<Parsed> = RefCell::new(Parsed::new(PARSED_BYTES));
}

/// Most bytes of key and record text [`Parsed`] keeps per isolate. Parsed
/// links take a few times their text, so this stays well inside a Worker's
/// memory.
pub const PARSED_BYTES: usize = 2 << 20;

/// Link records parsed (with their compiled targeting rules) by this
/// isolate, so a hot link is parsed once rather than on every request. An
/// entry is reused only while KV returns exactly the text it was parsed
/// from, so a changed record is parsed again on its first read and the
/// cache never answers with anything KV no longer says.
///
/// A list, oldest first, rather than a map: lookups scan at most
/// [`PARSED_ENTRIES`] short keys, which costs less than hashing would
/// save, and a map's code would weigh on the Worker bundle.
#[derive(Debug)]
pub struct Parsed {
    entries: Vec<(String, String, Rc<Link>)>,
    bytes: usize,
    max_bytes: usize,
}

/// Most records [`Parsed`] keeps.
pub const PARSED_ENTRIES: usize = 256;

impl Parsed {
    pub fn new(max_bytes: usize) -> Parsed {
        Parsed {
            entries: Vec::new(),
            bytes: 0,
            max_bytes,
        }
    }

    /// The link `json` (the record at `key`) describes, or `None` if it
    /// does not parse.
    pub fn parse(&mut self, key: &str, json: String) -> Option<Rc<Link>> {
        let at = self.entries.iter().position(|(k, _, _)| k == key);
        if let Some(i) = at {
            let (_, text, link) = &self.entries[i];
            if *text == json {
                return Some(link.clone());
            }
        }
        let link = Rc::new(serde_json::from_str::<Link>(&json).ok()?);
        if let Some(i) = at {
            self.evict(i);
        }
        let size = key.len() + json.len();
        if size > self.max_bytes {
            return Some(link);
        }
        // Drop the oldest entries until the new one fits.
        while !self.entries.is_empty()
            && (self.bytes + size > self.max_bytes || self.entries.len() >= PARSED_ENTRIES)
        {
            self.evict(0);
        }
        self.bytes += size;
        self.entries.push((key.to_owned(), json, link.clone()));
        Some(link)
    }

    fn evict(&mut self, i: usize) {
        let (k, text, _) = self.entries.remove(i);
        self.bytes -= k.len() + text.len();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes of key and record text held.
    pub fn bytes(&self) -> usize {
        self.bytes
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
    use relink_core::site::PLAIN;

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
            rules: Default::default(),
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
            serde_json::to_string(&EdgeDomain {
                id: 3,
                settings: DomainSettings::default(),
            })
            .unwrap(),
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
    fn the_origin_is_told_only_the_host_the_edge_routed_by() {
        let fwd = |h: &str| forwarded_host(&on(h, "abc"));
        assert_eq!(
            fwd("Go.Example.com.:443").as_deref(),
            Some("Go.Example.com")
        );
        assert_eq!(fwd("localhost").as_deref(), Some("localhost"));
        // A list, which the origin would read as its first entry, a space
        // or an IP literal: the edge routed these to the default domain,
        // so the origin is told nothing and routes by its own `Host`.
        for h in [
            "a.example.com,b.example.com",
            "a.example.com b",
            "[::1]:80",
            "",
        ] {
            assert_eq!(fwd(h), None, "{h:?}");
        }
        assert_eq!(forwarded_host(&req("abc")), None);
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
        // Garbage paths never reach the origin, whatever the host; on a
        // custom domain they cost the read of its record, for its 404 page.
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, "a.php")));
        assert_eq!((out.response.status, out.served), (404, Served::Edge));
        assert_eq!(origin.calls.get(), 3);
    }

    fn site() -> DomainSettings {
        DomainSettings {
            root_url: Some("https://www.example.com/".into()),
            not_found_page: Some("<h1>{{code}} not on {{host}}</h1>".into()),
            gone_page: Some("<p>{{code}} gone</p>".into()),
            prefixes: vec!["campaign".into()],
            case_insensitive: true,
        }
    }

    fn with_site(kv: &MemoryKv, host: &str, settings: DomainSettings) {
        kv.values.borrow_mut().insert(
            host_kv_key(host),
            serde_json::to_string(&EdgeDomain { id: 3, settings }).unwrap(),
        );
    }

    #[test]
    fn domain_settings_apply_at_the_edge() {
        let kv = CountingKv::default();
        with_site(&kv.inner, HOST, site());
        put(&kv.inner, domain_kv_key(HOST, "summer"), &link("summer"));
        let origin = FakeOrigin::default();
        let get = |path: &str| {
            kv.reads.borrow_mut().clear();
            run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, path)))
        };

        let out = get("");
        assert_eq!((out.response.status, out.served), (302, Served::Edge));
        assert_eq!(
            out.response.header("location"),
            Some("https://www.example.com/")
        );
        assert!(out.click.is_none());
        assert_eq!(*kv.reads.borrow(), ["host:go.example.com"]);

        // The plain code costs one read; prefixed or folded ones two more.
        assert_eq!(get("summer").response.status, 301);
        assert_eq!(kv.reads.borrow().len(), 1);
        for path in ["SUMMER", "campaign/summer", "Campaign/SUMMER"] {
            let out = get(path);
            assert_eq!(
                (out.response.status, out.served),
                (301, Served::Edge),
                "{path}"
            );
            assert_eq!(out.click.unwrap().link_id, 11);
            assert_eq!(
                kv.reads.borrow().last().unwrap(),
                "link:go.example.com/summer"
            );
        }
        assert_eq!(get("campaign/summer").response.status, 301);
        assert_eq!(
            *kv.reads.borrow(),
            ["host:go.example.com", "link:go.example.com/summer"],
            "a path with a prefix reads the domain first"
        );

        // The domain's own 404 page, escaped and confined, without the
        // origin; codes it might not have yet still go to the origin.
        for (path, code) in [
            ("other/summer", "summer"),
            ("a.php", "a.php"),
            ("x/y/z<", "z<"),
        ] {
            let out = get(path);
            assert_eq!(
                (out.response.status, out.served),
                (404, Served::Edge),
                "{path}"
            );
            assert_eq!(out.response.header("content-type"), Some(HTML));
            assert_eq!(
                out.response.header("content-security-policy"),
                Some(PAGE_CSP)
            );
            assert_eq!(
                out.response.header("x-content-type-options"),
                Some("nosniff")
            );
            let code = code.replace('<', "&lt;");
            assert_eq!(
                out.response.body,
                format!("<h1>{code} not on go.example.com</h1>")
            );
        }
        assert_eq!(origin.calls.get(), 0);
        assert_eq!(get("unknown").served, Served::Origin);
        assert_eq!(get("campaign/unknown").served, Served::Origin);
        assert_eq!(origin.calls.get(), 2);

        // Disabled and expired links found by the one-read path read the
        // domain for its pages.
        let mut off = link("off");
        off.enabled = false;
        put(&kv.inner, domain_kv_key(HOST, "off"), &off);
        let out = get("off");
        assert_eq!(out.response.status, 404);
        assert_eq!(out.response.body, "<h1>off not on go.example.com</h1>");
        assert_eq!(
            *kv.reads.borrow(),
            ["link:go.example.com/off", "host:go.example.com"]
        );
        let mut old = link("old");
        old.expires_at = Some(chrono::DateTime::from_timestamp(0, 0).unwrap());
        put(&kv.inner, domain_kv_key(HOST, "old"), &old);
        let out = get("campaign/OLD");
        assert_eq!((out.response.status, out.served), (410, Served::Edge));
        assert_eq!(out.response.body, "<p>OLD gone</p>");
        assert_eq!(kv.reads.borrow().len(), 2, "the record read once");
    }

    #[test]
    fn domains_without_settings_or_records_keep_the_built_in_pages() {
        let kv = MemoryKv::default();
        with_site(&kv, HOST, DomainSettings::default());
        let mut old = link("old");
        old.expires_at = Some(chrono::DateTime::from_timestamp(0, 0).unwrap());
        put(&kv, domain_kv_key(HOST, "old"), &old);
        put(&kv, domain_kv_key(HOST, "ABC"), &link("ABC"));
        let origin = FakeOrigin::default();
        let get = |path: &str| run(handle(&kv, &origin, &SETTINGS, DEFAULT, &on(HOST, path)));
        for path in ["", "campaign/abc", "a.php"] {
            let out = get(path);
            assert_eq!(
                (out.response.status, out.served),
                (404, Served::Edge),
                "{path}"
            );
            assert_eq!(out.response.header("content-type"), Some(PLAIN));
            assert_eq!(out.response.body, NOT_FOUND_TEXT);
            assert!(out.response.header("content-security-policy").is_none());
        }
        let out = get("old");
        assert_eq!(
            (out.response.status, out.response.body.as_str()),
            (410, EXPIRED_TEXT)
        );
        // Case matters without the setting.
        assert_eq!(get("ABC").response.status, 301);
        assert_eq!(get("abc").served, Served::Origin);

        // A link whose domain record is gone gets the built-in page; a
        // failing read lets the origin decide.
        kv.values.borrow_mut().remove(&host_kv_key(HOST));
        let out = get("old");
        assert_eq!(
            (out.response.status, out.response.body.as_str()),
            (410, EXPIRED_TEXT)
        );
        let failing = FailAfter {
            inner: MemoryKv::default(),
            left: std::cell::Cell::new(1),
        };
        put(&failing.inner, domain_kv_key(HOST, "old"), &old);
        let out = run(handle(
            &failing,
            &origin,
            &SETTINGS,
            DEFAULT,
            &on(HOST, "old"),
        ));
        assert_eq!(out.served, Served::Origin);
        // A host record that will not parse sends prefixed paths there too.
        kv.values.borrow_mut().insert(host_kv_key(HOST), "{".into());
        assert_eq!(get("campaign/abc").served, Served::Origin);

        // The default domain keeps `/` and prefixes meaningless.
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &req("")));
        assert_eq!((out.response.status, out.served), (404, Served::Edge));
        assert_eq!(out.response.body, NOT_FOUND_TEXT);
    }

    /// A KV that answers `left` reads, then fails.
    struct FailAfter {
        inner: MemoryKv,
        left: std::cell::Cell<usize>,
    }

    impl Kv for FailAfter {
        async fn get(&self, key: &str) -> Result<Option<String>, EdgeError> {
            match self.left.get() {
                0 => Err(EdgeError("kv down".into())),
                n => {
                    self.left.set(n - 1);
                    self.inner.get(key).await
                }
            }
        }
    }

    #[test]
    fn parsed_records_are_reused_only_while_kv_text_is_unchanged() {
        let mut ruled = link("promo");
        ruled.rules = serde_json::from_str(
            r#"[{"if": {"country": ["DE"]}, "url": "https://example.com/de"}]"#,
        )
        .unwrap();
        let json = serde_json::to_string(&ruled).unwrap();
        let mut p = Parsed::new(1 << 20);
        let a = p.parse("link:promo", json.clone()).unwrap();
        let b = p.parse("link:promo", json.clone()).unwrap();
        assert!(Rc::ptr_eq(&a, &b), "the same text is parsed once");
        assert_eq!(a.rules.compiled().steps().len(), 1);
        assert_eq!((p.len(), p.bytes()), (1, "link:promo".len() + json.len()));

        ruled.destinations[0].url = "https://example.com/new".into();
        let changed = serde_json::to_string(&ruled).unwrap();
        let c = p.parse("link:promo", changed.clone()).unwrap();
        assert_eq!(c.destinations[0].url, "https://example.com/new");
        assert_eq!(
            (p.len(), p.bytes()),
            (1, "link:promo".len() + changed.len())
        );
        assert!(p.parse("link:promo", "{not json".into()).is_none());
        assert!(Rc::ptr_eq(&c, &p.parse("link:promo", changed).unwrap()));
    }

    #[test]
    fn parsed_records_stay_within_their_byte_budget() {
        let json = serde_json::to_string(&link("promo")).unwrap();
        let one = "link:aaaa".len() + json.len();
        let mut p = Parsed::new(one * 3);
        for key in [
            "link:aaaa",
            "link:bbbb",
            "link:cccc",
            "link:dddd",
            "link:eeee",
        ] {
            assert!(p.parse(key, json.clone()).is_some());
            assert!(p.bytes() <= one * 3);
        }
        assert_eq!(p.len(), 3);
        // The oldest go first: the newest three are still parsed once.
        let e = p.parse("link:eeee", json.clone()).unwrap();
        assert!(Rc::ptr_eq(&e, &p.parse("link:eeee", json.clone()).unwrap()));
        assert!(p.parse("link:cccc", json.clone()).is_some());
        assert_eq!(p.len(), 3);
        // And never more than PARSED_ENTRIES, whatever the budget.
        let mut wide = Parsed::new(usize::MAX / 2);
        for i in 0..PARSED_ENTRIES + 10 {
            assert!(wide.parse(&format!("link:k{i}"), json.clone()).is_some());
        }
        assert_eq!(wide.len(), PARSED_ENTRIES);
        // A record bigger than the whole budget is served but not kept.
        let mut tiny = Parsed::new(8);
        assert!(tiny.parse("link:aaaa", json).is_some());
        assert!(tiny.is_empty() && tiny.bytes() == 0);
    }

    #[test]
    fn rules_read_every_visitor_fact_at_the_edge() {
        let mut ruled = link("promo");
        ruled.rules = serde_json::from_str(
            r#"[{"if": {"all": [{"region": ["US-CA"]}, {"language": ["de"]},
                               {"referrer": ["news.example"]}, {"os": ["android"]},
                               {"query": {"name": "src", "values": ["mail"]}}]},
                 "url": "https://example.com/rule"}]"#,
        )
        .unwrap();
        let kv = MemoryKv::with(&ruled);
        let origin = FakeOrigin::default();
        let mut r = req("promo");
        r.country = Some(*b"US");
        r.region = Some(b"CA".to_vec());
        r.accept_language = Some(b"de-AT,de;q=0.9".to_vec());
        r.referer = Some(b"https://m.news.example/x".to_vec());
        r.user_agent = Some(b"Mozilla/5.0 (Linux; Android 14) Chrome/124.0 Mobile".to_vec());
        r.query = Some("src=mail".into());
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &r));
        assert_eq!(out.served, Served::Edge);
        assert_eq!(out.response.status, 301);
        assert_eq!(
            out.response.header("location"),
            Some("https://example.com/rule")
        );
        assert_eq!(out.response.header("cache-control"), Some("no-store"));
        assert!(
            out.click.is_some(),
            "a rule's redirect is a click like any other"
        );
        r.query = Some("src=ads".into());
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &r));
        assert_eq!(
            out.response.header("location"),
            Some("https://example.com/landing")
        );
        assert_eq!(out.response.header("cache-control"), Some("no-store"));
        assert_eq!(origin.calls.get(), 0);
    }

    #[test]
    fn records_with_written_rules_go_to_the_origin() {
        // What the origin published before rules were compiled for the
        // edge: the written list under `rules`. Ignoring it would serve the
        // link without its rules, so the record must not parse.
        let mut record = serde_json::to_value(link("promo")).unwrap();
        record["rules"] = serde_json::json!([
            {"if": {"country": ["DE"]}, "url": "https://example.com/de"}
        ]);
        let kv = MemoryKv::default();
        kv.values
            .borrow_mut()
            .insert(kv_key("promo"), record.to_string());
        let origin = FakeOrigin::default();
        let out = run(handle(&kv, &origin, &SETTINGS, DEFAULT, &req("promo")));
        assert_eq!(out.served, Served::Origin);
        assert_eq!(origin.calls.get(), 1);
    }
}

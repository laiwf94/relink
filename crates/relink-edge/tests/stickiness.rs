//! A visitor assigned an A/B variant by one target keeps it on the other:
//! the origin and the edge sign and read the same cookie. Traffic moves
//! between them whenever KV is missing a link or the origin is bypassed, so
//! this has to hold in both directions.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, header};
use relink_core::abtest::Signer;
use relink_core::model::{Destination, Link};
use relink_core::rules::Settings;
use relink_edge::logic::{EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, Served, handle};
use relink_server::config::Config;
use relink_server::limiter::{LeaseStore, StoreUnavailable};
use relink_server::metrics::Metrics;
use relink_server::resolver::LinkSource;
use relink_server::server::{App, open_db};
use relink_server::store::DbError;
use relink_server::util::BoxFuture;

const KEY_HEX: &str = "7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d";

fn split_link() -> Link {
    Link {
        id: 42,
        code: "pricing".into(),
        destinations: ["a", "b", "c"]
            .iter()
            .map(|v| Destination {
                url: format!("https://example.com/{v}"),
                weight: 1,
            })
            .collect(),
        destinations_version: 3,
        redirect_status: 302,
        expires_at: None,
        max_clicks: None,
        geo: None,
        fallback_url: None,
        enabled: true,
        health_check: false,
        unhealthy: vec![false; 3],
    }
}

struct OneLink(Link);

impl LinkSource for OneLink {
    fn load<'a>(&'a self, code: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
        Box::pin(async move { Ok((code == self.0.code).then(|| self.0.clone())) })
    }
}

struct NoLeases;

impl LeaseStore for NoLeases {
    fn reserve(&self, _: i64, _: i64) -> BoxFuture<'_, Result<i64, StoreUnavailable>> {
        Box::pin(async { Err(StoreUnavailable) })
    }
    fn release(&self, _: i64, _: i64) -> BoxFuture<'_, Result<(), StoreUnavailable>> {
        Box::pin(async { Ok(()) })
    }
}

fn origin_app() -> Arc<App> {
    let cfg = Config::from_vars(&|k| match k {
        // Never contacted: the link comes from memory.
        "RELINK_DATABASE_URL" => Some("postgres://x:x@127.0.0.1:1/x".into()),
        "RELINK_COOKIE_KEY" => Some(KEY_HEX.into()),
        _ => None,
    })
    .unwrap();
    let db = open_db(&cfg).unwrap();
    let (app, _rx) = App::new(
        cfg,
        db,
        Arc::new(OneLink(split_link())),
        Arc::new(NoLeases),
        Arc::new(Metrics::default()),
    );
    app
}

struct EdgeKv(String);

impl Kv for EdgeKv {
    async fn get(&self, _: &str) -> Result<Option<String>, EdgeError> {
        Ok(Some(self.0.clone()))
    }
}

struct Unreachable;

impl Origin for Unreachable {
    async fn redirect(&self, _: &EdgeRequest) -> Result<EdgeResponse, EdgeError> {
        panic!("the edge must answer this itself")
    }
}

fn edge_signer() -> Signer {
    let bytes = relink_core::hex::decode(KEY_HEX).unwrap();
    Signer::new(bytes.try_into().unwrap())
}

async fn at_origin(app: &App, cookie: Option<&str>) -> (String, Option<String>) {
    let mut headers = HeaderMap::new();
    if let Some(c) = cookie {
        headers.insert(header::COOKIE, HeaderValue::from_str(c).unwrap());
    }
    let peer: IpAddr = "203.0.113.8".parse().unwrap();
    let (resp, _) = relink_server::redirect::handle(app, "pricing", &headers, peer).await;
    let get = |name| {
        resp.headers()
            .get(name)
            .map(|v: &HeaderValue| v.to_str().unwrap().to_owned())
    };
    (get(header::LOCATION).unwrap(), get(header::SET_COOKIE))
}

async fn at_edge(cookie: Option<&str>, random: u64) -> (String, Option<String>) {
    let signer = edge_signer();
    let settings = Settings {
        signer: &signer,
        cookie_secure: true,
    };
    let kv = EdgeKv(serde_json::to_string(&split_link()).unwrap());
    let req = EdgeRequest {
        code: "pricing".into(),
        cookies: cookie.map(|c| c.as_bytes().to_vec()).into_iter().collect(),
        now_ms: 1,
        random,
        ..EdgeRequest::default()
    };
    let out = handle(&kv, &Unreachable, &settings, &req).await;
    assert_eq!(out.served, Served::Edge);
    (
        out.response.header("location").unwrap().to_owned(),
        out.response.header("set-cookie").map(str::to_owned),
    )
}

fn pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn origin_assignment_holds_at_the_edge() {
    let app = origin_app();
    for _ in 0..50 {
        let (dest, set) = at_origin(&app, None).await;
        let cookie = pair(&set.expect("new visitors get a cookie"));
        // Whatever the edge's own random draw would pick.
        for random in [0, u64::MAX / 2, u64::MAX] {
            let (edge_dest, edge_set) = at_edge(Some(&cookie), random).await;
            assert_eq!(edge_dest, dest);
            assert!(edge_set.is_none(), "no reassignment at the edge");
        }
    }
}

#[tokio::test]
async fn edge_assignment_holds_at_the_origin() {
    let app = origin_app();
    for i in 0..50u64 {
        let (dest, set) = at_edge(None, i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).await;
        let cookie = pair(&set.expect("new visitors get a cookie"));
        for _ in 0..3 {
            let (origin_dest, origin_set) = at_origin(&app, Some(&cookie)).await;
            assert_eq!(origin_dest, dest);
            assert!(origin_set.is_none(), "no reassignment at the origin");
        }
    }
}

#[tokio::test]
async fn a_different_key_does_not_carry_over() {
    let app = origin_app();
    let other = Signer::new([1; 32]);
    let settings = Settings {
        signer: &other,
        cookie_secure: true,
    };
    let kv = EdgeKv(serde_json::to_string(&split_link()).unwrap());
    let req = EdgeRequest {
        code: "pricing".into(),
        now_ms: 1,
        random: 7,
        ..EdgeRequest::default()
    };
    let out = handle(&kv, &Unreachable, &settings, &req).await;
    let cookie = pair(out.response.header("set-cookie").unwrap());
    let (_, reassigned) = at_origin(&app, Some(&cookie)).await;
    assert!(
        reassigned.is_some(),
        "a cookie signed with another key is ignored"
    );
}

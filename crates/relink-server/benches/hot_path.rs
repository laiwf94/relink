//! Benchmarks for the redirect hot path and the parsers it runs.
//!
//! `cargo bench` runs everything in-process: no sockets, no database. The
//! full-router cases go through axum routing, the request middleware and the
//! redirect handler exactly as a real request would.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use criterion::{Criterion, criterion_group, criterion_main};
use relink_server::abtest::{Signer, choose};
use relink_server::cache::{Cache, Config as CacheConfig};
use relink_server::classify::{device_class, referrer_host};
use relink_server::config::Config;
use relink_server::destination::{Policy, normalize};
use relink_server::limiter::{LeaseStore, StoreUnavailable};
use relink_server::metrics::Metrics;
use relink_server::model::{Destination, Link};
use relink_server::redirect::handle;
use relink_server::resolver::LinkSource;
use relink_server::server::{App, public_router};
use relink_server::store::{Db, DbConfig, DbError};
use relink_server::util::BoxFuture;
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

const UA: &str =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";

fn link(code: &str, destinations: usize) -> Link {
    Link {
        id: 1,
        code: code.into(),
        destinations: (0..destinations)
            .map(|i| Destination {
                url: format!("https://example.com/landing/{i}?utm_source=bench"),
                weight: 1,
            })
            .collect(),
        destinations_version: 1,
        redirect_status: 302,
        expires_at: None,
        max_clicks: None,
        geo: None,
        fallback_url: None,
        enabled: true,
        health_check: false,
        unhealthy: vec![false; destinations],
    }
}

/// In-memory links; unknown codes are "not found".
struct Links(Vec<Link>);

impl LinkSource for Links {
    fn load<'a>(&'a self, code: &'a str) -> BoxFuture<'a, Result<Option<Link>, DbError>> {
        Box::pin(async move { Ok(self.0.iter().find(|l| l.code == code).cloned()) })
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

fn app(rt: &tokio::runtime::Runtime) -> Arc<App> {
    let cfg = Config::from_vars(&|k| match k {
        // Never contacted: links come from memory.
        "RELINK_DATABASE_URL" => Some("postgres://bench:bench@127.0.0.1:1/bench".into()),
        "RELINK_COOKIE_KEY" => Some("11".repeat(32)),
        _ => None,
    })
    .unwrap();
    let _guard = rt.enter();
    let db = Db::connect(
        PgConnectOptions::from_str(&cfg.database_url).unwrap(),
        &DbConfig {
            max_connections: 1,
            timeout: Duration::from_secs(1),
            health_threshold: 2,
            kv_outbox: false,
        },
    );
    let source = Arc::new(Links(vec![link("bench", 1), link("split", 3)]));
    let (app, mut rx) = App::new(
        cfg,
        db,
        source,
        Arc::new(NoLeases),
        Arc::new(Metrics::default()),
    );
    // Drain the click queue the way the flusher would.
    rt.spawn(async move { while rx.recv().await.is_some() {} });
    app
}

fn redirect_path(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let app = app(&rt);
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", UA.parse().unwrap());
    headers.insert("referer", "https://news.example.org/story".parse().unwrap());
    headers.insert("cf-ipcountry", "DE".parse().unwrap());
    let peer = "203.0.113.9".parse().unwrap();
    rt.block_on(handle(&app, "bench", &headers, peer));
    rt.block_on(handle(&app, "split", &headers, peer));

    let mut g = c.benchmark_group("redirect");
    g.bench_function("handler_cache_hit", |b| {
        b.to_async(&rt)
            .iter(|| handle(&app, "bench", &headers, peer))
    });
    g.bench_function("handler_ab_split_new_visitor", |b| {
        b.to_async(&rt)
            .iter(|| handle(&app, "split", &headers, peer))
    });
    g.bench_function("handler_negative_hit", |b| {
        rt.block_on(handle(&app, "missing", &headers, peer));
        b.to_async(&rt)
            .iter(|| handle(&app, "missing", &headers, peer))
    });
    let router = public_router(app.clone());
    let addr: SocketAddr = "203.0.113.9:4000".parse().unwrap();
    g.bench_function("full_router_cache_hit", |b| {
        b.to_async(&rt).iter(|| {
            let mut req = Request::get("/bench")
                .header("user-agent", UA)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            router.clone().oneshot(req)
        })
    });
    g.finish();
}

fn components(c: &mut Criterion) {
    let cache = Cache::new(CacheConfig {
        capacity: 100_000,
        ttl: Duration::from_secs(60),
        negative_ttl: Duration::from_secs(10),
        stale_while_revalidate: Duration::from_secs(60),
        stale_if_error: Duration::from_secs(3600),
    });
    let codes: Vec<String> = (0..100_000).map(|i| format!("c{i:06}")).collect();
    let l = Arc::new(link("x", 1));
    for code in &codes {
        cache.insert(code, Some(l.clone()), Instant::now(), cache.begin_load());
    }
    let mut i = 0;
    c.bench_function("cache_get_100k_entries", |b| {
        b.iter(|| {
            i = (i + 7919) % codes.len();
            cache.get(&codes[i], Instant::now())
        })
    });

    c.bench_function("normalize_url", |b| {
        b.iter(|| {
            normalize(
                "https://Example.com:443/path/to/page?utm_source=x&id=42#top",
                Policy::default(),
            )
        })
    });
    c.bench_function("device_class", |b| {
        b.iter(|| device_class(Some(UA.as_bytes())))
    });
    c.bench_function("referrer_host", |b| {
        b.iter(|| referrer_host(Some(b"https://news.example.org/story?id=1")))
    });
    let signer = Signer::new([9; 32]);
    let cookie = signer.sign(42, 3, 1);
    c.bench_function("ab_cookie_verify", |b| {
        b.iter(|| signer.verify(42, 3, &cookie, 3))
    });
    c.bench_function("ab_choose_10_variants", |b| {
        let w = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        let mut r = 0u64;
        b.iter(|| {
            r = r.wrapping_add(0x9e37_79b9_7f4a_7c15);
            choose(&w, |_| true, r)
        })
    });
}

criterion_group!(benches, redirect_path, components);
criterion_main!(benches);

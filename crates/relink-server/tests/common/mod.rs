//! Shared test harness: a throwaway database per test, a TCP proxy that can
//! cut the database off, and a running server with API keys.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use relink_server::auth::{generate_key, hash_key};
use relink_server::config::Config;
use relink_server::server::{Running, migrate_with_retry, open_db, start};
use relink_server::store::Db;
use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Admin connection URL for the test Postgres, from RELINK_TEST_DATABASE_URL.
/// Returns None (and the test is skipped with a message) when it is unset,
/// except under CI, where a missing database is a failure.
pub fn admin_url() -> Option<String> {
    match std::env::var("RELINK_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            if std::env::var("CI").is_ok() {
                panic!("RELINK_TEST_DATABASE_URL must be set in CI");
            }
            eprintln!("skipping: set RELINK_TEST_DATABASE_URL to run database tests");
            None
        }
    }
}

/// A fresh, empty database. Dropped (best effort) when the guard is dropped.
pub struct TestDb {
    pub url: String,
    pub name: String,
    admin: String,
}

impl TestDb {
    pub async fn create(admin: &str) -> TestDb {
        let mut suffix = [0u8; 6];
        getrandom::fill(&mut suffix).unwrap();
        let name = format!("relink_test_{}", relink_server::util::hex_encode(&suffix));
        let mut conn = PgConnection::connect(admin)
            .await
            .expect("connect to test postgres");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut conn)
            .await
            .expect("create test database");
        let opts = PgConnectOptions::from_str(admin).unwrap().database(&name);
        let url = format!(
            "postgres://{}:{}@{}:{}/{}",
            opts.get_username(),
            password(admin),
            opts.get_host(),
            opts.get_port(),
            name
        );
        TestDb {
            url,
            name,
            admin: admin.to_owned(),
        }
    }

    /// The same database reached through `proxy`.
    pub fn url_via(&self, proxy: SocketAddr) -> String {
        let opts = PgConnectOptions::from_str(&self.url).unwrap();
        format!(
            "postgres://{}:{}@{}/{}",
            opts.get_username(),
            password(&self.url),
            proxy,
            self.name
        )
    }
}

fn password(url: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .password()
        .unwrap_or_default()
        .to_owned()
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin = self.admin.clone();
        let name = self.name.clone();
        // A dedicated runtime: Drop may run inside or outside one.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                if let Ok(mut conn) = PgConnection::connect(&admin).await {
                    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                    )))
                    .execute(&mut conn)
                    .await;
                }
            });
        })
        .join();
    }
}

/// A TCP proxy in front of Postgres. `cut()` drops every connection and
/// refuses new ones (accepts and immediately closes them), as if the database
/// had stopped; `restore()` brings it back.
pub struct ChaosProxy {
    pub addr: SocketAddr,
    down: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: JoinHandle<()>,
}

impl ChaosProxy {
    pub async fn start(target: SocketAddr) -> ChaosProxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let down = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let (d, c) = (down.clone(), conns.clone());
        let accept = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    continue;
                };
                if d.load(Ordering::SeqCst) {
                    drop(client);
                    continue;
                }
                let task = tokio::spawn(async move {
                    if let Ok(mut server) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
                c.lock().unwrap().push(task);
            }
        });
        ChaosProxy {
            addr,
            down,
            conns,
            accept,
        }
    }

    pub fn cut(&self) {
        self.down.store(true, Ordering::SeqCst);
        for t in self.conns.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    pub fn restore(&self) {
        self.down.store(false, Ordering::SeqCst);
    }
}

impl Drop for ChaosProxy {
    fn drop(&mut self) {
        self.accept.abort();
        self.cut();
    }
}

/// Where the test Postgres listens (host:port from the admin URL).
pub fn pg_addr(admin: &str) -> SocketAddr {
    let opts = PgConnectOptions::from_str(admin).unwrap();
    let host = match opts.get_host() {
        "localhost" => "127.0.0.1",
        h => h,
    };
    format!("{host}:{}", opts.get_port()).parse().unwrap()
}

/// Base configuration for tests; `extra` overrides any variable.
pub fn config(database_url: &str, extra: &[(&str, &str)]) -> Config {
    let mut vars: HashMap<String, String> = [
        ("RELINK_DATABASE_URL", database_url),
        ("RELINK_ADDR", "127.0.0.1:0"),
        ("RELINK_ADMIN_ADDR", "127.0.0.1:0"),
        ("RELINK_COOKIE_KEY", &"5a".repeat(32)),
        ("RELINK_COOKIE_SECURE", "false"),
        ("RELINK_HEALTH_ENABLED", "false"),
        // Tests play the CDN from loopback.
        ("RELINK_TRUSTED_PROXIES", "127.0.0.1,::1"),
        ("RELINK_COUNTRY_HEADER", "cf-ipcountry"),
        ("RELINK_CLICK_FLUSH_MS", "50"),
        // Generous: connection set-up (SCRAM) is slow in instrumented builds.
        ("RELINK_DB_TIMEOUT_MS", "5000"),
        ("RELINK_API_RATE", "1000"),
        ("RELINK_API_BURST", "1000"),
        ("RELINK_SHUTDOWN_TIMEOUT_S", "5"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        vars.insert(k.to_string(), v.to_string());
    }
    Config::from_vars(&move |k| vars.get(k).cloned()).expect("test config")
}

/// A running server on a fresh database, optionally behind a chaos proxy,
/// with API keys for alice and bob.
pub struct Harness {
    pub db: TestDb,
    pub proxy: ChaosProxy,
    pub server: Option<Running>,
    pub store: Db,
    pub http: reqwest::Client,
    pub alice: String,
    pub bob: String,
    pub base: String,
    pub admin: String,
}

impl Harness {
    pub async fn start(admin: &str, extra: &[(&str, &str)]) -> Harness {
        let db = TestDb::create(admin).await;
        let proxy = ChaosProxy::start(pg_addr(admin)).await;
        let cfg = config(&db.url_via(proxy.addr), extra);
        let store = open_db(&cfg).unwrap();
        migrate_with_retry(&store, Duration::from_secs(10))
            .await
            .unwrap();
        let alice = generate_key();
        let bob = generate_key();
        store
            .insert_api_key("alice", "test", &hash_key(&alice))
            .await
            .unwrap();
        store
            .insert_api_key("bob", "test", &hash_key(&bob))
            .await
            .unwrap();
        // The server gets its own pool; shutting it down must not close ours.
        let server = start(cfg.clone(), open_db(&cfg).unwrap()).await.unwrap();
        let app = server.app.clone();
        assert!(
            eventually(Duration::from_secs(5), || {
                let app = app.clone();
                async move { app.change_feed.load(Ordering::Acquire) }
            })
            .await,
            "change feed did not connect"
        );
        let base = format!("http://{}", server.addr);
        let admin = format!("http://{}", server.admin_addr);
        Harness {
            db,
            proxy,
            server: Some(server),
            store,
            http: client(),
            alice,
            bob,
            base,
            admin,
        }
    }

    /// Another instance on the same database (and proxy).
    pub async fn second_instance(&self, extra: &[(&str, &str)]) -> Running {
        let cfg = config(&self.db.url_via(self.proxy.addr), extra);
        let store = open_db(&cfg).unwrap();
        let running = start(cfg, store).await.unwrap();
        let app = running.app.clone();
        assert!(
            eventually(Duration::from_secs(5), || {
                let app = app.clone();
                async move { app.change_feed.load(Ordering::Acquire) }
            })
            .await,
            "change feed did not connect"
        );
        running
    }

    pub fn app(&self) -> &Arc<relink_server::server::App> {
        &self.server.as_ref().unwrap().app
    }

    pub async fn shutdown(&mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown().await;
        }
    }

    pub async fn api(
        &self,
        method: reqwest::Method,
        path: &str,
        key: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(key);
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let json = if text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
        };
        (status, json)
    }

    pub async fn create(&self, body: serde_json::Value) -> serde_json::Value {
        let (status, json) = self
            .api(reqwest::Method::POST, "/v1/links", &self.alice, Some(body))
            .await;
        assert_eq!(status, 201, "create failed: {json}");
        json
    }

    /// GET /{code} without following redirects.
    pub async fn visit(&self, code: &str, headers: &[(&str, &str)]) -> reqwest::Response {
        let mut req = self.http.get(format!("{}/{code}", self.base));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send().await.unwrap()
    }

    pub async fn metrics(&self) -> String {
        self.http
            .get(format!("{}/metrics", self.admin))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }
}

/// An HTTP client that never follows redirects and never uses proxies.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap()
}

/// Reads one metric value (first line starting with `name`).
pub fn metric(text: &str, name: &str) -> f64 {
    text.lines()
        .find(|l| l.starts_with(name) && l[name.len()..].starts_with([' ']))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("metric {name} not found"))
}

/// Polls `f` until it returns true or the timeout passes.
pub async fn eventually<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// Inserts a link into its owner's personal workspace (created on first
/// use), the way an API request with that owner's key would.
pub async fn insert_link(
    store: &Db,
    new: &relink_server::store::NewLink,
    code_len: usize,
) -> Result<relink_server::store::StoredLink, relink_server::store::DbError> {
    let ws = store.personal_workspace(&new.owner).await?;
    store.tenant(ws).insert_link(new, code_len).await
}

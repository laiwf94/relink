//! Wiring: shared state, routers, background tasks and graceful shutdown.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::ListenerExt;
use sqlx::postgres::{PgConnectOptions, PgListener};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

use crate::abtest::Signer;
use crate::acme::{self, AcmeWorker, ChallengeMap};
use crate::api;
use crate::auth::{Authenticator, Credential, LookupLimits};
use crate::cache::Cache;
use crate::clicks::{ClickEvent, ClickQueue, ClickSink, Flusher};
use crate::config::Config;
use crate::dns::{DnsClient, parse_resolv_conf};
use crate::domains::{self, DomainMap};
use crate::health::HealthWorker;
use crate::invite;
use crate::kvsync::{CloudflareKv, KvSync};
use crate::limiter::{ClickLimiter, LeaseStore};
use crate::metrics::{DbOp, Gauges, Metrics};
use crate::oidc::{self, Oidc};
use crate::ratelimit::{KeyedLimiter, Rate};
use crate::redirect;
use crate::resolver::{LinkSource, Resolver};
use crate::session;
use crate::store::{CHANGES_CHANNEL, DOMAINS_CHANGED, Db, DbConfig, parse_change};
use crate::tls::{self, Sealer, Tls, TlsListener};
use crate::util::{now_ms, secure_random, stopped, utc_day};

/// State shared by every request and background task.
pub struct App {
    pub cfg: Config,
    pub db: Db,
    pub resolver: Resolver,
    pub limiter: ClickLimiter,
    pub clicks: ClickQueue,
    pub signer: Signer,
    pub metrics: Arc<Metrics>,
    pub auth: Authenticator,
    pub api_limiter: KeyedLimiter<Credential>,
    pub shutting_down: AtomicBool,
    /// Whether the change notification connection is up.
    pub change_feed: AtomicBool,
    /// Poked on every change so the KV sync runs without waiting for its poll.
    pub kv_wake: Arc<Notify>,
    /// `Cache-Control` for redirects whose answer never varies.
    pub cache_control: HeaderValue,
    /// OpenID Connect sign-in, when configured.
    pub oidc: Option<Arc<Oidc>>,
    /// Verified custom domains, for routing redirects by `Host`.
    pub domains: DomainMap,
    /// TXT lookups for domain verification.
    pub dns: DnsClient,
    /// Pending ACME HTTP-01 challenges, answered on every instance.
    pub challenges: ChallengeMap,
    /// Poked when a domain is verified, so its certificate is ordered
    /// without waiting for the next round.
    pub acme_wake: Arc<Notify>,
    /// Encrypts and decrypts stored private keys, when a key is configured.
    pub sealer: Option<Arc<Sealer>>,
    /// Certificates for the TLS listener, when there is one.
    pub tls: Option<Tls>,
}

/// Credentials tracked by the API rate limiter (one bucket per key or person).
const MAX_RATE_LIMITED_KEYS: usize = 100_000;

impl App {
    /// Builds the state. `source` and `leases` are the database in
    /// production; tests and benchmarks may substitute in-memory versions.
    pub fn new(
        cfg: Config,
        db: Db,
        source: Arc<dyn LinkSource>,
        leases: Arc<dyn LeaseStore>,
        metrics: Arc<Metrics>,
    ) -> (Arc<App>, mpsc::Receiver<ClickEvent>) {
        let key = cfg.cookie_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            secure_random(&mut k);
            k
        });
        let (clicks, rx) = ClickQueue::new(cfg.click_queue, metrics.clone());
        let cache_control =
            HeaderValue::from_str(&format!("private, max-age={}", cfg.redirect_max_age))
                .expect("digits are header-safe");
        let app = App {
            resolver: Resolver::new(
                Cache::new(cfg.cache),
                source,
                cfg.lookup_concurrency,
                metrics.clone(),
            ),
            limiter: ClickLimiter::new(leases, cfg.max_lease).with_metrics(metrics.clone()),
            clicks,
            signer: Signer::new(key),
            auth: Authenticator::new(
                db.clone(),
                10_000,
                LookupLimits {
                    per_ip: Rate {
                        per_second: cfg.auth_lookup_rate_per_ip,
                        burst: (cfg.auth_lookup_rate_per_ip * 2.0).max(1.0),
                    },
                    global: cfg.auth_lookup_rate,
                },
            ),
            api_limiter: KeyedLimiter::new(cfg.api_rate, MAX_RATE_LIMITED_KEYS),
            oidc: cfg.oidc.clone().map(|c| {
                Arc::new(Oidc::new(c).expect("OIDC settings are validated with the configuration"))
            }),
            domains: DomainMap::default(),
            dns: DnsClient::new(
                cfg.dns_servers.clone().unwrap_or_else(|| {
                    parse_resolv_conf(
                        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
                    )
                }),
                cfg.dns_timeout,
            ),
            challenges: ChallengeMap::default(),
            acme_wake: Arc::new(Notify::new()),
            sealer: cfg.key_encryption_key.map(|k| Arc::new(Sealer::new(&k))),
            tls: cfg.tls.clone().map(Tls::new),
            shutting_down: AtomicBool::new(false),
            change_feed: AtomicBool::new(false),
            kv_wake: Arc::new(Notify::new()),
            metrics,
            cache_control,
            db,
            cfg,
        };
        (Arc::new(app), rx)
    }

    /// Point-in-time values for /metrics.
    pub fn gauges(&self) -> Gauges {
        Gauges {
            queue_depth: self.clicks.depth(),
            queue_capacity: self.clicks.capacity(),
            backlog_keys: self.metrics.backlog.load(Ordering::Relaxed) as usize,
            cache_entries: self.resolver.cache().len(),
            leases: self.limiter.len(),
            db_pool_size: self.db.pool_stats().0,
            db_pool_idle: self.db.pool_stats().1,
            tls_certificates: self.tls.as_ref().map_or(0, |t| t.store.len()),
        }
    }

    /// Applies a change notification (or a local change) for a link, by
    /// its [`crate::store::link_key`].
    pub async fn link_changed(&self, id: i64, key: &str) {
        self.resolver.invalidate(key);
        self.limiter.invalidate(id).await;
        self.kv_wake.notify_one();
    }
}

/// The public router: redirects, the management API and probes.
pub fn public_router(app: Arc<App>) -> Router {
    let api = Router::new()
        .route("/v1/links", get(api::list_links).post(api::create_link))
        .route(
            "/v1/links/{code}",
            get(api::get_link)
                .patch(api::update_link)
                .delete(api::delete_link),
        )
        .route("/v1/links/{code}/stats", get(api::link_stats))
        .route("/v1/usage", get(api::usage))
        .route(
            "/v1/domains",
            get(domains::list_domains).post(domains::create_domain),
        )
        .route(
            "/v1/domains/{hostname}",
            get(domains::get_domain).delete(domains::delete_domain),
        )
        .route(
            "/v1/domains/{hostname}/verify",
            post(domains::verify_domain),
        )
        .route("/v1/auth/login", get(oidc::login))
        .route("/v1/auth/callback", get(oidc::callback))
        .route("/v1/auth/session", get(session::get_session))
        .route("/v1/auth/logout", post(session::logout))
        .route(
            "/v1/invitations",
            get(invite::list_invitations).post(invite::create_invitation),
        )
        .route(
            "/v1/invitations/{id}",
            axum::routing::delete(invite::revoke_invitation),
        )
        .route("/v1/invites/{token}", get(invite::preview_invite))
        .route("/v1/invites/{token}/accept", post(invite::accept_invite))
        .layer(DefaultBodyLimit::max(api::MAX_BODY));
    let edge = Router::new()
        .route("/v1/edge/clicks", post(api::edge_clicks))
        .layer(DefaultBodyLimit::max(api::MAX_EDGE_BODY));
    Router::new()
        .merge(api)
        .merge(edge)
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .route("/openapi.json", get(api::openapi))
        .route("/.well-known/acme-challenge/{token}", get(acme::http01))
        .route("/{code}", get(redirect::redirect))
        .fallback(api::not_found)
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            api::request_context,
        ))
        .with_state(app)
}

/// The admin router (metrics and probes), on its own listener that defaults
/// to loopback.
pub fn admin_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .fallback(api::not_found)
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            api::request_context,
        ))
        .with_state(app)
}

async fn metrics(State(app): State<Arc<App>>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        app.metrics.render(&app.gauges()),
    )
        .into_response()
}

/// Opens the database pool (lazily) from configuration.
pub fn open_db(cfg: &Config) -> Result<Db, String> {
    let options = PgConnectOptions::from_str(&cfg.database_url)
        .map_err(|_| "RELINK_DATABASE_URL is not a valid postgres:// URL".to_owned())?;
    Ok(Db::connect(
        options,
        &DbConfig {
            max_connections: cfg.db_max_connections,
            lookup_connections: cfg.db_lookup_connections,
            timeout: cfg.db_timeout,
            health_threshold: cfg.health.failure_threshold,
            kv_outbox: cfg.kv.is_some(),
        },
    ))
}

/// Runs migrations, retrying while the database is starting up.
pub async fn migrate_with_retry(db: &Db, deadline: Duration) -> Result<(), String> {
    let until = Instant::now() + deadline;
    let mut wait = Duration::from_millis(200);
    loop {
        match db.migrate().await {
            Ok(()) => return Ok(()),
            Err(crate::store::DbError::Unavailable(e)) if Instant::now() + wait < until => {
                tracing::warn!(error = %e, "database not reachable yet; retrying");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(2));
            }
            Err(e) => return Err(format!("migrations failed: {e}")),
        }
    }
}

/// A running server.
pub struct Running {
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    /// The TLS listener's address, when there is one.
    pub tls_addr: Option<SocketAddr>,
    pub app: Arc<App>,
    stop: watch::Sender<bool>,
    done: JoinHandle<()>,
}

impl Running {
    /// Stops accepting requests, drains in-flight ones, flushes clicks,
    /// returns unspent click leases, then returns.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.done.await;
    }

    /// Waits until the server stops on its own (it does not, except on shutdown).
    pub async fn wait(self) {
        let _ = self.done.await;
    }

    /// A handle that triggers shutdown from elsewhere (signal handlers).
    pub fn stopper(&self) -> watch::Sender<bool> {
        self.stop.clone()
    }
}

/// Starts listeners and background tasks. Migrations must already be applied.
pub async fn start(cfg: Config, db: Db) -> Result<Running, String> {
    let metrics = Arc::new(Metrics::default());
    if cfg.cookie_key.is_none() {
        tracing::warn!(
            "RELINK_COOKIE_KEY is not set: A/B assignments use a random key and reset on restart"
        );
    }
    let source: Arc<dyn LinkSource> = Arc::new(db.clone());
    let leases: Arc<dyn LeaseStore> = Arc::new(db.clone());
    let (app, rx) = App::new(cfg.clone(), db.clone(), source, leases, metrics.clone());
    if app.dns.servers().is_empty() {
        tracing::warn!(
            "no DNS resolver found in /etc/resolv.conf and RELINK_DNS_SERVERS is not set: \
             custom domains cannot be verified"
        );
    }
    // Route custom domains from the first request. If the database is not
    // there yet, requests for other hosts get 503 until the change listener
    // connects and loads them.
    if let Err(e) = app.reload_domains().await {
        tracing::warn!(error = %e, "could not load verified domains yet");
    }
    if let Err(e) = app.reload_challenges().await {
        tracing::debug!(error = %e, "could not load ACME challenges yet");
    }
    let tls_listener = match &app.tls {
        Some(t) => {
            // A default certificate that cannot be read is a configuration
            // error, found now rather than at the first handshake.
            t.reload_files()?;
            if let Err(e) = app.reload_certificates().await {
                tracing::warn!(error = %e, "could not load certificates yet");
            }
            let tcp = TcpListener::bind(t.config.addr)
                .await
                .map_err(|e| format!("cannot listen on {}: {e}", t.config.addr))?;
            Some(
                TlsListener::new(
                    tcp,
                    tls::server_config(t.store.clone()),
                    t.config.handshake_timeout,
                    metrics.clone(),
                )
                .map_err(|e| e.to_string())?,
            )
        }
        None => None,
    };
    let tls_addr = tls_listener
        .as_ref()
        .map(|l| axum::serve::Listener::local_addr(l).expect("the TLS listener knows its address"));

    let public = TcpListener::bind(cfg.addr)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", cfg.addr))?;
    let admin = TcpListener::bind(cfg.admin_addr)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", cfg.admin_addr))?;
    let addr = public.local_addr().map_err(|e| e.to_string())?;
    let admin_addr = admin.local_addr().map_err(|e| e.to_string())?;

    let (stop_tx, stop_rx) = watch::channel(false);
    let (bg_tx, bg_rx) = watch::channel(false);

    let (drain_tx, drain_rx) = watch::channel(None);
    let sink: Arc<dyn ClickSink> = Arc::new(db.clone());
    let flusher = tokio::spawn(Flusher::new(sink, metrics.clone(), cfg.flush).run(rx, drain_rx));
    let listener = tokio::spawn(listen_for_changes(app.clone(), bg_rx.clone()));
    let maintenance = tokio::spawn(maintain(app.clone(), bg_rx.clone()));
    let health = if cfg.health.enabled {
        let worker = HealthWorker::new(
            db.clone(),
            cfg.health,
            cfg.destination_policy.allow_private,
            metrics.clone(),
        )
        .map_err(|e| format!("cannot build the health check client: {e}"))?;
        Some(tokio::spawn(worker.run(bg_rx.clone())))
    } else {
        None
    };

    let kv = match &cfg.kv {
        Some(kv_cfg) => {
            let api = CloudflareKv::new(kv_cfg)
                .map_err(|e| format!("cannot build the KV client: {e}"))?;
            let sync = KvSync::new(
                db.clone(),
                Arc::new(api),
                metrics.clone(),
                kv_cfg.poll,
                kv_cfg.reconcile,
                app.kv_wake.clone(),
            );
            Some(tokio::spawn(sync.run(bg_rx.clone())))
        }
        None => None,
    };

    let certificates = match &cfg.acme {
        Some(acme_cfg) => {
            let worker = AcmeWorker::new(
                acme_cfg.clone(),
                db.clone(),
                metrics.clone(),
                app.acme_wake.clone(),
                app.sealer
                    .clone()
                    .expect("the configuration requires a key encryption key with ACME"),
            )
            .map_err(|e| format!("cannot build the ACME client: {e}"))?;
            Some(tokio::spawn(worker.run(bg_rx.clone())))
        }
        None => None,
    };

    let public_srv = tokio::spawn(serve(public, public_router(app.clone()), stop_rx.clone()));
    let admin_srv = tokio::spawn(serve(admin, admin_router(app.clone()), stop_rx.clone()));
    let tls_srv = tls_listener.map(|l| {
        // TapIo, which does nothing here, is what gives connections through
        // a listener of our own the peer address the handlers read.
        tokio::spawn(serve(
            l.tap_io(|_| {}),
            public_router(app.clone()),
            stop_rx.clone(),
        ))
    });

    let supervisor_app = app.clone();
    let timeout = cfg.shutdown_timeout;
    let done = tokio::spawn(async move {
        let mut stop = stop_rx;
        stopped(&mut stop).await;
        // One budget for every phase, so a slow phase eats into the next
        // instead of stretching shutdown past the orchestrator's grace period.
        let deadline = tokio::time::Instant::now() + timeout;
        supervisor_app.shutting_down.store(true, Ordering::Release);
        tracing::info!("shutting down: draining requests");
        for mut srv in [public_srv, admin_srv].into_iter().chain(tls_srv) {
            if tokio::time::timeout_at(deadline, &mut srv).await.is_err() {
                tracing::warn!("in-flight requests did not finish before the shutdown deadline");
                srv.abort();
            }
        }
        // No request can take a click from here on; stop handing out leases.
        supervisor_app.limiter.close();
        let _ = bg_tx.send(true);
        // The flusher stops retrying a little early so it can still count
        // what it could not write before the supervisor gives up on it.
        let _ = drain_tx.send(Some(deadline - timeout / 10));
        let mut tasks: Vec<JoinHandle<()>> = vec![flusher, listener, maintenance];
        tasks.extend(health);
        tasks.extend(kv);
        tasks.extend(certificates);
        for mut task in tasks {
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
            }
        }
        if tokio::time::timeout_at(deadline, supervisor_app.limiter.release_all())
            .await
            .is_err()
        {
            tracing::warn!("could not return unspent click leases before the shutdown deadline");
        }
        supervisor_app.db.close().await;
        tracing::info!("shutdown complete");
    });

    tracing::info!(%addr, %admin_addr, tls_addr = ?tls_addr, "listening");
    Ok(Running {
        addr,
        admin_addr,
        tls_addr,
        app,
        stop: stop_tx,
        done,
    })
}

async fn serve<L>(listener: L, router: Router, mut stop: watch::Receiver<bool>)
where
    L: axum::serve::Listener<Addr = SocketAddr>,
    SocketAddr: for<'a> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'a, L>>,
{
    let result = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        stopped(&mut stop).await;
    })
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, "server error");
    }
}

/// Keeps the cache coherent across instances: every link change is
/// published with `pg_notify` and evicted here. Whenever the notification
/// connection is (re)established, changes may have been missed, so every
/// cached entry is demoted to stale and max-click marks are cleared.
async fn listen_for_changes(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut wait = Duration::from_millis(200);
    loop {
        let connect = async {
            let mut l = PgListener::connect_with(app.db.pool()).await?;
            l.eager_reconnect(false);
            l.listen(CHANGES_CHANNEL).await?;
            Ok::<_, sqlx::Error>(l)
        };
        let connected = tokio::select! {
            r = connect => r,
            _ = stopped(&mut stop) => return,
        };
        let mut listener = match connected {
            Ok(l) => l,
            Err(e) => {
                app.metrics.db_error(DbOp::Listen);
                tracing::debug!(error = %e, "change listener cannot connect");
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = stopped(&mut stop) => return,
                }
                wait = (wait * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        wait = Duration::from_millis(200);
        app.resolver.cache().bump_epoch();
        app.limiter.forget_exhausted();
        // Domain and challenge changes may have been missed too.
        domains::spawn_reload(app.clone());
        acme::spawn_reload(app.clone());
        tls::spawn_reload(app.clone());
        app.change_feed.store(true, Ordering::Release);
        tracing::info!("listening for link changes");
        loop {
            tokio::select! {
                msg = listener.try_recv() => match msg {
                    Ok(Some(n)) => {
                        if n.payload() == DOMAINS_CHANGED {
                            domains::spawn_reload(app.clone());
                            // A newly verified domain needs a certificate;
                            // a deleted one's is no longer served.
                            app.acme_wake.notify_one();
                            tls::spawn_reload(app.clone());
                        } else if n.payload() == tls::CERTIFICATES_CHANGED {
                            tls::spawn_reload(app.clone());
                        } else if n.payload() == acme::CHALLENGES_CHANGED {
                            acme::spawn_reload(app.clone());
                        } else if let Some((id, key)) = parse_change(n.payload()) {
                            app.link_changed(id, key).await;
                        }
                    }
                    Ok(None) | Err(_) => {
                        app.change_feed.store(false, Ordering::Release);
                        app.metrics.db_error(DbOp::Listen);
                        tracing::warn!("change listener lost its connection; reconnecting");
                        break;
                    }
                },
                _ = stopped(&mut stop) => return,
            }
        }
    }
}

/// Periodic housekeeping: visitor-hash roll-up and salt deletion, expired
/// sessions and sign-ins, idle lease return, rate limiter cleanup, and a
/// reload of the verified domains, pending ACME challenges and certificates
/// in case a notification was lost (and of the default certificate files,
/// which have no notification).
async fn maintain(app: Arc<App>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stopped(&mut stop) => return,
        }
        if let Err(e) = app.db.maintain_visitors(utc_day(now_ms())).await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "visitor maintenance failed");
        }
        if let Err(e) = app.db.purge_expired_sessions().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "session clean-up failed");
        }
        if let Err(e) = app.reload_domains().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload verified domains");
        }
        if let Err(e) = app.reload_challenges().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload ACME challenges");
        }
        if let Err(e) = app.reload_certificates().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload certificates");
        }
        if let Some(Err(e)) = app.tls.as_ref().map(Tls::reload_files) {
            tracing::warn!(error = %e, "could not reload the default certificate; keeping the old one");
        }
        app.limiter.sweep(Instant::now()).await;
        app.api_limiter.sweep(Instant::now());
        app.auth.sweep(Instant::now());
    }
}

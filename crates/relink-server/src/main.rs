//! The `relink` server and its admin commands.
//!
//! ```text
//! relink                      run the server (same as `relink serve`)
//! relink migrate              apply database migrations and exit
//! relink create-key OWNER [NAME]
//!                             create an API key for OWNER; prints it once
//! relink revoke-key ID        revoke an API key by its ID
//! relink kv-record CODE       print the JSON the edge would get for CODE
//! ```
//!
//! Configuration is read from the environment:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `RELINK_DATABASE_URL` | required | `postgres://user:pass@host:5432/db` |
//! | `RELINK_ADDR` | `0.0.0.0:8080` | Public listener: redirects, API, probes |
//! | `RELINK_ADMIN_ADDR` | `127.0.0.1:9090` | Admin listener: `/metrics`, probes |
//! | `RELINK_PUBLIC_BASE_URL` | `http://localhost:8080` | Prefix for `short_url` in responses |
//! | `RELINK_CODE_LENGTH` | `7` | Generated code length, 4 to 32 |
//! | `RELINK_COOKIE_KEY` | random | 64+ hex chars; HMAC key for A/B cookies. Set it so assignments survive restarts and match across instances |
//! | `RELINK_COOKIE_SECURE` | `true` | Add `Secure` to A/B cookies |
//! | `RELINK_TRUSTED_PROXIES` | unset | Comma-separated addresses or CIDR blocks of your CDN or load balancer; the two headers below are read only from these peers |
//! | `RELINK_COUNTRY_HEADER` | unset | Header with the visitor's country set by the CDN, e.g. `cf-ipcountry` |
//! | `RELINK_CLIENT_IP_HEADER` | unset | Header with the client address chain, e.g. `x-forwarded-for`; the rightmost untrusted hop is used. Unset uses the socket peer |
//! | `RELINK_ALLOW_IP_LITERALS` | `false` | Accept public IP-address destinations |
//! | `RELINK_ALLOW_PRIVATE_DESTINATIONS` | `false` | Accept private/loopback destinations and let health checks reach them (development only) |
//! | `RELINK_CACHE_CAPACITY` | `100000` | Cached links (0 disables the cache) |
//! | `RELINK_CACHE_TTL_MS` | `30000` | Fresh period for a cached link |
//! | `RELINK_CACHE_NEGATIVE_TTL_MS` | `10000` | Fresh period for "no such code" |
//! | `RELINK_CACHE_SWR_MS` | `300000` | Stale-while-revalidate window after the TTL |
//! | `RELINK_CACHE_STALE_IF_ERROR_MS` | `86400000` | How long after the TTL a cached link is served while the database is down |
//! | `RELINK_LOOKUP_CONCURRENCY` | `32` | Database lookups in flight for cache misses |
//! | `RELINK_CLICK_QUEUE` | `65536` | Click queue capacity; clicks beyond it are dropped and counted |
//! | `RELINK_CLICK_FLUSH_MS` | `1000` | Longest time between click flushes |
//! | `RELINK_CLICK_BATCH` | `5000` | Clicks that trigger an early flush |
//! | `RELINK_CLICK_BACKLOG` | `200000` | Aggregated rows kept in memory while the database is down |
//! | `RELINK_LEASE_MAX` | `100` | Largest click lease for max-click links |
//! | `RELINK_HEALTH_ENABLED` | `true` | Run the destination health worker |
//! | `RELINK_HEALTH_INTERVAL_S` | `300` | Seconds between checks of one link |
//! | `RELINK_HEALTH_CONCURRENCY` | `16` | Probes in flight |
//! | `RELINK_HEALTH_PER_HOST_RPS` | `1` | Probes per second to one host |
//! | `RELINK_HEALTH_TIMEOUT_MS` | `5000` | Probe timeout |
//! | `RELINK_HEALTH_FAILURE_THRESHOLD` | `2` | Consecutive failures before a destination is unhealthy |
//! | `RELINK_HEALTH_BATCH` | `100` | Links claimed per round |
//! | `RELINK_API_RATE` / `RELINK_API_BURST` | `10` / `20` | Per-key token bucket for the API |
//! | `RELINK_AUTH_LOOKUP_RATE` | `200` | Database lookups per second for API keys not in the auth cache; excess callers get 429 |
//! | `RELINK_AUTH_LOOKUP_RATE_PER_IP` | `5` | The same per client address (burst twice that) |
//! | `RELINK_DB_MAX_CONNECTIONS` | `16` | Pool size |
//! | `RELINK_DB_TIMEOUT_MS` | `2000` | Bound on every query, including waiting for a connection |
//! | `RELINK_REDIRECT_MAX_AGE_S` | `0` | `Cache-Control: max-age` for redirects that never vary |
//! | `RELINK_SHUTDOWN_TIMEOUT_S` | `10` | One budget for the whole shutdown: draining requests, flushing clicks, returning leases |
//! | `RELINK_EDGE_TOKEN` | unset | Shared secret (32+ characters) the edge worker uses for `POST /v1/edge/clicks`; unset disables the endpoint |
//! | `RELINK_KV_ACCOUNT_ID`, `RELINK_KV_NAMESPACE_ID`, `RELINK_KV_API_TOKEN` | unset | Publish link records to Workers KV for the edge; all three or none |
//! | `RELINK_KV_API_BASE` | `https://api.cloudflare.com/client/v4` | KV API endpoint; must be https |
//! | `RELINK_KV_POLL_MS` / `RELINK_KV_RECONCILE_S` | `1000` / `3600` | Outbox poll interval when no change notification arrives / full KV reconciliation interval |
//! | `RELINK_LOG` | `info,sqlx::postgres::notice=warn` | Log filter (`tracing` env-filter syntax) |

use std::process::ExitCode;
use std::time::Duration;

use relink_server::auth::{generate_key, hash_key, is_valid_owner};
use relink_server::config::Config;
use relink_server::server::{migrate_with_retry, open_db, start};

const USAGE: &str =
    "usage: relink [serve | migrate | create-key OWNER [NAME] | revoke-key ID | kv-record CODE]";

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [] | ["serve"] => serve().await,
        ["migrate"] => migrate().await,
        ["create-key", owner] => create_key(owner, "").await,
        ["create-key", owner, name] => create_key(owner, name).await,
        ["revoke-key", id] => revoke_key(id).await,
        ["kv-record", code] => kv_record(code).await,
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "relink failed");
            ExitCode::FAILURE
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("RELINK_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sqlx::postgres::notice=warn"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .init();
}

async fn prepare() -> Result<(Config, relink_server::store::Db), String> {
    let cfg = Config::from_env()?;
    let db = open_db(&cfg)?;
    migrate_with_retry(&db, Duration::from_secs(30)).await?;
    Ok((cfg, db))
}

async fn serve() -> Result<(), String> {
    let (cfg, db) = prepare().await?;
    tracing::info!(config = ?cfg, "starting");
    let running = start(cfg, db).await?;
    let stop = running.stopper();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });
    running.wait().await;
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot listen for SIGTERM; only Ctrl-C stops the server");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

async fn migrate() -> Result<(), String> {
    prepare().await?;
    println!("migrations applied");
    Ok(())
}

async fn create_key(owner: &str, name: &str) -> Result<(), String> {
    if !is_valid_owner(owner) {
        return Err(
            "OWNER must be 1-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
                .into(),
        );
    }
    if name.chars().count() > 100 {
        return Err("NAME must be at most 100 characters".into());
    }
    let (_, db) = prepare().await?;
    let key = generate_key();
    let id = db
        .insert_api_key(owner, name, &hash_key(&key))
        .await
        .map_err(|e| e.to_string())?;
    // The key itself goes to stdout only, never to the log.
    println!("id={id} owner={owner} key={key}");
    Ok(())
}

async fn revoke_key(id: &str) -> Result<(), String> {
    let id: i64 = id.parse().map_err(|_| "ID must be a number")?;
    let (_, db) = prepare().await?;
    if db.revoke_api_key(id).await.map_err(|e| e.to_string())? {
        println!("revoked key {id}");
        Ok(())
    } else {
        Err(format!("no active key with id {id}"))
    }
}

async fn kv_record(code: &str) -> Result<(), String> {
    let (_, db) = prepare().await?;
    let stored = db
        .link_by_code(code)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no link with code {code:?}"))?;
    let json = serde_json::to_string(&stored.link).map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}

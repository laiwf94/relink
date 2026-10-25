//! Publishing link records to Workers KV for the edge worker.
//!
//! Every link change writes the code into `kv_outbox` in the same
//! transaction (see `Db::changed`). This worker drains the outbox: it reads
//! the current row and PUTs its JSON to KV, or DELETEs the key if the link is
//! gone. An entry is removed only after KV accepted the write and only if the
//! link did not change again in the meantime, so a crash, a timeout or a KV
//! outage just means a retry. A periodic reconciliation compares the KV key
//! list with the database and queues anything that drifted (keys deleted by
//! hand, a namespace restored from an old copy).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};

use crate::config::KvConfig;
use crate::metrics::{DbOp, Metrics};
use crate::store::Db;
use crate::util::{BoxFuture, stopped};
use relink_core::wire::{KV_PREFIX, kv_key};

/// Why a KV call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvError(pub String);

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kv: {}", self.0)
    }
}

impl std::error::Error for KvError {}

/// One page of KV key names and the cursor for the next page.
pub type KeyPage = (Vec<String>, Option<String>);

/// The three KV operations the sync needs. Implemented over the Cloudflare
/// HTTP API; the integration tests point it at a local fake of that API.
pub trait KvApi: Send + Sync {
    fn put<'a>(&'a self, key: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), KvError>>;
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), KvError>>;
    /// One page of keys starting with `prefix`, and the cursor for the next.
    fn list<'a>(
        &'a self,
        prefix: &'a str,
        cursor: Option<&'a str>,
    ) -> BoxFuture<'a, Result<KeyPage, KvError>>;
}

/// The Cloudflare KV REST API:
/// `{base}/accounts/{account}/storage/kv/namespaces/{namespace}/values/{key}`.
pub struct CloudflareKv {
    client: reqwest::Client,
    namespace_url: String,
    token: String,
}

impl CloudflareKv {
    pub fn new(cfg: &KvConfig) -> Result<CloudflareKv, reqwest::Error> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(CloudflareKv {
            client,
            namespace_url: format!(
                "{}/accounts/{}/storage/kv/namespaces/{}",
                cfg.api_base, cfg.account_id, cfg.namespace_id
            ),
            token: cfg.api_token.clone(),
        })
    }

    fn value_url(&self, key: &str) -> String {
        // Keys are "link:" plus a code of [A-Za-z0-9_-]; only ':' needs escaping.
        format!("{}/values/{}", self.namespace_url, key.replace(':', "%3A"))
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, KvError> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| KvError(format!("request failed: {}", e.without_url())))?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(KvError(format!("status {}", resp.status().as_u16())))
        }
    }
}

#[derive(serde::Deserialize)]
struct ListPage {
    result: Vec<ListKey>,
    #[serde(default)]
    result_info: Option<ListInfo>,
}

#[derive(serde::Deserialize)]
struct ListKey {
    name: String,
}

#[derive(serde::Deserialize)]
struct ListInfo {
    #[serde(default)]
    cursor: Option<String>,
}

impl KvApi for CloudflareKv {
    fn put<'a>(&'a self, key: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), KvError>> {
        Box::pin(async move {
            self.send(self.client.put(self.value_url(key)).body(value.to_owned()))
                .await
                .map(|_| ())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), KvError>> {
        Box::pin(async move {
            match self.send(self.client.delete(self.value_url(key))).await {
                // Deleting a key that is already gone is success.
                Err(KvError(m)) if m == "status 404" => Ok(()),
                other => other.map(|_| ()),
            }
        })
    }

    fn list<'a>(
        &'a self,
        prefix: &'a str,
        cursor: Option<&'a str>,
    ) -> BoxFuture<'a, Result<KeyPage, KvError>> {
        Box::pin(async move {
            let mut query = vec![("prefix", prefix), ("limit", "1000")];
            if let Some(c) = cursor {
                query.push(("cursor", c));
            }
            let url =
                reqwest::Url::parse_with_params(&format!("{}/keys", self.namespace_url), &query)
                    .map_err(|e| KvError(e.to_string()))?;
            let resp = self.send(self.client.get(url)).await?;
            let body = resp
                .bytes()
                .await
                .map_err(|e| KvError(format!("reading list: {}", e.without_url())))?;
            let page: ListPage =
                serde_json::from_slice(&body).map_err(|e| KvError(format!("list body: {e}")))?;
            let next = page
                .result_info
                .and_then(|i| i.cursor)
                .filter(|c| !c.is_empty());
            Ok((page.result.into_iter().map(|k| k.name).collect(), next))
        })
    }
}

/// Outbox entries handled per round.
const BATCH: i64 = 100;

/// Drains the outbox into KV and reconciles periodically.
pub struct KvSync {
    db: Db,
    api: Arc<dyn KvApi>,
    metrics: Arc<Metrics>,
    poll: Duration,
    reconcile: Duration,
    wake: Arc<Notify>,
}

impl KvSync {
    pub fn new(
        db: Db,
        api: Arc<dyn KvApi>,
        metrics: Arc<Metrics>,
        poll: Duration,
        reconcile: Duration,
        wake: Arc<Notify>,
    ) -> KvSync {
        KvSync {
            db,
            api,
            metrics,
            poll,
            reconcile,
            wake,
        }
    }

    /// One pass over the due outbox entries. Returns how many were synced.
    pub async fn round(&self) -> usize {
        let due = match self.db.claim_outbox(BATCH).await {
            Ok(due) => due,
            Err(e) => {
                self.metrics.db_error(DbOp::Kv);
                tracing::warn!(error = %e, "could not read the KV outbox");
                return 0;
            }
        };
        let mut synced = 0;
        for (code, enqueued_at) in due {
            match self.sync_one(&code).await {
                Ok(()) => {
                    synced += 1;
                    if let Err(e) = self.db.finish_outbox(&code, enqueued_at).await {
                        // Harmless: the entry is retried and rewrites the same value.
                        self.metrics.db_error(DbOp::Kv);
                        tracing::warn!(error = %e, %code, "could not clear a KV outbox entry");
                    }
                }
                Err(e) => {
                    self.metrics.kv_errors.inc();
                    tracing::warn!(error = %e, %code, "KV sync failed; will retry");
                }
            }
        }
        synced
    }

    async fn sync_one(&self, code: &str) -> Result<(), KvError> {
        let key = kv_key(code);
        match self.db.link_by_code(code).await {
            Ok(Some(stored)) => {
                let json = serde_json::to_string(&stored.link)
                    .map_err(|e| KvError(format!("encoding {code}: {e}")))?;
                self.api.put(&key, &json).await?;
                self.metrics.kv_writes.inc();
                Ok(())
            }
            Ok(None) => {
                self.api.delete(&key).await?;
                self.metrics.kv_deletes.inc();
                Ok(())
            }
            Err(e) => Err(KvError(format!("reading {code}: {e}"))),
        }
    }

    /// Queues every code that is in the database but not in KV, or in KV but
    /// not in the database. Returns how many were queued.
    pub async fn reconcile_once(&self) -> Result<usize, KvError> {
        let mut in_kv = HashSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let (keys, next) = self.api.list(KV_PREFIX, cursor.as_deref()).await?;
            in_kv.extend(
                keys.into_iter()
                    .filter_map(|k| k.strip_prefix(KV_PREFIX).map(str::to_owned)),
            );
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let mut drift = Vec::new();
        let mut after = String::new();
        loop {
            let page = self
                .db
                .codes_after(&after, 5_000)
                .await
                .map_err(|e| KvError(format!("listing links: {e}")))?;
            let Some(last) = page.last().cloned() else {
                break;
            };
            for code in page {
                if !in_kv.remove(&code) {
                    drift.push(code);
                }
            }
            after = last;
        }
        // Whatever is left exists only in KV.
        drift.extend(in_kv);
        self.db
            .enqueue_outbox(&drift)
            .await
            .map_err(|e| KvError(format!("queueing drift: {e}")))?;
        self.metrics.kv_reconciled.add(drift.len() as u64);
        Ok(drift.len())
    }

    /// Runs until shutdown: a round on every change notification or poll
    /// tick, a reconciliation at start and then every `reconcile` interval.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut reconcile = tokio::time::interval(self.reconcile);
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = reconcile.tick() => {
                    match self.reconcile_once().await {
                        Ok(n) if n > 0 => tracing::info!(queued = n, "KV reconciliation found drift"),
                        Ok(_) => {}
                        Err(e) => {
                            self.metrics.kv_errors.inc();
                            tracing::warn!(error = %e, "KV reconciliation failed");
                        }
                    }
                }
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(self.poll) => {}
                _ = stopped(&mut stop) => return,
            }
            while self.round().await as i64 == BATCH {}
        }
    }
}

//! Publishing link and domain records to Workers KV for the edge worker.
//!
//! Every link change writes the link's KV key into `kv_outbox` in the same
//! transaction (see `Db::changed`), and so does verifying or deleting a
//! domain, for its `host:` record (`Db::domains_changed`). Keys are those of
//! `relink_core::wire`: `link:<code>` on the default domain,
//! `link:<host>/<code>` on a custom domain and `host:<host>` for a verified
//! domain. This worker drains the outbox: it reads the current state and
//! PUTs its JSON to KV, or DELETEs the key if the record is gone. An entry
//! is removed only after KV accepted the write and only if it was not queued
//! again in the meantime, so a crash, a timeout or a KV outage just means a
//! retry. A periodic reconciliation compares the KV key list with the
//! database and queues anything that drifted (keys deleted by hand, a
//! namespace restored from an old copy).
//!
//! Custom hostnames: when `RELINK_KV_ZONE_ID` is set, a verified domain is
//! also registered as a custom hostname of that Cloudflare zone (Cloudflare
//! for SaaS), which is what routes the domain's traffic to the Worker, and
//! removed once the domain is gone. Registration comes before the `host:`
//! record is written and removal after it is deleted, so a failure at either
//! step retries the whole entry. Reconciliation also registers any verified
//! domain the zone lacks; it never removes hostnames on its own, since the
//! zone may hold names relink did not add.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};

use crate::config::KvConfig;
use crate::metrics::{DbOp, Metrics};
use crate::store::Db;
use crate::util::{BoxFuture, stopped};
use relink_core::wire::{EdgeDomain, HOST_PREFIX, KV_PREFIX, KvKey, host_kv_key};

use crate::store::link_key;

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
        format!("{}/values/{}", self.namespace_url, escape_key(key))
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

/// A KV key as one URL path segment. Keys are `link:` or `host:` followed
/// by codes of `[A-Za-z0-9_-]` and hostnames of `[a-z0-9.-]`, joined by `/`;
/// only `:` and `/` need escaping, and `%` in case a stray key holds one.
fn escape_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 8);
    for c in key.chars() {
        match c {
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '%' => out.push_str("%25"),
            c => out.push(c),
        }
    }
    out
}

/// Registering custom domains as custom hostnames of the edge's zone.
pub trait HostnameApi: Send + Sync {
    /// Makes `hostname` a custom hostname of the zone, if it is not one.
    fn ensure<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Result<bool, KvError>>;
    /// Removes `hostname` from the zone, if it is there.
    fn remove<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Result<bool, KvError>>;
    /// Every custom hostname of the zone.
    fn list(&self) -> BoxFuture<'_, Result<Vec<String>, KvError>>;
}

/// The Cloudflare for SaaS custom hostname API:
/// `{base}/zones/{zone}/custom_hostnames`. Certificates for the hostnames
/// are Cloudflare's own (HTTP validation), issued once the domain's DNS
/// points at the zone.
pub struct CloudflareHostnames {
    client: reqwest::Client,
    url: String,
    token: String,
}

/// Custom hostnames per page of a list (the API's most).
const HOSTNAME_PAGE: usize = 50;

/// Most pages read in one list, so a misbehaving API cannot keep the sync
/// paging forever: 50,000 hostnames.
const MAX_HOSTNAME_PAGES: u32 = 1_000;

#[derive(serde::Deserialize)]
struct HostnamePage {
    result: Vec<HostnameEntry>,
    #[serde(default)]
    result_info: Option<PageInfo>,
}

#[derive(serde::Deserialize)]
struct HostnameEntry {
    id: String,
    hostname: String,
}

#[derive(serde::Deserialize)]
struct PageInfo {
    #[serde(default)]
    total_pages: Option<u32>,
}

impl CloudflareHostnames {
    /// `None` when the KV configuration names no zone.
    pub fn new(cfg: &KvConfig) -> Result<Option<CloudflareHostnames>, reqwest::Error> {
        let Some(zone) = &cfg.zone_id else {
            return Ok(None);
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Some(CloudflareHostnames {
            client,
            url: format!("{}/zones/{zone}/custom_hostnames", cfg.api_base),
            token: cfg.api_token.clone(),
        }))
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, KvError> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| KvError(format!("hostname request failed: {}", e.without_url())))?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(KvError(format!(
                "hostname API status {}",
                resp.status().as_u16()
            )))
        }
    }

    /// One page of custom hostnames, optionally only those matching
    /// `hostname`, and the number of pages.
    async fn page(
        &self,
        hostname: Option<&str>,
        page: u32,
    ) -> Result<(Vec<HostnameEntry>, u32), KvError> {
        let page_s = page.to_string();
        let per_page = HOSTNAME_PAGE.to_string();
        let mut query = vec![("page", page_s.as_str()), ("per_page", per_page.as_str())];
        if let Some(h) = hostname {
            query.push(("hostname", h));
        }
        let url = reqwest::Url::parse_with_params(&self.url, &query)
            .map_err(|e| KvError(e.to_string()))?;
        let body = self
            .send(self.client.get(url))
            .await?
            .bytes()
            .await
            .map_err(|e| KvError(format!("reading hostnames: {}", e.without_url())))?;
        let page: HostnamePage =
            serde_json::from_slice(&body).map_err(|e| KvError(format!("hostname body: {e}")))?;
        let pages = page.result_info.and_then(|i| i.total_pages).unwrap_or(1);
        Ok((page.result, pages))
    }

    /// The IDs of the custom hostnames named exactly `hostname`.
    async fn ids_of(&self, hostname: &str) -> Result<Vec<String>, KvError> {
        // The filter may match more loosely than equality; only exact names
        // count.
        let (entries, _) = self.page(Some(hostname), 1).await?;
        Ok(entries
            .into_iter()
            .filter(|e| e.hostname.eq_ignore_ascii_case(hostname))
            .map(|e| e.id)
            .collect())
    }
}

impl HostnameApi for CloudflareHostnames {
    fn ensure<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Result<bool, KvError>> {
        Box::pin(async move {
            if !self.ids_of(hostname).await?.is_empty() {
                return Ok(false);
            }
            let body = serde_json::json!({
                "hostname": hostname,
                "ssl": {"method": "http", "type": "dv"},
            });
            self.send(
                self.client
                    .post(&self.url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.to_string()),
            )
            .await?;
            Ok(true)
        })
    }

    fn remove<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Result<bool, KvError>> {
        Box::pin(async move {
            let ids = self.ids_of(hostname).await?;
            for id in &ids {
                // IDs come from the API; keep them to one path segment.
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return Err(KvError(format!("unexpected custom hostname id {id:?}")));
                }
                self.send(self.client.delete(format!("{}/{id}", self.url)))
                    .await?;
            }
            Ok(!ids.is_empty())
        })
    }

    fn list(&self) -> BoxFuture<'_, Result<Vec<String>, KvError>> {
        Box::pin(async move {
            let mut names = Vec::new();
            let mut page = 1;
            loop {
                let (entries, pages) = self.page(None, page).await?;
                let last = entries.len() < HOSTNAME_PAGE;
                names.extend(entries.into_iter().map(|e| e.hostname.to_ascii_lowercase()));
                if last || page >= pages || page >= MAX_HOSTNAME_PAGES {
                    return Ok(names);
                }
                page += 1;
            }
        })
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
    hostnames: Option<Arc<dyn HostnameApi>>,
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
            hostnames: None,
            metrics,
            poll,
            reconcile,
            wake,
        }
    }

    /// Also registers verified domains as custom hostnames through `api`.
    pub fn with_hostnames(mut self, api: Arc<dyn HostnameApi>) -> KvSync {
        self.hostnames = Some(api);
        self
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
        for (key, enqueued_at) in due {
            match self.sync_one(&key).await {
                Ok(()) => {
                    synced += 1;
                    if let Err(e) = self.db.finish_outbox(&key, enqueued_at).await {
                        // Harmless: the entry is retried and rewrites the same value.
                        self.metrics.db_error(DbOp::Kv);
                        tracing::warn!(error = %e, %key, "could not clear a KV outbox entry");
                    }
                }
                Err(e) => {
                    self.metrics.kv_errors.inc();
                    tracing::warn!(error = %e, %key, "KV sync failed; will retry");
                }
            }
        }
        synced
    }

    async fn sync_one(&self, key: &str) -> Result<(), KvError> {
        let json = match KvKey::parse(key) {
            Some(KvKey::Link { host: None, code }) => self.link_json(code, None).await?,
            Some(KvKey::Link {
                host: Some(host),
                code,
            }) => match self.domain_id(host).await? {
                Some(id) => self.link_json(code, Some(id)).await?,
                None => None,
            },
            Some(KvKey::Host(host)) => return self.sync_host(key, host).await,
            // Not a key relink writes (found by reconciliation): remove it.
            None => None,
        };
        self.write(key, json).await
    }

    /// PUTs `json` at `key`, or DELETEs the key when there is none.
    async fn write(&self, key: &str, json: Option<String>) -> Result<(), KvError> {
        match json {
            Some(json) => {
                self.api.put(key, &json).await?;
                self.metrics.kv_writes.inc();
            }
            None => {
                self.api.delete(key).await?;
                self.metrics.kv_deletes.inc();
            }
        }
        Ok(())
    }

    async fn domain_id(&self, host: &str) -> Result<Option<i64>, KvError> {
        self.db
            .verified_domain_id(host)
            .await
            .map_err(|e| KvError(format!("reading domain {host}: {e}")))
    }

    /// The JSON of the link with `code` on `domain` (the default domain when
    /// `None`), if there is one.
    async fn link_json(&self, code: &str, domain: Option<i64>) -> Result<Option<String>, KvError> {
        let key = link_key(domain, code);
        match self.db.link_by_key(&key).await {
            Ok(Some(stored)) => serde_json::to_string(&stored.link)
                .map(Some)
                .map_err(|e| KvError(format!("encoding {key}: {e}"))),
            Ok(None) => Ok(None),
            Err(e) => Err(KvError(format!("reading {key}: {e}"))),
        }
    }

    /// A domain's `host:` record and custom hostname.
    async fn sync_host(&self, key: &str, host: &str) -> Result<(), KvError> {
        let domain = self
            .db
            .verified_domain(host)
            .await
            .map_err(|e| KvError(format!("reading domain {host}: {e}")))?;
        match domain {
            Some((id, settings)) => {
                if let Some(h) = &self.hostnames
                    && h.ensure(host).await?
                {
                    self.metrics.edge_hostnames_added.inc();
                    tracing::info!(%host, "registered custom hostname");
                }
                let json = serde_json::to_string(&EdgeDomain::publish(id, settings))
                    .map_err(|e| KvError(format!("encoding {key}: {e}")))?;
                self.write(key, Some(json)).await
            }
            None => {
                self.write(key, None).await?;
                if let Some(h) = &self.hostnames
                    && h.remove(host).await?
                {
                    self.metrics.edge_hostnames_removed.inc();
                    tracing::info!(%host, "removed custom hostname");
                }
                Ok(())
            }
        }
    }

    /// Every KV key starting with `prefix`.
    async fn kv_keys(&self, prefix: &str) -> Result<HashSet<String>, KvError> {
        let mut keys = HashSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let (page, next) = self.api.list(prefix, cursor.as_deref()).await?;
            keys.extend(page.into_iter().filter(|k| k.starts_with(prefix)));
            match next {
                Some(c) => cursor = Some(c),
                None => return Ok(keys),
            }
        }
    }

    /// Queues every record that is in the database but not in KV, or in KV
    /// but not in the database, and every verified domain that is not a
    /// custom hostname of the zone. Returns how many keys were queued.
    pub async fn reconcile_once(&self) -> Result<usize, KvError> {
        let mut in_kv = self.kv_keys(KV_PREFIX).await?;
        in_kv.extend(self.kv_keys(HOST_PREFIX).await?);
        let mut drift = Vec::new();
        let mut after = (0, String::new());
        loop {
            let (keys, next) = self
                .db
                .published_links_after(&after, 5_000)
                .await
                .map_err(|e| KvError(format!("listing links: {e}")))?;
            for key in keys {
                if !in_kv.remove(&key) {
                    drift.push(key);
                }
            }
            match next {
                Some(n) => after = n,
                None => break,
            }
        }
        let verified = self
            .db
            .verified_domains()
            .await
            .map_err(|e| KvError(format!("listing domains: {e}")))?;
        let registered: Option<HashSet<String>> = match &self.hostnames {
            Some(h) => Some(h.list().await?.into_iter().collect()),
            None => None,
        };
        for d in verified {
            let host = d.hostname;
            let key = host_kv_key(&host);
            let in_zone = registered.as_ref().is_none_or(|r| r.contains(&host));
            if !in_kv.remove(&key) || !in_zone {
                drift.push(key);
            }
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

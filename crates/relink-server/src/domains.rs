//! Custom domains: a workspace adds a hostname, proves it controls it with
//! a DNS TXT record, and then creates links on it. Codes are unique per
//! domain, and a redirect is routed by its `Host` header.
//!
//! Verification: adding `go.example.com` gives the workspace a random token
//! to publish as a TXT record `relink-domain-verification=<token>` at
//! `_relink-challenge.go.example.com`. `POST /v1/domains/{hostname}/verify`
//! looks the record up through the configured recursive resolvers
//! (src/dns.rs) and marks the domain verified when the token is there. Many
//! workspaces may claim a hostname, but only the first to prove it gets it
//! (a unique index over verified hostnames), so an unverified claim cannot
//! lock the real owner out. Hostnames pass the same public-host rules as
//! destinations before anything is looked up, and relink never connects to
//! the domain itself.
//!
//! Routing: every instance keeps the verified hostnames in memory
//! ([`DomainMap`]), loaded at start, on every change notification, whenever
//! the change listener reconnects and once a minute. A request whose `Host`
//! is a verified domain looks its code up on that domain only; any other
//! host, including the one in `RELINK_PUBLIC_BASE_URL`, is the default
//! domain, as before custom domains existed. Until the first load succeeds,
//! requests for hosts that could be custom domains are answered 503 rather
//! than guessed at.
//!
//! Settings: `PATCH /v1/domains/{hostname}` sets a domain's root redirect,
//! its own 404 and 410 pages, the path prefixes it accepts and whether its
//! codes ignore case (`relink_core::site`). They travel with the domain in
//! [`DomainMap`] and in its edge record, so the origin and the edge make
//! the same decisions with the same code. Turning case-insensitivity on is
//! refused while the domain has a code with uppercase letters, and links
//! created on such a domain get lowercase codes.
//!
//! Limits: the plan's `max_domains` and a hard [`MAX_DOMAINS`] per
//! workspace, checked when a domain is added under the workspace row lock
//! (src/quota.rs). Managing domains needs `links:write` (reading them
//! `links:read`) and the admin or owner role.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::api::{ApiError, StrictJson, json};
use crate::audit::{self, Action, Change};
use crate::auth::Role;
use crate::destination::{Policy, normalize};
use crate::quota;
use crate::server::App;
use crate::store::{Db, DbError};
use crate::tenant::{Allowed, LinksRead, LinksWrite, Tenant};
use crate::util::{hex_encode, secure_random};
use relink_core::deeplink::{AndroidApp, Apps, IosApp};
use relink_core::host::custom_host;
use relink_core::site::DomainSettings;
use sqlx::types::Json;

/// The label in front of a hostname where its verification record lives.
pub const CHALLENGE_LABEL: &str = "_relink-challenge";

/// What the verification record's text starts with; the token follows.
pub const RECORD_PREFIX: &str = "relink-domain-verification=";

/// Most domains a workspace may hold whatever its plan, so a list of them is
/// always one bounded answer.
pub const MAX_DOMAINS: i64 = 1_000;

pub use relink_core::host::{MAX_HOSTNAME, host_part, is_valid_hostname};

/// Validates a hostname a workspace wants to add and returns its stored
/// form: lowercase, IDNA applied (`bücher.example.com` becomes
/// `xn--bcher-kva.example.com`), no final dot. It must be a public name by
/// the rules destinations follow (no IP addresses, single labels,
/// `localhost`, `.internal` and the like), use only letters, digits and
/// hyphens, and not be `default_host`.
pub fn parse_hostname(raw: &str, default_host: &str) -> Result<String, String> {
    let raw = raw.trim();
    // One final dot, as a `Host` header may carry (see `host_part`), and no
    // more: `2x.0x..` would get past the URL parser's check that a name
    // does not end in a number and be stored as `2x.0x`, which that check
    // refuses.
    let raw = raw.strip_suffix('.').unwrap_or(raw);
    if raw.is_empty() {
        return Err("hostname is required".into());
    }
    if raw.ends_with('.') {
        return Err("hostname must not end in more than one dot".into());
    }
    if raw.len() > 4 * MAX_HOSTNAME
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/:@?#[]\\%".contains(c))
    {
        return Err(
            "hostname must be a bare host name such as go.example.com, without a scheme, \
             port or path"
                .into(),
        );
    }
    let policy = Policy {
        allow_ip_literals: false,
        allow_private: false,
    };
    let url = normalize(&format!("https://{raw}/"), policy).map_err(|e| {
        format!(
            "hostname: {}",
            e.to_string()
                .replace("URL host", "the host")
                .replace("URL", "it")
        )
    })?;
    let host = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .ok_or("hostname is not a valid host name")?;
    let host = host.trim_end_matches('.').to_owned();
    if !is_valid_hostname(&host) {
        return Err(
            "hostname must be labels of letters, digits and hyphens (not at either end of a \
             label), at most 63 characters each and 253 in all, with at least two labels"
                .into(),
        );
    }
    if host == default_host {
        return Err(format!(
            "{host} is this server's own domain and needs no verification"
        ));
    }
    Ok(host)
}

/// Which domain a redirect request is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// The default domain: codes without a custom domain.
    Default,
    /// The verified custom domain with this ID and settings.
    Domain(Arc<Site>),
    /// The verified domains have not been loaded yet, and the host is not
    /// the default one, so the answer could be wrong either way.
    Unavailable,
}

/// A verified domain as routing needs it.
#[derive(Debug, PartialEq, Eq)]
pub struct Site {
    pub id: i64,
    pub settings: DomainSettings,
}

/// A verified domain as [`Db::verified_domains`] lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDomain {
    pub hostname: String,
    pub id: i64,
    pub settings: DomainSettings,
}

const SHARDS: usize = 16;

/// The verified hostnames and their IDs, in memory on every instance. Split
/// into shards so requests for different domains rarely share a lock, and
/// skipped entirely while no domain is verified.
pub struct DomainMap {
    shards: [RwLock<HashMap<Box<str>, Arc<Site>>>; SHARDS],
    loaded: AtomicBool,
    len: AtomicUsize,
}

impl Default for DomainMap {
    fn default() -> Self {
        DomainMap {
            shards: Default::default(),
            loaded: AtomicBool::new(false),
            len: AtomicUsize::new(0),
        }
    }
}

/// FNV-1a: a few instructions, and the hostnames are verified ones, which
/// no stranger chooses, so flooding a shard is not a concern.
fn shard_of(host: &str) -> usize {
    let mut h: u32 = 0x811c_9dc5;
    for b in host.bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    h as usize % SHARDS
}

impl DomainMap {
    /// Whether a load has succeeded since start.
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    /// Verified domains known.
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A verified domain by its lowercase hostname.
    pub fn get(&self, host: &str) -> Option<Arc<Site>> {
        self.shards[shard_of(host)]
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            .cloned()
    }

    /// Replaces the contents with `domains`.
    pub fn replace(&self, domains: Vec<VerifiedDomain>) {
        let mut fresh: [HashMap<Box<str>, Arc<Site>>; SHARDS] = Default::default();
        let n = domains.len();
        for d in domains {
            let site = Arc::new(Site {
                id: d.id,
                settings: d.settings,
            });
            fresh[shard_of(&d.hostname)].insert(d.hostname.into_boxed_str(), site);
        }
        for (shard, map) in self.shards.iter().zip(fresh) {
            *shard.write().unwrap_or_else(|e| e.into_inner()) = map;
        }
        self.len.store(n, Ordering::Release);
        self.loaded.store(true, Ordering::Release);
    }

    /// Routes a request by its `Host` header. No header, or one that
    /// cannot name a verified domain (an IP address, a single label), is the
    /// default domain, whether or not the domains have loaded.
    pub fn route(&self, host_header: Option<&[u8]>, default_host: &str) -> Route {
        let Some(host) = custom_host(host_header, default_host) else {
            return Route::Default;
        };
        if !self.is_loaded() {
            return Route::Unavailable;
        }
        if self.is_empty() {
            return Route::Default;
        }
        match self.get(&host.to_ascii_lowercase()) {
            Some(site) => Route::Domain(site),
            None => Route::Default,
        }
    }
}

/// The DNS name whose TXT records verify `hostname`.
pub fn challenge_name(hostname: &str) -> String {
    format!("{CHALLENGE_LABEL}.{hostname}")
}

/// The TXT record text that verifies a domain with `token`.
pub fn expected_record(token: &str) -> String {
    format!("{RECORD_PREFIX}{token}")
}

/// A fresh verification token: 128 random bits as 32 hex characters.
pub fn generate_token() -> String {
    let mut b = [0u8; 16];
    secure_random(&mut b);
    hex_encode(&b)
}

/// Whether the TXT `records` found at the challenge name prove `token`.
/// Surrounding spaces are forgiven (some DNS consoles add them); anything
/// else must match exactly. The error says what was found instead.
pub fn check_records(records: &[String], token: &str) -> Result<(), String> {
    let want = expected_record(token);
    if records.iter().any(|r| r.trim() == want) {
        return Ok(());
    }
    let ours = records
        .iter()
        .filter(|r| r.trim().starts_with(RECORD_PREFIX))
        .count();
    Err(match (records.len(), ours) {
        (0, _) => "no TXT record found".to_owned(),
        (_, 0) => format!(
            "{} TXT record(s) found, none starting with {RECORD_PREFIX}",
            records.len()
        ),
        _ => format!(
            "a {RECORD_PREFIX} record was found, but with another token (from an earlier \
             attempt, or another workspace's)"
        ),
    })
}

/// A domain as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub id: i64,
    pub hostname: String,
    pub verification_token: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub checked_at: Option<DateTime<Utc>>,
    pub check_error: Option<String>,
    /// The certificate's state (migration 0011, src/acme.rs).
    pub tls: TlsState,
    /// Root redirect, pages, prefixes and case rule (migration 0015).
    pub settings: DomainSettings,
}

/// Where a domain's certificate stands, as the ACME worker last left it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsState {
    pub not_after: Option<DateTime<Utc>>,
    pub renew_at: Option<DateTime<Utc>>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub failures: i32,
    pub checked_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Columns read into a [`Domain`], as a literal so queries stay `&'static str`.
macro_rules! domain_columns {
    () => {
        "id, hostname, verification_token, created_by, created_at, verified_at, checked_at, \
         check_error, tls_not_after, tls_renew_at, tls_next_attempt_at, tls_failures, \
         tls_checked_at, tls_error, settings"
    };
}

fn row_to_domain(r: &PgRow) -> Result<Domain, sqlx::Error> {
    Ok(Domain {
        id: r.try_get("id")?,
        hostname: r.try_get("hostname")?,
        verification_token: r.try_get("verification_token")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        verified_at: r.try_get("verified_at")?,
        checked_at: r.try_get("checked_at")?,
        check_error: r.try_get("check_error")?,
        tls: TlsState {
            not_after: r.try_get("tls_not_after")?,
            renew_at: r.try_get("tls_renew_at")?,
            next_attempt_at: r.try_get("tls_next_attempt_at")?,
            failures: r.try_get("tls_failures")?,
            checked_at: r.try_get("tls_checked_at")?,
            error: r.try_get("tls_error")?,
        },
        settings: r.try_get::<Json<DomainSettings>, _>("settings")?.0,
    })
}

/// A domain as the audit log shows it. Settings appear once they are
/// anything but the defaults.
pub fn domain_state(d: &Domain) -> Value {
    let mut v = json!({
        "id": d.id,
        "hostname": d.hostname,
        "verified_at": d.verified_at,
    });
    if !d.settings.is_default() {
        v["settings"] = json!(d.settings);
    }
    v
}

/// The record to publish, as `GET /v1/domains` shows it.
#[derive(Debug, Serialize)]
pub struct VerificationView {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub name: String,
    pub value: String,
}

/// A domain as the API returns it.
#[derive(Debug, Serialize)]
pub struct DomainView {
    pub hostname: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification: VerificationView,
    pub checked_at: Option<DateTime<Utc>>,
    pub check_error: Option<String>,
    /// For a verified domain: its certificate's state.
    pub certificate: Option<CertificateView>,
    /// Every setting, defaults included, so a client sees them all.
    pub settings: SettingsView,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// A domain's settings as the API returns them: every field, null or empty
/// when unset.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    pub root_url: Option<String>,
    pub not_found_page: Option<String>,
    pub gone_page: Option<String>,
    pub prefixes: Vec<String>,
    pub case_insensitive: bool,
    pub apps: AppsView,
}

/// The apps a domain belongs to, both lists always present.
#[derive(Debug, Serialize)]
pub struct AppsView {
    pub ios: Vec<IosApp>,
    pub android: Vec<AndroidApp>,
}

impl From<&DomainSettings> for SettingsView {
    fn from(s: &DomainSettings) -> SettingsView {
        SettingsView {
            root_url: s.root_url.clone(),
            not_found_page: s.not_found_page.clone(),
            gone_page: s.gone_page.clone(),
            prefixes: s.prefixes.clone(),
            case_insensitive: s.case_insensitive,
            apps: AppsView {
                ios: s.apps.ios.clone(),
                android: s.apps.android.clone(),
            },
        }
    }
}

/// A verified domain's certificate, as the API returns it. `status` is
/// `issued` once there is one (renewal failures then show in `error`
/// while it is still valid), else `pending` until an attempt fails, then
/// `failed` with `error` saying why and `next_attempt_at` when it is retried.
#[derive(Debug, Serialize)]
pub struct CertificateView {
    pub status: &'static str,
    pub not_after: Option<DateTime<Utc>>,
    pub renew_at: Option<DateTime<Utc>>,
    pub checked_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub next_attempt_at: Option<DateTime<Utc>>,
}

impl From<&TlsState> for CertificateView {
    fn from(t: &TlsState) -> CertificateView {
        let status = if t.not_after.is_some() {
            "issued"
        } else if t.error.is_some() {
            "failed"
        } else {
            "pending"
        };
        CertificateView {
            status,
            not_after: t.not_after,
            renew_at: t.renew_at,
            checked_at: t.checked_at,
            error: t.error.clone(),
            // While an order is in flight this is its lease, not a retry.
            next_attempt_at: t.error.as_ref().and(t.next_attempt_at),
        }
    }
}

impl From<&Domain> for DomainView {
    fn from(d: &Domain) -> DomainView {
        DomainView {
            hostname: d.hostname.clone(),
            verified: d.verified_at.is_some(),
            verified_at: d.verified_at,
            verification: VerificationView {
                kind: "TXT",
                name: challenge_name(&d.hostname),
                value: expected_record(&d.verification_token),
            },
            checked_at: d.checked_at,
            check_error: d.check_error.clone(),
            certificate: d.verified_at.map(|_| CertificateView::from(&d.tls)),
            settings: SettingsView::from(&d.settings),
            created_by: d.created_by.clone(),
            created_at: d.created_at,
        }
    }
}

/// Longest stored check error; the column allows 300.
const MAX_CHECK_ERROR: usize = 300;

fn clip(mut s: String) -> String {
    if s.len() > MAX_CHECK_ERROR {
        let mut end = MAX_CHECK_ERROR;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

impl Db {
    /// Every verified domain, for routing and edge reconciliation. Crosses
    /// workspaces by design, so it runs as the server's own role.
    pub async fn verified_domains(&self) -> Result<Vec<VerifiedDomain>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "SELECT hostname, id, settings FROM domains WHERE verified_at IS NOT NULL",
                )
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(VerifiedDomain {
                    hostname: r.try_get("hostname")?,
                    id: r.try_get("id")?,
                    settings: r.try_get::<Json<DomainSettings>, _>("settings")?.0,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// The verified domain with this hostname, with its settings, if any.
    pub async fn verified_domain(
        &self,
        hostname: &str,
    ) -> Result<Option<(i64, DomainSettings)>, DbError> {
        let row: Option<(i64, Json<DomainSettings>)> = self
            .timed(
                sqlx::query_as(
                    "SELECT id, settings FROM domains \
                     WHERE hostname = $1 AND verified_at IS NOT NULL",
                )
                .bind(hostname)
                .fetch_optional(self.pool()),
            )
            .await?;
        Ok(row.map(|(id, s)| (id, s.0)))
    }
}

impl Tenant<'_> {
    /// Adds `hostname` (already validated) to this workspace, unverified,
    /// with a fresh token, if the plan admits another domain. The same
    /// hostname twice in one workspace is `Conflict`.
    pub async fn add_domain(&self, hostname: &str, created_by: &str) -> Result<Domain, DbError> {
        let token = generate_token();
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                if let Err(q) = quota::admit_new_domain(&mut tx, MAX_DOMAINS).await? {
                    return Ok(Err(DbError::Quota(q)));
                }
                let row = sqlx::query(concat!(
                    "INSERT INTO domains (hostname, verification_token, created_by) \
                     VALUES ($1, $2, $3) RETURNING ",
                    domain_columns!()
                ))
                .bind(hostname)
                .bind(&token)
                .bind(created_by)
                .fetch_one(&mut *tx)
                .await?;
                let domain = row_to_domain(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::DomainCreate,
                    target: format!("domain:{}", domain.id),
                    before: None,
                    after: Some(domain_state(&domain)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(domain))
            })
            .await?
    }

    /// This workspace's domains, by hostname.
    pub async fn domains(&self) -> Result<Vec<Domain>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    domain_columns!(),
                    " FROM domains ORDER BY hostname"
                ))
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_domain)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// One of this workspace's domains by hostname.
    pub async fn domain(&self, hostname: &str) -> Result<Domain, DbError> {
        let row = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    domain_columns!(),
                    " FROM domains WHERE hostname = $1"
                ))
                .bind(hostname)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(row)
            })
            .await?
            .ok_or(DbError::NotFound)?;
        row_to_domain(&row).map_err(DbError::from)
    }

    /// Records the outcome of a verification attempt for a domain that was
    /// not verified: `Ok` verifies it (audited, and every instance is told),
    /// `Err` stores why not. A hostname another workspace verified first is
    /// `Conflict`. A domain verified meanwhile is returned as it is.
    pub async fn record_check(
        &self,
        hostname: &str,
        outcome: Result<(), String>,
    ) -> Result<Domain, DbError> {
        let ok = outcome.is_ok();
        let error = outcome.err().map(clip);
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "UPDATE domains SET checked_at = now(), check_error = $2, \
                            verified_at = CASE WHEN $3 THEN now() END \
                      WHERE hostname = $1 AND verified_at IS NULL RETURNING ",
                    domain_columns!()
                ))
                .bind(hostname)
                .bind(&error)
                .bind(ok)
                .fetch_optional(&mut *tx)
                .await?;
                let Some(row) = row else {
                    // Verified by a concurrent request, or deleted.
                    let row = sqlx::query(concat!(
                        "SELECT ",
                        domain_columns!(),
                        " FROM domains WHERE hostname = $1"
                    ))
                    .bind(hostname)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)?;
                    tx.commit().await?;
                    return row_to_domain(&row);
                };
                let domain = row_to_domain(&row)?;
                if ok {
                    let change = Change {
                        workspace_id: self.workspace_id(),
                        action: Action::DomainVerify,
                        target: format!("domain:{}", domain.id),
                        before: Some(domain_state(&Domain {
                            verified_at: None,
                            ..domain.clone()
                        })),
                        after: Some(domain_state(&domain)),
                    };
                    audit::record(&mut tx, self.actor(), change).await?;
                    self.db().domains_changed(&mut tx, &domain.hostname).await?;
                }
                tx.commit().await?;
                Ok(domain)
            })
            .await
    }

    /// Replaces a domain's settings with `settings` (already validated).
    /// Turning case-insensitivity on is refused (`Precondition`) while a
    /// code on the domain has uppercase letters: it could never be reached
    /// again. The domain row is locked first, which waits for links being
    /// created on it (they hold `FOR KEY SHARE` until they commit) and makes
    /// later ones see the new rule.
    pub async fn update_domain_settings(
        &self,
        hostname: &str,
        settings: &DomainSettings,
    ) -> Result<Domain, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    domain_columns!(),
                    " FROM domains WHERE hostname = $1 FOR UPDATE"
                ))
                .bind(hostname)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let before = row_to_domain(&row)?;
                if settings.case_insensitive && !before.settings.case_insensitive {
                    let mixed: Option<String> = sqlx::query_scalar(
                        "SELECT code FROM links WHERE domain_id = $1 AND code <> lower(code) \
                         ORDER BY code LIMIT 1",
                    )
                    .bind(before.id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some(code) = mixed {
                        return Ok(Err(DbError::Precondition(format!(
                            "case_insensitive: {hostname} has links whose codes have uppercase \
                             letters, such as {code}; delete or recreate them first"
                        ))));
                    }
                }
                let row = sqlx::query(concat!(
                    "UPDATE domains SET settings = $2 WHERE id = $1 RETURNING ",
                    domain_columns!()
                ))
                .bind(before.id)
                .bind(Json(settings))
                .fetch_one(&mut *tx)
                .await?;
                let after = row_to_domain(&row)?;
                if after.settings != before.settings {
                    let change = Change {
                        workspace_id: self.workspace_id(),
                        action: Action::DomainUpdate,
                        target: format!("domain:{}", after.id),
                        before: Some(domain_state(&before)),
                        after: Some(domain_state(&after)),
                    };
                    audit::record(&mut tx, self.actor(), change).await?;
                    if after.verified_at.is_some() {
                        self.db().domains_changed(&mut tx, &after.hostname).await?;
                    }
                }
                tx.commit().await?;
                Ok(Ok(after))
            })
            .await?
    }

    /// Deletes a domain. One that still has links is refused
    /// (`Precondition`): their short URLs are out there, and deleting
    /// the domain would break them silently.
    pub async fn delete_domain(&self, hostname: &str) -> Result<Domain, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let deleted = sqlx::query(concat!(
                    "DELETE FROM domains WHERE hostname = $1 RETURNING ",
                    domain_columns!()
                ))
                .bind(hostname)
                .fetch_optional(&mut *tx)
                .await;
                let row = match deleted {
                    Err(e) if DbError::is_fk_violation(&e) => {
                        return Ok(Err(DbError::Precondition(format!(
                            "{hostname} still has links; delete them before the domain"
                        ))));
                    }
                    other => other?.ok_or(sqlx::Error::RowNotFound)?,
                };
                let domain = row_to_domain(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::DomainDelete,
                    target: format!("domain:{}", domain.id),
                    before: Some(domain_state(&domain)),
                    after: None,
                };
                audit::record(&mut tx, self.actor(), change).await?;
                if domain.verified_at.is_some() {
                    self.db().domains_changed(&mut tx, &domain.hostname).await?;
                }
                tx.commit().await?;
                Ok(Ok(domain))
            })
            .await?
    }
}

impl App {
    /// Reloads the verified domains from the database. On failure the
    /// previous set stays in use.
    pub async fn reload_domains(&self) -> Result<(), DbError> {
        let domains = self.db.verified_domains().await?;
        self.domains.replace(domains);
        Ok(())
    }
}

/// Reloads the verified domains in the background (from the change
/// listener, which must not wait on a query).
pub fn spawn_reload(app: Arc<App>) {
    tokio::spawn(async move {
        if let Err(e) = app.reload_domains().await {
            app.metrics.db_error(crate::metrics::DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload verified domains");
        }
    });
}

/// Managing domains is for admins and owners: a domain is the workspace's
/// public name, and its plan may limit how many it has.
fn require_admin(app: &App, role: Role) -> Result<(), ApiError> {
    if role.manages(Role::Editor) {
        Ok(())
    } else {
        app.metrics.permission_denied.inc();
        Err(ApiError::permission_denied(format!(
            "managing domains needs the admin or owner role; this member is {}",
            role.as_str()
        )))
    }
}

/// A hostname from a path, lowercased; the lookup decides whether it exists.
fn path_hostname(raw: &str) -> String {
    raw.trim_end_matches('.').to_ascii_lowercase()
}

fn domain_error(e: DbError, hostname: &str) -> ApiError {
    match e {
        DbError::NotFound => {
            ApiError::not_found_msg(format!("no domain {hostname} in this workspace"))
        }
        other => ApiError::from(other),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDomain {
    pub hostname: String,
}

/// `PATCH /v1/domains/{hostname}` body: the settings to change. An absent
/// field keeps its value; `null` (or `[]` for prefixes, `false` for case)
/// returns it to the default.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDomain {
    #[serde(default, deserialize_with = "nullable")]
    pub root_url: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub not_found_page: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable")]
    pub gone_page: Option<Option<String>>,
    pub prefixes: Option<Vec<String>>,
    pub case_insensitive: Option<bool>,
    /// Replaces the apps the domain belongs to; `null` removes them.
    #[serde(default, deserialize_with = "nullable")]
    pub apps: Option<Option<AppsInput>>,
}

/// A domain's apps as the API takes them ([`relink_core::deeplink::Apps`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppsInput {
    #[serde(default)]
    pub ios: Vec<IosAppInput>,
    #[serde(default)]
    pub android: Vec<AndroidAppInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IosAppInput {
    pub team_id: String,
    pub bundle_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidAppInput {
    pub package: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

impl From<AppsInput> for Apps {
    fn from(a: AppsInput) -> Apps {
        Apps {
            ios: a
                .ios
                .into_iter()
                .map(|i| IosApp {
                    team_id: i.team_id,
                    bundle_id: i.bundle_id,
                })
                .collect(),
            android: a
                .android
                .into_iter()
                .map(|a| AndroidApp {
                    package: a.package,
                    sha256_cert_fingerprints: a.sha256_cert_fingerprints,
                })
                .collect(),
        }
    }
}

/// Distinguishes "absent" (outer None) from "null" (Some(None)).
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

impl UpdateDomain {
    /// `current` with this patch applied, not yet validated.
    pub fn apply(self, current: &DomainSettings) -> DomainSettings {
        let mut s = current.clone();
        if let Some(v) = self.root_url {
            s.root_url = v;
        }
        if let Some(v) = self.not_found_page {
            s.not_found_page = v;
        }
        if let Some(v) = self.gone_page {
            s.gone_page = v;
        }
        if let Some(v) = self.prefixes {
            s.prefixes = v;
        }
        if let Some(v) = self.case_insensitive {
            s.case_insensitive = v;
        }
        if let Some(v) = self.apps {
            s.apps = v.map(Apps::from).unwrap_or_default();
        }
        s
    }
}

#[derive(Serialize)]
struct DomainList {
    domains: Vec<DomainView>,
}

/// `POST /v1/domains`: adds an unverified domain and returns the record to
/// publish.
pub async fn create_domain(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    StrictJson(req): StrictJson<CreateDomain>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hostname =
        parse_hostname(&req.hostname, &app.cfg.default_host).map_err(ApiError::invalid)?;
    let domain = ws
        .tenant(&app.db)
        .add_domain(&hostname, &ws.principal.owner)
        .await
        .map_err(|e| match e {
            DbError::Conflict => {
                ApiError::conflict(format!("this workspace already has the domain {hostname}"))
            }
            DbError::Quota(q) => {
                app.metrics.quota_exceeded(q.kind);
                ApiError::from(DbError::Quota(q))
            }
            other => ApiError::from(other),
        })?;
    tracing::info!(domain = domain.id, "domain added");
    let mut resp = json(StatusCode::CREATED, &DomainView::from(&domain));
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/domains/{}", domain.hostname)) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(resp)
}

/// `GET /v1/domains`: every domain of the workspace.
pub async fn list_domains(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
) -> Result<Response, ApiError> {
    let domains = ws.tenant(&app.db).domains().await?;
    Ok(json(
        StatusCode::OK,
        &DomainList {
            domains: domains.iter().map(DomainView::from).collect(),
        },
    ))
}

/// `GET /v1/domains/{hostname}`.
pub async fn get_domain(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(hostname): Path<String>,
) -> Result<Response, ApiError> {
    let hostname = path_hostname(&hostname);
    let domain = ws
        .tenant(&app.db)
        .domain(&hostname)
        .await
        .map_err(|e| domain_error(e, &hostname))?;
    Ok(json(StatusCode::OK, &DomainView::from(&domain)))
}

/// `POST /v1/domains/{hostname}/verify`: looks the TXT record up now. The
/// answer is the domain, verified or with `check_error` saying what was
/// found instead; a hostname another workspace verified first is
/// `already_exists`.
pub async fn verify_domain(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(hostname): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hostname = path_hostname(&hostname);
    let tenant = ws.tenant(&app.db);
    let domain = tenant
        .domain(&hostname)
        .await
        .map_err(|e| domain_error(e, &hostname))?;
    if domain.verified_at.is_some() {
        return Ok(json(StatusCode::OK, &DomainView::from(&domain)));
    }
    let outcome = match app.dns.txt(&challenge_name(&hostname)).await {
        Ok(records) => check_records(&records, &domain.verification_token),
        Err(e) => Err(e.to_string()),
    };
    let checked = tenant
        .record_check(&hostname, outcome)
        .await
        .map_err(|e| match e {
            DbError::Conflict => ApiError::conflict(format!(
                "{hostname} is already verified by another workspace"
            )),
            other => domain_error(other, &hostname),
        })?;
    if checked.verified_at.is_some() {
        // This instance routes the domain at once; others when the change
        // notification arrives.
        if let Err(e) = app.reload_domains().await {
            tracing::warn!(error = %e, "could not reload verified domains");
        }
        // Its certificate is ordered now, not at the next round.
        app.acme_wake.notify_one();
        tracing::info!(domain = checked.id, "domain verified");
    }
    Ok(json(StatusCode::OK, &DomainView::from(&checked)))
}

/// `PATCH /v1/domains/{hostname}`: changes the domain's settings. A root
/// URL follows the rules destinations do.
pub async fn update_domain(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(hostname): Path<String>,
    StrictJson(req): StrictJson<UpdateDomain>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hostname = path_hostname(&hostname);
    let tenant = ws.tenant(&app.db);
    let current = tenant
        .domain(&hostname)
        .await
        .map_err(|e| domain_error(e, &hostname))?;
    let settings = req
        .apply(&current.settings)
        .validated(app.cfg.destination_policy)
        .map_err(|e| ApiError::invalid(e.to_string()))?;
    let domain = tenant
        .update_domain_settings(&hostname, &settings)
        .await
        .map_err(|e| domain_error(e, &hostname))?;
    if domain.verified_at.is_some()
        && let Err(e) = app.reload_domains().await
    {
        tracing::warn!(error = %e, "could not reload verified domains");
    }
    tracing::info!(domain = domain.id, "domain settings changed");
    Ok(json(StatusCode::OK, &DomainView::from(&domain)))
}

/// `DELETE /v1/domains/{hostname}`: only once it has no links.
pub async fn delete_domain(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(hostname): Path<String>,
) -> Result<Response, ApiError> {
    require_admin(&app, ws.principal.role)?;
    let hostname = path_hostname(&hostname);
    let domain = ws
        .tenant(&app.db)
        .delete_domain(&hostname)
        .await
        .map_err(|e| domain_error(e, &hostname))?;
    if domain.verified_at.is_some()
        && let Err(e) = app.reload_domains().await
    {
        tracing::warn!(error = %e, "could not reload verified domains");
    }
    tracing::info!(domain = domain.id, "domain deleted");
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "s.relink.dev";

    #[test]
    fn hostnames_are_normalised_and_checked() {
        let ok = |raw: &str| parse_hostname(raw, DEFAULT).unwrap();
        assert_eq!(ok("go.example.com"), "go.example.com");
        assert_eq!(ok("  Go.Example.COM. "), "go.example.com");
        assert_eq!(ok("bücher.example.com"), "xn--bcher-kva.example.com");
        assert_eq!(ok("a-b.c-d.co"), "a-b.c-d.co");
        let label = "a".repeat(63);
        assert_eq!(ok(&format!("{label}.com")), format!("{label}.com"));
        let err = |raw: &str| parse_hostname(raw, DEFAULT).unwrap_err();
        assert!(err("").contains("required"));
        assert!(err(" . ").contains("required"));
        for raw in ["go.example.com..", "2X.0X..", "a.b..."] {
            assert!(
                err(raw).contains("more than one dot"),
                "{raw}: {}",
                err(raw)
            );
        }
        // Accepted only in a form that is accepted again unchanged.
        assert!(err("2x.0x").contains("hostname"));
        for raw in [
            "https://go.example.com",
            "go.example.com/x",
            "go.example.com:443",
            "user@go.example.com",
            "go example.com",
            "go.example.com?x",
            "[::1]",
            "go%2eexample.com",
        ] {
            assert!(err(raw).contains("bare host name"), "{raw}: {}", err(raw));
        }
        for raw in ["127.0.0.1", "10.0.0.1", "0x7f.1"] {
            assert!(err(raw).contains("IP address"), "{raw}: {}", err(raw));
        }
        for raw in [
            "localhost",
            "intranet",
            "db.internal",
            "x.local",
            "a.test",
            "foo.onion",
        ] {
            assert!(err(raw).contains("public"), "{raw}: {}", err(raw));
        }
        for raw in [
            "go_x.example.com",
            "-go.example.com",
            "go-.example.com",
            &format!("{}a.com", "a".repeat(63)),
            &format!("{}com", "a.".repeat(126)),
        ] {
            assert!(err(raw).contains("labels"), "{raw}: {}", err(raw));
        }
        assert!(err("S.Relink.dev").contains("own domain"));
    }

    #[test]
    fn valid_hostnames_match_the_database_check() {
        for ok in [
            "a.b",
            "go.example.com",
            "xn--bcher-kva.example",
            "1.example.com",
            "a.b2",
        ] {
            assert!(is_valid_hostname(ok), "{ok}");
        }
        for bad in [
            "", "com", "a..b", ".a.b", "a.b.", "A.b", "a_b.c", "1.2.3.4", "a.-b", "a.b-",
        ] {
            assert!(!is_valid_hostname(bad), "{bad}");
        }
    }

    #[test]
    fn host_headers_are_reduced_to_their_host() {
        assert_eq!(host_part(b"go.example.com"), Some("go.example.com"));
        assert_eq!(host_part(b"Go.Example.com:8080"), Some("Go.Example.com"));
        assert_eq!(host_part(b"go.example.com."), Some("go.example.com"));
        assert_eq!(host_part(b"go.example.com.:443"), Some("go.example.com"));
        assert_eq!(host_part(b"127.0.0.1:80"), Some("127.0.0.1"));
        for bad in [
            &b""[..],
            b"[::1]:8080",
            b"go.example.com:",
            b"go.example.com:http",
            b"go.example.com:123456",
            b"a:b:c",
            b"go example.com",
            b"go_x.com",
            b".",
            b"\xff.com",
        ] {
            assert_eq!(host_part(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(host_part("a".repeat(300).as_bytes()), None);
    }

    #[test]
    fn requests_route_by_host() {
        let map = DomainMap::default();
        // Before the first load only the default host can be answered.
        assert_eq!(
            map.route(Some(b"go.example.com"), DEFAULT),
            Route::Unavailable
        );
        assert_eq!(
            map.route(Some(b"S.RELINK.dev:443"), DEFAULT),
            Route::Default
        );
        assert_eq!(map.route(None, DEFAULT), Route::Default);
        assert_eq!(map.route(Some(b"[::1]:80"), DEFAULT), Route::Default);
        for never_a_domain in [
            &b"127.0.0.1:8080"[..],
            b"localhost",
            b"intranet:80",
            b"a..b",
        ] {
            assert_eq!(map.route(Some(never_a_domain), DEFAULT), Route::Default);
        }
        map.replace(vec![]);
        assert!(map.is_loaded() && map.is_empty());
        assert_eq!(map.route(Some(b"go.example.com"), DEFAULT), Route::Default);
        let ci = DomainSettings {
            case_insensitive: true,
            ..DomainSettings::default()
        };
        map.replace(vec![
            verified("go.example.com", 7, ci.clone()),
            verified("x.example.org", 9, DomainSettings::default()),
        ]);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.route(Some(b"Go.Example.com:8443"), DEFAULT),
            Route::Domain(Arc::new(Site {
                id: 7,
                settings: ci
            }))
        );
        assert_eq!(
            map.route(Some(b"x.example.org."), DEFAULT),
            Route::Domain(Arc::new(Site {
                id: 9,
                settings: DomainSettings::default()
            }))
        );
        // Unknown hosts get the default domain, as before custom domains.
        assert_eq!(
            map.route(Some(b"other.example.com"), DEFAULT),
            Route::Default
        );
        assert_eq!(map.route(Some(b"127.0.0.1:8080"), DEFAULT), Route::Default);
        // A reload drops what is no longer verified.
        map.replace(vec![verified(
            "x.example.org",
            9,
            DomainSettings::default(),
        )]);
        assert_eq!(map.get("go.example.com"), None);
        assert_eq!(map.route(Some(b"go.example.com"), DEFAULT), Route::Default);
        // Many domains spread over the shards and are all found.
        let many: Vec<VerifiedDomain> = (0..500)
            .map(|i| verified(&format!("d{i}.example.com"), i, DomainSettings::default()))
            .collect();
        map.replace(many.clone());
        for d in many {
            assert_eq!(map.get(&d.hostname).map(|s| s.id), Some(d.id));
        }
    }

    fn verified(hostname: &str, id: i64, settings: DomainSettings) -> VerifiedDomain {
        VerifiedDomain {
            hostname: hostname.into(),
            id,
            settings,
        }
    }

    #[test]
    fn patches_change_only_the_fields_they_name() {
        let current = DomainSettings {
            root_url: Some("https://a.example/".into()),
            not_found_page: Some("nf".into()),
            gone_page: Some("g".into()),
            prefixes: vec!["p".into()],
            case_insensitive: true,
            apps: Default::default(),
        };
        let patch: UpdateDomain = serde_json::from_str(r#"{"root_url":null}"#).unwrap();
        let s = patch.apply(&current);
        assert_eq!(s.root_url, None);
        assert_eq!(s.not_found_page.as_deref(), Some("nf"));
        assert!(s.case_insensitive);
        let patch: UpdateDomain = serde_json::from_str(
            r#"{"not_found_page":"x","gone_page":null,"prefixes":[],"case_insensitive":false}"#,
        )
        .unwrap();
        let s = patch.apply(&current);
        assert_eq!(s.root_url.as_deref(), Some("https://a.example/"));
        assert_eq!(s.not_found_page.as_deref(), Some("x"));
        assert_eq!(
            (s.gone_page, s.prefixes.len(), s.case_insensitive),
            (None, 0, false)
        );
        assert_eq!(UpdateDomain::default().apply(&current), current);
        assert!(serde_json::from_str::<UpdateDomain>(r#"{"x":1}"#).is_err());
    }

    #[test]
    fn audit_state_shows_settings_once_set() {
        let mut d = Domain {
            id: 1,
            hostname: "go.example.com".into(),
            verification_token: "0".repeat(32),
            created_by: "a".into(),
            created_at: Utc::now(),
            verified_at: None,
            checked_at: None,
            check_error: None,
            tls: TlsState::default(),
            settings: DomainSettings::default(),
        };
        assert!(domain_state(&d).get("settings").is_none());
        d.settings.prefixes = vec!["p".into()];
        assert_eq!(domain_state(&d)["settings"], json!({"prefixes": ["p"]}));
        let view = serde_json::to_value(DomainView::from(&d)).unwrap();
        assert_eq!(view["settings"]["prefixes"], json!(["p"]));
        assert_eq!(view["settings"]["root_url"], Value::Null);
    }

    #[test]
    fn records_prove_the_token_or_say_why_not() {
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            challenge_name("go.example.com"),
            "_relink-challenge.go.example.com"
        );
        let good = expected_record(token);
        assert_eq!(check_records(std::slice::from_ref(&good), token), Ok(()));
        assert_eq!(
            check_records(&["v=spf1 -all".into(), format!(" {good} ")], token),
            Ok(())
        );
        assert!(
            check_records(&[], token)
                .unwrap_err()
                .contains("no TXT record")
        );
        assert!(
            check_records(&["v=spf1 -all".into()], token)
                .unwrap_err()
                .contains("none starting with relink-domain-verification=")
        );
        assert!(
            check_records(&[expected_record(&"f".repeat(32))], token)
                .unwrap_err()
                .contains("another token")
        );
        // A record that merely contains the token is not enough.
        assert!(check_records(&[format!("x{good}")], token).is_err());
        assert!(check_records(&[good.to_uppercase()], token).is_err());
        let t = generate_token();
        assert_eq!(t.len(), 32);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(t, generate_token());
    }

    #[test]
    fn views_and_states() {
        let d = Domain {
            id: 3,
            hostname: "go.example.com".into(),
            verification_token: "ab".repeat(16),
            created_by: "alice".into(),
            created_at: Utc::now(),
            verified_at: None,
            checked_at: None,
            check_error: Some("no TXT record found".into()),
            tls: TlsState::default(),
            settings: DomainSettings::default(),
        };
        let v = serde_json::to_value(DomainView::from(&d)).unwrap();
        assert_eq!(v["verified"], false);
        assert_eq!(
            v["certificate"],
            Value::Null,
            "only verified domains have one"
        );
        assert_eq!(v["verification"]["type"], "TXT");
        assert_eq!(
            v["verification"]["name"],
            "_relink-challenge.go.example.com"
        );
        assert_eq!(
            v["verification"]["value"],
            format!("relink-domain-verification={}", "ab".repeat(16))
        );
        assert_eq!(
            domain_state(&d),
            json!({"id": 3, "hostname": "go.example.com", "verified_at": null})
        );
        // A verified domain's certificate, through its states.
        let at: DateTime<Utc> = "2026-11-09T00:00:00Z".parse().unwrap();
        let mut d = Domain {
            verified_at: Some(at),
            ..d
        };
        let cert =
            |d: &Domain| serde_json::to_value(DomainView::from(d)).unwrap()["certificate"].clone();
        assert_eq!(cert(&d)["status"], "pending");
        d.tls.next_attempt_at = Some(at);
        assert_eq!(
            cert(&d)["next_attempt_at"],
            Value::Null,
            "a lease, not a retry"
        );
        d.tls.error = Some("validation failed: connection refused".into());
        d.tls.failures = 1;
        assert_eq!(cert(&d)["status"], "failed");
        assert_eq!(cert(&d)["next_attempt_at"], json!(at));
        d.tls.not_after = Some(at);
        d.tls.renew_at = Some(at);
        assert_eq!(cert(&d)["status"], "issued");
        assert_eq!(cert(&d)["not_after"], json!(at));
        assert_eq!(clip("é".repeat(200)).len(), 300);
        assert_eq!(clip("x".repeat(10)), "x".repeat(10));
        assert_eq!(path_hostname("Go.Example.com."), "go.example.com");
    }
}

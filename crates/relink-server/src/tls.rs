//! Terminating TLS for custom domains (docs/DESIGN.md, "Terminating TLS").
//!
//! Three pieces. [`Sealer`] encrypts private keys before they reach
//! Postgres, with AES-256-GCM under `RELINK_KEY_ENCRYPTION_KEY`, bound to
//! the row they belong to. [`CertStore`] holds every verified domain's
//! certificate in memory and picks one by SNI during the handshake; it is
//! reloaded on the `certificates` change notification, so a renewal on any
//! instance is served by every instance without a restart, and only the
//! certificates that changed are read and parsed again. [`TlsListener`]
//! accepts TCP connections and runs handshakes concurrently, each under a
//! timeout and a cap on how many are in flight, handing finished
//! connections to axum like a plain listener would.
//!
//! The cryptography is rustls on the aws-lc-rs provider, both already in
//! the tree through reqwest.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sqlx::Row;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::der;
use crate::metrics::{DbOp, Metrics};
use crate::server::App;
use crate::store::{Db, DbError};

/// The change notification payload sent when a certificate is stored.
pub const CERTIFICATES_CHANGED: &str = "certificates";

/// The first bytes of every sealed key: "rlk" and the format version.
/// Migration 0012 refuses any stored key that does not start with them.
pub const SEAL_MAGIC: [u8; 4] = *b"rlk\x01";
const TAG_LEN: usize = 16;

/// Handshakes in progress at once; further connections wait in the
/// kernel's accept queue.
const MAX_HANDSHAKES: usize = 1_024;
/// Finished handshakes waiting for the HTTP server to take them.
const ACCEPTED_QUEUE: usize = 64;

// ---------------------------------------------------------------------------
// Keys at rest

/// Encrypts and decrypts private keys for storage. The key never leaves
/// the process and is never printed.
pub struct Sealer {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sealer(<redacted>)")
    }
}

/// A sealed key that does not open: another encryption key, another row,
/// or altered bytes. AES-GCM cannot tell these apart, by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealError;

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the stored key does not open with RELINK_KEY_ENCRYPTION_KEY \
             (another key, another row, or altered)",
        )
    }
}

impl std::error::Error for SealError {}

impl Sealer {
    pub fn new(key: &[u8; 32]) -> Sealer {
        Sealer {
            key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("32-byte key")),
            rng: SystemRandom::new(),
        }
    }

    /// `plaintext` encrypted and authenticated together with `context`,
    /// which must be given again to open it. A random 96-bit nonce per
    /// key: relink seals a few keys a day, far from the 2³² messages a
    /// random nonce allows under one key.
    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).expect("the OS random source");
        let mut out = Vec::with_capacity(SEAL_MAGIC.len() + NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&SEAL_MAGIC);
        out.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context),
                &mut body,
            )
            .expect("keys are far below the AES-GCM length limit");
        out.extend_from_slice(&body);
        out
    }

    /// The plaintext of a [`Sealer::seal`] result with the same context.
    pub fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, SealError> {
        let rest = sealed.strip_prefix(&SEAL_MAGIC[..]).ok_or(SealError)?;
        if rest.len() < NONCE_LEN + TAG_LEN {
            return Err(SealError);
        }
        let (nonce, body) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError)?;
        let mut buf = body.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(context), &mut buf)
            .map_err(|_| SealError)?;
        Ok(plain.to_vec())
    }
}

/// The associated data for a domain's certificate key: a key sealed for
/// one domain does not open as another's.
pub fn certificate_context(domain_id: i64) -> Vec<u8> {
    let mut c = b"relink certificate key\0".to_vec();
    c.extend_from_slice(&domain_id.to_be_bytes());
    c
}

/// The associated data for an ACME account key.
pub fn account_context(directory_url: &str) -> Vec<u8> {
    let mut c = b"relink acme account key\0".to_vec();
    c.extend_from_slice(directory_url.as_bytes());
    c
}

// ---------------------------------------------------------------------------
// Certificates by SNI

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A chain and its key, ready to serve. The key must be the one the leaf
/// certifies.
fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'_>,
) -> Result<Arc<CertifiedKey>, String> {
    if chain.is_empty() {
        return Err("no certificate in the chain".into());
    }
    let signing = provider()
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| format!("unusable private key: {e}"))?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match()
        .map_err(|e| format!("the key is not the one the certificate certifies: {e}"))?;
    Ok(Arc::new(ck))
}

/// A stored certificate: the chain as PEM (leaf first) and the PKCS#8 key.
pub fn certified_key(chain_pem: &str, pkcs8: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let chain = der::pem_decode_all(chain_pem, "CERTIFICATE")
        .ok_or("the certificate chain is not valid PEM")?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    certified(
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
    )
}

/// The default certificate from PEM files: a chain, and a key in PKCS#8,
/// PKCS#1 or SEC1 form.
pub fn certified_key_from_files(
    cert: &PathBuf,
    key: &PathBuf,
) -> Result<Arc<CertifiedKey>, String> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    certified(chain, key)
}

#[derive(Clone)]
struct Served {
    domain_id: i64,
    issued_at: DateTime<Utc>,
    key: Arc<CertifiedKey>,
}

/// What [`CertStore::plan`] says to do: which certificates to read again.
#[derive(Debug, PartialEq, Eq)]
pub struct Stored {
    pub domain_id: i64,
    pub hostname: String,
    pub issued_at: DateTime<Utc>,
}

/// A certificate read back from the database, opened and parsed.
pub struct Fresh {
    pub domain_id: i64,
    pub issued_at: DateTime<Utc>,
    pub key: Arc<CertifiedKey>,
}

/// Certificates by hostname, chosen by SNI; and the default certificate,
/// for the server's own host, clients without SNI and hosts without one.
#[derive(Default)]
pub struct CertStore {
    hosts: RwLock<HashMap<String, Served>>,
    fallback: RwLock<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("hosts", &self.len())
            .finish_non_exhaustive()
    }
}

impl CertStore {
    pub fn len(&self) -> usize {
        self.hosts.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn set_fallback(&self, key: Option<Arc<CertifiedKey>>) {
        *self.fallback.write().unwrap_or_else(|e| e.into_inner()) = key;
    }

    /// The certificate for `sni` (any case, with or without the final
    /// dot), or the default one.
    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            let hosts = self.hosts.read().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = hosts.get(&name) {
                return Some(s.key.clone());
            }
        }
        self.fallback
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The domains whose stored certificate is not the one in memory.
    pub fn stale(&self, stored: &[Stored]) -> Vec<i64> {
        let hosts = self.hosts.read().unwrap_or_else(|e| e.into_inner());
        stored
            .iter()
            .filter(|s| {
                hosts
                    .get(&s.hostname)
                    .is_none_or(|h| h.domain_id != s.domain_id || h.issued_at != s.issued_at)
            })
            .map(|s| s.domain_id)
            .collect()
    }

    /// Replaces the map: every stored domain gets its fresh certificate,
    /// or keeps the one in memory when the new one could not be loaded (a
    /// bad renewal does not take a working certificate away). Domains no
    /// longer stored are dropped. Returns how many were swapped in.
    pub fn apply(&self, stored: Vec<Stored>, fresh: Vec<Fresh>) -> usize {
        let mut fresh: HashMap<i64, Fresh> = fresh.into_iter().map(|f| (f.domain_id, f)).collect();
        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        let mut next = HashMap::with_capacity(stored.len());
        let mut swapped = 0;
        for s in stored {
            let served = match fresh.remove(&s.domain_id) {
                Some(f) => {
                    swapped += 1;
                    Served {
                        domain_id: f.domain_id,
                        issued_at: f.issued_at,
                        key: f.key,
                    }
                }
                None => match hosts.remove(&s.hostname) {
                    Some(old) if old.domain_id == s.domain_id => old,
                    _ => continue,
                },
            };
            next.insert(s.hostname, served);
        }
        *hosts = next;
        swapped
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(hello.server_name())
    }
}

/// The rustls configuration: TLS 1.2 and 1.3, HTTP/1.1, certificates
/// from `store`.
pub fn server_config(store: Arc<CertStore>) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("the provider supports the default versions")
        .with_no_client_auth()
        .with_cert_resolver(store);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// TLS settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    pub addr: SocketAddr,
    /// The default certificate and its key, PEM; re-read every minute.
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// How long a client may take to finish its handshake.
    pub handshake_timeout: Duration,
}

/// The TLS state of a running server.
pub struct Tls {
    pub store: Arc<CertStore>,
    pub config: TlsConfig,
    /// One reload at a time, so an older read never replaces a newer one.
    reload: tokio::sync::Mutex<()>,
}

impl Tls {
    pub fn new(config: TlsConfig) -> Tls {
        Tls {
            store: Arc::new(CertStore::default()),
            config,
            reload: tokio::sync::Mutex::new(()),
        }
    }

    /// Reads the default certificate files again. On failure the one in
    /// memory stays.
    pub fn reload_files(&self) -> Result<(), String> {
        if let (Some(cert), Some(key)) = (&self.config.cert_file, &self.config.key_file) {
            self.store
                .set_fallback(Some(certified_key_from_files(cert, key)?));
        }
        Ok(())
    }
}

impl Db {
    /// Every verified domain's certificate, without the certificate: what
    /// [`CertStore::stale`] compares.
    pub async fn stored_certificates(&self) -> Result<Vec<Stored>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "SELECT d.id, d.hostname, c.issued_at
                       FROM domain_certificates c JOIN domains d ON d.id = c.domain_id
                      WHERE d.verified_at IS NOT NULL",
                )
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(Stored {
                    domain_id: r.try_get("id")?,
                    hostname: r.try_get("hostname")?,
                    issued_at: r.try_get("issued_at")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// The certificates of these domains: (domain, chain PEM, sealed key,
    /// issued at).
    pub async fn certificates_of(
        &self,
        domain_ids: &[i64],
    ) -> Result<Vec<(i64, String, Vec<u8>, DateTime<Utc>)>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "SELECT domain_id, chain_pem, key_sealed, issued_at
                       FROM domain_certificates WHERE domain_id = ANY($1)",
                )
                .bind(domain_ids)
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("domain_id")?,
                    r.try_get("chain_pem")?,
                    r.try_get("key_sealed")?,
                    r.try_get("issued_at")?,
                ))
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }
}

impl App {
    /// Brings the certificates in memory up to date with the database,
    /// reading only those that changed. A certificate that cannot be
    /// opened or parsed is logged and counted; the domain keeps the one it
    /// had. Without a TLS listener or a key encryption key, nothing to do.
    pub async fn reload_certificates(&self) -> Result<(), DbError> {
        let (Some(tls), Some(sealer)) = (&self.tls, &self.sealer) else {
            return Ok(());
        };
        let _one = tls.reload.lock().await;
        let stored = self.db.stored_certificates().await?;
        let stale = tls.store.stale(&stored);
        let mut fresh = Vec::with_capacity(stale.len());
        if !stale.is_empty() {
            for (domain_id, chain, sealed, issued_at) in self.db.certificates_of(&stale).await? {
                let loaded = sealer
                    .open(&sealed, &certificate_context(domain_id))
                    .map_err(|e| e.to_string())
                    .and_then(|pkcs8| certified_key(&chain, &pkcs8));
                match loaded {
                    Ok(key) => fresh.push(Fresh {
                        domain_id,
                        issued_at,
                        key,
                    }),
                    Err(e) => {
                        self.metrics.tls_certificate_errors.inc();
                        tracing::error!(domain = domain_id, error = %e, "cannot serve the stored certificate");
                    }
                }
            }
        }
        let swapped = tls.store.apply(stored, fresh);
        if swapped > 0 {
            tracing::info!(swapped, serving = tls.store.len(), "certificates loaded");
        }
        Ok(())
    }
}

/// Reloads the certificates in the background (from the change listener,
/// which must not wait on a query).
pub fn spawn_reload(app: Arc<App>) {
    if app.tls.is_none() {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = app.reload_certificates().await {
            app.metrics.db_error(DbOp::Maintenance);
            tracing::warn!(error = %e, "could not reload certificates");
        }
    });
}

// ---------------------------------------------------------------------------
// The listener

/// A listener whose connections have finished a TLS handshake. Handshakes
/// run in their own tasks, so a slow client holds up nobody else; each
/// has [`TlsConfig::handshake_timeout`] to finish, and at most
/// [`MAX_HANDSHAKES`] run at once. Dropping the listener closes the socket.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: JoinHandle<()>,
}

impl TlsListener {
    pub fn new(
        tcp: TcpListener,
        config: Arc<ServerConfig>,
        handshake_timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> io::Result<TlsListener> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(ACCEPTED_QUEUE);
        let task = tokio::spawn(accept_loop(
            tcp,
            TlsAcceptor::from(config),
            handshake_timeout,
            tx,
            metrics,
        ));
        Ok(TlsListener { rx, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn accept_loop(
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    timeout: Duration,
    tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
    metrics: Arc<Metrics>,
) {
    let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = match tcp.accept().await {
            Ok(c) => c,
            Err(e) => {
                // As axum does: errors about one connection are that
                // connection's; anything else (out of descriptors) is
                // waited out.
                if !is_connection_error(&e) {
                    tracing::error!(error = %e, "TLS accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        let tx = tx.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    metrics.tls_handshakes.inc();
                    // Fails only once the server stopped accepting.
                    let _ = tx.send((tls, peer)).await;
                }
                Ok(Err(e)) => {
                    metrics.tls_handshake_failures.inc();
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                }
                Err(_) => {
                    metrics.tls_handshake_failures.inc();
                    tracing::debug!(%peer, "TLS handshake timed out");
                }
            }
        });
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept loop ended: nothing more will come.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

    fn sealer() -> Sealer {
        Sealer::new(&[7; 32])
    }

    #[test]
    fn sealed_keys_open_only_with_their_key_and_row() {
        let s = sealer();
        let ctx = certificate_context(42);
        let sealed = s.seal(b"secret pkcs8", &ctx);
        assert!(sealed.starts_with(&SEAL_MAGIC));
        assert_eq!(sealed.len(), 4 + 12 + 12 + 16);
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(s.open(&sealed, &ctx).unwrap(), b"secret pkcs8");
        // Two seals of one key differ (fresh nonce) and both open.
        let again = s.seal(b"secret pkcs8", &ctx);
        assert_ne!(again, sealed);
        assert_eq!(s.open(&again, &ctx).unwrap(), b"secret pkcs8");

        // Another row, another key, altered bytes, truncation, no header.
        assert_eq!(s.open(&sealed, &certificate_context(43)), Err(SealError));
        assert_eq!(
            s.open(&sealed, &account_context("https://ca/dir")),
            Err(SealError)
        );
        assert_eq!(Sealer::new(&[8; 32]).open(&sealed, &ctx), Err(SealError));
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(s.open(&bad, &ctx), Err(SealError), "byte {i}");
        }
        assert_eq!(s.open(&sealed[..31], &ctx), Err(SealError));
        assert_eq!(s.open(b"0\x82\x01\x00plain", &ctx), Err(SealError));
        assert_eq!(s.open(&[], &ctx), Err(SealError));
        assert!(SealError.to_string().contains("RELINK_KEY_ENCRYPTION_KEY"));
        assert_eq!(format!("{s:?}"), "Sealer(<redacted>)");
    }

    #[test]
    fn contexts_never_collide() {
        assert_ne!(certificate_context(1), certificate_context(256));
        assert_ne!(account_context("a"), account_context("b"));
        assert_ne!(&certificate_context(0)[..], &account_context("")[..]);
    }

    /// A served certificate whose chain is a marker: the store never looks
    /// inside it.
    fn key(marker: u8) -> Arc<CertifiedKey> {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let signing = provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(pkcs8.as_ref().to_vec().into()))
            .unwrap();
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(vec![marker])],
            signing,
        ))
    }

    fn marker(k: &Arc<CertifiedKey>) -> u8 {
        k.cert[0].as_ref()[0]
    }

    fn at(s: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + s, 0).unwrap()
    }

    fn stored(id: i64, host: &str, t: i64) -> Stored {
        Stored {
            domain_id: id,
            hostname: host.into(),
            issued_at: at(t),
        }
    }

    fn fresh(id: i64, t: i64, m: u8) -> Fresh {
        Fresh {
            domain_id: id,
            issued_at: at(t),
            key: key(m),
        }
    }

    #[test]
    fn sni_picks_the_domain_or_falls_back() {
        let store = CertStore::default();
        assert!(store.lookup(Some("go.example.com")).is_none());
        assert!(store.lookup(None).is_none());
        assert_eq!(
            store.apply(vec![stored(1, "go.example.com", 0)], vec![fresh(1, 0, 1)]),
            1
        );
        for sni in ["go.example.com", "GO.Example.COM", "go.example.com."] {
            assert_eq!(marker(&store.lookup(Some(sni)).unwrap()), 1, "{sni}");
        }
        assert!(store.lookup(Some("other.example.com")).is_none());
        store.set_fallback(Some(key(9)));
        assert_eq!(marker(&store.lookup(Some("other.example.com")).unwrap()), 9);
        assert_eq!(marker(&store.lookup(None).unwrap()), 9);
        assert_eq!(marker(&store.lookup(Some("go.example.com")).unwrap()), 1);
        store.set_fallback(None);
        assert!(store.lookup(None).is_none());
        assert_eq!(format!("{store:?}"), "CertStore { hosts: 1, .. }");
    }

    #[test]
    fn only_changed_certificates_are_read_again_and_swapped() {
        let store = CertStore::default();
        assert!(store.is_empty());
        let first = vec![stored(1, "a.example.com", 0), stored(2, "b.example.com", 0)];
        assert_eq!(store.stale(&first), [1, 2]);
        store.apply(first, vec![fresh(1, 0, 1), fresh(2, 0, 2)]);
        assert_eq!(store.len(), 2);

        // Nothing changed: nothing to read.
        let same = vec![stored(1, "a.example.com", 0), stored(2, "b.example.com", 0)];
        assert!(store.stale(&same).is_empty());
        assert_eq!(store.apply(same, vec![]), 0);
        assert_eq!(marker(&store.lookup(Some("a.example.com")).unwrap()), 1);

        // b renewed; a deleted; c added. Only b and c are read.
        let next = vec![
            stored(2, "b.example.com", 60),
            stored(3, "c.example.com", 0),
        ];
        assert_eq!(store.stale(&next), [2, 3]);
        assert_eq!(store.apply(next, vec![fresh(2, 60, 20), fresh(3, 0, 3)]), 2);
        assert!(store.lookup(Some("a.example.com")).is_none());
        assert_eq!(marker(&store.lookup(Some("b.example.com")).unwrap()), 20);
        assert_eq!(marker(&store.lookup(Some("c.example.com")).unwrap()), 3);

        // A renewal that cannot be loaded keeps the working certificate,
        // and is tried again next time.
        let broken = vec![
            stored(2, "b.example.com", 120),
            stored(3, "c.example.com", 0),
        ];
        assert_eq!(store.stale(&broken), [2]);
        assert_eq!(store.apply(broken, vec![]), 0);
        assert_eq!(marker(&store.lookup(Some("b.example.com")).unwrap()), 20);
        assert_eq!(store.stale(&[stored(2, "b.example.com", 120)]), [2]);

        // The hostname moved to another workspace's domain: the old
        // certificate is not served for it, even if the new one is broken.
        let moved = vec![stored(4, "c.example.com", 0)];
        assert_eq!(store.stale(&moved), [4]);
        store.apply(moved, vec![]);
        assert!(store.lookup(Some("c.example.com")).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn stored_certificates_must_match_their_key() {
        assert!(certified_key("not pem", &[1, 2, 3]).is_err());
        assert_eq!(
            certified_key("", &[1]).unwrap_err(),
            "no certificate in the chain"
        );
        let pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        assert!(
            certified_key(pem, &[1, 2, 3])
                .unwrap_err()
                .contains("unusable private key")
        );
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        // Not a certificate at all, so it cannot certify the key.
        assert!(
            certified_key(pem, pkcs8.as_ref())
                .unwrap_err()
                .contains("not the one")
        );
        let missing = PathBuf::from("/nonexistent/relink.pem");
        assert!(
            certified_key_from_files(&missing, &missing)
                .unwrap_err()
                .contains("/nonexistent")
        );
    }

    #[test]
    fn the_server_speaks_http1_over_tls12_and_13() {
        let cfg = server_config(Arc::new(CertStore::default()));
        assert_eq!(cfg.alpn_protocols, [b"http/1.1".to_vec()]);
        assert!(is_connection_error(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
        assert!(!is_connection_error(&io::Error::other(
            "too many open files"
        )));
    }
}

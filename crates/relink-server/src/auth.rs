//! API keys: generation, hashing and request authentication.
//!
//! Keys are `rlk_` followed by 64 hex characters (256 random bits). Only the
//! SHA-256 of a key is stored. A fast hash is appropriate here, unlike for
//! passwords, because the input has full entropy: there is nothing to
//! brute-force. Lookups go through the unique index on the hash, and the
//! stored hash is then compared in constant time.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::cache::{Cache, Config as CacheConfig, Lookup};
use crate::ratelimit::{KeyedLimiter, Rate};
use crate::store::{Db, DbError};
use crate::util::{hex_encode, secure_random};

pub const KEY_PREFIX: &str = "rlk_";
const KEY_HEX_LEN: usize = 64;

/// The caller behind a valid key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub key_id: i64,
    pub owner: String,
}

/// Why authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Missing, malformed, unknown or revoked key.
    Unauthenticated,
    /// The key could not be checked because the database is unavailable.
    Unavailable,
    /// Too many uncached keys are being checked; try again shortly.
    Busy,
}

/// Generates a new key from the OS CSPRNG.
pub fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    secure_random(&mut bytes);
    format!("{KEY_PREFIX}{}", hex_encode(&bytes))
}

pub fn hash_key(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// Shape check before any database work: right prefix, 64 lowercase hex.
pub fn is_well_formed(key: &str) -> bool {
    key.strip_prefix(KEY_PREFIX).is_some_and(|hex| {
        hex.len() == KEY_HEX_LEN && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Owner names: lowercase, 1 to 63 characters of `[a-z0-9._-]`, starting
/// with a letter or digit. Mirrors the database constraint.
pub fn is_valid_owner(owner: &str) -> bool {
    let b = owner.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// How long a key check is remembered. Revoking a key takes effect within
/// this window on every instance.
pub const AUTH_CACHE_TTL: Duration = Duration::from_secs(30);

/// How long "no such key" is remembered. Short, so a key created on another
/// instance works here within seconds.
pub const UNKNOWN_KEY_TTL: Duration = Duration::from_secs(5);

/// Authenticates bearer keys against the database, with a short cache of
/// results (positive and negative) keyed by the key's hash.
pub struct Authenticator {
    db: Db,
    known: Cache<Arc<Principal>>,
    /// Hashes the database said are unknown or revoked. Separate from
    /// `known` so a flood of made-up keys cannot evict real ones.
    unknown: Cache<()>,
    per_ip: KeyedLimiter<IpAddr>,
    global: KeyedLimiter<()>,
}

/// Limits on database lookups for keys that are not cached.
#[derive(Clone, Copy, Debug)]
pub struct LookupLimits {
    /// Per client address, so one client cannot use up the global budget.
    pub per_ip: Rate,
    /// Across all clients: the most queries invalid keys can cause.
    pub global: f64,
}

impl Authenticator {
    pub fn new(db: Db, capacity: usize, limits: LookupLimits) -> Authenticator {
        let cache = |ttl| CacheConfig {
            capacity,
            ttl,
            negative_ttl: ttl,
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
        };
        Authenticator {
            db,
            known: Cache::new(cache(AUTH_CACHE_TTL)),
            unknown: Cache::new(cache(UNKNOWN_KEY_TTL)),
            per_ip: KeyedLimiter::new(limits.per_ip, 100_000),
            global: KeyedLimiter::new(
                Rate {
                    per_second: limits.global,
                    burst: limits.global.max(1.0),
                },
                1,
            ),
        }
    }

    /// Checks an `Authorization` header value (`Bearer <key>`) sent by `client`.
    pub async fn authenticate(
        &self,
        header: Option<&[u8]>,
        client: IpAddr,
    ) -> Result<Principal, AuthError> {
        let header = header
            .and_then(|h| std::str::from_utf8(h).ok())
            .ok_or(AuthError::Unauthenticated)?;
        let key = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .map(str::trim)
            .ok_or(AuthError::Unauthenticated)?;
        if !is_well_formed(key) {
            return Err(AuthError::Unauthenticated);
        }
        let hash = hash_key(key);
        let cache_key = hex_encode(&hash);
        let now = Instant::now();
        if let Lookup::Found(Some(p), _) = self.known.get(&cache_key, now) {
            return Ok((*p).clone());
        }
        if let Lookup::Found(..) = self.unknown.get(&cache_key, now) {
            return Err(AuthError::Unauthenticated);
        }
        if self.per_ip.check(&client, now).is_err() || self.global.check(&(), now).is_err() {
            return Err(AuthError::Busy);
        }
        let token = self.known.begin_load();
        let found = match self.db.api_key_by_hash(&hash).await {
            Ok(found) => found,
            Err(DbError::Unavailable(_)) => return Err(AuthError::Unavailable),
            Err(e) => {
                tracing::error!(error = %e, "API key lookup failed");
                return Err(AuthError::Unavailable);
            }
        };
        let principal = found.and_then(|(key_id, owner, stored)| {
            bool::from(stored.as_slice().ct_eq(&hash)).then_some(Principal { key_id, owner })
        });
        match &principal {
            Some(p) => {
                self.known
                    .insert(&cache_key, Some(Arc::new(p.clone())), Instant::now(), token)
            }
            None => {
                let token = self.unknown.begin_load();
                self.unknown
                    .insert(&cache_key, Some(()), Instant::now(), token)
            }
        }
        principal.ok_or(AuthError::Unauthenticated)
    }

    /// Drops idle per-address buckets.
    pub fn sweep(&self, now: Instant) {
        self.per_ip.sweep(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let k = generate_key();
        assert!(is_well_formed(&k));
        assert_ne!(k, generate_key());
        assert_eq!(hash_key(&k), hash_key(&k));
        assert!(!is_well_formed("rlk_short"));
        assert!(!is_well_formed(&k.to_uppercase()));
        assert!(!is_well_formed(&k.replace("rlk_", "xxx_")));
        assert!(!is_well_formed(&format!("{k}0")));
    }

    #[test]
    fn owners() {
        for ok in ["alice", "acme-corp", "a", "team.ops_1"] {
            assert!(is_valid_owner(ok), "{ok}");
        }
        for bad in ["", "Alice", "-x", ".x", "a b", "ä", &"a".repeat(64)] {
            assert!(!is_valid_owner(bad), "{bad}");
        }
    }
}

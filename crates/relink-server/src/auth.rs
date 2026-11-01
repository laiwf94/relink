//! API keys: generation, hashing and request authentication.
//!
//! Keys are `rlk_` followed by 64 hex characters (256 random bits). Only the
//! SHA-256 of a key is stored. A fast hash is appropriate here, unlike for
//! passwords, because the input has full entropy: there is nothing to
//! brute-force. Lookups go through the unique index on the hash, and the
//! stored hash is then compared in constant time.
//!
//! What a key may do is the intersection of two things: the scopes the key
//! carries ([`Scope`]) and the rights of its owner's role in the key's
//! workspace ([`Role`]). The role is read with the key, so demoting a member
//! narrows every key they hold, and removing them disables those keys, within
//! [`AUTH_CACHE_TTL`]. A key may also expire; rotation creates a successor
//! and shortens the old key's life to an overlap window, so deployments can
//! switch over without a moment where neither key works.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::cache::{Cache, Config as CacheConfig, Lookup};
use crate::ratelimit::{KeyedLimiter, Rate};
use crate::store::{Db, DbError};
use crate::util::{hex_encode, secure_random};

pub const KEY_PREFIX: &str = "rlk_";
const KEY_HEX_LEN: usize = 64;

/// One permission an API key can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Read links: list and get.
    LinksRead,
    /// Create, change and delete links.
    LinksWrite,
    /// Read link statistics.
    StatsRead,
}

impl Scope {
    pub const ALL: [Scope; 3] = [Scope::LinksRead, Scope::LinksWrite, Scope::StatsRead];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::LinksRead => "links:read",
            Scope::LinksWrite => "links:write",
            Scope::StatsRead => "stats:read",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|sc| sc.as_str() == s)
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of scopes, as a bit set.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Scopes(u8);

impl Scopes {
    pub const NONE: Scopes = Scopes(0);
    pub const ALL: Scopes =
        Scopes(Scope::LinksRead.bit() | Scope::LinksWrite.bit() | Scope::StatsRead.bit());

    pub fn contains(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }

    pub fn is_subset(self, other: Scopes) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn intersect(self, other: Scopes) -> Scopes {
        Scopes(self.0 & other.0)
    }

    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |&s| self.contains(s))
    }

    /// The scope names, in a fixed order, as stored in `api_keys.scopes`.
    pub fn names(self) -> Vec<&'static str> {
        self.iter().map(Scope::as_str).collect()
    }

    /// From stored names. An unknown name is an error rather than ignored:
    /// the database constraint forbids it, so it means a newer schema.
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Result<Scopes, String> {
        names.iter().try_fold(Scopes::NONE, |acc, n| {
            Scope::parse(n.as_ref())
                .map(|s| acc | s)
                .ok_or_else(|| format!("unknown scope {:?}", n.as_ref()))
        })
    }

    /// A comma-separated list such as `links:read,stats:read`, as typed on
    /// the command line. Empty entries, unknown names and an empty set are
    /// refused.
    pub fn parse_list(list: &str) -> Result<Scopes, String> {
        let mut set = Scopes::NONE;
        for name in list.split(',').map(str::trim) {
            let s = Scope::parse(name).ok_or_else(|| {
                format!(
                    "unknown scope {name:?}; expected some of {}",
                    Scopes::ALL.names().join(", ")
                )
            })?;
            set = set | s;
        }
        if set.is_empty() {
            return Err("at least one scope is required".into());
        }
        Ok(set)
    }
}

impl std::ops::BitOr<Scope> for Scopes {
    type Output = Scopes;
    fn bitor(self, s: Scope) -> Scopes {
        Scopes(self.0 | s.bit())
    }
}

impl From<Scope> for Scopes {
    fn from(s: Scope) -> Scopes {
        Scopes(s.bit())
    }
}

impl fmt::Debug for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.iter().map(Scope::as_str))
            .finish()
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.names().join(","))
    }
}

/// A member's role in a workspace, from least to most privileged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Reads links and statistics.
    Viewer,
    /// Also creates, changes and deletes links.
    Editor,
    /// Also manages members below admin and their keys.
    Admin,
    /// Everything, including other admins and owners.
    Owner,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Viewer, Role::Editor, Role::Admin, Role::Owner];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The scopes a key held by someone with this role can use.
    pub fn grants(self) -> Scopes {
        match self {
            Role::Viewer => Scopes::from(Scope::LinksRead) | Scope::StatsRead,
            Role::Editor | Role::Admin | Role::Owner => Scopes::ALL,
        }
    }

    /// Whether this role may create, rotate and revoke keys for, and change
    /// the role of, a member whose role is `other`. Owners manage everyone;
    /// admins manage editors and viewers; nobody else manages anyone.
    pub fn manages(self, other: Role) -> bool {
        match self {
            Role::Owner => true,
            Role::Admin => other < Role::Admin,
            Role::Editor | Role::Viewer => false,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The caller behind a valid key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub key_id: i64,
    pub owner: String,
    /// The workspace the key belongs to; it acts only there.
    pub workspace_id: i64,
    /// The key owner's role in that workspace, read with the key.
    pub role: Role,
    /// The scopes the key carries.
    pub scopes: Scopes,
    /// When the key stops working, if ever.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why a principal may not do something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The key was not given the scope.
    KeyScope(Scope),
    /// The key has the scope but its owner's role does not grant it.
    Role(Scope, Role),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::KeyScope(s) => write!(f, "this API key does not have the {s} scope"),
            Denied::Role(s, r) => write!(
                f,
                "the {r} role does not grant {s}; ask a workspace admin for a higher role"
            ),
        }
    }
}

impl Principal {
    /// What the key can actually use: its scopes within its owner's role.
    pub fn effective(&self) -> Scopes {
        self.scopes.intersect(self.role.grants())
    }

    /// Ok if the key may use `scope`, else why not.
    pub fn require(&self, scope: Scope) -> Result<(), Denied> {
        if !self.scopes.contains(scope) {
            Err(Denied::KeyScope(scope))
        } else if !self.role.grants().contains(scope) {
            Err(Denied::Role(scope, self.role))
        } else {
            Ok(())
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|e| e <= now)
    }
}

/// Longest overlap a rotation may leave the old key alive for.
pub const MAX_ROTATION_OVERLAP: Duration = Duration::from_secs(30 * 86_400);

/// Overlap used when `rotate-key` is not given one.
pub const DEFAULT_ROTATION_OVERLAP: Duration = Duration::from_secs(86_400);

/// Longest lifetime a key may be created with (ten years); beyond that,
/// create a key without expiry.
pub const MAX_KEY_LIFETIME: Duration = Duration::from_secs(3_650 * 86_400);

/// Parses a duration such as `90d`, `12h`, `30m` or `45s`: a decimal count
/// and one unit. Used for key lifetimes and rotation overlaps.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let err = || format!("{s:?} is not a duration such as 90d, 12h, 30m or 45s");
    let split = s.len().checked_sub(1).ok_or_else(err)?;
    if !s.is_char_boundary(split) {
        return Err(err());
    }
    let (n, unit) = s.split_at(split);
    if n.is_empty() || n.len() > 10 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err());
    }
    let n: u64 = n.parse().map_err(|_| err())?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(err()),
    };
    Ok(Duration::from_secs(n * secs))
}

/// Why authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Missing, malformed, unknown, revoked or expired key, or one whose
    /// owner is no longer a member of its workspace.
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
            // Expiry is exact even for a cached key; revocation and role
            // changes take effect within the cache TTL.
            if p.is_expired(Utc::now()) {
                return Err(AuthError::Unauthenticated);
            }
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
        let principal = found.and_then(|k| {
            let matches = bool::from(k.hash.as_slice().ct_eq(&hash));
            // No role: the owner left the workspace, so the key is dead.
            let role = k.role?;
            (matches && !k.is_expired_at(Utc::now())).then_some(Principal {
                key_id: k.id,
                owner: k.owner,
                workspace_id: k.workspace_id,
                role,
                scopes: k.scopes,
                expires_at: k.expires_at,
            })
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

    fn principal(role: Role, scopes: Scopes) -> Principal {
        Principal {
            key_id: 1,
            owner: "alice".into(),
            workspace_id: 1,
            role,
            scopes,
            expires_at: None,
        }
    }

    #[test]
    fn scopes_parse_and_print() {
        assert_eq!(
            Scopes::parse_list("links:read"),
            Ok(Scope::LinksRead.into())
        );
        assert_eq!(
            Scopes::parse_list("stats:read, links:read,links:read"),
            Ok(Scopes::from(Scope::LinksRead) | Scope::StatsRead)
        );
        assert_eq!(
            Scopes::parse_list("links:read,links:write,stats:read"),
            Ok(Scopes::ALL)
        );
        for bad in ["", ",", "links:read,", "links:*", "LINKS:READ", "admin"] {
            assert!(Scopes::parse_list(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Scopes::ALL.to_string(), "links:read,links:write,stats:read");
        assert_eq!(Scopes::NONE.to_string(), "");
        assert_eq!(
            format!("{:?}", Scopes::from(Scope::StatsRead)),
            r#"{"stats:read"}"#
        );
        assert_eq!(
            Scopes::from_names(&["links:write"]),
            Ok(Scope::LinksWrite.into())
        );
        assert!(Scopes::from_names(&["links:write", "billing:read"]).is_err());
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
            assert_eq!(s.to_string(), s.as_str());
        }
        assert!(Scopes::NONE.is_subset(Scopes::ALL));
        assert!(!Scopes::ALL.is_subset(Scope::LinksRead.into()));
    }

    #[test]
    fn roles_are_ordered_and_grant_scopes() {
        assert!(Role::Viewer < Role::Editor && Role::Editor < Role::Admin);
        assert!(Role::Admin < Role::Owner);
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
            assert_eq!(r.to_string(), r.as_str());
        }
        assert_eq!(Role::parse("superuser"), None);
        assert!(!Role::Viewer.grants().contains(Scope::LinksWrite));
        assert!(Role::Viewer.grants().contains(Scope::LinksRead));
        assert!(Role::Viewer.grants().contains(Scope::StatsRead));
        for r in [Role::Editor, Role::Admin, Role::Owner] {
            assert_eq!(r.grants(), Scopes::ALL);
        }
        // Each role grants at least what every lower role does.
        for w in Role::ALL.windows(2) {
            assert!(w[0].grants().is_subset(w[1].grants()));
        }
    }

    #[test]
    fn who_manages_whom() {
        for other in Role::ALL {
            assert!(Role::Owner.manages(other));
            assert!(!Role::Editor.manages(other));
            assert!(!Role::Viewer.manages(other));
        }
        assert!(Role::Admin.manages(Role::Editor));
        assert!(Role::Admin.manages(Role::Viewer));
        assert!(!Role::Admin.manages(Role::Admin));
        assert!(!Role::Admin.manages(Role::Owner));
    }

    #[test]
    fn a_key_can_use_its_scopes_within_its_role() {
        let editor = principal(Role::Editor, Scopes::ALL);
        for s in Scope::ALL {
            assert_eq!(editor.require(s), Ok(()));
        }
        let read_only = principal(Role::Owner, Scopes::from(Scope::LinksRead));
        assert_eq!(read_only.require(Scope::LinksRead), Ok(()));
        assert_eq!(
            read_only.require(Scope::LinksWrite),
            Err(Denied::KeyScope(Scope::LinksWrite))
        );
        assert_eq!(
            read_only.require(Scope::StatsRead),
            Err(Denied::KeyScope(Scope::StatsRead))
        );
        // A viewer's all-scopes key (made before a demotion) cannot write.
        let viewer = principal(Role::Viewer, Scopes::ALL);
        assert_eq!(
            viewer.require(Scope::LinksWrite),
            Err(Denied::Role(Scope::LinksWrite, Role::Viewer))
        );
        assert_eq!(viewer.require(Scope::StatsRead), Ok(()));
        assert_eq!(viewer.effective(), Role::Viewer.grants());
        assert!(
            Denied::Role(Scope::LinksWrite, Role::Viewer)
                .to_string()
                .contains("viewer role does not grant links:write")
        );
        assert!(
            Denied::KeyScope(Scope::StatsRead)
                .to_string()
                .contains("does not have the stats:read scope")
        );
    }

    #[test]
    fn expiry() {
        let now = Utc::now();
        let mut p = principal(Role::Owner, Scopes::ALL);
        assert!(!p.is_expired(now));
        p.expires_at = Some(now + chrono::Duration::seconds(1));
        assert!(!p.is_expired(now));
        p.expires_at = Some(now);
        assert!(p.is_expired(now), "the expiry instant itself is expired");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1_800)));
        assert_eq!(parse_duration("12h"), Ok(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("90d"), Ok(Duration::from_secs(7_776_000)));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert_eq!(
            parse_duration("9999999999d"),
            Ok(Duration::from_secs(9_999_999_999 * 86_400))
        );
        for bad in [
            "",
            "d",
            "10",
            "10x",
            "-1d",
            "+1d",
            "1.5h",
            " 1d",
            "1d ",
            "1 d",
            "1dd",
            "10é",
            "é",
            "99999999999d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
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

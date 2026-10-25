//! A bounded, sharded, in-process cache with freshness states.
//!
//! Reads take a shard's read lock and set an atomic "referenced" bit, so
//! concurrent readers never block each other. Eviction is CLOCK (second
//! chance), an LRU approximation that needs no write on the read path
//! (Corbató). Keys are hashed with SipHash and a random key, so an
//! attacker choosing codes cannot force collisions.
//!
//! Each entry remembers when it was loaded. With `ttl` and the
//! stale-while-revalidate and stale-if-error windows (RFC 5861) an entry moves
//! through Fresh → Stale → Expired → unusable. An entry that may predate a
//! change (it raced an invalidation, or notifications may have been missed)
//! is Suspect instead. Entries store `None` for codes the database said do
//! not exist (negative caching), with a shorter TTL.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Freshness windows. All are measured from the moment an entry was loaded.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Total entries across all shards. Zero disables caching.
    pub capacity: usize,
    /// How long a positive entry is served without asking the database.
    pub ttl: Duration,
    /// How long a negative ("no such code") entry is served.
    pub negative_ttl: Duration,
    /// After the TTL, how long the entry is still served while one background
    /// refresh runs.
    pub stale_while_revalidate: Duration,
    /// After the TTL, how long the entry may be served when the database
    /// cannot be reached.
    pub stale_if_error: Duration,
}

/// How usable a cached entry is right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Serve it.
    Fresh,
    /// Serve it and refresh in the background.
    Stale,
    /// Refresh first; serve it only if the refresh fails.
    Expired,
    /// It may predate a change we were told about (or may have missed), for
    /// example a link being disabled. Wait for a reload; use it only if the
    /// database cannot answer.
    Suspect,
}

/// A cache lookup result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<V> {
    /// No usable entry.
    Miss,
    /// An entry; `None` means the code is known not to exist.
    Found(Option<V>, Freshness),
}

struct Slot<V> {
    key: Arc<str>,
    value: Option<V>,
    loaded: Instant,
    epoch: u64,
    raced: bool,
    referenced: AtomicBool,
}

struct Shard<V> {
    index: HashMap<Arc<str>, usize>,
    slots: Vec<Slot<V>>,
    hand: usize,
    capacity: usize,
}

/// The cache. `V` is cheap to clone (an `Arc` in practice).
pub struct Cache<V> {
    shards: Box<[RwLock<Shard<V>>]>,
    hasher: RandomState,
    cfg: Config,
    epoch: AtomicU64,
    invalidations: AtomicU64,
}

/// Taken before a load starts and handed to [`Cache::insert`], so that a load
/// which raced with an invalidation is never stored as fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadToken {
    epoch: u64,
    invalidations: u64,
}

const SHARDS: usize = 64;

impl<V: Clone> Cache<V> {
    pub fn new(cfg: Config) -> Self {
        let per_shard = cfg.capacity.div_ceil(SHARDS);
        let shards = (0..SHARDS)
            .map(|_| {
                RwLock::new(Shard {
                    index: HashMap::with_capacity(per_shard.min(4096)),
                    slots: Vec::with_capacity(per_shard.min(4096)),
                    hand: 0,
                    capacity: per_shard,
                })
            })
            .collect();
        Cache {
            shards,
            hasher: RandomState::new(),
            cfg,
            epoch: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn shard(&self, key: &str) -> &RwLock<Shard<V>> {
        let h = self.hasher.hash_one(key);
        &self.shards[(h as usize) & (SHARDS - 1)]
    }

    /// Looks up `key` as of `now`.
    pub fn get(&self, key: &str, now: Instant) -> Lookup<V> {
        let shard = self.shard(key).read().unwrap_or_else(|e| e.into_inner());
        let Some(&i) = shard.index.get(key) else {
            return Lookup::Miss;
        };
        let slot = &shard.slots[i];
        slot.referenced.store(true, Ordering::Relaxed);
        let age = now.saturating_duration_since(slot.loaded);
        let ttl = if slot.value.is_some() {
            self.cfg.ttl
        } else {
            self.cfg.negative_ttl
        };
        if age >= ttl + self.cfg.stale_if_error {
            return Lookup::Miss;
        }
        let freshness = if slot.raced || slot.epoch < self.epoch.load(Ordering::Acquire) {
            Freshness::Suspect
        } else if age < ttl {
            Freshness::Fresh
        } else if age < ttl + self.cfg.stale_while_revalidate {
            Freshness::Stale
        } else {
            Freshness::Expired
        };
        Lookup::Found(slot.value.clone(), freshness)
    }

    /// Call before reading the source of truth; pass the token to [`Cache::insert`].
    pub fn begin_load(&self) -> LoadToken {
        LoadToken {
            epoch: self.epoch.load(Ordering::Acquire),
            invalidations: self.invalidations.load(Ordering::Acquire),
        }
    }

    /// Inserts or replaces `key`, loaded at `loaded`. If any invalidation
    /// happened since `token` was taken, the value may predate the change and
    /// is stored as [`Freshness::Suspect`].
    pub fn insert(&self, key: &str, value: Option<V>, loaded: Instant, token: LoadToken) {
        let raced = token.invalidations != self.invalidations.load(Ordering::Acquire);
        let epoch = token.epoch;
        let mut shard = self.shard(key).write().unwrap_or_else(|e| e.into_inner());
        if shard.capacity == 0 {
            return;
        }
        if let Some(&i) = shard.index.get(key) {
            let slot = &mut shard.slots[i];
            slot.value = value;
            slot.loaded = loaded;
            slot.epoch = epoch;
            slot.raced = raced;
            slot.referenced.store(true, Ordering::Relaxed);
            return;
        }
        let key: Arc<str> = Arc::from(key);
        let slot = Slot {
            key: key.clone(),
            value,
            loaded,
            epoch,
            raced,
            referenced: AtomicBool::new(false),
        };
        if shard.slots.len() < shard.capacity {
            let i = shard.slots.len();
            shard.slots.push(slot);
            shard.index.insert(key, i);
            return;
        }
        // CLOCK: advance the hand, clearing reference bits, until an entry
        // that was not read since the last pass is found. Terminates within
        // two passes because every visited bit is cleared.
        let len = shard.slots.len();
        let victim = loop {
            let hand = shard.hand;
            shard.hand = (hand + 1) % len;
            if !shard.slots[hand].referenced.swap(false, Ordering::Relaxed) {
                break hand;
            }
        };
        let old = std::mem::replace(&mut shard.slots[victim], slot);
        shard.index.remove(&old.key);
        shard.index.insert(key, victim);
    }

    /// Removes `key` because it changed. Loads in flight become suspect (see
    /// [`Cache::insert`]). Returns true if it was present.
    pub fn invalidate(&self, key: &str) -> bool {
        self.invalidations.fetch_add(1, Ordering::AcqRel);
        self.remove(key)
    }

    /// Removes `key`. Returns true if it was present.
    pub fn remove(&self, key: &str) -> bool {
        let mut shard = self.shard(key).write().unwrap_or_else(|e| e.into_inner());
        let Some(i) = shard.index.remove(key) else {
            return false;
        };
        shard.slots.swap_remove(i);
        if i < shard.slots.len() {
            let moved = shard.slots[i].key.clone();
            shard.index.insert(moved, i);
        }
        if shard.hand >= shard.slots.len() {
            shard.hand = 0;
        }
        true
    }

    /// Marks every entry [`Freshness::Suspect`]. Used when change
    /// notifications may have been missed, e.g. after the notification
    /// connection dropped.
    pub fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Number of entries, including negative ones.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().unwrap_or_else(|e| e.into_inner()).slots.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(capacity: usize) -> Config {
        Config {
            capacity,
            ttl: Duration::from_secs(10),
            negative_ttl: Duration::from_secs(2),
            stale_while_revalidate: Duration::from_secs(5),
            stale_if_error: Duration::from_secs(100),
        }
    }

    #[test]
    fn freshness_windows() {
        let c = Cache::new(cfg(100));
        let t0 = Instant::now();
        c.insert("a", Some(1), t0, c.begin_load());
        let at = |s| t0 + Duration::from_secs(s);
        assert_eq!(c.get("a", at(0)), Lookup::Found(Some(1), Freshness::Fresh));
        assert_eq!(c.get("a", at(9)), Lookup::Found(Some(1), Freshness::Fresh));
        assert_eq!(c.get("a", at(10)), Lookup::Found(Some(1), Freshness::Stale));
        assert_eq!(c.get("a", at(14)), Lookup::Found(Some(1), Freshness::Stale));
        assert_eq!(
            c.get("a", at(15)),
            Lookup::Found(Some(1), Freshness::Expired)
        );
        assert_eq!(
            c.get("a", at(109)),
            Lookup::Found(Some(1), Freshness::Expired)
        );
        assert_eq!(c.get("a", at(110)), Lookup::Miss);
        assert_eq!(c.get("missing", at(0)), Lookup::Miss);
    }

    #[test]
    fn negative_entries_use_their_own_ttl() {
        let c: Cache<u32> = Cache::new(cfg(100));
        let t0 = Instant::now();
        c.insert("gone", None, t0, c.begin_load());
        assert_eq!(c.get("gone", t0), Lookup::Found(None, Freshness::Fresh));
        assert_eq!(
            c.get("gone", t0 + Duration::from_secs(2)),
            Lookup::Found(None, Freshness::Stale)
        );
    }

    #[test]
    fn epoch_bump_makes_entries_suspect() {
        let c = Cache::new(cfg(100));
        let t0 = Instant::now();
        let before = c.begin_load();
        c.insert("a", Some(1), t0, before);
        c.bump_epoch();
        assert_eq!(c.get("a", t0), Lookup::Found(Some(1), Freshness::Suspect));
        // A reload under the new epoch is fresh again.
        c.insert("a", Some(2), t0, c.begin_load());
        assert_eq!(c.get("a", t0), Lookup::Found(Some(2), Freshness::Fresh));
        // A load that started before a bump stays stale.
        let started = c.begin_load();
        c.bump_epoch();
        c.insert("a", Some(3), t0, started);
        assert_eq!(c.get("a", t0), Lookup::Found(Some(3), Freshness::Suspect));
    }

    #[test]
    fn load_racing_an_invalidation_is_suspect() {
        let c = Cache::new(cfg(100));
        let t0 = Instant::now();
        let token = c.begin_load();
        // Another key changing is enough: the cache cannot tell which.
        assert!(!c.invalidate("other"));
        c.insert("a", Some(1), t0, token);
        assert_eq!(c.get("a", t0), Lookup::Found(Some(1), Freshness::Suspect));
        c.insert("a", Some(2), t0, c.begin_load());
        assert_eq!(c.get("a", t0), Lookup::Found(Some(2), Freshness::Fresh));
        assert!(c.invalidate("a"));
        assert_eq!(c.get("a", t0), Lookup::Miss);
    }

    #[test]
    fn bounded_and_evicts_unreferenced_first() {
        let c = Cache::new(cfg(SHARDS * 2));
        let t0 = Instant::now();
        for i in 0..10_000 {
            c.insert(&format!("k{i}"), Some(i), t0, c.begin_load());
        }
        assert_eq!(c.len(), SHARDS * 2);

        // In one shard: fill it, read one key, insert more; the read key survives.
        let c = Cache::new(cfg(SHARDS * 4));
        let keys: Vec<String> = (0..100_000)
            .map(|i| format!("x{i}"))
            .filter(|k| std::ptr::eq(c.shard(k), &c.shards[0]))
            .take(8)
            .collect();
        for (i, k) in keys[..4].iter().enumerate() {
            c.insert(k, Some(i), t0, c.begin_load());
        }
        let _ = c.get(&keys[1], t0);
        for (i, k) in keys[4..7].iter().enumerate() {
            c.insert(k, Some(i), t0, c.begin_load());
        }
        assert!(matches!(c.get(&keys[1], t0), Lookup::Found(..)));
        assert_eq!(c.shards[0].read().unwrap().slots.len(), 4);
    }

    #[test]
    fn replace_and_remove() {
        let c = Cache::new(cfg(100));
        let t0 = Instant::now();
        c.insert("a", Some(1), t0, c.begin_load());
        c.insert("a", Some(2), t0, c.begin_load());
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("a", t0), Lookup::Found(Some(2), Freshness::Fresh));
        for k in ["b", "c", "d"] {
            c.insert(k, Some(9), t0, c.begin_load());
        }
        assert!(c.remove("a"));
        assert!(!c.remove("a"));
        assert_eq!(c.get("a", t0), Lookup::Miss);
        for k in ["b", "c", "d"] {
            assert!(matches!(c.get(k, t0), Lookup::Found(Some(9), _)), "{k}");
        }
        assert!(!c.is_empty());
    }

    #[test]
    fn remove_keeps_indexes_consistent_within_a_shard() {
        let c = Cache::new(cfg(SHARDS * 8));
        let t0 = Instant::now();
        let keys: Vec<String> = (0..100_000)
            .map(|i| format!("y{i}"))
            .filter(|k| std::ptr::eq(c.shard(k), &c.shards[3]))
            .take(8)
            .collect();
        for (i, k) in keys.iter().enumerate() {
            c.insert(k, Some(i), t0, c.begin_load());
        }
        // Remove from the front so swap_remove moves the last slot.
        assert!(c.remove(&keys[0]));
        assert!(c.remove(&keys[3]));
        for (i, k) in keys.iter().enumerate() {
            let want = if i == 0 || i == 3 {
                Lookup::Miss
            } else {
                Lookup::Found(Some(i), Freshness::Fresh)
            };
            assert_eq!(c.get(k, t0), want, "{k}");
        }
        // Eviction still works after removals moved the hand.
        for (i, k) in (0..20).map(|i| (i, format!("z{i}"))) {
            c.insert(&k, Some(100 + i), t0, c.begin_load());
        }
        assert!(c.len() <= SHARDS * 8);
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let c = Cache::new(cfg(0));
        c.insert("a", Some(1), Instant::now(), c.begin_load());
        assert_eq!(c.get("a", Instant::now()), Lookup::Miss);
        assert!(c.is_empty());
    }

    #[test]
    fn concurrent_readers_and_writers() {
        let c = Arc::new(Cache::new(cfg(1000)));
        let t0 = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for i in 0..20_000u32 {
                        let k = format!("k{}", (i * 7 + t) % 3000);
                        if i % 3 == 0 {
                            c.insert(&k, Some(i), t0, c.begin_load());
                        } else if i % 101 == 0 {
                            c.remove(&k);
                        } else {
                            let _ = c.get(&k, t0);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(c.len() <= 1000 + SHARDS);
        assert_eq!(c.config().capacity, 1000);
    }
}

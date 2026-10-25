//! Token buckets keyed by an identifier (API key, destination host).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rate and burst for every bucket in a [`KeyedLimiter`].
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    /// Tokens added per second.
    pub per_second: f64,
    /// Bucket size: the largest burst allowed after a quiet period.
    pub burst: f64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// One token bucket per key, bounded in number. When the map is full, idle
/// buckets (those that have refilled completely, so forgetting them changes
/// nothing) are dropped first; if none are idle the request is refused,
/// which fails closed under a flood of distinct keys.
pub struct KeyedLimiter<K> {
    rate: Rate,
    max_keys: usize,
    buckets: Mutex<HashMap<K, Bucket>>,
}

impl<K: Eq + Hash + Clone> KeyedLimiter<K> {
    pub fn new(rate: Rate, max_keys: usize) -> Self {
        assert!(rate.per_second > 0.0 && rate.burst >= 1.0);
        KeyedLimiter {
            rate,
            max_keys,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `key`. On refusal returns how long until a token
    /// is available.
    pub fn check(&self, key: &K, now: Instant) -> Result<(), Duration> {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(key) && map.len() >= self.max_keys {
            self.evict_idle(&mut map, now);
            if map.len() >= self.max_keys {
                return Err(Duration::from_secs_f64(1.0 / self.rate.per_second));
            }
        }
        let bucket = map.entry(key.clone()).or_insert(Bucket {
            tokens: self.rate.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate.per_second).min(self.rate.burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - bucket.tokens) / self.rate.per_second;
            Err(Duration::from_secs_f64(wait))
        }
    }

    fn evict_idle(&self, map: &mut HashMap<K, Bucket>, now: Instant) {
        let full_after = self.rate.burst / self.rate.per_second;
        map.retain(|_, b| now.saturating_duration_since(b.updated).as_secs_f64() < full_after);
    }

    /// Drops buckets that have fully refilled. Called periodically.
    pub fn sweep(&self, now: Instant) {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        self.evict_idle(&mut map, now);
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_refills_at_rate() {
        let l = KeyedLimiter::new(
            Rate {
                per_second: 2.0,
                burst: 3.0,
            },
            10,
        );
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.check(&"a", t0).is_ok());
        }
        let wait = l.check(&"a", t0).unwrap_err();
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-9);
        // Another key has its own bucket.
        assert!(l.check(&"b", t0).is_ok());
        // Half a second later exactly one more token.
        let t1 = t0 + Duration::from_millis(500);
        assert!(l.check(&"a", t1).is_ok());
        assert!(l.check(&"a", t1).is_err());
        // Never more than the burst after a long pause.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(l.check(&"a", t2).is_ok());
        }
        assert!(l.check(&"a", t2).is_err());
    }

    #[test]
    fn bounded_key_count() {
        let l = KeyedLimiter::new(
            Rate {
                per_second: 1.0,
                burst: 1.0,
            },
            2,
        );
        let t0 = Instant::now();
        assert!(l.check(&1, t0).is_ok());
        assert!(l.check(&2, t0).is_ok());
        // Full and nothing idle: a new key is refused.
        assert!(l.check(&3, t0).is_err());
        assert_eq!(l.len(), 2);
        // After the buckets refill they are idle and can be replaced.
        let t1 = t0 + Duration::from_secs(2);
        assert!(l.check(&3, t1).is_ok());
        assert!(l.len() <= 2);
        l.sweep(t1 + Duration::from_secs(5));
        assert!(l.is_empty());
    }
}

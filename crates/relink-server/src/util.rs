//! Randomness, time and shutdown helpers.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;

/// A boxed, sendable future, used where a trait must stay object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Fills `buf` from the operating system's CSPRNG.
///
/// The OS generator failing is not recoverable for a service that mints
/// secrets and identifiers, so this panics rather than returning weak bytes.
pub fn secure_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system random number generator failed");
}

thread_local! {
    static FAST_RNG: Cell<u64> = Cell::new({
        let mut seed = [0u8; 8];
        secure_random(&mut seed);
        u64::from_le_bytes(seed) | 1
    });
}

/// A fast, non-cryptographic random number (SplitMix64, seeded per thread
/// from the OS). Used for A/B assignment and request IDs, where speed matters
/// and unpredictability does not protect anything.
pub fn fast_random() -> u64 {
    FAST_RNG.with(|state| {
        let next = state.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
        state.set(next);
        let mut z = next;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    })
}

pub use relink_core::hex::{decode as hex_decode, encode as hex_encode};

/// Resolves once `rx` holds `true` (or its sender is gone). Shutdown
/// signalling for background tasks.
pub async fn stopped(rx: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Days since the Unix epoch, in UTC, for a timestamp in milliseconds.
pub fn utc_day(unix_ms: i64) -> i32 {
    unix_ms.div_euclid(86_400_000) as i32
}

/// The current time in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_random_varies() {
        let a = fast_random();
        let b = fast_random();
        assert_ne!(a, b);
    }

    #[test]
    fn secure_random_fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        secure_random(&mut a);
        secure_random(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn utc_day_handles_negative_times() {
        assert_eq!(utc_day(0), 0);
        assert_eq!(utc_day(86_399_999), 0);
        assert_eq!(utc_day(86_400_000), 1);
        assert_eq!(utc_day(-1), -1);
        assert!(now_ms() > 0);
    }
}

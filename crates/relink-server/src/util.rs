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

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 section 5), as used by JSON Web
/// Tokens, JWKs and PKCE.
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | ((b as u32) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Decodes base64url without padding. Padding, characters outside the
/// alphabet, an impossible length and non-zero trailing bits are refused, so
/// every byte string has exactly one accepted encoding.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= (value(c)? as u32) << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        // Bits below the last whole byte must be zero.
        if n & ((1u32 << (24 - 8 * bytes)) - 1) != 0 {
            return None;
        }
        out.extend((0..bytes).map(|i| (n >> (16 - 8 * i)) as u8));
    }
    Some(out)
}

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
    fn b64url_round_trips() {
        // RFC 4648 section 10 vectors, unpadded.
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64url_encode(raw.as_bytes()), enc);
            assert_eq!(b64url_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), [0xfb, 0xff]);
        for len in 0..40 {
            let mut buf = vec![0u8; len];
            secure_random(&mut buf);
            assert_eq!(b64url_decode(&b64url_encode(&buf)).unwrap(), buf);
        }
    }

    #[test]
    fn b64url_rejects_non_canonical_input() {
        for bad in ["Z", "Zg==", "Zm9v+", "Zm9v/", "Zh", "Zm9", "Zm 9v", "é"] {
            assert_eq!(b64url_decode(bad), None, "{bad:?}");
        }
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

//! A/B splits: weighted choice of a destination and a signed cookie that
//! keeps a visitor on the same variant.
//!
//! The cookie value is `<variant>.<tag>` where the tag is the first 16 bytes
//! of HMAC-SHA256 over the link ID, the link's destination version and the
//! variant. Visitors cannot pick a variant by editing the cookie, and changing
//! a link's destinations bumps its version, which invalidates every old
//! assignment.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::hex;

type HmacSha256 = Hmac<Sha256>;

/// Bytes of the HMAC kept in the cookie (128 bits).
const TAG_LEN: usize = 16;

/// Longest accepted cookie value: variant digits, dot, hex tag.
const MAX_VALUE_LEN: usize = 3 + 1 + TAG_LEN * 2;

/// Signs and verifies variant assignments.
#[derive(Clone)]
pub struct Signer {
    key: [u8; 32],
}

impl Signer {
    pub const fn new(key: [u8; 32]) -> Self {
        Signer { key }
    }

    fn mac(&self, link_id: i64, version: i32, variant: usize) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"relink-ab\0");
        mac.update(&link_id.to_be_bytes());
        mac.update(&version.to_be_bytes());
        mac.update(&(variant as u32).to_be_bytes());
        mac
    }

    /// The cookie value assigning `variant`.
    pub fn sign(&self, link_id: i64, version: i32, variant: usize) -> String {
        let tag = self.mac(link_id, version, variant).finalize().into_bytes();
        format!("{variant}.{}", hex::encode(&tag[..TAG_LEN]))
    }

    /// Returns the variant in `value` if its tag is valid for this link and
    /// version and the variant exists. The tag comparison is constant time.
    pub fn verify(
        &self,
        link_id: i64,
        version: i32,
        value: &str,
        variants: usize,
    ) -> Option<usize> {
        if value.len() > MAX_VALUE_LEN {
            return None;
        }
        let (variant, tag) = value.split_once('.')?;
        // Canonical decimal only: no sign, no leading zeros.
        if variant.is_empty()
            || variant.len() > 3
            || (variant.len() > 1 && variant.starts_with('0'))
            || !variant.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let variant: usize = variant.parse().ok()?;
        if variant >= variants {
            return None;
        }
        let tag = hex::decode(tag)?;
        if tag.len() != TAG_LEN {
            return None;
        }
        self.mac(link_id, version, variant)
            .verify_truncated_left(&tag)
            .ok()?;
        Some(variant)
    }
}

/// Picks an index with probability proportional to its weight, skipping
/// entries where `usable` is false. `r` is a uniform random 64-bit number.
/// Returns `None` when no entry is usable.
pub fn choose(weights: &[u32], usable: impl Fn(usize) -> bool, r: u64) -> Option<usize> {
    let total: u64 = weights
        .iter()
        .enumerate()
        .filter(|(i, _)| usable(*i))
        .map(|(_, &w)| u64::from(w))
        .sum();
    if total == 0 {
        return None;
    }
    // Multiply-shift maps r onto [0, total) (Lemire); the bias is at
    // most total / 2^64, far below anything measurable.
    let mut point = ((u128::from(r) * u128::from(total)) >> 64) as u64;
    for (i, &w) in weights.iter().enumerate() {
        if !usable(i) {
            continue;
        }
        let w = u64::from(w);
        if point < w {
            return Some(i);
        }
        point -= w;
    }
    unreachable!("point is below the sum of usable weights")
}

/// Finds cookie `name` in one or more Cookie header values (RFC 6265
/// `name=value; name2=value2`). Returns the first match.
pub fn find_cookie<'a>(headers: impl IntoIterator<Item = &'a [u8]>, name: &str) -> Option<&'a str> {
    for header in headers {
        let Ok(header) = std::str::from_utf8(header) else {
            continue;
        };
        for pair in header.split(';') {
            let pair = pair.trim_matches(|c| c == ' ' || c == '\t');
            if let Some((k, v)) = pair.split_once('=')
                && k == name
            {
                return Some(v.trim_matches('"'));
            }
        }
    }
    None
}

/// Cookie name for a link. Codes only contain `[A-Za-z0-9_-]`, which are
/// valid cookie-name characters.
pub fn cookie_name(code: &str) -> String {
    format!("rl_{code}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new([7u8; 32])
    }

    #[test]
    fn sign_and_verify() {
        let s = signer();
        let v = s.sign(42, 1, 2);
        assert_eq!(s.verify(42, 1, &v, 3), Some(2));
        // Different link, version, key or variant count: rejected.
        assert_eq!(s.verify(43, 1, &v, 3), None);
        assert_eq!(s.verify(42, 2, &v, 3), None);
        assert_eq!(Signer::new([8u8; 32]).verify(42, 1, &v, 3), None);
        assert_eq!(s.verify(42, 1, &v, 2), None);
    }

    #[test]
    fn rejects_tampering() {
        let s = signer();
        let v = s.sign(1, 1, 0);
        let (_, tag) = v.split_once('.').unwrap();
        for bad in [
            format!("1.{tag}"),
            format!("0.{}", &tag[..30]),
            format!("0.{tag}00"),
            format!("00.{tag}"),
            format!("+0.{tag}"),
            format!(".{tag}"),
            "0".to_string(),
            format!("0.{}", "z".repeat(32)),
            format!("1000.{tag}"),
            String::new(),
        ] {
            assert_eq!(s.verify(1, 1, &bad, 3), None, "{bad}");
        }
    }

    #[test]
    fn choose_respects_weights_and_usable() {
        let w = [1, 3];
        assert_eq!(choose(&w, |_| true, 0), Some(0));
        assert_eq!(choose(&w, |_| true, u64::MAX / 4 - 1), Some(0));
        assert_eq!(choose(&w, |_| true, u64::MAX / 4 + 1), Some(1));
        assert_eq!(choose(&w, |_| true, u64::MAX), Some(1));
        assert_eq!(choose(&w, |i| i == 0, u64::MAX), Some(0));
        assert_eq!(choose(&w, |_| false, 1), None);
        assert_eq!(choose(&[], |_| true, 1), None);
    }

    #[test]
    fn cookies() {
        let headers: [&[u8]; 2] = [b"a=1; rl_abc=\"0.ff\"", b"rl_xyz=2"];
        assert_eq!(find_cookie(headers, "rl_abc"), Some("0.ff"));
        assert_eq!(find_cookie(headers, "rl_xyz"), Some("2"));
        assert_eq!(find_cookie(headers, "rl_ab"), None);
        let invalid: [&[u8]; 1] = [&[0xff, b'=']];
        assert_eq!(find_cookie(invalid, "x"), None);
        assert_eq!(cookie_name("abc"), "rl_abc");
    }
}

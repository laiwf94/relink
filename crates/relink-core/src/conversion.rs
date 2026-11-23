//! Click ids for conversion tracking.
//!
//! A link with conversion tracking on sends every visitor on with a click id
//! in the destination's query string, `rl_cid=<id>`. The destination's
//! server keeps it, and when the visitor later signs up or buys, posts it
//! back to `POST /v1/conversions` with the event. The id carries everything
//! the attribution needs, signed, so the redirect never writes anything per
//! click and the edge mints ids exactly as the origin does:
//!
//! | Bytes | Field |
//! |---|---|
//! | 0 | format version, 1 |
//! | 1..9 | link id, big-endian |
//! | 9..13 | click time, Unix seconds, big-endian |
//! | 13 | what chose the URL: destination, rule, app target or fallback |
//! | 14 | the destination or rule index, 0 otherwise |
//! | 15..19 | `SHA-256("relink-cid-url\0" \| url)[0..4]`, the URL sent to |
//! | 19..26 | nonce, so two clicks in the same second differ |
//! | 26..36 | `HMAC-SHA256(key, "relink-cid\0" \| bytes 0..26)[0..10]` |
//!
//! 36 bytes are 48 characters of unpadded base64url. The key is the A/B
//! cookie key, under its own label, so tags never transfer between the two
//! uses. Nobody can make up an id or change one without the key; the MAC
//! comparison is constant time. The id is signed, not encrypted: it shows
//! the link id, the time and the index to whoever holds it, nothing about
//! the visitor.
//!
//! The URL hash lets the origin name the destination a conversion came
//! from even after the link's destinations changed: it compares the hash
//! with the URLs of the link now and of its kept versions.

use std::borrow::Cow;

use hmac::Mac;
use sha2::{Digest, Sha256};

use crate::abtest::Signer;
use crate::model::Link;
use crate::rules::Redirect;

/// The query parameter that carries the click id.
pub const PARAM: &str = "rl_cid";

/// Longest attribution window a link can have, in days.
pub const MAX_WINDOW_DAYS: u16 = 365;

/// Length of a click id in characters.
pub const ID_LEN: usize = 48;

const VERSION: u8 = 1;
const RAW_LEN: usize = 36;
const SIGNED_LEN: usize = 26;
const MAC_LEN: usize = RAW_LEN - SIGNED_LEN;

/// What chose the URL a click was sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// One of the link's destinations, by index: the A/B variant.
    Destination(u8),
    /// A targeting rule, by index.
    Rule(u8),
    /// The link's app target for the visitor's phone.
    App,
    /// The fallback URL, because no destination was healthy.
    Fallback,
}

impl Target {
    /// The name the API uses.
    pub fn kind(self) -> &'static str {
        match self {
            Target::Destination(_) => "destination",
            Target::Rule(_) => "rule",
            Target::App => "app",
            Target::Fallback => "fallback",
        }
    }

    /// The destination or rule index; 0 for the others.
    pub fn index(self) -> u8 {
        match self {
            Target::Destination(i) | Target::Rule(i) => i,
            Target::App | Target::Fallback => 0,
        }
    }

    /// The inverse of [`Target::kind`] and [`Target::index`].
    pub fn from_parts(kind: &str, index: u8) -> Option<Target> {
        match (kind, index) {
            ("destination", i) => Some(Target::Destination(i)),
            ("rule", i) => Some(Target::Rule(i)),
            ("app", 0) => Some(Target::App),
            ("fallback", 0) => Some(Target::Fallback),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Target::Destination(_) => 0,
            Target::Rule(_) => 1,
            Target::App => 2,
            Target::Fallback => 3,
        }
    }

    fn from_code(code: u8, index: u8) -> Option<Target> {
        match code {
            0 => Some(Target::Destination(index)),
            1 => Some(Target::Rule(index)),
            2 if index == 0 => Some(Target::App),
            3 if index == 0 => Some(Target::Fallback),
            _ => None,
        }
    }
}

/// The hash of a URL that a click id carries.
pub fn url_hash(url: &str) -> [u8; 4] {
    let digest = Sha256::new()
        .chain_update(b"relink-cid-url\0")
        .chain_update(url.as_bytes())
        .finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// One click, as its id describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClickId {
    pub link_id: i64,
    /// Unix seconds.
    pub at_secs: u32,
    pub target: Target,
    pub url_hash: [u8; 4],
    pub nonce: [u8; 7],
}

impl ClickId {
    /// The id of a click on `link_id` at `now_ms`, sent to `url` because
    /// of `target`. `random` only makes ids unique; it need not be secret.
    pub fn new(link_id: i64, now_ms: i64, target: Target, url: &str, random: u64) -> ClickId {
        let secs = now_ms.div_euclid(1000).clamp(0, i64::from(u32::MAX)) as u32;
        // Mixed, so the bits the A/B choice read are not shown as they are.
        let mixed = splitmix64(random).to_be_bytes();
        let mut nonce = [0u8; 7];
        nonce.copy_from_slice(&mixed[..7]);
        ClickId {
            link_id,
            at_secs: secs,
            target,
            url_hash: url_hash(url),
            nonce,
        }
    }

    /// The click time in milliseconds since the Unix epoch.
    pub fn at_ms(&self) -> i64 {
        i64::from(self.at_secs) * 1000
    }

    fn signed_bytes(&self) -> [u8; SIGNED_LEN] {
        let mut b = [0u8; SIGNED_LEN];
        b[0] = VERSION;
        b[1..9].copy_from_slice(&self.link_id.to_be_bytes());
        b[9..13].copy_from_slice(&self.at_secs.to_be_bytes());
        b[13] = self.target.code();
        b[14] = self.target.index();
        b[15..19].copy_from_slice(&self.url_hash);
        b[19..26].copy_from_slice(&self.nonce);
        b
    }

    /// The id as it goes in a URL: 48 characters of base64url.
    pub fn encode(&self, signer: &Signer) -> String {
        let signed = self.signed_bytes();
        let tag = mac(signer, &signed).finalize().into_bytes();
        let mut raw = [0u8; RAW_LEN];
        raw[..SIGNED_LEN].copy_from_slice(&signed);
        raw[SIGNED_LEN..].copy_from_slice(&tag[..MAC_LEN]);
        base64url(&raw)
    }

    /// Reads an id made by [`ClickId::encode`] under the same key. `None`
    /// for anything else: another length or alphabet, another version, a
    /// tag that does not match, or an index its kind cannot have.
    pub fn decode(signer: &Signer, id: &str) -> Option<ClickId> {
        let raw = unbase64url(id)?;
        let (signed, tag) = raw.split_at(SIGNED_LEN);
        mac(signer, signed).verify_truncated_left(tag).ok()?;
        if signed[0] != VERSION {
            return None;
        }
        let link_id = i64::from_be_bytes(signed[1..9].try_into().ok()?);
        let at_secs = u32::from_be_bytes(signed[9..13].try_into().ok()?);
        let target = Target::from_code(signed[13], signed[14])?;
        Some(ClickId {
            link_id,
            at_secs,
            target,
            url_hash: signed[15..19].try_into().ok()?,
            nonce: signed[19..26].try_into().ok()?,
        })
    }
}

fn mac(signer: &Signer, signed: &[u8]) -> crate::abtest::HmacSha256 {
    let mut mac = signer.hmac();
    mac.update(b"relink-cid\0");
    mac.update(signed);
    mac
}

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(raw: &[u8; RAW_LEN]) -> String {
    let mut out = String::with_capacity(ID_LEN);
    let (groups, _) = raw.as_chunks::<3>();
    for &[a, b, c] in groups {
        let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
        }
    }
    out
}

fn unbase64url(s: &str) -> Option<[u8; RAW_LEN]> {
    let bytes = s.as_bytes();
    if bytes.len() != ID_LEN {
        return None;
    }
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut raw = [0u8; RAW_LEN];
    let (quads, _) = bytes.as_chunks::<4>();
    for (i, quad) in quads.iter().enumerate() {
        let mut n = 0u32;
        for &c in quad {
            n = (n << 6) | u32::from(value(c)?);
        }
        raw[i * 3] = (n >> 16) as u8;
        raw[i * 3 + 1] = (n >> 8) as u8;
        raw[i * 3 + 2] = n as u8;
    }
    Some(raw)
}

/// `location` with `rl_cid=<id>` as the last query parameter, before any
/// fragment. Parameters already named `rl_cid`, and empty ones, are left
/// out, so the destination always reads exactly one id.
pub fn tag(location: &str, id: &str) -> String {
    let (before, fragment) = match location.find('#') {
        Some(i) => location.split_at(i),
        None => (location, ""),
    };
    let (base, query) = match before.split_once('?') {
        Some((b, q)) => (b, q),
        None => (before, ""),
    };
    let mut out = String::with_capacity(location.len() + PARAM.len() + id.len() + 2);
    out.push_str(base);
    out.push('?');
    for pair in query.split('&') {
        let name = pair.split_once('=').map_or(pair, |(n, _)| n);
        if pair.is_empty() || name == PARAM {
            continue;
        }
        out.push_str(pair);
        out.push('&');
    }
    out.push_str(PARAM);
    out.push('=');
    out.push_str(id);
    out.push_str(fragment);
    out
}

/// Where `redirect` sends the visitor: its location, with a fresh click id
/// when `link` tracks conversions. The preview page and geo fallbacks use
/// the plain location; only a click gets an id.
pub fn location<'a>(
    link: &Link,
    redirect: &Redirect<'a>,
    signer: &Signer,
    now_ms: i64,
    random: u64,
) -> Cow<'a, str> {
    if link.conversion_window_days.is_none() {
        return Cow::Borrowed(redirect.location);
    }
    let id = ClickId::new(link.id, now_ms, redirect.target, redirect.location, random);
    Cow::Owned(tag(redirect.location, &id.encode(signer)))
}

/// The click id in a URL's query string, if there is exactly one.
pub fn find(url: &str) -> Option<&str> {
    let query = url.split('#').next()?.split_once('?')?.1;
    let mut found = None;
    for pair in query.split('&') {
        if let Some((PARAM, v)) = pair.split_once('=') {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER: Signer = Signer::new([7; 32]);

    fn sample() -> ClickId {
        ClickId::new(
            42,
            1_764_000_000_123,
            Target::Destination(2),
            "https://a.example.com/",
            99,
        )
    }

    #[test]
    fn round_trips() {
        let id = sample();
        let s = id.encode(&SIGNER);
        assert_eq!(s.len(), ID_LEN);
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_eq!(ClickId::decode(&SIGNER, &s), Some(id));
        assert_eq!(id.at_ms(), 1_764_000_000_000);
        for t in [
            Target::Destination(0),
            Target::Rule(31),
            Target::App,
            Target::Fallback,
        ] {
            let id = ClickId { target: t, ..id };
            assert_eq!(ClickId::decode(&SIGNER, &id.encode(&SIGNER)), Some(id));
            assert_eq!(Target::from_parts(t.kind(), t.index()), Some(t));
        }
        assert_eq!(Target::from_parts("app", 1), None);
        assert_eq!(Target::from_parts("other", 0), None);
    }

    #[test]
    fn known_answer() {
        // Pins the format: a change here breaks every id already handed
        // out, which destinations may still post back.
        let id = ClickId {
            link_id: 1,
            at_secs: 2,
            target: Target::Rule(3),
            url_hash: url_hash("https://example.com/"),
            nonce: [4; 7],
        };
        let s = id.encode(&Signer::new([0; 32]));
        // Computed independently: HMAC-SHA256 under 32 zero bytes, base64url.
        assert_eq!(s, "AQAAAAAAAAABAAAAAgEDQU4nywQEBAQEBAQKRyI0N8EE9u-x");
        assert_eq!(ClickId::decode(&Signer::new([0; 32]), &s), Some(id));
    }

    #[test]
    fn refuses_forged_and_malformed_ids() {
        let s = sample().encode(&SIGNER);
        assert_eq!(ClickId::decode(&Signer::new([8; 32]), &s), None);
        for i in 0..s.len() {
            let mut b = s.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            let changed = String::from_utf8(b).unwrap();
            assert_eq!(ClickId::decode(&SIGNER, &changed), None, "byte {i}");
        }
        assert_eq!(ClickId::decode(&SIGNER, &s[1..]), None);
        assert_eq!(ClickId::decode(&SIGNER, &format!("{s}A")), None);
        assert_eq!(ClickId::decode(&SIGNER, &s.replace('A', "=")), None);
        assert_eq!(ClickId::decode(&SIGNER, ""), None);
        assert_eq!(ClickId::decode(&SIGNER, &"é".repeat(24)), None);
    }

    #[test]
    fn refuses_validly_signed_ids_it_cannot_read() {
        // Another version or a kind it does not know, signed with the key:
        // the MAC passes and the fields still refuse it.
        let sign = |mutate: fn(&mut [u8; SIGNED_LEN])| {
            let mut signed = sample().signed_bytes();
            mutate(&mut signed);
            let tag = mac(&SIGNER, &signed).finalize().into_bytes();
            let mut raw = [0u8; RAW_LEN];
            raw[..SIGNED_LEN].copy_from_slice(&signed);
            raw[SIGNED_LEN..].copy_from_slice(&tag[..MAC_LEN]);
            base64url(&raw)
        };
        assert_eq!(ClickId::decode(&SIGNER, &sign(|b| b[0] = 2)), None);
        assert_eq!(ClickId::decode(&SIGNER, &sign(|b| b[13] = 4)), None);
        assert_eq!(
            ClickId::decode(&SIGNER, &sign(|b| (b[13], b[14]) = (2, 1))),
            None
        );
        assert!(ClickId::decode(&SIGNER, &sign(|_| {})).is_some());
    }

    #[test]
    fn ids_differ_per_click() {
        let a = ClickId::new(1, 5_000, Target::App, "x:", 1);
        let b = ClickId::new(1, 5_000, Target::App, "x:", 2);
        assert_ne!(a.encode(&SIGNER), b.encode(&SIGNER));
        assert_ne!(a.nonce, 1u64.to_be_bytes()[..7]);
        // Times before the epoch or past 2106 are clamped, not wrapped.
        assert_eq!(ClickId::new(1, -5, Target::App, "x:", 0).at_secs, 0);
        assert_eq!(
            ClickId::new(1, i64::MAX, Target::App, "x:", 0).at_secs,
            u32::MAX
        );
    }

    #[test]
    fn tags_locations() {
        let cases = [
            ("https://a.example/", "https://a.example/?rl_cid=ID"),
            (
                "https://a.example/p?x=1",
                "https://a.example/p?x=1&rl_cid=ID",
            ),
            (
                "https://a.example/p?x=1#top",
                "https://a.example/p?x=1&rl_cid=ID#top",
            ),
            ("https://a.example/#a?b", "https://a.example/?rl_cid=ID#a?b"),
            (
                "https://a.example/?rl_cid=old&x=1&rl_cid&&y",
                "https://a.example/?x=1&y&rl_cid=ID",
            ),
            ("https://a.example/?", "https://a.example/?rl_cid=ID"),
            (
                "https://a.example/?rl_cidx=1",
                "https://a.example/?rl_cidx=1&rl_cid=ID",
            ),
            (
                "intent://a.example/p#Intent;scheme=https;package=com.example;end",
                "intent://a.example/p?rl_cid=ID#Intent;scheme=https;package=com.example;end",
            ),
        ];
        for (location, want) in cases {
            assert_eq!(tag(location, "ID"), want, "{location}");
            assert_eq!(find(want), Some("ID"), "{want}");
        }
        assert_eq!(find("https://a.example/"), None);
        assert_eq!(find("https://a.example/?rl_cid=a&rl_cid=b"), None);
        assert_eq!(find("https://a.example/#?rl_cid=a"), None);
    }

    #[test]
    fn url_hash_is_keyed_by_label() {
        assert_eq!(url_hash("a"), url_hash("a"));
        assert_ne!(url_hash("a"), url_hash("b"));
        let plain = Sha256::digest(b"a");
        assert_ne!(url_hash("a"), [plain[0], plain[1], plain[2], plain[3]]);
    }
}

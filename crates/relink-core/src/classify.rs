//! Turns request headers into the low-cardinality dimensions stored with
//! click counts: device class, referrer host and country.
//!
//! Every function here takes untrusted header bytes and returns a bounded
//! value, so a hostile client cannot create unbounded rows or huge strings.

/// Coarse device class derived from the User-Agent header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Device {
    Desktop,
    Mobile,
    Tablet,
    Bot,
    Other,
}

impl Device {
    pub const ALL: [Device; 5] = [
        Device::Desktop,
        Device::Mobile,
        Device::Tablet,
        Device::Bot,
        Device::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Device::Desktop => "desktop",
            Device::Mobile => "mobile",
            Device::Tablet => "tablet",
            Device::Bot => "bot",
            Device::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Device> {
        Device::ALL.into_iter().find(|d| d.as_str() == s)
    }
}

/// Only the start of the header is inspected; real User-Agents put the
/// interesting tokens early, and this bounds the work per request.
const UA_SCAN_LIMIT: usize = 512;

/// Classifies a User-Agent with simple token rules, in this order: bots
/// ([`bot_kind`]), tablets, phones, desktops. This is deliberately coarse;
/// the goal is a stable breakdown, not browser identification.
pub fn device_class(user_agent: Option<&[u8]>) -> Device {
    let mut buf = [0u8; UA_SCAN_LIMIT];
    let ua = lowercase_prefix(user_agent, &mut buf);
    if ua.is_empty() {
        return Device::Other;
    }
    if bot_kind_of(ua).is_some() {
        return Device::Bot;
    }
    let has = |needle: &str| ua.contains(needle);
    if has("ipad") || has("tablet") || (has("android") && !has("mobile")) {
        return Device::Tablet;
    }
    if has("mobi") || has("iphone") || has("ipod") || has("windows phone") {
        return Device::Mobile;
    }
    if has("windows") || has("macintosh") || has("x11") || has("cros") || has("linux") {
        return Device::Desktop;
    }
    Device::Other
}

/// The kind of automated client a User-Agent names. Every kind is counted
/// as the device class [`Device::Bot`], which analytics leave out unless
/// asked to include them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BotKind {
    /// Search engines, SEO tools, archivers and AI crawlers.
    Crawler,
    /// Link-preview fetchers: the request a chat app, social network or
    /// mail client makes when a link is pasted, to draw its card.
    Preview,
    /// Uptime and performance monitors.
    Monitor,
    /// HTTP libraries, command-line clients and headless browsers.
    Tool,
}

impl BotKind {
    pub const ALL: [BotKind; 4] = [
        BotKind::Crawler,
        BotKind::Preview,
        BotKind::Monitor,
        BotKind::Tool,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            BotKind::Crawler => "crawler",
            BotKind::Preview => "preview",
            BotKind::Monitor => "monitor",
            BotKind::Tool => "tool",
        }
    }

    pub fn parse(s: &str) -> Option<BotKind> {
        BotKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// The version of [`AGENTS`], [`GENERIC_AGENTS`] and [`NOT_AGENTS`]. Any
/// change to them bumps it, so a report can say which list classified its
/// clicks; the `list_is_versioned` test fails until it is bumped.
pub const BOT_LIST_VERSION: u32 = 1;

use BotKind::{Crawler, Monitor, Preview, Tool};

/// Named automated clients: lowercase tokens found where a word of the
/// User-Agent starts. Sorted by first byte (checked at compile time) so a scan
/// looks only at the tokens that start with the byte in front of it.
/// Where several match, the one that starts first in the User-Agent wins.
pub static AGENTS: &[(&str, BotKind)] = &[
    ("adsbot-google", Crawler),
    ("ahrefsbot", Crawler),
    ("aiohttp/", Tool),
    ("amazonbot", Crawler),
    ("anthropic-ai", Crawler),
    ("apache-httpclient/", Tool),
    ("apis-google", Crawler),
    ("applebot", Crawler),
    ("archive.org_bot", Crawler),
    ("axios/", Tool),
    ("baiduspider", Crawler),
    ("bingbot", Crawler),
    ("bingpreview", Preview),
    ("bitlybot", Preview),
    ("blexbot", Crawler),
    ("bytespider", Crawler),
    ("cardyb", Preview),
    ("ccbot", Crawler),
    ("chatgpt-user", Crawler),
    ("checkly", Monitor),
    ("chrome-lighthouse", Monitor),
    ("claude-web", Crawler),
    ("claudebot", Crawler),
    ("curl/", Tool),
    ("datadog/synthetics", Monitor),
    ("diffbot", Crawler),
    ("discordbot", Preview),
    ("dotbot", Crawler),
    ("duckassistbot", Crawler),
    ("duckduckbot", Crawler),
    ("duckduckgo-favicons-bot", Crawler),
    ("embedly", Preview),
    ("facebookexternalhit", Preview),
    ("facebot", Preview),
    ("go-http-client/", Tool),
    ("google-inspectiontool", Crawler),
    ("googlebot", Crawler),
    ("googleother", Crawler),
    ("gptbot", Crawler),
    ("guzzlehttp/", Tool),
    ("headlesschrome", Tool),
    ("httpie/", Tool),
    ("ia_archiver", Crawler),
    ("iframely", Preview),
    ("insomnia/", Tool),
    ("java/", Tool),
    ("kakaotalk-scrap", Preview),
    ("libwww-perl/", Tool),
    ("linkedinbot", Preview),
    ("mastodon/", Preview),
    ("mediapartners-google", Crawler),
    ("meta-externalagent", Crawler),
    ("meta-externalfetcher", Preview),
    ("microsoftpreview", Preview),
    ("mj12bot", Crawler),
    ("msnbot", Crawler),
    ("newrelicpinger", Monitor),
    ("node-fetch", Tool),
    ("oai-searchbot", Crawler),
    ("perplexitybot", Crawler),
    ("petalbot", Crawler),
    ("phantomjs", Tool),
    ("pingdom", Monitor),
    ("pinterestbot", Preview),
    ("postmanruntime/", Tool),
    ("python-httpx/", Tool),
    ("python-requests/", Tool),
    ("python-urllib/", Tool),
    ("redditbot", Preview),
    ("scrapy/", Tool),
    ("semrushbot", Crawler),
    ("seznambot", Crawler),
    ("site24x7", Monitor),
    ("skypeuripreview", Preview),
    ("slackbot", Preview),
    ("slurp", Crawler),
    ("snap url preview", Preview),
    ("sogou", Crawler),
    ("statuscake", Monitor),
    ("storebot-google", Crawler),
    ("telegrambot", Preview),
    ("twitterbot", Preview),
    ("undici", Tool),
    ("updown.io", Monitor),
    ("uptime-kuma/", Monitor),
    ("uptimerobot/", Monitor),
    ("vkshare", Preview),
    ("wget/", Tool),
    ("whatsapp/", Preview),
    ("xing-contenttabreceiver", Preview),
    ("yandexbot", Crawler),
];

/// Catch-all words, tried in order only when no named agent matched: most
/// automated clients that announce themselves say one of these.
pub static GENERIC_AGENTS: &[(&str, BotKind)] = &[
    ("bot", Crawler),
    ("crawl", Crawler),
    ("spider", Crawler),
    ("preview", Preview),
    ("headless", Tool),
];

/// Words in real browsers' User-Agents that contain a generic word: a
/// generic match inside one of these is not a bot. CUBOT is a phone maker.
pub static NOT_AGENTS: &[&str] = &["cubot"];

/// For each byte `b`, the entries of [`AGENTS`] that start with `b` are
/// `AGENTS[INDEX[b]..INDEX[b + 1]]`.
static INDEX: [u16; 257] = first_byte_index(AGENTS);

/// One bit per pair of bytes that starts a token of [`AGENTS`], so the scan
/// skips almost every word of a browser's User-Agent with one load. 8 KiB,
/// nearly all zero.
static PAIRS: [u64; 1024] = token_pairs(AGENTS);

const fn first_byte_index(list: &[(&str, BotKind)]) -> [u16; 257] {
    let mut idx = [0u16; 257];
    let mut i = 0;
    let mut b = 0;
    while b < 257 {
        while i < list.len() && (list[i].0.as_bytes()[0] as usize) < b {
            i += 1;
        }
        idx[b] = i as u16;
        b += 1;
    }
    idx
}

const fn token_pairs(list: &[(&str, BotKind)]) -> [u64; 1024] {
    let mut bits = [0u64; 1024];
    let mut i = 0;
    while i < list.len() {
        let t = list[i].0.as_bytes();
        assert!(t[0].is_ascii_alphanumeric(), "named tokens start a word");
        let pair = ((t[0] as usize) << 8) | t[1] as usize;
        bits[pair / 64] |= 1 << (pair % 64);
        i += 1;
    }
    bits
}

/// A list's invariants, checked when the crate compiles: tokens are at
/// least two bytes of ASCII without uppercase, sorted by first byte if
/// `sorted`, and no token starts with an earlier one of the same first byte
/// (which would make it unreachable).
const fn check_agents(list: &[(&str, BotKind)], sorted: bool) -> bool {
    assert!(list.len() < u16::MAX as usize);
    let mut i = 0;
    while i < list.len() {
        let t = list[i].0.as_bytes();
        assert!(t.len() >= 2, "tokens are indexed by their first two bytes");
        let mut k = 0;
        while k < t.len() {
            assert!(t[k].is_ascii() && !t[k].is_ascii_uppercase());
            k += 1;
        }
        if sorted && i > 0 {
            assert!(
                list[i - 1].0.as_bytes()[0] <= t[0],
                "AGENTS must be sorted by first byte"
            );
        }
        let mut j = 0;
        while j < i {
            let e = list[j].0.as_bytes();
            if e[0] == t[0] && e.len() <= t.len() {
                let mut same = true;
                let mut k = 0;
                while k < e.len() {
                    same &= e[k] == t[k];
                    k += 1;
                }
                assert!(!same, "a token in AGENTS starts with an earlier one");
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(check_agents(AGENTS, true) && check_agents(GENERIC_AGENTS, false));

/// The automated client a User-Agent names, if any, by [`AGENTS`], then
/// [`GENERIC_AGENTS`]. Only the first 512 bytes are read, case-insensitively.
/// A User-Agent can be anything the client likes, so this catches clients
/// that announce themselves; one that pretends to be a browser counts as one.
pub fn bot_kind(user_agent: Option<&[u8]>) -> Option<BotKind> {
    let mut buf = [0u8; UA_SCAN_LIMIT];
    bot_kind_of(lowercase_prefix(user_agent, &mut buf))
}

/// [`bot_kind`] of an already lowercased prefix. Named agents match where
/// a word starts (at the start, or after a byte that is not a letter or
/// digit), which is where every real one puts its name; the first returns
/// at once. Generic words match anywhere, in list order.
fn bot_kind_of(ua: &str) -> Option<BotKind> {
    let b = ua.as_bytes();
    // Eight bytes at a time, find the bytes that start a word, then look
    // only at those whose first two bytes start a token.
    let mut carry = 0u64;
    let mut base = 0;
    while base < b.len() {
        let chunk = match b.get(base..base + 8) {
            Some(c) => u64::from_le_bytes(c.try_into().expect("8 bytes")),
            None => {
                let mut tail = [0u8; 8];
                tail[..b.len() - base].copy_from_slice(&b[base..]);
                u64::from_le_bytes(tail)
            }
        };
        let (mut starts, next) = word_starts(chunk, carry);
        carry = next;
        while starts != 0 {
            let i = base + (starts.trailing_zeros() / 8) as usize;
            starts &= starts - 1;
            let c = usize::from(b[i]);
            let bit = (c << 8) | usize::from(b.get(i + 1).copied().unwrap_or(0));
            // Most words fail here.
            if PAIRS[bit / 64] >> (bit % 64) & 1 == 0 {
                continue;
            }
            let rest = &b[i..];
            let second = rest.get(1).copied().unwrap_or(0);
            if let Some(&(_, kind)) = AGENTS[usize::from(INDEX[c])..usize::from(INDEX[c + 1])]
                .iter()
                .find(|(t, _)| t.as_bytes()[1] == second && rest.starts_with(t.as_bytes()))
            {
                return Some(kind);
            }
        }
        base += 8;
    }
    // `contains` has a vectorised path that `match_indices` lacks, and the
    // words are almost never there.
    GENERIC_AGENTS.iter().find_map(|&(word, kind)| {
        (ua.contains(word)
            && ua
                .match_indices(word)
                .any(|(at, _)| !inside_not_agent(ua, at, word.len())))
        .then_some(kind)
    })
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

/// The high bit of every byte of `x` that is strictly between `lo` and
/// `hi`; every byte of `x` must be below 128 and `hi` at most 128.
const fn bytes_between(x: u64, lo: u8, hi: u8) -> u64 {
    let low7 = x & (ONES * 127);
    (ONES * (127 + hi as u64)).wrapping_sub(low7) & !x & (low7 + ONES * (127 - lo as u64)) & HIGHS
}

/// For eight ASCII bytes in little-endian order: the high bit of each byte
/// that is a lowercase letter or digit and follows one that is not, and the
/// carry for the next eight (whether the last byte was a letter or digit).
/// `carry` is the previous call's, or 0 at the start.
fn word_starts(x: u64, carry: u64) -> (u64, u64) {
    let alnum = bytes_between(x, b'0' - 1, b'9' + 1) | bytes_between(x, b'a' - 1, b'z' + 1);
    (alnum & !((alnum << 8) | carry), alnum >> 56)
}

/// Whether `ua[at..at + len]` lies inside an occurrence of a [`NOT_AGENTS`]
/// word.
fn inside_not_agent(ua: &str, at: usize, len: usize) -> bool {
    NOT_AGENTS.iter().any(|w| {
        ua.match_indices(w)
            .any(|(start, _)| start <= at && at + len <= start + w.len())
    })
}

/// The first [`UA_SCAN_LIMIT`] bytes of a User-Agent, lowercased into `buf`.
/// Bytes outside ASCII are replaced so the result is always valid UTF-8.
fn lowercase_prefix<'b>(user_agent: Option<&[u8]>, buf: &'b mut [u8; UA_SCAN_LIMIT]) -> &'b str {
    let raw = user_agent.unwrap_or_default();
    let len = raw.len().min(UA_SCAN_LIMIT);
    for (dst, &b) in buf.iter_mut().zip(&raw[..len]) {
        *dst = if b.is_ascii() {
            b.to_ascii_lowercase()
        } else {
            b'?'
        };
    }
    std::str::from_utf8(&buf[..len]).expect("ASCII is UTF-8")
}

/// Operating system family derived from the User-Agent header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Os {
    Ios,
    Android,
    Windows,
    Macos,
    Linux,
    Chromeos,
    Other,
}

impl Os {
    pub const ALL: [Os; 7] = [
        Os::Ios,
        Os::Android,
        Os::Windows,
        Os::Macos,
        Os::Linux,
        Os::Chromeos,
        Os::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Os::Ios => "ios",
            Os::Android => "android",
            Os::Windows => "windows",
            Os::Macos => "macos",
            Os::Linux => "linux",
            Os::Chromeos => "chromeos",
            Os::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Os> {
        Os::ALL.into_iter().find(|o| o.as_str() == s)
    }
}

/// The operating system family, by token rules in this order: iOS (whose
/// User-Agents also say "like Mac OS X"), Android (which also says Linux),
/// ChromeOS, Windows, macOS, Linux.
pub fn os_family(user_agent: Option<&[u8]>) -> Os {
    let mut buf = [0u8; UA_SCAN_LIMIT];
    let ua = lowercase_prefix(user_agent, &mut buf);
    let has = |needle: &str| ua.contains(needle);
    if has("iphone") || has("ipad") || has("ipod") {
        Os::Ios
    } else if has("android") {
        Os::Android
    } else if has("cros") {
        Os::Chromeos
    } else if has("windows") {
        Os::Windows
    } else if has("macintosh") || has("mac os x") {
        Os::Macos
    } else if has("linux") || has("x11") {
        Os::Linux
    } else {
        Os::Other
    }
}

/// Browser family derived from the User-Agent header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Safari,
    Firefox,
    Edge,
    Opera,
    Samsung,
    Other,
}

impl Browser {
    pub const ALL: [Browser; 7] = [
        Browser::Chrome,
        Browser::Safari,
        Browser::Firefox,
        Browser::Edge,
        Browser::Opera,
        Browser::Samsung,
        Browser::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Safari => "safari",
            Browser::Firefox => "firefox",
            Browser::Edge => "edge",
            Browser::Opera => "opera",
            Browser::Samsung => "samsung",
            Browser::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Browser> {
        Browser::ALL.into_iter().find(|b| b.as_str() == s)
    }
}

/// The browser family. Browsers built on Chromium also claim Chrome and
/// Safari, and Chrome claims Safari, so the more specific tokens are tried
/// first: Edge, Opera, Samsung Internet, Firefox, Chrome, then Safari.
pub fn browser_family(user_agent: Option<&[u8]>) -> Browser {
    let mut buf = [0u8; UA_SCAN_LIMIT];
    let ua = lowercase_prefix(user_agent, &mut buf);
    let has = |needle: &str| ua.contains(needle);
    if has("edg/") || has("edge/") || has("edga/") || has("edgios/") {
        Browser::Edge
    } else if has("opr/") || has("opera") {
        Browser::Opera
    } else if has("samsungbrowser/") {
        Browser::Samsung
    } else if has("firefox/") || has("fxios/") {
        Browser::Firefox
    } else if has("chrome/") || has("crios/") || has("chromium/") {
        Browser::Chrome
    } else if has("safari/") && has("version/") {
        Browser::Safari
    } else {
        Browser::Other
    }
}

/// Bytes of Accept-Language inspected, and the most entries considered.
pub const ACCEPT_LANGUAGE_SCAN_LIMIT: usize = 512;
const ACCEPT_LANGUAGE_MAX_ENTRIES: usize = 16;

/// Whether `tag` is a language tag relink accepts: a primary subtag of 1 to
/// 8 letters, then subtags of 1 to 8 letters or digits joined by `-`, 35
/// characters in all (case not checked).
pub fn is_language_tag(tag: &str) -> bool {
    let b = tag.as_bytes();
    if b.is_empty() || b.len() > 35 {
        return false;
    }
    let mut parts = tag.split('-');
    let primary = parts.next().unwrap_or_default();
    (1..=8).contains(&primary.len())
        && primary.bytes().all(|c| c.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_alphanumeric()))
}

/// The visitor's most preferred language from Accept-Language, case as
/// sent: the entry with the highest `q` (the first one on a tie), ignoring
/// `*`, `q=0` and malformed entries. Only the first 512 bytes and 16
/// entries are read.
pub fn preferred_language(accept_language: Option<&[u8]>) -> Option<&str> {
    let raw = accept_language?;
    let raw = &raw[..raw.len().min(ACCEPT_LANGUAGE_SCAN_LIMIT)];
    // A cut in the middle of a UTF-8 character only loses the tail.
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(e) => std::str::from_utf8(&raw[..e.valid_up_to()]).expect("valid prefix"),
    };
    let mut best: Option<(&str, u16)> = None;
    for entry in text.split(',').take(ACCEPT_LANGUAGE_MAX_ENTRIES) {
        let mut parts = entry.split(';');
        let tag = parts.next().unwrap_or_default().trim();
        if tag == "*" || !is_language_tag(tag) {
            continue;
        }
        let mut q = Some(1000);
        for param in parts {
            let param = param.trim();
            if let Some(v) = param
                .strip_prefix("q=")
                .or_else(|| param.strip_prefix("Q="))
            {
                q = parse_qvalue(v.trim());
            }
        }
        match q {
            Some(q) if q > 0 && best.is_none_or(|(_, b)| q > b) => best = Some((tag, q)),
            _ => {}
        }
    }
    best.map(|(tag, _)| tag)
}

/// An RFC 9110 qvalue in thousandths: `0`, `1`, `0.` to three digits, or
/// `1.` followed by up to three zeros.
fn parse_qvalue(v: &str) -> Option<u16> {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    if frac.len() > 3 || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut thousandths: u16 = 0;
    for (i, c) in frac.bytes().enumerate() {
        thousandths += u16::from(c - b'0') * [100, 10, 1][i];
    }
    match int {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// Longest stored referrer host (the DNS limit).
pub const MAX_HOST_LEN: usize = 253;

/// Extracts the lowercase host from a Referer header, without port,
/// credentials or path. Returns `None` when there is no usable host, which is
/// stored as "(direct)".
pub fn referrer_host(referer: Option<&[u8]>) -> Option<String> {
    let raw = std::str::from_utf8(referer?).ok()?.trim();
    let rest = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .or_else(|| {
            // Case-insensitive scheme without allocating.
            let lower = raw.get(..8)?.to_ascii_lowercase();
            if lower == "https://" {
                raw.get(8..)
            } else if lower.starts_with("http://") {
                raw.get(7..)
            } else {
                None
            }
        })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        let end = v6.find(']')?;
        &host_port[..end + 2]
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > MAX_HOST_LEN
        || !host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'[' | b']' | b':')
        })
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// A two-letter country code from the CDN header, uppercased. Anything else
/// (missing, wrong length, non-letters) is unknown.
pub fn country(header: Option<&[u8]>) -> Option<[u8; 2]> {
    match header? {
        [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphanumeric() => {
            Some([a.to_ascii_uppercase(), b.to_ascii_uppercase()])
        }
        _ => None,
    }
}

/// The code stored for clicks whose country is unknown.
pub const UNKNOWN_COUNTRY: [u8; 2] = *b"XX";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices() {
        let cases: &[(&str, Device)] = &[
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
                Device::Desktop,
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
                Device::Desktop,
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                Device::Desktop,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
                Device::Mobile,
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0 Mobile Safari/537.36",
                Device::Mobile,
            ),
            (
                "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Mobile/15E148",
                Device::Tablet,
            ),
            (
                "Mozilla/5.0 (Linux; Android 13; SM-X700) Chrome/120.0 Safari/537.36",
                Device::Tablet,
            ),
            (
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                Device::Bot,
            ),
            ("curl/8.4.0", Device::Bot),
            ("Slackbot-LinkExpanding 1.0", Device::Bot),
            ("SomethingElse/1.0", Device::Other),
            ("", Device::Other),
        ];
        for (ua, want) in cases {
            assert_eq!(device_class(Some(ua.as_bytes())), *want, "{ua}");
        }
        assert_eq!(device_class(None), Device::Other);
        assert_eq!(Device::parse("phone"), None);
        for d in [
            Device::Desktop,
            Device::Mobile,
            Device::Tablet,
            Device::Bot,
            Device::Other,
        ] {
            assert_eq!(Device::parse(d.as_str()), Some(d));
        }
    }

    #[test]
    fn operating_systems_and_browsers() {
        let cases: &[(&str, Os, Browser)] = &[
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
                Os::Windows,
                Browser::Chrome,
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0",
                Os::Windows,
                Browser::Edge,
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
                Os::Macos,
                Browser::Safari,
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                Os::Linux,
                Browser::Firefox,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
                Os::Ios,
                Browser::Safari,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120.0 Mobile/15E148 Safari/604.1",
                Os::Ios,
                Browser::Chrome,
            ),
            (
                "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) FxiOS/120.0 Mobile/15E148",
                Os::Ios,
                Browser::Firefox,
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0 Mobile Safari/537.36",
                Os::Android,
                Browser::Chrome,
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) SamsungBrowser/23.0 Chrome/115.0 Mobile Safari/537.36",
                Os::Android,
                Browser::Samsung,
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36 OPR/105.0",
                Os::Windows,
                Browser::Opera,
            ),
            (
                "Mozilla/5.0 (X11; CrOS x86_64 15633.0.0) Chrome/120.0 Safari/537.36",
                Os::Chromeos,
                Browser::Chrome,
            ),
            ("curl/8.4.0", Os::Other, Browser::Other),
            ("", Os::Other, Browser::Other),
        ];
        for (ua, os, browser) in cases {
            assert_eq!(os_family(Some(ua.as_bytes())), *os, "{ua}");
            assert_eq!(browser_family(Some(ua.as_bytes())), *browser, "{ua}");
        }
        assert_eq!(os_family(None), Os::Other);
        assert_eq!(browser_family(None), Browser::Other);
        for o in Os::ALL {
            assert_eq!(Os::parse(o.as_str()), Some(o));
        }
        for b in Browser::ALL {
            assert_eq!(Browser::parse(b.as_str()), Some(b));
        }
        assert_eq!(Os::parse("iOS"), None);
        assert_eq!(Browser::parse("ie"), None);
    }

    #[test]
    fn languages() {
        let cases: &[(&str, Option<&str>)] = &[
            ("en-US,en;q=0.9,de;q=0.8", Some("en-US")),
            ("de;q=0.5, fr-CA;q=0.9, en;q=0.7", Some("fr-CA")),
            ("*, pt-BR;q=0.1", Some("pt-BR")),
            ("en;q=0, de;q=0.001", Some("de")),
            ("en;q=0", None),
            ("en;q=1.0, de", Some("en")),
            ("en;q=1.5, de;q=0.2", Some("de")),
            ("en;q=0.1234, de;q=0.2", Some("de")),
            ("en;q=x, de;q=0.2", Some("de")),
            ("en;Q=0.2, de;q=0.3", Some("de")),
            ("zh-Hant-TW", Some("zh-Hant-TW")),
            ("toolonglanguage", None),
            ("e1", None),
            ("en-", None),
            ("", None),
        ];
        for (header, want) in cases {
            assert_eq!(
                preferred_language(Some(header.as_bytes())),
                *want,
                "{header}"
            );
        }
        assert_eq!(preferred_language(None), None);
        // Entries past the scan limit are not read.
        let mut long = "x;q=0.1,".repeat(ACCEPT_LANGUAGE_SCAN_LIMIT / 8);
        long.push_str("en");
        assert_eq!(preferred_language(Some(long.as_bytes())), Some("x"));
        let many = format!("{}en", "e;q=0.1,".repeat(16));
        assert_eq!(preferred_language(Some(many.as_bytes())), Some("e"));
        // Invalid UTF-8 ends the header without losing what came before.
        assert_eq!(preferred_language(Some(b"fr,\xffen;q=2")), Some("fr"));
        assert!(is_language_tag("x-private-use1"));
        assert!(!is_language_tag(&format!("en-{}", "abcdefgh-".repeat(4))));
    }

    /// Real User-Agents of automated clients, by kind.
    const BOTS: &[(&str, BotKind)] = &[
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            Crawler,
        ),
        (
            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            Crawler,
        ),
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0 Safari/537.36",
            Crawler,
        ),
        (
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            Crawler,
        ),
        (
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            Crawler,
        ),
        (
            "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
            Crawler,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
            Crawler,
        ),
        (
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            Crawler,
        ),
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            Crawler,
        ),
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            Crawler,
        ),
        ("CCBot/2.0 (https://commoncrawl.org/faq/)", Crawler),
        (
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            Crawler,
        ),
        ("Mozilla/5.0 (compatible; SomeNewCrawler/1.0)", Crawler),
        (
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            Preview,
        ),
        // iMessage, which claims to be Facebook and Twitter.
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0",
            Preview,
        ),
        ("Twitterbot/1.0", Preview),
        (
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
            Preview,
        ),
        (
            "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
            Preview,
        ),
        ("WhatsApp/2.23.20.0 A", Preview),
        ("TelegramBot (like TwitterBot)", Preview),
        (
            "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
            Preview,
        ),
        (
            "Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5 skype-url-preview@microsoft.com",
            Preview,
        ),
        (
            "http.rb/5.1.1 (Mastodon/4.2.1; +https://mastodon.social/) Bot",
            Preview,
        ),
        (
            "Mozilla/5.0 (compatible; Bluesky Cardyb/1.1; +mailto:support@bsky.app)",
            Preview,
        ),
        (
            "Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)",
            Preview,
        ),
        (
            "Mozilla/5.0 (compatible; Embedly/0.2; +http://support.embed.ly/)",
            Preview,
        ),
        (
            "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
            Monitor,
        ),
        (
            "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",
            Monitor,
        ),
        (
            "Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 Chrome-Lighthouse",
            Monitor,
        ),
        ("Datadog/Synthetics", Monitor),
        ("curl/8.4.0", Tool),
        ("Wget/1.21.4", Tool),
        ("python-requests/2.31.0", Tool),
        ("Go-http-client/2.0", Tool),
        ("axios/1.6.2", Tool),
        ("PostmanRuntime/7.36.0", Tool),
        (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0 Safari/537.36",
            Tool,
        ),
        ("Java/17.0.9", Tool),
    ];

    /// Real browsers, in-app browsers included, that must not be bots.
    const PEOPLE: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/440.0.0.0;FBBV/1;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/17.0]",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Instagram 307.0.0.0 (iPhone15,2; iOS 17_0; en_US)",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 [LinkedInApp]/9.29",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 Telegram-Android/10.3.2",
        "Mozilla/5.0 (Linux; Android 10; CUBOT_X30) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) FxiOS/120.0 Mobile/15E148",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    ];

    #[test]
    fn bots_by_kind() {
        for (ua, want) in BOTS {
            assert_eq!(bot_kind(Some(ua.as_bytes())), Some(*want), "{ua}");
            assert_eq!(device_class(Some(ua.as_bytes())), Device::Bot, "{ua}");
            assert_eq!(
                bot_kind(Some(ua.to_ascii_uppercase().as_bytes())),
                Some(*want),
                "case does not matter: {ua}"
            );
        }
        for ua in PEOPLE {
            assert_eq!(bot_kind(Some(ua.as_bytes())), None, "{ua}");
            assert_ne!(device_class(Some(ua.as_bytes())), Device::Bot, "{ua}");
        }
        assert_eq!(
            device_class(Some(PEOPLE[5].as_bytes())),
            Device::Mobile,
            "a CUBOT phone is a phone"
        );
        // A CUBOT phone that runs a crawler is still a crawler.
        assert_eq!(
            bot_kind(Some(b"Mozilla/5.0 (Linux; Android 10; CUBOT_X30) robot")),
            Some(Crawler)
        );
        assert_eq!(bot_kind(None), None);
        assert_eq!(bot_kind(Some(b"")), None);
        assert_eq!(bot_kind(Some(&[0xff; 600])), None);
        for k in BotKind::ALL {
            assert_eq!(BotKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(BotKind::parse("Crawler"), None);
    }

    #[test]
    fn the_named_agent_that_starts_first_wins() {
        // A link-preview fetcher built on an HTTP library.
        assert_eq!(bot_kind(Some(b"Twitterbot/1.0 curl/8.0")), Some(Preview));
        assert_eq!(bot_kind(Some(b"curl/8.0 Twitterbot/1.0")), Some(Tool));
        // A named agent beats an earlier generic word.
        assert_eq!(bot_kind(Some(b"previewer UptimeRobot/2.0")), Some(Monitor));
        // Named agents start a word; inside one, only generic words count.
        assert_eq!(bot_kind(Some(b"Mozilla/5.0 notcurl/1.0")), None);
        assert_eq!(bot_kind(Some(b"Mozilla/5.0 (+notwhatsapp/2)")), None);
        assert_eq!(bot_kind(Some(b"MyGooglebot/1.0")), Some(Crawler));
        assert_eq!(bot_kind(Some(b"x;Twitterbot/1.0")), Some(Preview));
        assert_eq!(
            bot_kind(Some(b"Mozilla/5.0+(compatible;+UptimeRobot/2.0)")),
            Some(Monitor)
        );
    }

    #[test]
    fn every_agent_is_found_by_its_own_token() {
        for &(token, kind) in AGENTS {
            let ua = format!("Mozilla/5.0 (compatible; {token} 1.0)");
            assert_eq!(bot_kind(Some(ua.as_bytes())), Some(kind), "{token}");
        }
        for &(word, kind) in GENERIC_AGENTS {
            let ua = format!("Mozilla/5.0 (x{word}x)");
            assert_eq!(bot_kind(Some(ua.as_bytes())), Some(kind), "{word}");
        }
        let index_len: usize = (0..256).map(|b| usize::from(INDEX[b + 1] - INDEX[b])).sum();
        assert_eq!(index_len, AGENTS.len());
        let pairs: u32 = PAIRS.iter().map(|w| w.count_ones()).sum();
        assert!(pairs > 50 && pairs as usize <= AGENTS.len());
    }

    #[test]
    fn word_starts_agree_with_a_byte_loop() {
        let naive = |bytes: &[u8]| -> Vec<usize> {
            let alnum = |c: u8| c.is_ascii_digit() || c.is_ascii_lowercase();
            (0..bytes.len())
                .filter(|&i| alnum(bytes[i]) && (i == 0 || !alnum(bytes[i - 1])))
                .collect()
        };
        let swar = |bytes: &[u8]| -> Vec<usize> {
            let mut out = Vec::new();
            let mut carry = 0;
            for (k, c) in bytes.chunks(8).enumerate() {
                let mut chunk = [0u8; 8];
                chunk[..c.len()].copy_from_slice(c);
                let (mut s, next) = word_starts(u64::from_le_bytes(chunk), carry);
                carry = next;
                while s != 0 {
                    out.push(k * 8 + (s.trailing_zeros() / 8) as usize);
                    s &= s - 1;
                }
            }
            out
        };
        // Every ASCII byte in every lane, after every other byte.
        for a in 0..128u8 {
            for c in 0..128u8 {
                for lane in 0..8 {
                    let mut v = [b' '; 9];
                    v[lane] = a;
                    v[lane + 1] = c;
                    assert_eq!(swar(&v), naive(&v), "{a} {c} {lane}");
                }
            }
        }
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for len in 0..200 {
            let v: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    b"ab09 /(;_-.z+\x7f\0"[(x % 15) as usize]
                })
                .collect();
            assert_eq!(swar(&v), naive(&v), "{v:?}");
        }
    }

    /// Fails when the lists change without a new [`BOT_LIST_VERSION`]:
    /// update both the version and the digest together.
    #[test]
    fn list_is_versioned() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for &b in bytes.iter().chain(b"\0") {
                h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
        };
        for (token, kind) in AGENTS.iter().chain(GENERIC_AGENTS) {
            feed(token.as_bytes());
            feed(kind.as_str().as_bytes());
        }
        for w in NOT_AGENTS {
            feed(w.as_bytes());
        }
        assert_eq!(
            (BOT_LIST_VERSION, h),
            (1, 0x3422_d88c_a4aa_c1a0),
            "the bot lists changed: bump BOT_LIST_VERSION and update this digest"
        );
    }

    #[test]
    fn bot_token_beyond_scan_limit_is_ignored() {
        let mut ua = "Mozilla/5.0 (Windows NT 10.0) ".to_string();
        ua.push_str(&"x".repeat(UA_SCAN_LIMIT));
        ua.push_str(" bot");
        assert_eq!(device_class(Some(ua.as_bytes())), Device::Desktop);
    }

    #[test]
    fn referrers() {
        let cases: &[(&str, Option<&str>)] = &[
            ("https://www.Example.com/path?q=1", Some("www.example.com")),
            ("http://news.example.org:8080/", Some("news.example.org")),
            ("HTTPS://Example.com", Some("example.com")),
            ("Http://example.com.", Some("example.com")),
            ("https://user:pw@example.net/x", Some("example.net")),
            ("https://[2001:db8::1]:443/", Some("[2001:db8::1]")),
            ("https://[2001:db8::1", None),
            ("android-app://com.example", None),
            ("https://", None),
            ("https:///path", None),
            ("https://exa mple.com/", None),
            ("", None),
            ("x", None),
        ];
        for (input, want) in cases {
            assert_eq!(
                referrer_host(Some(input.as_bytes())).as_deref(),
                *want,
                "{input}"
            );
        }
        assert_eq!(referrer_host(None), None);
        assert_eq!(referrer_host(Some(&[0xff, 0xfe])), None);
        let long = format!("https://{}.com/", "a".repeat(300));
        assert_eq!(referrer_host(Some(long.as_bytes())), None);
    }

    #[test]
    fn countries() {
        assert_eq!(country(Some(b"us")), Some(*b"US"));
        assert_eq!(country(Some(b"DE")), Some(*b"DE"));
        assert_eq!(country(Some(b"T1")), Some(*b"T1"));
        assert_eq!(country(Some(b"USA")), None);
        assert_eq!(country(Some(b"1A")), None);
        assert_eq!(country(Some(b"")), None);
        assert_eq!(country(None), None);
    }
}

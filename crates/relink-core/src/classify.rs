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

/// Classifies a User-Agent with simple token rules, in this order: bots,
/// tablets, phones, desktops. This is deliberately coarse; the goal is a
/// stable breakdown, not browser identification.
pub fn device_class(user_agent: Option<&[u8]>) -> Device {
    let mut buf = [0u8; UA_SCAN_LIMIT];
    let ua = lowercase_prefix(user_agent, &mut buf);
    if ua.is_empty() {
        return Device::Other;
    }
    let has = |needle: &str| ua.contains(needle);
    if has("bot")
        || has("crawl")
        || has("spider")
        || has("slurp")
        || has("facebookexternalhit")
        || has("preview")
        || has("curl/")
        || has("wget/")
        || has("python-requests")
        || has("go-http-client")
    {
        return Device::Bot;
    }
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

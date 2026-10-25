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
        [
            Device::Desktop,
            Device::Mobile,
            Device::Tablet,
            Device::Bot,
            Device::Other,
        ]
        .into_iter()
        .find(|d| d.as_str() == s)
    }
}

/// Only the start of the header is inspected; real User-Agents put the
/// interesting tokens early, and this bounds the work per request.
const UA_SCAN_LIMIT: usize = 512;

/// Classifies a User-Agent with simple token rules, in this order: bots,
/// tablets, phones, desktops. This is deliberately coarse; the goal is a
/// stable breakdown, not browser identification.
pub fn device_class(user_agent: Option<&[u8]>) -> Device {
    let Some(raw) = user_agent else {
        return Device::Other;
    };
    let len = raw.len().min(UA_SCAN_LIMIT);
    if len == 0 {
        return Device::Other;
    }
    // Lowercase once into a stack buffer, then use substring search. Bytes
    // outside ASCII are replaced so the buffer is always valid UTF-8.
    let mut buf = [0u8; UA_SCAN_LIMIT];
    for (dst, &b) in buf.iter_mut().zip(&raw[..len]) {
        *dst = if b.is_ascii() {
            b.to_ascii_lowercase()
        } else {
            b'?'
        };
    }
    let ua = std::str::from_utf8(&buf[..len]).expect("ASCII is UTF-8");
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

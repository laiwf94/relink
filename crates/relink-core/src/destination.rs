//! Destination URL validation and normalisation.
//!
//! Every URL a link can send visitors to (destinations and fallbacks) goes
//! through [`normalize`] before it is stored. The rules keep the redirect
//! service from becoming a tool for phishing via credentials in URLs, and keep
//! the health checker from being pointed at internal services.

use std::fmt;
use std::net::IpAddr;

use url::{Host, Url};

use crate::netguard::is_public_ip;

/// Longest accepted destination, before and after normalisation. Browsers
/// and CDNs handle much longer URLs, but nothing legitimate needs more here.
pub const MAX_URL_LEN: usize = 2048;

/// Which hosts are acceptable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Accept IP-address hosts such as `http://203.0.113.7/` (public ones only,
    /// unless `allow_private` is also set).
    pub allow_ip_literals: bool,
    /// Accept loopback, private, link-local and other non-public hosts,
    /// including single-label names like `intranet`. For development only.
    pub allow_private: bool,
}

/// Why a URL was refused. The variants map to stable messages in the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    Empty,
    TooLong,
    Malformed,
    Scheme,
    Credentials,
    MissingHost,
    IpLiteral,
    NonPublicHost,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UrlError::Empty => "URL is empty",
            UrlError::TooLong => "URL is longer than 2048 characters",
            UrlError::Malformed => "URL is not a valid absolute URL",
            UrlError::Scheme => "URL must use http or https",
            UrlError::Credentials => "URL must not contain a user name or password",
            UrlError::MissingHost => "URL must have a host",
            UrlError::IpLiteral => "URL host must be a domain name, not an IP address",
            UrlError::NonPublicHost => "URL host is not a public internet address",
        })
    }
}

impl std::error::Error for UrlError {}

/// Domain suffixes that never resolve on the public internet (RFC 6761,
/// RFC 6762, RFC 8375) plus the `internal` name reserved for private use.
const NON_PUBLIC_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "home.arpa",
    "test",
    "invalid",
    "example",
    "onion",
];

/// Validates `raw` and returns its normalised form (WHATWG serialisation:
/// lowercase scheme and host, IDNA to punycode, default port removed, path
/// percent-encoded).
pub fn normalize(raw: &str, policy: Policy) -> Result<String, UrlError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UrlError::Empty);
    }
    if trimmed.len() > MAX_URL_LEN {
        return Err(UrlError::TooLong);
    }
    let url = Url::parse(trimmed).map_err(|_| UrlError::Malformed)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(UrlError::Scheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlError::Credentials);
    }
    match url.host() {
        None => return Err(UrlError::MissingHost),
        Some(Host::Domain(domain)) => check_domain(domain, policy)?,
        Some(Host::Ipv4(ip)) => check_ip(IpAddr::V4(ip), policy)?,
        Some(Host::Ipv6(ip)) => check_ip(IpAddr::V6(ip), policy)?,
    }
    let out = String::from(url);
    if out.len() > MAX_URL_LEN {
        return Err(UrlError::TooLong);
    }
    Ok(out)
}

fn check_ip(ip: IpAddr, policy: Policy) -> Result<(), UrlError> {
    if policy.allow_private {
        return Ok(());
    }
    if !policy.allow_ip_literals {
        return Err(UrlError::IpLiteral);
    }
    if !is_public_ip(ip) {
        return Err(UrlError::NonPublicHost);
    }
    Ok(())
}

fn check_domain(domain: &str, policy: Policy) -> Result<(), UrlError> {
    if domain.is_empty() {
        return Err(UrlError::MissingHost);
    }
    if policy.allow_private {
        return Ok(());
    }
    let name = domain.strip_suffix('.').unwrap_or(domain);
    // Single-label names ("intranet", "db") resolve through search domains
    // to internal hosts.
    if !name.contains('.') {
        return Err(UrlError::NonPublicHost);
    }
    for suffix in NON_PUBLIC_SUFFIXES {
        if name == *suffix
            || (name.len() > suffix.len()
                && name.ends_with(suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
        {
            return Err(UrlError::NonPublicHost);
        }
    }
    Ok(())
}

/// The host part of a stored (already normalised) URL, used to rate limit
/// health checks per host.
pub fn host_of(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: Policy = Policy {
        allow_ip_literals: false,
        allow_private: false,
    };

    #[test]
    fn normalises() {
        assert_eq!(
            normalize("  HTTPS://Example.COM:443/a b?q=1#frag ", STRICT).unwrap(),
            "https://example.com/a%20b?q=1#frag"
        );
        assert_eq!(
            normalize("http://bücher.example.org/", STRICT).unwrap(),
            "http://xn--bcher-kva.example.org/"
        );
        assert_eq!(
            normalize("https://example.com", STRICT).unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn rejects() {
        let cases = [
            ("", UrlError::Empty),
            ("   ", UrlError::Empty),
            ("not a url", UrlError::Malformed),
            ("/relative", UrlError::Malformed),
            ("ftp://example.com/", UrlError::Scheme),
            ("javascript:alert(1)", UrlError::Scheme),
            ("data:text/html,hi", UrlError::Scheme),
            ("https://user:pw@example.com/", UrlError::Credentials),
            ("https://user@example.com/", UrlError::Credentials),
            ("https://localhost/", UrlError::NonPublicHost),
            ("https://api.localhost/", UrlError::NonPublicHost),
            ("https://printer.local/", UrlError::NonPublicHost),
            ("https://db.internal./", UrlError::NonPublicHost),
            ("https://router.home.arpa/", UrlError::NonPublicHost),
            ("https://intranet/", UrlError::NonPublicHost),
            ("http://127.0.0.1/", UrlError::IpLiteral),
            ("http://2130706433/", UrlError::IpLiteral),
            ("http://[::1]/", UrlError::IpLiteral),
            ("http://8.8.8.8/", UrlError::IpLiteral),
        ];
        for (input, want) in cases {
            assert_eq!(normalize(input, STRICT), Err(want), "{input}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(normalize(&long, STRICT), Err(UrlError::TooLong));
        // Grows past the limit only once spaces are percent-encoded.
        let grows = format!("https://example.com/{}", " a".repeat(1000));
        assert_eq!(normalize(&grows, STRICT), Err(UrlError::TooLong));
    }

    #[test]
    fn suffix_match_is_on_label_boundary() {
        assert!(normalize("https://notlocal/", STRICT).is_err());
        assert!(normalize("https://mylocal.com/", STRICT).is_ok());
        assert!(normalize("https://gettest.io/", STRICT).is_ok());
        assert!(normalize("https://example.com.local/", STRICT).is_err());
    }

    #[test]
    fn ip_literal_policy() {
        let literals = Policy {
            allow_ip_literals: true,
            allow_private: false,
        };
        assert_eq!(
            normalize("http://8.8.8.8/x", literals).unwrap(),
            "http://8.8.8.8/x"
        );
        assert_eq!(
            normalize("http://10.0.0.1/", literals),
            Err(UrlError::NonPublicHost)
        );
        assert_eq!(
            normalize("http://[::ffff:169.254.169.254]/", literals),
            Err(UrlError::NonPublicHost)
        );
        let private = Policy {
            allow_ip_literals: false,
            allow_private: true,
        };
        assert!(normalize("http://127.0.0.1:8080/", private).is_ok());
        assert!(normalize("http://localhost/", private).is_ok());
    }

    #[test]
    fn errors_have_messages() {
        for e in [
            UrlError::Empty,
            UrlError::TooLong,
            UrlError::Malformed,
            UrlError::Scheme,
            UrlError::Credentials,
            UrlError::MissingHost,
            UrlError::IpLiteral,
            UrlError::NonPublicHost,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("https://example.com/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("nope"), None);
    }
}

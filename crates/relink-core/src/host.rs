//! Reading the host a request is for, the same way at the origin and at the
//! edge, so both agree on which requests could be for a custom domain.

/// Longest hostname (RFC 1035 section 2.3.4, without the final dot).
pub const MAX_HOSTNAME: usize = 253;

/// Whether `host` (lowercase, no final dot) is a hostname the `domains`
/// table accepts: at least two labels of `[a-z0-9-]`, 1 to 63 characters,
/// no hyphen at either end, 253 characters in all, and a top-level label
/// that is not all digits (that would be an IPv4 address).
pub fn is_valid_hostname(host: &str) -> bool {
    !host.bytes().any(|b| b.is_ascii_uppercase()) && could_be_domain(host)
}

/// [`is_valid_hostname`] ignoring case: whether a `Host` could name a
/// verified domain at all. IP addresses and single labels never can.
pub fn could_be_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOSTNAME {
        return false;
    }
    let mut labels = 0;
    let mut last = "";
    for l in host.split('.') {
        let ok = !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return false;
        }
        labels += 1;
        last = l;
    }
    labels >= 2 && !last.bytes().all(|b| b.is_ascii_digit())
}

/// The host part of a `Host` header value: without the port and the final
/// dot, case preserved. `None` for an IP literal in brackets, a malformed
/// port, or anything that cannot be a hostname; those requests can only be
/// for the default domain.
pub fn host_part(raw: &[u8]) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_HOSTNAME + 7 || raw[0] == b'[' {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?;
    let host = match s.rsplit_once(':') {
        Some((h, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            h
        }
        None => s,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    let ok = !host.is_empty()
        && host.len() <= MAX_HOSTNAME
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    ok.then_some(host)
}

/// The host of a request that could be for a custom domain, as sent (case
/// preserved; compare in lowercase). `None` means the request is for the
/// default domain whatever domains exist: no `Host`, one that cannot be a
/// hostname (an IP address, a single label, a malformed port), or
/// `default_host` itself.
pub fn custom_host<'a>(host_header: Option<&'a [u8]>, default_host: &str) -> Option<&'a str> {
    let host = host_part(host_header?)?;
    (!host.eq_ignore_ascii_case(default_host) && could_be_domain(host)).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_headers_are_reduced_to_their_host() {
        assert_eq!(host_part(b"Go.Example.com:8443"), Some("Go.Example.com"));
        assert_eq!(host_part(b"go.example.com."), Some("go.example.com"));
        assert_eq!(host_part(b"go.example.com.:80"), Some("go.example.com"));
        assert_eq!(host_part(b"[::1]:80"), None);
        assert_eq!(host_part(b"go.example.com:"), None);
        assert_eq!(host_part(b"go.example.com:123456"), None);
        assert_eq!(host_part(b"go.example.com:8x"), None);
        assert_eq!(host_part(b""), None);
        assert_eq!(host_part(b"."), None);
        assert_eq!(host_part(b"a b"), None);
        assert_eq!(host_part(&[0xff, b'a']), None);
        assert_eq!(host_part("x".repeat(300).as_bytes()), None);
    }

    #[test]
    fn hostnames() {
        assert!(is_valid_hostname("go.example.com"));
        assert!(is_valid_hostname("xn--bcher-kva.example"));
        assert!(!is_valid_hostname("Go.example.com"));
        assert!(could_be_domain("Go.example.com"));
        for bad in [
            "",
            "localhost",
            "10.0.0.1",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            "a_b.example.com",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(!could_be_domain(bad), "{bad}");
        }
    }

    #[test]
    fn only_possible_domains_are_custom_hosts() {
        let d = "relink.example";
        assert_eq!(custom_host(None, d), None);
        assert_eq!(custom_host(Some(b"Relink.Example:443"), d), None);
        assert_eq!(custom_host(Some(b"127.0.0.1:8080"), d), None);
        assert_eq!(custom_host(Some(b"localhost"), d), None);
        assert_eq!(custom_host(Some(b"[::1]"), d), None);
        assert_eq!(
            custom_host(Some(b"Go.Example.com:443"), d),
            Some("Go.Example.com")
        );
        assert_eq!(
            custom_host(Some(b"go.example.com"), ""),
            Some("go.example.com")
        );
    }
}

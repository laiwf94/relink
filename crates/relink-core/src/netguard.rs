//! Classifies IP addresses as publicly routable or not.
//!
//! Used twice: when a destination URL is created (IP literals) and when the
//! health checker resolves a host name (every resolved address). The second
//! check is what actually stops server-side request forgery, because a public
//! looking name can resolve to `127.0.0.1` or change its answer later.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns true only for addresses that are globally routable unicast.
///
/// IPv4 blocks follow the IANA special-purpose registry (RFC 6890 and
/// successors). IPv6 is an allow list: only `2000::/3` global unicast is
/// accepted, minus documentation, benchmarking and protocol ranges, and any
/// IPv6 form that embeds an IPv4 address (mapped, NAT64, 6to4) is judged by the
/// embedded address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let blocked = a == 0                                  // "this network"
        || a == 10                                        // private
        || (a == 100 && (b & 0xc0) == 64)                 // carrier-grade NAT 100.64/10
        || a == 127                                       // loopback
        || (a == 169 && b == 254)                         // link-local, cloud metadata
        || (a == 172 && (b & 0xf0) == 16)                 // private 172.16/12
        || (a == 192 && b == 0 && c == 0)                 // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)                 // documentation
        || (a == 192 && b == 88 && c == 99)               // 6to4 relay anycast
        || (a == 192 && b == 168)                         // private
        || (a == 198 && (b & 0xfe) == 18)                 // benchmarking 198.18/15
        || (a == 198 && b == 51 && c == 100)              // documentation
        || (a == 203 && b == 0 && c == 113)               // documentation
        || a >= 224; // multicast, reserved, broadcast
    !blocked
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    let embedded_v4 =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return is_public_v4(embedded_v4(s[6], s[7]));
    }
    // 6to4 2002::/16 carries an IPv4 address in bits 16..48.
    if s[0] == 0x2002 {
        return is_public_v4(embedded_v4(s[1], s[2]));
    }
    // Only global unicast 2000::/3 is reachable on the internet.
    if (s[0] & 0xe000) != 0x2000 {
        return false;
    }
    let blocked = (s[0] == 0x2001 && s[1] < 0x0200)       // IETF protocol assignments, Teredo, benchmarking
        || (s[0] == 0x2001 && s[1] == 0x0db8)             // documentation
        || (s[0] == 0x3fff && s[1] < 0x1000); // documentation 3fff::/20
    !blocked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(s: &str) -> bool {
        is_public_ip(s.parse().unwrap())
    }

    #[test]
    fn ipv4_ranges() {
        for blocked in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public(blocked), "{blocked} should be blocked");
        }
        for open in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(public(open), "{open} should be public");
        }
    }

    #[test]
    fn ipv6_ranges() {
        for blocked in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2002:c0a8:101::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2001:2::1",
            "3fff::1",
            "100::1",
            "::127.0.0.1",
        ] {
            assert!(!public(blocked), "{blocked} should be blocked");
        }
        for open in [
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:4860::8888",
        ] {
            assert!(public(open), "{open} should be public");
        }
    }
}

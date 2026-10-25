//! Which proxies may tell us who the client is.
//!
//! `X-Forwarded-For`, `CF-Connecting-IP` and `CF-IPCountry` are plain request
//! headers: any client can send them. They mean something only when the
//! socket peer is a proxy we run or pay for, and even then only the entries
//! that proxy appended. So headers are read only from peers inside
//! `RELINK_TRUSTED_PROXIES`, and the client address is the rightmost entry
//! that is not itself a trusted proxy.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// An address block such as `10.0.0.0/8` or `2001:db8::/32`. A bare address
/// is a block of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrError(String);

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not an address or address/prefix", self.0)
    }
}

impl std::error::Error for CidrError {}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Cidr, CidrError> {
        let err = || CidrError(s.to_owned());
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = addr.trim().parse().map_err(|_| err())?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => max,
            Some(b) if !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()) && b.len() <= 3 => {
                b.parse::<u8>().map_err(|_| err())?
            }
            Some(_) => return Err(err()),
        };
        if bits > max {
            return Err(err());
        }
        Ok(Cidr {
            net: net.to_canonical(),
            bits,
        })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The configured proxy blocks. Empty means no forwarding header is trusted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// Parses a comma-separated list.
    pub fn parse(list: &str) -> Result<TrustedProxies, CidrError> {
        list.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Cidr::from_str)
            .collect::<Result<_, _>>()
            .map(TrustedProxies)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// The client address for a request from `peer` carrying `forwarded` (a
    /// comma-separated list, oldest hop first). Falls back to `peer` when the
    /// peer is not trusted or the header has nothing usable.
    pub fn client_ip(&self, peer: IpAddr, forwarded: Option<&str>) -> IpAddr {
        let Some(list) = forwarded.filter(|_| self.contains(peer)) else {
            return peer;
        };
        let hops: Vec<IpAddr> = list
            .split(',')
            .filter_map(|h| h.trim().parse::<IpAddr>().ok())
            .collect();
        hops.iter()
            .rev()
            .find(|ip| !self.contains(**ip))
            .or(hops.first())
            .copied()
            .unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_blocks() {
        assert!(
            "10.0.0.0/8"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("10.9.8.7"))
        );
        assert!(
            !"10.0.0.0/8"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("11.0.0.1"))
        );
        assert!("0.0.0.0/0".parse::<Cidr>().unwrap().contains(ip("8.8.8.8")));
        assert!("::/0".parse::<Cidr>().unwrap().contains(ip("2001:db8::1")));
        assert!(
            "2001:db8::/32"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("2001:db8:ffff::1"))
        );
        assert!(
            "203.0.113.5"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("203.0.113.5"))
        );
        assert!(
            !"203.0.113.5"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("203.0.113.6"))
        );
        // IPv4-mapped IPv6 peers match IPv4 blocks.
        assert!(
            "10.0.0.0/8"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("::ffff:10.0.0.1"))
        );
        assert!(
            !"10.0.0.0/8"
                .parse::<Cidr>()
                .unwrap()
                .contains(ip("2001:db8::1"))
        );
        for bad in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "x/8",
            "10.0.0.0/8/8",
            "10.0.0.0/+8",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
        assert!(!CidrError("x".into()).to_string().is_empty());
    }

    #[test]
    fn client_ip_uses_rightmost_untrusted_hop() {
        let t = TrustedProxies::parse("10.0.0.0/8, 192.0.2.10").unwrap();
        assert!(!t.is_empty());
        let proxy = ip("10.1.1.1");
        // A client spoofs the first entry; the proxy appended the real one.
        assert_eq!(
            t.client_ip(proxy, Some("1.2.3.4, 198.51.100.7")),
            ip("198.51.100.7")
        );
        // Trusted hops at the end are skipped.
        assert_eq!(
            t.client_ip(proxy, Some("198.51.100.7, 192.0.2.10, 10.2.2.2")),
            ip("198.51.100.7")
        );
        // Everything trusted: the oldest hop.
        assert_eq!(
            t.client_ip(proxy, Some("10.3.3.3, 10.4.4.4")),
            ip("10.3.3.3")
        );
        // Garbage or absent header: the socket peer.
        assert_eq!(t.client_ip(proxy, Some("nonsense")), proxy);
        assert_eq!(t.client_ip(proxy, None), proxy);
        // An untrusted peer's header is ignored entirely.
        let stranger = ip("198.51.100.99");
        assert_eq!(t.client_ip(stranger, Some("1.2.3.4")), stranger);
        assert!(TrustedProxies::default().is_empty());
        assert!(TrustedProxies::parse("10.0.0.0/8,bogus").is_err());
    }
}

//! The visitor fingerprint used for unique counts. The edge and the origin
//! must compute the same value for the same visitor, or a visitor who moves
//! between them is counted twice, so it lives here.

use std::net::IpAddr;

use sha2::{Digest, Sha256};

/// Bytes of User-Agent included in the fingerprint.
pub const UA_FINGERPRINT_LIMIT: usize = 256;

/// SHA-256 over (address, User-Agent prefix), truncated to 16 bytes. This
/// never leaves process memory; what gets stored is an HMAC of it under a
/// daily salt (see the server's `clicks` module).
pub fn fingerprint(ip: IpAddr, user_agent: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"relink-visitor\0");
    match ip {
        IpAddr::V4(v4) => h.update(v4.octets()),
        IpAddr::V6(v6) => h.update(v6.octets()),
    }
    h.update([0u8]);
    h.update(&user_agent[..user_agent.len().min(UA_FINGERPRINT_LIMIT)]);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differs_by_address_and_ignores_long_user_agent_tails() {
        let a = fingerprint("203.0.113.1".parse().unwrap(), b"ua");
        let b = fingerprint("203.0.113.2".parse().unwrap(), b"ua");
        let c = fingerprint("2001:db8::1".parse().unwrap(), b"ua");
        assert_ne!(a, b);
        assert_ne!(a, c);
        let long1 = [b'x'; 300];
        let mut long2 = [b'x'; 300];
        long2[299] = b'y';
        let ip = "203.0.113.1".parse().unwrap();
        assert_eq!(fingerprint(ip, &long1), fingerprint(ip, &long2));
    }
}

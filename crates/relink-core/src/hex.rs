//! Lowercase hex, enough for MAC tags and cursors without another dependency.

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes hex in either case. `None` for odd lengths or non-hex characters.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| Some((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode(&data);
        assert_eq!(encoded.len(), 512);
        assert_eq!(decode(&encoded).unwrap(), data);
        assert_eq!(decode(&encoded.to_uppercase()).unwrap(), data);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }
}

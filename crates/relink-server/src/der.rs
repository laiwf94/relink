//! Just enough ASN.1 DER for ACME (src/acme.rs): writing the PKCS#10
//! certificate request for a certificate key, reading the validity period
//! and subject alternative names of an issued X.509 certificate, and PEM
//! armour with standard base64.
//!
//! The reader is strict DER: definite lengths in their shortest form, no
//! trailing bytes, and every length checked against what is left, so an
//! untrusted certificate can make it return `None` but never panic or
//! allocate more than its own size.

use chrono::{DateTime, NaiveDate, Utc};

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

/// `id-ecPublicKey` (RFC 5480).
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`, the P-256 curve (RFC 5480).
pub const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256` (RFC 5758).
pub const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `id-at-commonName`.
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `pkcs-9-at-extensionRequest` (RFC 2985).
pub const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
/// `id-ce-subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// `[n]` constructed, context-specific.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// `[n]` primitive, context-specific (`dNSName` in a `GeneralName` is `[2]`).
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// One TLV with `content` as its value.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A constructed value of `parts`, concatenated.
pub fn constructed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    constructed(TAG_SEQUENCE, parts)
}

pub fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(TAG_OID, encoded)
}

/// A non-negative INTEGER from big-endian magnitude bytes.
pub fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len().saturating_sub(1));
    let m = if magnitude.is_empty() {
        &[0u8][..]
    } else {
        &magnitude[start..]
    };
    let mut content = Vec::with_capacity(m.len() + 1);
    if m[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(m);
    tlv(TAG_INTEGER, &content)
}

/// A BIT STRING with no unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0);
    content.extend_from_slice(bytes);
    tlv(TAG_BIT_STRING, &content)
}

/// The `SubjectPublicKeyInfo` of a P-256 key from its uncompressed point.
pub fn p256_spki(point: &[u8]) -> Vec<u8> {
    sequence(&[
        &sequence(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P256)]),
        &bit_string(point),
    ])
}

/// `AlgorithmIdentifier` for ECDSA with SHA-256 (no parameters).
pub fn ecdsa_sha256_algorithm() -> Vec<u8> {
    sequence(&[&oid(OID_ECDSA_SHA256)])
}

/// A `Name` with a single common name.
pub fn common_name(cn: &str) -> Vec<u8> {
    sequence(&[&constructed(
        TAG_SET,
        &[&sequence(&[
            &oid(OID_COMMON_NAME),
            &tlv(TAG_UTF8_STRING, cn.as_bytes()),
        ])],
    )])
}

/// The `subjectAltName` extension value: `GeneralNames` of DNS names.
pub fn dns_names(names: &[&str]) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = names
        .iter()
        .map(|n| tlv(context_primitive(2), n.as_bytes()))
        .collect();
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    sequence(&refs)
}

/// An `Extension` (not critical) with `value` as its `extnValue`.
pub fn extension(id: &[u8], value: &[u8]) -> Vec<u8> {
    sequence(&[&oid(id), &tlv(TAG_OCTET_STRING, value)])
}

/// The `CertificationRequestInfo` of a PKCS#10 request (RFC 2986) for
/// `names`, the first also the common name, with the P-256 key `point`.
/// Signed by the caller and wrapped with [`certification_request`].
pub fn certification_request_info(names: &[&str], point: &[u8]) -> Vec<u8> {
    let san = extension(OID_SUBJECT_ALT_NAME, &dns_names(names));
    let attribute = sequence(&[
        &oid(OID_EXTENSION_REQUEST),
        &constructed(TAG_SET, &[&sequence(&[&san])]),
    ]);
    sequence(&[
        &unsigned_integer(&[0]),
        &common_name(names.first().copied().unwrap_or_default()),
        &p256_spki(point),
        &constructed(context(0), &[&attribute]),
    ])
}

/// A signed request: the info, the algorithm and the ASN.1 ECDSA signature.
pub fn certification_request(info: &[u8], signature: &[u8]) -> Vec<u8> {
    sequence(&[info, &ecdsa_sha256_algorithm(), &bit_string(signature)])
}

/// A DER reader over one buffer.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

/// One element: its tag, its value, and its whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Element<'a> {
    /// A reader over the value of a constructed element.
    pub fn contents(&self) -> Reader<'a> {
        Reader::new(self.value)
    }
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next element, if well formed. Tags must fit one byte (every tag
    /// X.509 uses does).
    pub fn read(&mut self) -> Option<Element<'a>> {
        let buf = self.buf;
        let (&tag, rest) = buf.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            // Shortest form only.
            if len < 0x80 {
                return None;
            }
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        let header = buf.len() - rest.len();
        let element = Element {
            tag,
            value: &rest[..len],
            raw: &buf[..header + len],
        };
        self.buf = &rest[len..];
        Some(element)
    }

    /// The next element, which must have `tag`.
    pub fn expect(&mut self, tag: u8) -> Option<Element<'a>> {
        self.read().filter(|e| e.tag == tag)
    }

    /// Skips the next element if it has `tag`; returns it if so.
    pub fn optional(&mut self, tag: u8) -> Option<Element<'a>> {
        if self.buf.first() == Some(&tag) {
            self.read()
        } else {
            None
        }
    }

    /// `Some(())` when nothing is left.
    pub fn finish(&self) -> Option<()> {
        self.buf.is_empty().then_some(())
    }
}

/// Parses one element that must span all of `buf`.
pub fn parse_one(buf: &[u8], tag: u8) -> Option<Element<'_>> {
    let mut r = Reader::new(buf);
    let e = r.expect(tag)?;
    r.finish()?;
    Some(e)
}

fn digits(s: &[u8]) -> Option<u32> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        s.iter()
            .fold(0u32, |acc, &b| acc * 10 + u32::from(b - b'0')),
    )
}

/// A `Time`: UTCTime `YYMMDDHHMMSSZ` (years 1950 to 2049) or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`, the only forms RFC 5280 allows.
pub fn parse_time(e: &Element<'_>) -> Option<DateTime<Utc>> {
    let v = e.value;
    let (year, rest) = match e.tag {
        TAG_UTC_TIME if v.len() == 13 => {
            let yy = digits(&v[..2])? as i32;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        TAG_GENERALIZED_TIME if v.len() == 15 => (digits(&v[..4])? as i32, &v[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let field = |i: usize| digits(&rest[i..i + 2]);
    NaiveDate::from_ymd_opt(year, field(0)?, field(2)?)?
        .and_hms_opt(field(4)?, field(6)?, field(8)?)
        .map(|t| t.and_utc())
}

/// What relink needs from an issued certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// DNS names in the subject alternative name extension.
    pub dns_names: Vec<String>,
    /// The `SubjectPublicKeyInfo`, whole.
    pub spki: Vec<u8>,
}

/// Reads the validity, the DNS names and the public key of an X.509
/// certificate (RFC 5280). The signature is not checked: the certificate
/// came from the CA over TLS and is checked against the key relink
/// generated, which is what matters for serving it.
pub fn parse_certificate(der: &[u8]) -> Option<CertInfo> {
    let cert = parse_one(der, TAG_SEQUENCE)?;
    let mut c = cert.contents();
    let tbs = c.expect(TAG_SEQUENCE)?;
    c.expect(TAG_SEQUENCE)?; // signatureAlgorithm
    c.expect(TAG_BIT_STRING)?;
    c.finish()?;
    let mut t = tbs.contents();
    t.optional(context(0)); // version
    t.expect(TAG_INTEGER)?; // serialNumber
    t.expect(TAG_SEQUENCE)?; // signature
    t.expect(TAG_SEQUENCE)?; // issuer
    let validity = t.expect(TAG_SEQUENCE)?;
    t.expect(TAG_SEQUENCE)?; // subject
    let spki = t.expect(TAG_SEQUENCE)?;
    t.optional(context_primitive(1)); // issuerUniqueID
    t.optional(context_primitive(2)); // subjectUniqueID
    let mut dns_names = Vec::new();
    if let Some(exts) = t.optional(context(3)) {
        let list = parse_one(exts.value, TAG_SEQUENCE)?;
        let mut l = list.contents();
        while !l.is_empty() {
            let ext = l.expect(TAG_SEQUENCE)?;
            let mut x = ext.contents();
            let id = x.expect(TAG_OID)?;
            x.optional(TAG_BOOLEAN);
            let value = x.expect(TAG_OCTET_STRING)?;
            x.finish()?;
            if id.value == OID_SUBJECT_ALT_NAME {
                let names = parse_one(value.value, TAG_SEQUENCE)?;
                let mut n = names.contents();
                while let Some(name) = n.read() {
                    if name.tag == context_primitive(2) {
                        dns_names.push(String::from_utf8(name.value.to_vec()).ok()?);
                    }
                }
            }
        }
    }
    t.finish()?;
    let mut v = validity.contents();
    let not_before = parse_time(&v.read()?)?;
    let not_after = parse_time(&v.read()?)?;
    v.finish()?;
    (not_after > not_before).then(|| CertInfo {
        not_before,
        not_after,
        dns_names,
        spki: spki.raw.to_vec(),
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | ((b as u32) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64, padded, ignoring ASCII whitespace (PEM wraps
/// lines). Anything else outside the alphabet is refused.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let chunks = clean.len() / 4;
    for (i, chunk) in clean.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != chunks) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in chunk[..4 - pad].iter().enumerate() {
            n |= (value(c)? as u32) << (18 - 6 * j);
        }
        out.extend((0..3 - pad).map(|j| (n >> (16 - 8 * j)) as u8));
    }
    Some(out)
}

/// PEM armour for `der` with `label`, lines of 64 characters.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = b64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Every `label` block in `pem`, decoded, in order. `None` if a block is
/// malformed or unterminated; text between blocks is ignored, as RFC 7468
/// allows.
pub fn pem_decode_all(pem: &str, label: &str) -> Option<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(&begin) {
        let body = &rest[start + begin.len()..];
        let stop = body.find(&end)?;
        out.push(b64_decode(&body[..stop])?);
        rest = &body[stop + end.len()..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn lengths_use_the_shortest_form() {
        assert_eq!(tlv(0x04, &[]), [0x04, 0x00]);
        assert_eq!(tlv(0x04, &[7; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(0x04, &[7; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[7; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
        for n in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0x1_0000] {
            let enc = tlv(0x04, &vec![1; n]);
            let e = parse_one(&enc, 0x04).unwrap();
            assert_eq!(e.value.len(), n);
            assert_eq!(e.raw, &enc[..]);
        }
    }

    #[test]
    fn integers_are_minimal_and_non_negative() {
        assert_eq!(unsigned_integer(&[0]), [0x02, 0x01, 0x00]);
        assert_eq!(unsigned_integer(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(unsigned_integer(&[0, 0, 5]), [0x02, 0x01, 0x05]);
        assert_eq!(unsigned_integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(unsigned_integer(&[0, 0xff, 1]), [0x02, 0x03, 0x00, 0xff, 1]);
    }

    #[test]
    fn the_reader_refuses_non_der() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x02, 0x01],             // short
            &[0x30, 0x81, 0x05, 0, 0, 0, 0], // long form for a short length
            &[0x30, 0x80, 0x00, 0x00],       // indefinite
            &[0x30, 0x82, 0x00, 0x80],       // leading zero in the length
            &[0x1f, 0x01, 0x00],             // multi-byte tag
            &[0x30, 0x85, 1, 1, 1, 1, 1],    // length too long
        ] {
            assert_eq!(Reader::new(bad).read(), None, "{bad:x?}");
        }
        // Trailing bytes after the one element.
        assert_eq!(parse_one(&[0x05, 0x00, 0x00], 0x05), None);
        assert_eq!(parse_one(&[0x05, 0x00], 0x04), None);
    }

    #[test]
    fn times_follow_rfc_5280() {
        fn utc(s: &str) -> Element<'_> {
            Element {
                tag: TAG_UTC_TIME,
                value: s.as_bytes(),
                raw: &[],
            }
        }
        fn gen_(s: &str) -> Element<'_> {
            Element {
                tag: TAG_GENERALIZED_TIME,
                value: s.as_bytes(),
                raw: &[],
            }
        }
        let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        assert_eq!(
            parse_time(&utc("261109120000Z")),
            Some(at("2026-11-09T12:00:00Z"))
        );
        assert_eq!(
            parse_time(&utc("500101000000Z")),
            Some(at("1950-01-01T00:00:00Z"))
        );
        assert_eq!(
            parse_time(&utc("491231235959Z")),
            Some(at("2049-12-31T23:59:59Z"))
        );
        assert_eq!(
            parse_time(&gen_("20500101000000Z")),
            Some(at("2050-01-01T00:00:00Z"))
        );
        for bad in [
            utc("2611091200Z"),
            utc("261109120000+"),
            utc("261309120000Z"),
            utc("261109250000Z"),
            utc("26110912000aZ"),
            gen_("261109120000Z"),
            gen_("20261109120000.5Z"),
        ] {
            assert_eq!(parse_time(&bad), None, "{:?}", bad.value);
        }
        let other = Element {
            tag: TAG_INTEGER,
            value: b"261109120000Z",
            raw: &[],
        };
        assert_eq!(parse_time(&other), None);
    }

    #[test]
    fn base64_matches_rfc_4648() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(raw.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(b64_decode("Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zm9v-", "Zm9v_", "é"] {
            assert_eq!(b64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pem_round_trips_and_finds_every_block() {
        let a = vec![1u8; 100];
        let b = vec![2u8; 3];
        let pem = format!(
            "junk\n{}between\n{}",
            pem_encode("CERTIFICATE", &a),
            pem_encode("CERTIFICATE", &b)
        );
        assert!(pem.lines().all(|l| l.len() <= 64 || l.starts_with("-----")));
        assert_eq!(pem_decode_all(&pem, "CERTIFICATE").unwrap(), vec![a, b]);
        assert_eq!(pem_decode_all(&pem, "PRIVATE KEY").unwrap().len(), 0);
        assert_eq!(
            pem_decode_all("-----BEGIN X-----\nZg==\n", "X"),
            None,
            "unterminated"
        );
        assert_eq!(
            pem_decode_all("-----BEGIN X-----\n*\n-----END X-----", "X"),
            None
        );
    }

    /// A self-signed-shaped certificate (the signature is not checked).
    fn certificate(not_before: &[u8], not_after: &[u8], names: &[&str]) -> Vec<u8> {
        let spki = p256_spki(&[4; 65]);
        let exts = constructed(
            context(3),
            &[&sequence(&[
                &sequence(&[
                    &oid(&[0x55, 0x1d, 0x13]),
                    &tlv(TAG_BOOLEAN, &[0xff]),
                    &tlv(TAG_OCTET_STRING, &sequence(&[])),
                ]),
                &extension(OID_SUBJECT_ALT_NAME, &dns_names(names)),
            ])],
        );
        let tbs = sequence(&[
            &constructed(context(0), &[&unsigned_integer(&[2])]),
            &unsigned_integer(&[0x12, 0x34]),
            &ecdsa_sha256_algorithm(),
            &common_name("Test CA"),
            &sequence(&[not_before, not_after]),
            &common_name(names[0]),
            &spki,
            &exts,
        ]);
        sequence(&[&tbs, &ecdsa_sha256_algorithm(), &bit_string(&[0; 70])])
    }

    #[test]
    fn reads_what_relink_needs_from_a_certificate() {
        let der = certificate(
            &tlv(TAG_UTC_TIME, b"261109000000Z"),
            &tlv(TAG_GENERALIZED_TIME, b"20270207000000Z"),
            &["go.example.com", "www.example.com"],
        );
        let info = parse_certificate(&der).unwrap();
        assert_eq!(
            info.not_before,
            "2026-11-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            info.not_after,
            "2027-02-07T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(info.dns_names, ["go.example.com", "www.example.com"]);
        assert_eq!(info.spki, p256_spki(&[4; 65]));
        // Validity backwards, truncated, or with trailing bytes.
        let backwards = certificate(
            &tlv(TAG_UTC_TIME, b"270207000000Z"),
            &tlv(TAG_UTC_TIME, b"261109000000Z"),
            &["a.example"],
        );
        assert_eq!(parse_certificate(&backwards), None);
        assert_eq!(parse_certificate(&der[..der.len() - 1]), None);
        let mut long = der.clone();
        long.push(0);
        assert_eq!(parse_certificate(&long), None);
    }

    #[test]
    fn builds_a_request_with_the_names_and_key() {
        let point = [4u8; 65];
        let info = certification_request_info(&["go.example.com"], &point);
        let csr = certification_request(&info, &[0x30, 0x00]);
        let outer = parse_one(&csr, TAG_SEQUENCE).unwrap();
        let mut r = outer.contents();
        let cri = r.expect(TAG_SEQUENCE).unwrap();
        assert_eq!(cri.raw, &info[..]);
        assert_eq!(
            r.expect(TAG_SEQUENCE).unwrap().raw,
            &ecdsa_sha256_algorithm()[..]
        );
        assert_eq!(r.expect(TAG_BIT_STRING).unwrap().value, [0, 0x30, 0x00]);
        let mut c = cri.contents();
        assert_eq!(c.expect(TAG_INTEGER).unwrap().value, [0]);
        assert_eq!(
            c.expect(TAG_SEQUENCE).unwrap().raw,
            &common_name("go.example.com")[..]
        );
        assert_eq!(c.expect(TAG_SEQUENCE).unwrap().raw, &p256_spki(&point)[..]);
        let attrs = c.expect(context(0)).unwrap();
        assert!(
            attrs
                .value
                .windows(b"go.example.com".len())
                .any(|w| w == b"go.example.com")
        );
        c.finish().unwrap();
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = parse_certificate(&bytes);
            let mut r = Reader::new(&bytes);
            while r.read().is_some() {}
        }

        #[test]
        fn base64_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            prop_assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);
        }
    }
}

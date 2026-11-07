//! A minimal DNS client for one question: the TXT records of a name
//! (RFC 1035), used to verify that a workspace controls a custom domain.
//!
//! The operating system's resolver (`getaddrinfo`) only answers address
//! queries, so TXT lookups speak the wire protocol themselves: one question
//! over UDP to the configured recursive resolvers, retried over TCP when the
//! answer is truncated. That is a few hundred lines, not worth a resolver
//! crate with its own caches and configuration.
//!
//! This client never contacts the domain being verified. It sends one
//! question to a resolver the operator chose, for a name that already passed
//! the public-host rules destinations follow (src/domains.rs), so a domain
//! cannot point relink at an internal service. Answers are accepted only if
//! they carry our random query ID, come from the address we asked, and
//! repeat our question, which is what makes forging one off-path hard.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::util::secure_random;

/// Resource record type TXT.
const TYPE_TXT: u16 = 16;
/// Resource record type CNAME.
const TYPE_CNAME: u16 = 5;
/// Class IN.
const CLASS_IN: u16 = 1;
/// Largest UDP answer we accept (EDNS is not offered, so 512 is the most a
/// conforming server sends; a larger buffer costs nothing).
const MAX_UDP: usize = 4096;
/// Largest TCP answer we read.
const MAX_TCP: usize = 65_535;
/// Longest name on the wire (RFC 1035 section 2.3.4).
pub const MAX_NAME: usize = 253;
/// CNAME hops followed inside one answer.
const MAX_CHAIN: usize = 8;

/// Why a lookup gave no answer. "The name has no TXT records" is not an
/// error: it is an empty list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The name cannot be asked about (too long, empty label...).
    BadName,
    /// No resolver answered in time, or every one failed.
    Unavailable(String),
    /// A resolver answered with an error other than "no such name".
    Server(u8),
    /// The answer could not be parsed or did not match the question.
    Malformed(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::BadName => f.write_str("the name cannot be looked up"),
            DnsError::Unavailable(m) => write!(f, "no DNS resolver answered: {m}"),
            DnsError::Server(2) => f.write_str("the DNS resolver failed (SERVFAIL)"),
            DnsError::Server(5) => f.write_str("the DNS resolver refused the query"),
            DnsError::Server(code) => write!(f, "the DNS resolver answered with error {code}"),
            DnsError::Malformed(why) => write!(f, "the DNS answer was malformed: {why}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Encodes a query for the TXT records of `name` with ID `id` and recursion
/// desired.
pub fn encode_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(DnsError::BadName);
    }
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0, OPCODE=0, RD=1; QDCOUNT=1, no other sections.
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// A parsed answer to our question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The TXT records of the name (each record's strings joined, as
    /// RFC 7208 section 3.3 does for SPF). Empty: the name exists but has no
    /// TXT records, or it does not exist.
    Records(Vec<String>),
    /// The answer did not fit in a datagram; ask again over TCP.
    Truncated,
}

struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, DnsError> {
        let b = *self
            .msg
            .get(self.pos)
            .ok_or(DnsError::Malformed("ends early"))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, DnsError> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.msg.len())
            .ok_or(DnsError::Malformed("ends early"))?;
        let out = &self.msg[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Reads a possibly compressed name at the current position, lowercased
    /// and without the final dot.
    fn name(&mut self) -> Result<String, DnsError> {
        let (name, next) = read_name(self.msg, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

/// Reads the name starting at `pos`, following compression pointers
/// (RFC 1035 section 4.1.4). Returns the name and the position after it in
/// the original sequence. Pointers must point backwards, so a loop is
/// impossible and the walk ends.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut after = None;
    let mut limit = pos;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Malformed("ends in a name"))?;
        match len & 0xc0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    break;
                }
                let label = msg
                    .get(pos..pos + len as usize)
                    .ok_or(DnsError::Malformed("ends in a name"))?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    // Labels we compare are hostnames; anything else is kept
                    // escaped so it can never equal one by accident.
                    if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                        name.push(b.to_ascii_lowercase() as char);
                    } else {
                        name.push_str(&format!("\\{b:03}"));
                    }
                }
                if name.len() > 4 * MAX_NAME {
                    return Err(DnsError::Malformed("name too long"));
                }
                pos += len as usize;
            }
            0xc0 => {
                let low = *msg
                    .get(pos + 1)
                    .ok_or(DnsError::Malformed("ends in a name"))?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= limit {
                    return Err(DnsError::Malformed(
                        "compression pointer does not point back",
                    ));
                }
                after.get_or_insert(pos + 2);
                limit = target;
                pos = target;
            }
            _ => return Err(DnsError::Malformed("reserved label type")),
        }
    }
    Ok((name, after.unwrap_or(pos)))
}

/// Parses `msg` as the answer to the TXT query for `name` with ID `id`.
pub fn parse_answer(msg: &[u8], id: u16, name: &str) -> Result<Answer, DnsError> {
    let want = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let mut r = Reader { msg, pos: 0 };
    if r.u16()? != id {
        return Err(DnsError::Malformed("wrong query ID"));
    }
    let flags = r.u16()?;
    if flags & 0x8000 == 0 {
        return Err(DnsError::Malformed("not a response"));
    }
    if (flags >> 11) & 0xf != 0 {
        return Err(DnsError::Malformed("wrong opcode"));
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0xf) as u8;
    let qdcount = r.u16()?;
    let ancount = r.u16()?;
    let _nscount = r.u16()?;
    let _arcount = r.u16()?;
    if qdcount != 1 {
        return Err(DnsError::Malformed("the question is not repeated"));
    }
    let qname = r.name()?;
    let (qtype, qclass) = (r.u16()?, r.u16()?);
    if qname != want || qtype != TYPE_TXT || qclass != CLASS_IN {
        return Err(DnsError::Malformed("the answer is to another question"));
    }
    if truncated {
        return Ok(Answer::Truncated);
    }
    match rcode {
        0 => {}
        // NXDOMAIN: the name does not exist, so it has no records.
        3 => return Ok(Answer::Records(Vec::new())),
        other => return Err(DnsError::Server(other)),
    }
    let mut cnames: Vec<(String, String)> = Vec::new();
    let mut txts: Vec<(String, String)> = Vec::new();
    for _ in 0..ancount {
        let owner = r.name()?;
        let rtype = r.u16()?;
        let class = r.u16()?;
        let _ttl = r.bytes(4)?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let rdata = r.bytes(rdlen)?;
        if class != CLASS_IN {
            continue;
        }
        match rtype {
            TYPE_CNAME => {
                let (target, end) = read_name(msg, start)?;
                if end != start + rdlen {
                    return Err(DnsError::Malformed("CNAME data has the wrong length"));
                }
                cnames.push((owner, target));
            }
            TYPE_TXT => {
                let mut text = Vec::new();
                let mut i = 0;
                while i < rdata.len() {
                    let n = rdata[i] as usize;
                    let s = rdata
                        .get(i + 1..i + 1 + n)
                        .ok_or(DnsError::Malformed("TXT string runs past its record"))?;
                    text.extend_from_slice(s);
                    i += 1 + n;
                }
                txts.push((owner, String::from_utf8_lossy(&text).into_owned()));
            }
            _ => {}
        }
    }
    // Follow the CNAME chain from the question, if any, and keep the TXT
    // records of the name it ends at. Records for other names are ignored.
    let mut target = want;
    for _ in 0..MAX_CHAIN {
        match cnames.iter().find(|(owner, _)| *owner == target) {
            Some((_, next)) => target = next.clone(),
            None => break,
        }
    }
    Ok(Answer::Records(
        txts.into_iter()
            .filter(|(owner, _)| *owner == target)
            .map(|(_, text)| text)
            .collect(),
    ))
}

/// Reads the `nameserver` lines of a resolv.conf.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            // A zone index ("fe80::1%eth0") cannot be used from here.
            let ip: IpAddr = words.next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .collect()
}

/// Parses `ip` or `ip:port` (IPv6 with a port in brackets), port 53 by
/// default.
pub fn parse_server(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    s.parse().ok()
}

/// Asks TXT questions of a fixed list of recursive resolvers, in order,
/// until one answers.
#[derive(Clone, Debug)]
pub struct DnsClient {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl DnsClient {
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration) -> DnsClient {
        DnsClient { servers, timeout }
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// The TXT records of `name`, from the first resolver that answers.
    /// Each resolver gets `timeout` for its UDP answer and, if truncated,
    /// `timeout` again over TCP.
    pub async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        if self.servers.is_empty() {
            return Err(DnsError::Unavailable(
                "no DNS resolver is configured".into(),
            ));
        }
        let mut last = DnsError::Unavailable("no resolver tried".into());
        for &server in &self.servers {
            match self.ask(server, name).await {
                Ok(records) => return Ok(records),
                Err(DnsError::BadName) => return Err(DnsError::BadName),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn ask(&self, server: SocketAddr, name: &str) -> Result<Vec<String>, DnsError> {
        let mut id = [0u8; 2];
        secure_random(&mut id);
        let id = u16::from_be_bytes(id);
        let query = encode_query(id, name)?;
        let unavailable = |e: std::io::Error| DnsError::Unavailable(format!("{server}: {e}"));
        let timed_out = || DnsError::Unavailable(format!("{server}: timed out"));
        let bind: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let udp = async {
            let sock = UdpSocket::bind(bind).await.map_err(unavailable)?;
            // Connected: the kernel drops datagrams from any other address.
            sock.connect(server).await.map_err(unavailable)?;
            sock.send(&query).await.map_err(unavailable)?;
            let mut buf = vec![0u8; MAX_UDP];
            loop {
                let n = sock.recv(&mut buf).await.map_err(unavailable)?;
                match parse_answer(&buf[..n], id, name) {
                    // Someone else's or garbled: keep waiting for ours.
                    Err(DnsError::Malformed(_)) => continue,
                    other => return other,
                }
            }
        };
        let answer = tokio::time::timeout(self.timeout, udp)
            .await
            .map_err(|_| timed_out())??;
        match answer {
            Answer::Records(r) => Ok(r),
            Answer::Truncated => {
                let tcp = async {
                    let mut stream = TcpStream::connect(server).await.map_err(unavailable)?;
                    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&query);
                    stream.write_all(&framed).await.map_err(unavailable)?;
                    let len = stream.read_u16().await.map_err(unavailable)? as usize;
                    let mut buf = vec![0u8; len.min(MAX_TCP)];
                    stream.read_exact(&mut buf).await.map_err(unavailable)?;
                    parse_answer(&buf, id, name)
                };
                match tokio::time::timeout(self.timeout, tcp)
                    .await
                    .map_err(|_| timed_out())??
                {
                    Answer::Records(r) => Ok(r),
                    Answer::Truncated => Err(DnsError::Malformed("truncated over TCP")),
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds an answer to `query` (as encoded by [`encode_query`]) with the
    /// given flags and answer records `(owner, type, rdata)`, owners written
    /// out in full.
    pub(crate) fn answer(query: &[u8], flags: u16, records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = query[..2].to_vec();
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&(records.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[12..]);
        for (owner, rtype, rdata) in records {
            out.extend_from_slice(&wire_name(owner));
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    pub(crate) fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub(crate) fn txt(strings: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in strings {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    const OK: u16 = 0x8180;

    #[test]
    fn queries_are_encoded_per_rfc_1035() {
        let q = encode_query(0xbeef, "_x.Go.example.com.").unwrap();
        assert_eq!(&q[..12], &[0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &q[12..q.len() - 4],
            wire_name("_x.Go.example.com").as_slice()
        );
        assert_eq!(&q[q.len() - 4..], &[0, 16, 0, 1]);
        assert_eq!(encode_query(1, ""), Err(DnsError::BadName));
        assert_eq!(encode_query(1, "a..b"), Err(DnsError::BadName));
        assert_eq!(
            encode_query(1, &format!("{}.com", "a".repeat(64))),
            Err(DnsError::BadName)
        );
        assert_eq!(
            encode_query(1, &format!("{}a", "a.".repeat(127))),
            Err(DnsError::BadName),
            "255 characters"
        );
        // 253 characters with a final dot is the longest name.
        assert!(encode_query(1, &"a.".repeat(127)).is_ok());
    }

    #[test]
    fn txt_records_of_the_name_are_returned() {
        let name = "_relink-challenge.go.example.com";
        let q = encode_query(7, name).unwrap();
        let a = answer(
            &q,
            OK,
            &[
                (name, TYPE_TXT, txt(&["relink-domain-verification=ab"])),
                // Several strings in one record are joined.
                (name, TYPE_TXT, txt(&["v=spf1 ", "-all"])),
                // Another name's records are not ours.
                ("evil.example.com", TYPE_TXT, txt(&["nope"])),
                // An unknown type is skipped.
                (name, 99, vec![1, 2, 3]),
            ],
        );
        assert_eq!(
            parse_answer(&a, 7, name),
            Ok(Answer::Records(vec![
                "relink-domain-verification=ab".into(),
                "v=spf1 -all".into()
            ]))
        );
        // Names compare without case and without the final dot.
        assert_eq!(
            parse_answer(&a, 7, "_RELINK-challenge.go.EXAMPLE.com."),
            parse_answer(&a, 7, name)
        );
    }

    #[test]
    fn cname_chains_are_followed_within_the_answer() {
        let name = "_relink-challenge.go.example.com";
        let q = encode_query(9, name).unwrap();
        // The CNAME target is written with a compression pointer back to
        // "example.com" in the question (offset 12 + 18 + 3).
        let suffix = 12 + 1 + 17 + 1 + 2;
        let mut target = vec![6];
        target.extend_from_slice(b"verify");
        target.extend_from_slice(&[0xc0, suffix as u8]);
        let a = answer(
            &q,
            OK,
            &[
                (name, TYPE_CNAME, target),
                ("verify.example.com", TYPE_TXT, txt(&["token"])),
                (name, TYPE_TXT, txt(&["ignored: the name is an alias"])),
            ],
        );
        assert_eq!(
            parse_answer(&a, 9, name),
            Ok(Answer::Records(vec!["token".into()]))
        );
    }

    #[test]
    fn errors_and_mismatches_are_told_apart() {
        let name = "a.example.com";
        let q = encode_query(5, name).unwrap();
        // NXDOMAIN and NOERROR without records both mean "no records".
        assert_eq!(
            parse_answer(&answer(&q, 0x8183, &[]), 5, name),
            Ok(Answer::Records(vec![]))
        );
        assert_eq!(
            parse_answer(&answer(&q, OK, &[]), 5, name),
            Ok(Answer::Records(vec![]))
        );
        assert_eq!(
            parse_answer(&answer(&q, 0x8182, &[]), 5, name),
            Err(DnsError::Server(2))
        );
        assert_eq!(
            parse_answer(&answer(&q, 0x8380, &[]), 5, name),
            Ok(Answer::Truncated)
        );
        // Another ID, a query instead of a response, another question.
        assert!(matches!(
            parse_answer(&answer(&q, OK, &[]), 6, name),
            Err(DnsError::Malformed(_))
        ));
        assert!(matches!(
            parse_answer(&answer(&q, 0x0100, &[]), 5, name),
            Err(DnsError::Malformed(_))
        ));
        assert!(matches!(
            parse_answer(&answer(&q, OK, &[]), 5, "b.example.com"),
            Err(DnsError::Malformed(_))
        ));
        // Truncated in the middle of a record.
        let full = answer(&q, OK, &[(name, TYPE_TXT, txt(&["abc"]))]);
        for cut in 0..full.len() {
            assert!(parse_answer(&full[..cut], 5, name).is_err(), "cut at {cut}");
        }
        // A TXT string longer than its record.
        let bad = answer(&q, OK, &[(name, TYPE_TXT, vec![10, b'a'])]);
        assert!(matches!(
            parse_answer(&bad, 5, name),
            Err(DnsError::Malformed(_))
        ));
    }

    #[test]
    fn compression_pointers_must_point_back() {
        let name = "a.example.com";
        let q = encode_query(5, name).unwrap();
        let mut a = answer(&q, OK, &[]);
        a[7] = 1; // one answer
        // Owner: a pointer to itself.
        let at = a.len();
        a.extend_from_slice(&[0xc0 | (at >> 8) as u8, at as u8]);
        a.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            parse_answer(&a, 5, name),
            Err(DnsError::Malformed(_))
        ));
        // A reserved label type.
        let mut b = answer(&q, OK, &[]);
        b[7] = 1;
        b.extend_from_slice(&[0x40, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            parse_answer(&b, 5, name),
            Err(DnsError::Malformed(_))
        ));
    }

    #[test]
    fn odd_label_bytes_never_equal_a_hostname() {
        let (name, _) = read_name(&[3, b'a', b'.', b'b', 0], 0).unwrap();
        assert_eq!(name, "a\\046b");
    }

    #[test]
    fn resolv_conf_and_server_addresses() {
        let conf = "# comment\nnameserver 10.0.0.2\nsearch corp\nnameserver ::1\n\
                    nameserver fe80::1%eth0\nnameserver\noptions ndots:2\n";
        assert_eq!(
            parse_resolv_conf(conf),
            vec!["10.0.0.2:53".parse().unwrap(), "[::1]:53".parse().unwrap()]
        );
        assert_eq!(parse_server("1.1.1.1"), "1.1.1.1:53".parse().ok());
        assert_eq!(
            parse_server(" 127.0.0.1:5353 "),
            "127.0.0.1:5353".parse().ok()
        );
        assert_eq!(
            parse_server("2606:4700::1111"),
            "[2606:4700::1111]:53".parse().ok()
        );
        assert_eq!(parse_server("[::1]:5353"), "[::1]:5353".parse().ok());
        assert_eq!(parse_server("dns.example.com"), None);
    }

    proptest::proptest! {
        #[test]
        fn parsing_arbitrary_bytes_never_panics(msg in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600)) {
            let _ = parse_answer(&msg, u16::from_be_bytes([msg.first().copied().unwrap_or(0), msg.get(1).copied().unwrap_or(0)]), "a.example.com");
        }
    }

    /// A resolver on loopback: answers over UDP (truncated when `truncate`),
    /// and over TCP in full.
    async fn fake_resolver(truncate: bool) -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
        let reply = |q: &[u8], flags: u16| {
            let name = "_relink-challenge.go.example.com";
            answer(q, flags, &[(name, TYPE_TXT, txt(&["over-tcp"]))])
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = udp.recv_from(&mut buf).await.unwrap();
                // A stray answer with the wrong ID first, which is ignored.
                let mut stray = reply(&buf[..n], 0x8180);
                stray[0] ^= 0xff;
                udp.send_to(&stray, from).await.unwrap();
                let flags = if truncate { 0x8380 } else { 0x8180 };
                udp.send_to(&reply(&buf[..n], flags), from).await.unwrap();
            }
        });
        tokio::spawn(async move {
            loop {
                let (mut s, _) = tcp.accept().await.unwrap();
                let len = s.read_u16().await.unwrap() as usize;
                let mut q = vec![0u8; len];
                s.read_exact(&mut q).await.unwrap();
                let a = reply(&q, 0x8180);
                s.write_all(&(a.len() as u16).to_be_bytes()).await.unwrap();
                s.write_all(&a).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn asks_over_udp_and_falls_back_to_tcp() {
        let name = "_relink-challenge.go.example.com";
        let t = Duration::from_secs(2);
        let udp = DnsClient::new(vec![fake_resolver(false).await], t);
        assert_eq!(udp.txt(name).await, Ok(vec!["over-tcp".to_owned()]));
        let tcp = DnsClient::new(vec![fake_resolver(true).await], t);
        assert_eq!(tcp.txt(name).await, Ok(vec!["over-tcp".to_owned()]));

        // A resolver that never answers times out; the next one is asked.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let short = Duration::from_millis(200);
        let both = DnsClient::new(vec![silent_addr, fake_resolver(false).await], short);
        assert_eq!(both.txt(name).await, Ok(vec!["over-tcp".to_owned()]));
        let only_silent = DnsClient::new(vec![silent_addr], short);
        let err = only_silent.txt(name).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        drop(silent);

        assert!(matches!(
            DnsClient::new(vec![], t).txt(name).await,
            Err(DnsError::Unavailable(_))
        ));
        assert_eq!(udp.txt("a..b").await, Err(DnsError::BadName));
        assert_eq!(udp.servers().len(), 1);
    }

    #[test]
    fn errors_read_well() {
        assert!(DnsError::Server(2).to_string().contains("SERVFAIL"));
        assert!(DnsError::Server(5).to_string().contains("refused"));
        assert!(DnsError::Server(4).to_string().contains("error 4"));
        assert!(DnsError::BadName.to_string().contains("cannot"));
        assert!(
            DnsError::Malformed("x")
                .to_string()
                .contains("malformed: x")
        );
        assert!(DnsError::Unavailable("y".into()).to_string().contains("y"));
    }
}

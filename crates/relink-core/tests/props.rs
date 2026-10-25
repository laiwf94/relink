//! Property tests against small, independent reference models.

use std::net::Ipv4Addr;

use proptest::prelude::*;
use relink_core::abtest::{Signer, choose};
use relink_core::code::{RESERVED, is_plausible_code, validate_alias};
use relink_core::destination::{MAX_URL_LEN, Policy, UrlError, normalize};

/// The alias rule written out the long way.
fn alias_model(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let ok_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let edge = |c: char| c.is_ascii_alphanumeric();
    chars.len() >= 3
        && chars.len() <= 64
        && chars.iter().all(|&c| ok_char(c))
        && edge(chars[0])
        && edge(chars[chars.len() - 1])
        && !RESERVED
            .iter()
            .any(|r| r.to_lowercase() == s.to_lowercase())
}

proptest! {
    #[test]
    fn alias_validation_matches_model(s in prop_oneof![
        "[A-Za-z0-9_-]{0,70}",
        any::<String>(),
        prop::sample::select(RESERVED.to_vec()).prop_map(|r| r.to_uppercase()),
    ]) {
        prop_assert_eq!(validate_alias(&s).is_ok(), alias_model(&s), "{:?}", s);
        if alias_model(&s) {
            prop_assert!(is_plausible_code(&s));
        }
    }
}

#[derive(Clone, Debug)]
enum HostKind {
    Domain(Vec<String>, &'static str),
    SingleLabel(String),
    Reserved(String, &'static str),
    V4([u8; 4]),
    V6([u16; 8]),
}

#[derive(Clone, Debug)]
struct UrlParts {
    scheme: &'static str,
    userinfo: Option<String>,
    host: HostKind,
    port: Option<u16>,
    path: Vec<String>,
    query: Option<String>,
}

impl UrlParts {
    fn render(&self) -> String {
        let host = match &self.host {
            HostKind::Domain(labels, tld) => format!("{}.{tld}", labels.join(".")),
            HostKind::SingleLabel(l) => l.clone(),
            HostKind::Reserved(l, suffix) => format!("{l}.{suffix}"),
            HostKind::V4(o) => Ipv4Addr::from(*o).to_string(),
            HostKind::V6(s) => format!("[{}]", std::net::Ipv6Addr::from(*s)),
        };
        let mut out = format!("{}://", self.scheme);
        if let Some(u) = &self.userinfo {
            out.push_str(u);
            out.push('@');
        }
        out.push_str(&host);
        if let Some(p) = self.port {
            out.push_str(&format!(":{p}"));
        }
        out.push('/');
        out.push_str(&self.path.join("/"));
        if let Some(q) = &self.query {
            out.push('?');
            out.push_str(q);
        }
        out
    }
}

/// Private and special-purpose IPv4 ranges as plain CIDR blocks.
const V4_BLOCKED: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 3),
];

fn v4_public_model(o: [u8; 4]) -> bool {
    let ip = u32::from_be_bytes(o);
    !V4_BLOCKED.iter().any(|(net, bits)| {
        let mask = u32::MAX << (32 - bits);
        ip & mask == u32::from_be_bytes(*net) & mask
    })
}

/// What `normalize` should say, from the parts alone.
fn url_model(p: &UrlParts, policy: Policy) -> Result<(), UrlError> {
    if !p.scheme.eq_ignore_ascii_case("http") && !p.scheme.eq_ignore_ascii_case("https") {
        return Err(UrlError::Scheme);
    }
    if p.userinfo.is_some() {
        return Err(UrlError::Credentials);
    }
    if policy.allow_private {
        return Ok(());
    }
    match &p.host {
        HostKind::Domain(..) => Ok(()),
        HostKind::SingleLabel(_) | HostKind::Reserved(..) => Err(UrlError::NonPublicHost),
        HostKind::V4(o) => {
            if !policy.allow_ip_literals {
                Err(UrlError::IpLiteral)
            } else if v4_public_model(*o) {
                Ok(())
            } else {
                Err(UrlError::NonPublicHost)
            }
        }
        HostKind::V6(_) if !policy.allow_ip_literals => Err(UrlError::IpLiteral),
        HostKind::V6(_) => Ok(()), // judged separately below
    }
}

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,12}"
}

fn host_kind() -> impl Strategy<Value = HostKind> {
    prop_oneof![
        3 => (prop::collection::vec(label(), 1..4), prop::sample::select(vec!["com", "org", "net", "io", "dev"]))
            .prop_map(|(l, t)| HostKind::Domain(l, t)),
        1 => "[a-z]{1,12}".prop_map(HostKind::SingleLabel),
        1 => (label(), prop::sample::select(vec![
                "localhost", "local", "internal", "home.arpa", "test", "invalid", "example", "onion"]))
            .prop_map(|(l, s)| HostKind::Reserved(l, s)),
        2 => prop_oneof![
                any::<[u8; 4]>(),
                (prop::sample::select(V4_BLOCKED.to_vec()), any::<u32>()).prop_map(|((net, bits), r)| {
                    let mask = u32::MAX << (32 - bits);
                    ((u32::from_be_bytes(net) & mask) | (r & !mask)).to_be_bytes()
                }),
            ].prop_map(HostKind::V4),
        1 => any::<[u16; 8]>().prop_map(HostKind::V6),
    ]
}

fn url_parts() -> impl Strategy<Value = UrlParts> {
    (
        prop::sample::select(vec![
            "http",
            "https",
            "HTTPS",
            "ftp",
            "ws",
            "javascript",
            "file",
        ]),
        prop::option::weighted(0.15, "[a-z]{1,8}(:[a-z0-9]{1,8})?"),
        host_kind(),
        prop::option::of(1u16..=65535),
        prop::collection::vec("[A-Za-z0-9._~-]{0,10}", 0..4),
        prop::option::of("[a-z]{1,5}=[A-Za-z0-9]{0,8}"),
    )
        .prop_map(|(scheme, userinfo, host, port, path, query)| UrlParts {
            scheme,
            userinfo,
            host,
            port,
            path,
            query,
        })
}

fn policies() -> impl Strategy<Value = Policy> {
    prop_oneof![
        Just(Policy::default()),
        Just(Policy {
            allow_ip_literals: true,
            allow_private: false
        }),
        Just(Policy {
            allow_ip_literals: false,
            allow_private: true
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn url_validation_matches_model(parts in url_parts(), policy in policies()) {
        let raw = parts.render();
        let got = normalize(&raw, policy);
        let want = url_model(&parts, policy);
        let bad_scheme = !parts.scheme.eq_ignore_ascii_case("http")
            && !parts.scheme.eq_ignore_ascii_case("https");
        match (&parts.host, policy) {
            // The URL parser may refuse the syntax of an unsupported scheme
            // (e.g. a port on file:) before the scheme check runs.
            _ if bad_scheme => {
                prop_assert!(matches!(got, Err(UrlError::Scheme) | Err(UrlError::Malformed)), "{} -> {:?}", raw, got);
            }
            // IPv6 public-ness has its own unit tests; here only check that
            // literals are refused unless allowed and the answer is stable.
            (HostKind::V6(_), Policy { allow_ip_literals: true, allow_private: false })
                if want.is_ok() =>
            {
                prop_assert!(matches!(got, Ok(_) | Err(UrlError::NonPublicHost)), "{} -> {:?}", raw, got);
            }
            _ => prop_assert_eq!(got.clone().map(|_| ()), want, "{}", raw),
        }
        if let Ok(out) = got {
            prop_assert!(out.starts_with("http://") || out.starts_with("https://"));
            prop_assert!(out.len() <= MAX_URL_LEN);
            // Normalising is idempotent.
            prop_assert_eq!(normalize(&out, policy), Ok(out.clone()));
        }
    }

    #[test]
    fn arbitrary_input_never_panics(s in any::<String>(), policy in policies()) {
        if let Ok(out) = normalize(&s, policy) {
            prop_assert_eq!(normalize(&out, policy), Ok(out.clone()));
            let parsed = url::Url::parse(&out).unwrap();
            prop_assert!(parsed.username().is_empty() && parsed.password().is_none());
        }
    }
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Observed shares match the weights within five standard deviations.
    #[test]
    fn assignment_follows_weights(
        weights in prop::collection::vec(1u32..=1000, 1..=10),
        usable_mask in any::<u16>(),
        seed in any::<u64>(),
    ) {
        let n = weights.len();
        let usable = |i: usize| usable_mask & (1 << i) != 0;
        let total: u64 = (0..n).filter(|&i| usable(i)).map(|i| u64::from(weights[i])).sum();
        let mut rng = seed;
        if total == 0 {
            prop_assert_eq!(choose(&weights, usable, splitmix(&mut rng)), None);
            return Ok(());
        }
        const SAMPLES: usize = 20_000;
        let mut counts = vec![0usize; n];
        for _ in 0..SAMPLES {
            let i = choose(&weights, usable, splitmix(&mut rng)).unwrap();
            prop_assert!(usable(i), "picked unusable {}", i);
            counts[i] += 1;
        }
        for i in 0..n {
            let p = if usable(i) { f64::from(weights[i]) / total as f64 } else { 0.0 };
            let expected = p * SAMPLES as f64;
            let sd = (SAMPLES as f64 * p * (1.0 - p)).sqrt();
            prop_assert!((counts[i] as f64 - expected).abs() <= 5.0 * sd + 1.0,
                "variant {}: {} vs expected {:.0}", i, counts[i], expected);
        }
    }

    /// A signed assignment always verifies to the same variant, and only for
    /// the same link, version and key.
    #[test]
    fn assignment_is_sticky_and_unforgeable(
        key in any::<[u8; 32]>(),
        link in 1i64..i64::MAX,
        version in 1i32..1000,
        variants in 1usize..=10,
        pick in any::<prop::sample::Index>(),
        junk in "[0-9]{1,3}\\.[0-9a-f]{32}",
    ) {
        let s = Signer::new(key);
        let variant = pick.index(variants);
        let cookie = s.sign(link, version, variant);
        for _ in 0..3 {
            prop_assert_eq!(s.verify(link, version, &cookie, variants), Some(variant));
        }
        prop_assert_eq!(s.verify(link.wrapping_add(1).max(1), version, &cookie, variants), None);
        prop_assert_eq!(s.verify(link, version + 1, &cookie, variants), None);
        let mut other = key;
        other[0] ^= 1;
        prop_assert_eq!(Signer::new(other).verify(link, version, &cookie, variants), None);
        if junk != cookie {
            prop_assert_eq!(s.verify(link, version, &junk, variants), None);
        }
    }
}

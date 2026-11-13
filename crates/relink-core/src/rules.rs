//! What to do with one visit to one link. Pure: the caller supplies the
//! clock, the visitor's country and region, the request headers targeting
//! rules read, the query string, their cookies and a random number, so the
//! origin server and the edge worker give the same answer for the same input.
//!
//! The order is fixed: a disabled link is not found, then expiry, then the
//! country rule, then the link's targeting rules ([`crate::rules_v2`],
//! compiled when the link was read), and only when no rule matches its own
//! destinations, A/B split, health and fallback. A redirect from a link
//! with any rules is never cacheable, whichever way it went: a cache in
//! between would hand one visitor's answer to the next.
//!
//! Max clicks are the one rule this cannot decide alone, because it needs a
//! shared counter. [`Redirect::needs_admission`] tells the caller to take a
//! click from its limiter before redirecting; the edge sends such links to
//! the origin instead.

use crate::abtest::{Signer, choose, cookie_name, find_cookie};
use crate::model::Link;
use crate::rules_v2::Request;

/// How long an A/B assignment cookie lives (30 days).
pub const AB_COOKIE_MAX_AGE: u32 = 30 * 24 * 3600;

/// The request facts the rules depend on. Header values are raw bytes as
/// received.
#[derive(Clone, Copy, Debug, Default)]
pub struct Visit<'a> {
    pub now_ms: i64,
    /// Two-letter country from a trusted header, if any.
    pub country: Option<[u8; 2]>,
    /// The subdivision part of the visitor's ISO 3166-2 region (`CA` for
    /// `US-CA`) from a trusted header, if any.
    pub region: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub accept_language: Option<&'a [u8]>,
    pub referer: Option<&'a [u8]>,
    /// The query string without the `?`.
    pub query: Option<&'a [u8]>,
    /// Raw `Cookie` header values.
    pub cookies: &'a [&'a [u8]],
    /// Uniform random bits, used only to assign new A/B visitors.
    pub random: u64,
}

impl<'a> Visit<'a> {
    /// The facts targeting rules read.
    pub fn request(&self) -> Request<'a> {
        Request {
            now_ms: self.now_ms,
            country: self.country,
            region: self.region,
            user_agent: self.user_agent,
            accept_language: self.accept_language,
            referer: self.referer,
            query: self.query,
        }
    }
}

/// Settings that must match on every target for cookies to carry over.
#[derive(Clone, Copy)]
pub struct Settings<'a> {
    pub signer: &'a Signer,
    pub cookie_secure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Unknown or disabled. Disabled links answer like missing ones.
    NotFound,
    Expired,
    /// Refused by the geo rule; send the visitor to `fallback` if set.
    GeoBlocked {
        fallback: Option<&'a str>,
    },
    Redirect(Redirect<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect<'a> {
    pub status: u16,
    pub location: &'a str,
    /// A `Set-Cookie` value assigning a new A/B visitor.
    pub set_cookie: Option<String>,
    /// False when the answer depends on the visitor or on time, so nothing
    /// in between may cache it.
    pub cacheable: bool,
    /// The fallback URL was chosen because no destination is healthy.
    pub fallback: bool,
    /// The link has a click limit: take a click before redirecting.
    pub needs_admission: bool,
    /// The targeting rule that chose `location`, by index.
    pub rule: Option<usize>,
}

pub fn evaluate<'a>(link: &'a Link, visit: &Visit<'_>, settings: &Settings<'_>) -> Decision<'a> {
    if !link.enabled || link.destinations.is_empty() {
        return Decision::NotFound;
    }
    if link
        .expires_at
        .is_some_and(|t| t.timestamp_millis() <= visit.now_ms)
    {
        return Decision::Expired;
    }
    if let Some(geo) = &link.geo
        && !geo.permits(visit.country)
    {
        return Decision::GeoBlocked {
            fallback: link.fallback_url.as_deref(),
        };
    }

    let status = match link.redirect_status {
        301 | 302 | 307 | 308 => link.redirect_status,
        _ => 302,
    };
    let rules = link.rules.compiled();
    if let Some(i) = rules.evaluate(&visit.request()) {
        return Decision::Redirect(Redirect {
            status,
            location: &rules.urls()[i],
            set_cookie: None,
            cacheable: false,
            fallback: false,
            needs_admission: link.max_clicks.is_some(),
            rule: Some(i),
        });
    }

    let any_healthy = (0..link.destinations.len()).any(|i| link.is_healthy(i));
    // With nothing healthy and no fallback, a possibly-broken destination
    // beats an error page.
    let usable = |i: usize| !any_healthy || link.is_healthy(i);
    let mut set_cookie = None;
    let (location, fallback) = match (&link.fallback_url, any_healthy) {
        (Some(url), false) => (url.as_str(), true),
        _ if link.destinations.len() == 1 => (link.destinations[0].url.as_str(), false),
        _ => {
            let name = cookie_name(&link.code);
            let sticky = find_cookie(visit.cookies.iter().copied(), &name)
                .and_then(|v| {
                    settings.signer.verify(
                        link.id,
                        link.destinations_version,
                        v,
                        link.destinations.len(),
                    )
                })
                .filter(|&i| usable(i));
            let chosen = match sticky {
                Some(i) => i,
                None => {
                    // Weights are at least 1 and something is usable, so
                    // choose() cannot come back empty.
                    let i = choose(&link.weights(), usable, visit.random).unwrap_or(0);
                    set_cookie = Some(assignment_cookie(link, &name, i, settings));
                    i
                }
            };
            (link.destinations[chosen].url.as_str(), false)
        }
    };

    let cacheable = link.geo.is_none()
        && link.rules.is_empty()
        && link.destinations.len() == 1
        && link.max_clicks.is_none()
        && link.expires_at.is_none()
        && !link.health_check;
    Decision::Redirect(Redirect {
        status,
        location,
        set_cookie,
        cacheable,
        fallback,
        needs_admission: link.max_clicks.is_some(),
        rule: None,
    })
}

fn assignment_cookie(link: &Link, name: &str, variant: usize, settings: &Settings<'_>) -> String {
    let value = settings
        .signer
        .sign(link.id, link.destinations_version, variant);
    let secure = if settings.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{name}={value}; Path=/{}; Max-Age={AB_COOKIE_MAX_AGE}; HttpOnly; SameSite=Lax{secure}",
        link.code
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Destination, GeoMode, GeoRule};
    use crate::rules_v2::RuleSet;
    use chrono::{TimeZone, Utc};

    fn link(urls: &[&str]) -> Link {
        Link {
            id: 9,
            code: "promo".into(),
            destinations: urls
                .iter()
                .map(|u| Destination {
                    url: u.to_string(),
                    weight: 1,
                })
                .collect(),
            destinations_version: 1,
            redirect_status: 302,
            expires_at: None,
            max_clicks: None,
            geo: None,
            fallback_url: None,
            enabled: true,
            health_check: false,
            unhealthy: vec![false; urls.len()],
            rules: RuleSet::default(),
        }
    }

    fn visit<'a>(cookies: &'a [&'a [u8]]) -> Visit<'a> {
        Visit {
            now_ms: 1_000_000,
            cookies,
            ..Visit::default()
        }
    }

    const SIGNER: Signer = Signer::new([4; 32]);
    const SETTINGS: Settings = Settings {
        signer: &SIGNER,
        cookie_secure: true,
    };

    fn redirect<'a>(d: Decision<'a>) -> Redirect<'a> {
        match d {
            Decision::Redirect(r) => r,
            other => panic!("expected a redirect, got {other:?}"),
        }
    }

    #[test]
    fn simple_link() {
        let l = link(&["https://a.example.com/"]);
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert_eq!(r.location, "https://a.example.com/");
        assert_eq!(r.status, 302);
        assert!(r.cacheable && !r.fallback && !r.needs_admission);
        assert!(r.set_cookie.is_none());
    }

    #[test]
    fn disabled_expired_and_odd_status() {
        let mut l = link(&["https://a.example.com/"]);
        l.enabled = false;
        assert_eq!(evaluate(&l, &visit(&[]), &SETTINGS), Decision::NotFound);
        l.enabled = true;
        l.expires_at = Some(Utc.timestamp_millis_opt(1_000_000).unwrap());
        assert_eq!(evaluate(&l, &visit(&[]), &SETTINGS), Decision::Expired);
        l.expires_at = Some(Utc.timestamp_millis_opt(1_000_001).unwrap());
        assert!(!redirect(evaluate(&l, &visit(&[]), &SETTINGS)).cacheable);
        l.redirect_status = 303;
        assert_eq!(redirect(evaluate(&l, &visit(&[]), &SETTINGS)).status, 302);
        l.destinations.clear();
        assert_eq!(evaluate(&l, &visit(&[]), &SETTINGS), Decision::NotFound);
    }

    #[test]
    fn geo_and_fallback() {
        let mut l = link(&["https://a.example.com/"]);
        l.geo = Some(GeoRule {
            mode: GeoMode::Allow,
            countries: vec![*b"US"],
        });
        let mut v = visit(&[]);
        assert_eq!(
            evaluate(&l, &v, &SETTINGS),
            Decision::GeoBlocked { fallback: None }
        );
        v.country = Some(*b"US");
        assert!(!redirect(evaluate(&l, &v, &SETTINGS)).cacheable);
        l.fallback_url = Some("https://elsewhere.example.com/".into());
        v.country = Some(*b"DE");
        assert_eq!(
            evaluate(&l, &v, &SETTINGS),
            Decision::GeoBlocked {
                fallback: Some("https://elsewhere.example.com/")
            }
        );
    }

    #[test]
    fn unhealthy_destinations() {
        let mut l = link(&["https://a.example.com/", "https://b.example.com/"]);
        l.health_check = true;
        l.unhealthy = vec![true, false];
        for r in [0, u64::MAX / 3, u64::MAX] {
            let v = Visit {
                random: r,
                ..visit(&[])
            };
            assert_eq!(
                redirect(evaluate(&l, &v, &SETTINGS)).location,
                "https://b.example.com/"
            );
        }
        l.unhealthy = vec![true, true];
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert!(!r.fallback, "no fallback: use a destination anyway");
        l.fallback_url = Some("https://fallback.example.com/".into());
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert_eq!(r.location, "https://fallback.example.com/");
        assert!(r.fallback && r.set_cookie.is_none());
    }

    #[test]
    fn ab_assignment_is_sticky_through_the_cookie() {
        let l = link(&["https://a.example.com/", "https://b.example.com/"]);
        let v = Visit {
            random: u64::MAX,
            ..visit(&[])
        };
        let first = redirect(evaluate(&l, &v, &SETTINGS));
        assert_eq!(first.location, "https://b.example.com/");
        let set = first.set_cookie.unwrap();
        assert!(set.starts_with("rl_promo=1."));
        assert!(set.ends_with("Path=/promo; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure"));
        let pair = set.split(';').next().unwrap().as_bytes();
        let cookies = [pair];
        // Even with a random number that would pick the other variant.
        let again = redirect(evaluate(&l, &visit(&cookies), &SETTINGS));
        assert_eq!(again.location, "https://b.example.com/");
        assert!(again.set_cookie.is_none());
        let insecure = Settings {
            signer: &SIGNER,
            cookie_secure: false,
        };
        let r = redirect(evaluate(&l, &v, &insecure));
        assert!(!r.set_cookie.unwrap().contains("Secure"));
    }

    #[test]
    fn max_clicks_needs_admission() {
        let mut l = link(&["https://a.example.com/"]);
        l.max_clicks = Some(3);
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert!(r.needs_admission && !r.cacheable);
    }

    fn with_rules(mut l: Link, json: &str) -> Link {
        l.rules = serde_json::from_str(json).unwrap();
        l
    }

    #[test]
    fn targeting_rules_choose_before_the_destinations() {
        let l = with_rules(
            link(&["https://a.example.com/", "https://b.example.com/"]),
            r#"[{"if": {"country": ["DE"]}, "url": "https://de.example.com/"},
                {"if": {"all": [{"os": ["ios"]}, {"query": {"name": "src", "values": ["mail"]}}]},
                 "url": "https://ios.example.com/"},
                {"if": {"region": ["US-CA"]}, "url": "https://ca.example.com/"},
                {"if": {"language": ["fr"]}, "url": "https://fr.example.com/"},
                {"if": {"referrer": ["news.example"]}, "url": "https://news.example.com/"}]"#,
        );
        let base = visit(&[]);
        let de = Visit {
            country: Some(*b"DE"),
            ..base
        };
        let r = redirect(evaluate(&l, &de, &SETTINGS));
        assert_eq!((r.location, r.rule), ("https://de.example.com/", Some(0)));
        assert!(!r.cacheable && r.set_cookie.is_none() && !r.fallback);

        let ios = Visit {
            user_agent: Some(b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
            query: Some(b"a=1&src=mail"),
            ..base
        };
        assert_eq!(
            redirect(evaluate(&l, &ios, &SETTINGS)).location,
            "https://ios.example.com/"
        );
        let ca = Visit {
            country: Some(*b"US"),
            region: Some(b"ca"),
            ..base
        };
        assert_eq!(redirect(evaluate(&l, &ca, &SETTINGS)).rule, Some(2));
        let fr = Visit {
            accept_language: Some(b"fr-CA,fr;q=0.9,en;q=0.5"),
            ..base
        };
        assert_eq!(redirect(evaluate(&l, &fr, &SETTINGS)).rule, Some(3));
        let news = Visit {
            referer: Some(b"https://www.news.example/story"),
            ..base
        };
        assert_eq!(redirect(evaluate(&l, &news, &SETTINGS)).rule, Some(4));

        // No rule holds: the A/B split answers, and still nothing caches it.
        let r = redirect(evaluate(&l, &base, &SETTINGS));
        assert_eq!(r.rule, None);
        assert!(r.set_cookie.is_some() && !r.cacheable);
        let single = with_rules(
            link(&["https://a.example.com/"]),
            r#"[{"if": {"country": ["DE"]}, "url": "https://de.example.com/"}]"#,
        );
        let r = redirect(evaluate(&single, &base, &SETTINGS));
        assert_eq!(r.location, "https://a.example.com/");
        assert!(
            !r.cacheable,
            "the answer depends on the rules even when none held"
        );
    }

    #[test]
    fn rules_come_after_expiry_and_geo_and_keep_status_and_limits() {
        let mut l = with_rules(
            link(&["https://a.example.com/"]),
            r#"[{"if": {"not": {"country": ["ZZ"]}}, "url": "https://rule.example.com/"}]"#,
        );
        l.redirect_status = 301;
        l.max_clicks = Some(5);
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert_eq!((r.status, r.location), (301, "https://rule.example.com/"));
        assert!(r.needs_admission);
        l.redirect_status = 303;
        assert_eq!(redirect(evaluate(&l, &visit(&[]), &SETTINGS)).status, 302);

        l.geo = Some(GeoRule {
            mode: GeoMode::Allow,
            countries: vec![*b"US"],
        });
        assert_eq!(
            evaluate(&l, &visit(&[]), &SETTINGS),
            Decision::GeoBlocked { fallback: None }
        );
        l.geo = None;
        l.expires_at = Some(Utc.timestamp_millis_opt(1).unwrap());
        assert_eq!(evaluate(&l, &visit(&[]), &SETTINGS), Decision::Expired);
        l.expires_at = None;
        l.enabled = false;
        assert_eq!(evaluate(&l, &visit(&[]), &SETTINGS), Decision::NotFound);
    }

    #[test]
    fn health_and_fallback_never_override_a_matching_rule() {
        let mut l = with_rules(
            link(&["https://a.example.com/"]),
            r#"[{"if": {"time": {"after": "1970-01-01T00:00:00Z"}}, "url": "https://rule.example.com/"}]"#,
        );
        l.health_check = true;
        l.unhealthy = vec![true];
        l.fallback_url = Some("https://fallback.example.com/".into());
        let r = redirect(evaluate(&l, &visit(&[]), &SETTINGS));
        assert_eq!(r.location, "https://rule.example.com/");
        assert!(!r.fallback);
        let early = Visit {
            now_ms: -1,
            ..visit(&[])
        };
        assert!(redirect(evaluate(&l, &early, &SETTINGS)).fallback);
    }
}

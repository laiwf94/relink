//! Protected links and the preview page.
//!
//! A link can ask for a password, for consent, or both, before it
//! redirects ([`Protection`]). The visitor gets an interstitial page with a
//! form that posts back to the link's own path; once the origin accepts
//! it, it sets a grant cookie ([`Signer::grant`]) and sends the visitor
//! back to the same path, which now redirects as usual. Only the origin
//! holds the password hash, so only the origin answers a protected link:
//! the server never publishes one to the edge.
//!
//! `/{code}+` is the link's preview page ([`crate::site::Target::Preview`]):
//! where the link goes, without going there, so a visitor can check a
//! short link before following it. A protected link's preview says it is
//! protected and never shows its destination.
//!
//! The pages run no script and load nothing: one inline style sheet and a
//! form whose action is the page's own URL ([`GATE_CSP`]).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::abtest::{HmacSha256, Signer, TAG_LEN};
use crate::hex;
use crate::model::Link;
use crate::rules::{Decision, Settings, Visit, evaluate};
use crate::site::escape;
use hmac::Mac;

/// Shortest password a link may have.
pub const MIN_PASSWORD_LEN: usize = 4;

/// Longest password a link may have, in bytes.
pub const MAX_PASSWORD_LEN: usize = 256;

/// Longest consent text, in characters.
pub const MAX_CONSENT_CHARS: usize = 1000;

/// Wrong passwords a link accepts per [`ATTEMPT_WINDOW_SECS`] when its
/// owner sets no limit of their own.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 10;

/// Highest per-link attempt limit.
pub const MAX_MAX_ATTEMPTS: u32 = 1000;

/// The window attempt limits count in: one hour.
pub const ATTEMPT_WINDOW_SECS: u32 = 3600;

/// How long an accepted password lets a visitor through: 12 hours.
pub const PASSWORD_GRANT_SECS: u32 = 12 * 3600;

/// How long a consent lasts when the link has no password: 30 days.
pub const CONSENT_GRANT_SECS: u32 = 30 * 24 * 3600;

/// Longest grant cookie value: expiry digits, dot, hex tag.
const MAX_GRANT_LEN: usize = 12 + 1 + TAG_LEN * 2;

/// What a visitor must do before a link redirects. Serialised without the
/// password hash, which only the origin's own copy of a link carries: the
/// audit log and the API show `password: true` and nothing more.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    /// Whether the link asks for a password.
    #[serde(default, skip_serializing_if = "is_false")]
    pub password: bool,
    /// Wrong passwords accepted per hour, with a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
    /// Text the visitor must agree to before continuing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,
    /// The password's argon2id hash in PHC form. Never serialised.
    #[serde(skip)]
    pub password_hash: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Protection {
    /// Whether the link asks for nothing.
    pub fn is_none(&self) -> bool {
        !self.password && self.consent.is_none()
    }

    /// Whether there is nothing to write out: what is read back is then
    /// the default, so a record round-trips whatever it held.
    pub fn is_empty(&self) -> bool {
        self.is_none() && self.max_attempts.is_none()
    }

    /// Reads a record's `protection` only as far as knowing it is there,
    /// which is all an edge needs: a protection that asks for something.
    /// A record never carries an empty one (it is omitted instead).
    pub fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Protection, D::Error> {
        serde::de::IgnoredAny::deserialize(d)?;
        Ok(Protection {
            password: true,
            ..Protection::default()
        })
    }

    /// The attempt limit in force: the link's own or the default.
    pub fn attempt_limit(&self) -> u32 {
        self.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS)
    }

    /// How long a grant lasts.
    pub fn grant_secs(&self) -> u32 {
        if self.password {
            PASSWORD_GRANT_SECS
        } else {
            CONSENT_GRANT_SECS
        }
    }

    /// A digest of what the visitor agreed to: changing the password or
    /// the consent text changes it, and so revokes every grant.
    pub fn tag(&self) -> [u8; TAG_LEN] {
        let mut h = Sha256::new();
        h.update(b"relink-protection\0");
        match &self.password_hash {
            Some(p) => {
                h.update([1]);
                h.update((p.len() as u32).to_be_bytes());
                h.update(p.as_bytes());
            }
            None => h.update([0]),
        }
        match &self.consent {
            Some(c) => {
                h.update([1]);
                h.update(c.as_bytes());
            }
            None => h.update([0]),
        }
        let d = h.finalize();
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&d[..TAG_LEN]);
        out
    }
}

/// Why a password or consent text was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectionError {
    PasswordLength,
    PasswordControl,
    ConsentEmpty,
    ConsentLength,
    ConsentControl,
    Attempts,
}

impl std::fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionError::PasswordLength => write!(
                f,
                "protection.password: must be {MIN_PASSWORD_LEN} to {MAX_PASSWORD_LEN} bytes"
            ),
            ProtectionError::PasswordControl => {
                write!(
                    f,
                    "protection.password: must not contain control characters"
                )
            }
            ProtectionError::ConsentEmpty => write!(
                f,
                "protection.consent: must not be empty (use null for no consent page)"
            ),
            ProtectionError::ConsentLength => write!(
                f,
                "protection.consent: must be at most {MAX_CONSENT_CHARS} characters"
            ),
            ProtectionError::ConsentControl => write!(
                f,
                "protection.consent: must not contain control characters other than newlines"
            ),
            ProtectionError::Attempts => write!(
                f,
                "protection.max_attempts: must be 1 to {MAX_MAX_ATTEMPTS}"
            ),
        }
    }
}

impl std::error::Error for ProtectionError {}

/// Checks a password a link is given.
pub fn check_password(p: &str) -> Result<(), ProtectionError> {
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&p.len()) {
        return Err(ProtectionError::PasswordLength);
    }
    if p.chars().any(char::is_control) {
        return Err(ProtectionError::PasswordControl);
    }
    Ok(())
}

/// Checks consent text and returns it with `\r\n` folded to `\n` and the
/// ends trimmed.
pub fn check_consent(c: &str) -> Result<String, ProtectionError> {
    let c = c.replace("\r\n", "\n");
    let c = c.trim();
    if c.is_empty() {
        return Err(ProtectionError::ConsentEmpty);
    }
    if c.chars().count() > MAX_CONSENT_CHARS {
        return Err(ProtectionError::ConsentLength);
    }
    if c.chars().any(|ch| ch.is_control() && ch != '\n') {
        return Err(ProtectionError::ConsentControl);
    }
    Ok(c.to_owned())
}

/// Checks an attempt limit.
pub fn check_attempts(n: u32) -> Result<u32, ProtectionError> {
    if (1..=MAX_MAX_ATTEMPTS).contains(&n) {
        Ok(n)
    } else {
        Err(ProtectionError::Attempts)
    }
}

/// The grant cookie's name for a link. `.` is not a code character, so it
/// never meets an A/B cookie (`rl_<code>`).
pub fn grant_cookie_name(code: &str) -> String {
    format!("rl.{code}")
}

impl Signer {
    fn grant_mac(&self, link_id: i64, tag: &[u8; TAG_LEN], expires: i64) -> HmacSha256 {
        let mut mac = self.hmac();
        mac.update(b"relink-gate\0");
        mac.update(&link_id.to_be_bytes());
        mac.update(tag);
        mac.update(&expires.to_be_bytes());
        mac
    }

    /// A grant cookie value: `<expiry, unix seconds>.<tag>`, the tag being
    /// the first 16 bytes of HMAC-SHA256 over the link ID, the
    /// protection's [`Protection::tag`] and the expiry.
    pub fn grant(&self, link_id: i64, protection: &Protection, expires: i64) -> String {
        let tag = self
            .grant_mac(link_id, &protection.tag(), expires)
            .finalize()
            .into_bytes();
        format!("{expires}.{}", hex::encode(&tag[..TAG_LEN]))
    }

    /// Whether `value` is an unexpired grant for this link as it is now
    /// protected. The tag comparison is constant time.
    pub fn verify_grant(
        &self,
        link_id: i64,
        protection: &Protection,
        value: &str,
        now_secs: i64,
    ) -> bool {
        if value.len() > MAX_GRANT_LEN {
            return false;
        }
        let Some((expires, tag)) = value.split_once('.') else {
            return false;
        };
        if expires.is_empty()
            || (expires.len() > 1 && expires.starts_with('0'))
            || !expires.bytes().all(|b| b.is_ascii_digit())
        {
            return false;
        }
        let Ok(expires) = expires.parse::<i64>() else {
            return false;
        };
        if expires <= now_secs {
            return false;
        }
        let Some(tag) = hex::decode(tag).filter(|t| t.len() == TAG_LEN) else {
            return false;
        };
        self.grant_mac(link_id, &protection.tag(), expires)
            .verify_truncated_left(&tag)
            .is_ok()
    }
}

/// The `Set-Cookie` value granting a visitor passage through a link's
/// protection until `expires` (unix seconds, `max_age` from now). On `/`,
/// so every path that names the link (`/abc`, `/campaign/abc`) sends it.
pub fn grant_cookie(code: &str, value: &str, max_age: u32, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}",
        grant_cookie_name(code)
    )
}

/// The `Content-Security-Policy` of the interstitial and preview pages: no
/// script, nothing loaded, forms only to the page's own origin, never
/// framed.
pub const GATE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
                            form-action 'self'; frame-ancestors 'none'";

/// What went wrong with the last submission, shown on the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    WrongPassword,
    /// The form was sent without the consent field.
    NoConsent,
    /// Too many wrong passwords; retry in this many seconds.
    Locked(u32),
}

impl Notice {
    fn text(self) -> String {
        match self {
            Notice::WrongPassword => "That password is not right. Try again.".into(),
            Notice::NoConsent => "Confirm below to continue.".into(),
            Notice::Locked(secs) => format!(
                "Too many wrong passwords for this link. Try again in {} minutes.",
                secs.div_ceil(60).max(1)
            ),
        }
    }

    /// The page's status code.
    pub fn status(self) -> u16 {
        match self {
            Notice::WrongPassword => 401,
            Notice::NoConsent => 400,
            Notice::Locked(_) => 429,
        }
    }
}

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#f6f6f4;\
color:#1d1d1b}main{max-width:28rem;margin:12vh auto;padding:2rem;background:#fff;\
border-radius:12px;box-shadow:0 1px 3px #0002}h1{font-size:1.25rem;margin:0 0 1rem}\
p{margin:0 0 1rem}.consent{white-space:pre-line}.notice{color:#a11;font-weight:600}\
.dest{word-break:break-all;font-family:ui-monospace,monospace;font-size:.9rem}\
label{display:block;margin:0 0 .25rem}input[type=password]{width:100%;box-sizing:border-box;\
padding:.5rem;font:inherit;margin:0 0 1rem}button,a.go{font:inherit;padding:.5rem 1rem;\
border:0;border-radius:6px;background:#1d1d1b;color:#fff;text-decoration:none;cursor:pointer}\
@media (prefers-color-scheme:dark){body{background:#151514;color:#eee}main{background:#222;\
box-shadow:none}button,a.go{background:#eee;color:#151514}.notice{color:#f88}}";

fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>{title}</title>\
         <style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    )
}

/// The interstitial for a protected link: a password field when it has a
/// password, its consent text when it has one, and one button. The form
/// posts to the page's own URL (no `action`), so the query string and any
/// path prefix come back with it.
pub fn gate_page(protection: &Protection, notice: Option<Notice>) -> String {
    let mut body = String::with_capacity(1024);
    let title = if protection.password {
        "This link is protected"
    } else {
        "Before you continue"
    };
    body.push_str("<h1>");
    body.push_str(title);
    body.push_str("</h1>");
    if let Some(n) = notice {
        body.push_str("<p class=\"notice\" role=\"alert\">");
        body.push_str(&escape(&n.text()));
        body.push_str("</p>");
    }
    if let Some(c) = &protection.consent {
        body.push_str("<p class=\"consent\">");
        body.push_str(&escape(c));
        body.push_str("</p>");
    }
    let locked = matches!(notice, Some(Notice::Locked(_)));
    if !locked {
        body.push_str("<form method=\"post\">");
        if protection.password {
            body.push_str(
                "<label for=\"password\">Password</label>\
                 <input type=\"password\" id=\"password\" name=\"password\" required \
                 autocomplete=\"current-password\" autofocus>",
            );
        }
        if protection.consent.is_some() {
            body.push_str("<input type=\"hidden\" name=\"consent\" value=\"yes\">");
        }
        let button = if protection.consent.is_some() {
            "I agree, continue"
        } else {
            "Continue"
        };
        body.push_str("<button type=\"submit\">");
        body.push_str(button);
        body.push_str("</button></form>");
    }
    shell(title, &body)
}

/// What a preview shows about where a link goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview<'a> {
    /// Where this visit would be sent, and how many destinations the link
    /// splits visitors between.
    Goes {
        location: &'a str,
        destinations: usize,
    },
    /// The link is protected: nothing about its destination.
    Protected,
}

/// The preview page of the link at `path` (its own path, without the `+`,
/// as requested).
pub fn preview_page(path: &str, what: Preview<'_>) -> String {
    let mut body = String::with_capacity(1024);
    body.push_str("<h1>Link preview</h1><p>The short link <span class=\"dest\">/");
    body.push_str(&escape(path));
    body.push_str("</span> ");
    match what {
        Preview::Goes {
            location,
            destinations,
        } => {
            body.push_str("goes to</p><p class=\"dest\">");
            body.push_str(&escape(location));
            body.push_str("</p>");
            if destinations > 1 {
                body.push_str(&format!(
                    "<p>It splits visitors between {destinations} destinations; this is one \
                     of them.</p>"
                ));
            }
        }
        Preview::Protected => {
            body.push_str(
                "is protected. Its destination is shown only to visitors who pass its \
                 password or consent page.</p>",
            );
        }
    }
    body.push_str("<p><a class=\"go\" href=\"/");
    body.push_str(&escape(path));
    body.push_str("\">Continue</a></p>");
    shell("Link preview", &body)
}

/// The preview page for `link` at `path` (as requested, without the `+`),
/// or the decision that stops the link for this visitor: a disabled,
/// expired or geo-blocked link gets the page it would get anyway. The
/// visit is evaluated as a redirect would be, so a link with targeting
/// rules or app targets previews where this visitor would go; no A/B
/// cookie is set and no click is taken or counted.
pub fn preview<'a>(
    link: &'a Link,
    path: &str,
    visit: &Visit<'_>,
    settings: &Settings<'_>,
) -> Result<String, Decision<'a>> {
    match evaluate(link, visit, settings) {
        Decision::Redirect(_) if link.is_protected() => Ok(preview_page(path, Preview::Protected)),
        Decision::Redirect(r) => {
            // A rule, an app target or the fallback is one place, whatever
            // the split.
            let split = r.rule.is_none() && !r.app && !r.fallback;
            let destinations = if split { link.destinations.len() } else { 1 };
            Ok(preview_page(
                path,
                Preview::Goes {
                    location: r.location,
                    destinations,
                },
            ))
        }
        other => Err(other),
    }
}

/// Reads one field of an `application/x-www-form-urlencoded` body: the
/// first with that name, percent-decoded (invalid UTF-8 becomes U+FFFD).
/// `None` when it is missing.
pub fn form_field(body: &[u8], name: &str) -> Option<String> {
    url::form_urlencoded::parse(body)
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected(password: Option<&str>, consent: Option<&str>) -> Protection {
        Protection {
            password: password.is_some(),
            max_attempts: password.map(|_| 5),
            consent: consent.map(str::to_owned),
            password_hash: password.map(|p| format!("$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ${p}")),
        }
    }

    #[test]
    fn protection_basics() {
        assert!(Protection::default().is_none());
        let p = protected(Some("x"), None);
        assert!(!p.is_none());
        assert_eq!(p.attempt_limit(), 5);
        assert_eq!(p.grant_secs(), PASSWORD_GRANT_SECS);
        let c = protected(None, Some("ok"));
        assert!(!c.is_none());
        assert_eq!(c.attempt_limit(), DEFAULT_MAX_ATTEMPTS);
        assert_eq!(c.grant_secs(), CONSENT_GRANT_SECS);
        // The tag follows the hash and the text.
        assert_ne!(p.tag(), protected(Some("y"), None).tag());
        assert_ne!(c.tag(), protected(None, Some("ok!")).tag());
        assert_ne!(p.tag(), protected(Some("x"), Some("ok")).tag());
        assert_eq!(p.tag(), protected(Some("x"), None).tag());
        assert_ne!(Protection::default().tag(), c.tag());
    }

    #[test]
    fn serialised_without_the_hash() {
        let p = protected(Some("secret"), Some("Adults only"));
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"password":true,"max_attempts":5,"consent":"Adults only"}"#
        );
        let back: Protection = serde_json::from_str(&json).unwrap();
        assert!(back.password_hash.is_none());
        // What the Worker reads: only that one is there.
        let mut de = serde_json::Deserializer::from_str(r#"{"consent":"x"}"#);
        assert!(!Protection::present(&mut de).unwrap().is_none());
        assert_eq!(serde_json::to_string(&Protection::default()).unwrap(), "{}");
        let odd: Protection = serde_json::from_str(r#"{"max_attempts":5}"#).unwrap();
        assert!(odd.is_none() && !odd.is_empty());
        assert!(Protection::default().is_empty());
    }

    #[test]
    fn checks() {
        assert!(check_password("1234").is_ok());
        assert_eq!(check_password("123"), Err(ProtectionError::PasswordLength));
        let long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert_eq!(check_password(&long), Err(ProtectionError::PasswordLength));
        assert!(check_password(&long[1..]).is_ok());
        assert_eq!(
            check_password("ab\ncd"),
            Err(ProtectionError::PasswordControl)
        );
        assert!(check_password("pässwörd 🙂").is_ok());

        assert_eq!(
            check_consent("  Over 18?\r\nYes  ").unwrap(),
            "Over 18?\nYes"
        );
        assert_eq!(check_consent(" \n "), Err(ProtectionError::ConsentEmpty));
        let long = "é".repeat(MAX_CONSENT_CHARS + 1);
        assert_eq!(check_consent(&long), Err(ProtectionError::ConsentLength));
        assert!(check_consent(&long[2..]).is_ok());
        assert_eq!(
            check_consent("a\u{7}b"),
            Err(ProtectionError::ConsentControl)
        );
        assert_eq!(check_consent("a\tb"), Err(ProtectionError::ConsentControl));

        assert_eq!(check_attempts(1), Ok(1));
        assert_eq!(check_attempts(MAX_MAX_ATTEMPTS), Ok(MAX_MAX_ATTEMPTS));
        assert_eq!(check_attempts(0), Err(ProtectionError::Attempts));
        assert_eq!(check_attempts(1001), Err(ProtectionError::Attempts));
        for e in [
            ProtectionError::PasswordLength,
            ProtectionError::PasswordControl,
            ProtectionError::ConsentEmpty,
            ProtectionError::ConsentLength,
            ProtectionError::ConsentControl,
            ProtectionError::Attempts,
        ] {
            assert!(e.to_string().starts_with("protection."), "{e}");
        }
    }

    #[test]
    fn grants() {
        let s = Signer::new([9; 32]);
        let p = protected(Some("secret"), None);
        let now = 1_800_000_000;
        let v = s.grant(42, &p, now + 60);
        assert!(s.verify_grant(42, &p, &v, now));
        assert!(s.verify_grant(42, &p, &v, now + 59));
        // Expired, another link, another password, another key.
        assert!(!s.verify_grant(42, &p, &v, now + 60));
        assert!(!s.verify_grant(43, &p, &v, now));
        assert!(!s.verify_grant(42, &protected(Some("other"), None), &v, now));
        assert!(!Signer::new([8; 32]).verify_grant(42, &p, &v, now));
        // A later expiry cannot be written in.
        let (_, tag) = v.split_once('.').unwrap();
        assert!(!s.verify_grant(42, &p, &format!("{}.{tag}", now + 999), now));
        for bad in [
            "",
            ".",
            "abc",
            "1800000060",
            "01800000060.00",
            "-1.00",
            "+1800000060.00",
            "1800000060.zz",
            "1800000060.00ff",
            "99999999999999999999.00",
        ] {
            assert!(!s.verify_grant(42, &p, bad, now), "{bad}");
        }
        assert!(!s.verify_grant(42, &p, &format!("{v}0"), now));
        assert!(!s.verify_grant(42, &p, &"9".repeat(100), now));
    }

    #[test]
    fn cookies() {
        assert_eq!(grant_cookie_name("abc"), "rl.abc");
        assert_eq!(
            grant_cookie("abc", "1.ff", 60, true),
            "rl.abc=1.ff; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!grant_cookie("abc", "1.ff", 60, false).contains("Secure"));
    }

    #[test]
    fn pages_escape_and_offer_the_right_form() {
        let p = protected(Some("pw"), Some("<b>Adults</b> only\nreally"));
        let html = gate_page(&p, None);
        assert!(html.contains("type=\"password\""));
        assert!(html.contains("name=\"consent\""));
        assert!(html.contains("&lt;b&gt;Adults&lt;/b&gt; only\nreally"));
        assert!(!html.contains("<b>"));
        assert!(!html.contains("action="));
        assert!(!html.contains("<script"));

        let wrong = gate_page(&p, Some(Notice::WrongPassword));
        assert!(wrong.contains("not right"));
        let locked = gate_page(&p, Some(Notice::Locked(61)));
        assert!(locked.contains("2 minutes"));
        assert!(!locked.contains("<form"));
        assert!(gate_page(&p, Some(Notice::Locked(5))).contains("1 minutes"));
        assert!(gate_page(&p, Some(Notice::NoConsent)).contains("Confirm"));
        assert_eq!(Notice::WrongPassword.status(), 401);
        assert_eq!(Notice::NoConsent.status(), 400);
        assert_eq!(Notice::Locked(1).status(), 429);

        let consent = gate_page(&protected(None, Some("ok")), None);
        assert!(!consent.contains("type=\"password\""));
        assert!(consent.contains("I agree"));
        let pw = gate_page(&protected(Some("x"), None), None);
        assert!(!pw.contains("name=\"consent\""));
        assert!(pw.contains(">Continue<"));
    }

    #[test]
    fn previews() {
        let html = preview_page(
            "promo",
            Preview::Goes {
                location: "https://example.com/?a=1&b=\"2\"",
                destinations: 1,
            },
        );
        assert!(html.contains("https://example.com/?a=1&amp;b=&quot;2&quot;"));
        assert!(html.contains("href=\"/promo\""));
        assert!(!html.contains("splits"));
        let split = preview_page(
            "c/promo",
            Preview::Goes {
                location: "https://example.com/",
                destinations: 3,
            },
        );
        assert!(split.contains("3 destinations"));
        assert!(split.contains("href=\"/c/promo\""));
        let hidden = preview_page("promo", Preview::Protected);
        assert!(hidden.contains("is protected"));
        assert!(!hidden.contains("https://"));
    }

    #[test]
    fn previews_follow_the_redirect_decision() {
        let link: Link = serde_json::from_str(
            r#"{"id":7,"code":"abc","destinations":[{"url":"https://a.example.com/"},
                {"url":"https://b.example.com/"}],"destinations_version":1,
                "redirect_status":302,"enabled":true}"#,
        )
        .unwrap();
        let signer = Signer::new([1; 32]);
        let settings = Settings {
            signer: &signer,
            cookie_secure: true,
        };
        let visit = Visit::default();
        let html = preview(&link, "abc", &visit, &settings).unwrap();
        assert!(html.contains("2 destinations"));
        let mut one = link.clone();
        one.destinations.truncate(1);
        let html = preview(&one, "abc", &visit, &settings).unwrap();
        assert!(html.contains("https://a.example.com/") && !html.contains("splits"));
        let mut off = link.clone();
        off.enabled = false;
        assert_eq!(
            preview(&off, "abc", &visit, &settings),
            Err(Decision::NotFound)
        );
        let mut hidden = one.clone();
        hidden.protection = protected(None, Some("ok"));
        let html = preview(&hidden, "abc", &visit, &settings).unwrap();
        assert!(html.contains("is protected") && !html.contains("a.example.com"));
        // The fallback for an all-unhealthy split is one place.
        let mut sick = link.clone();
        sick.health_check = true;
        sick.unhealthy = vec![true, true];
        sick.fallback_url = Some("https://f.example.com/".into());
        let html = preview(&sick, "abc", &visit, &settings).unwrap();
        assert!(html.contains("https://f.example.com/") && !html.contains("splits"));
    }

    #[test]
    fn form_fields() {
        let body = b"password=p%C3%A4ss+word%26&consent=yes&password=second";
        assert_eq!(form_field(body, "password").as_deref(), Some("päss word&"));
        assert_eq!(form_field(body, "consent").as_deref(), Some("yes"));
        assert_eq!(form_field(body, "other"), None);
        assert_eq!(form_field(b"", "password"), None);
    }
}

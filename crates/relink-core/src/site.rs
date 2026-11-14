//! Per-domain behaviour, decided the same way at the origin and the edge: a
//! custom domain's root redirect, its branded 404 and 410 pages, the path
//! prefixes it accepts in front of a code (`/campaign/abc`) and whether its
//! codes ignore case.
//!
//! The settings are stored with the domain at the origin and published to
//! the edge inside its `host:` record ([`crate::wire::EdgeDomain`]). The
//! default domain has none: a request for it is answered exactly as before
//! custom domains existed.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::code::{is_plausible_code, is_reserved};
use crate::deeplink::{AppError, AppFile, Apps, app_file_at};
use crate::destination::{Policy, UrlError, normalize};

/// Most path prefixes a domain may accept.
pub const MAX_PREFIXES: usize = 8;

/// Longest path prefix.
pub const MAX_PREFIX_LEN: usize = 32;

/// Largest 404 or 410 page, in bytes. KV values and the origin's memory
/// hold every verified domain's pages, so they stay small.
pub const MAX_PAGE_BYTES: usize = 16 * 1024;

/// The `{{code}}` placeholder in a page: the code as requested, escaped.
pub const CODE_PLACEHOLDER: &str = "{{code}}";

/// The `{{host}}` placeholder in a page: the domain, lowercase.
pub const HOST_PLACEHOLDER: &str = "{{host}}";

/// What a custom domain does besides serving its links. Every field is
/// optional; the default is a domain that behaves like the default one.
/// Unknown fields are ignored when read, so an origin may publish settings
/// an edge deployed earlier does not know yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainSettings {
    /// Where `/` redirects (302); without it `/` is the 404 page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_url: Option<String>,
    /// HTML served with 404 for unknown codes, disabled links and paths
    /// that cannot be a code here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found_page: Option<String>,
    /// HTML served with 410 for expired links and links at their click
    /// limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gone_page: Option<String>,
    /// Lowercase path segments accepted in front of a code: with
    /// `campaign`, `/campaign/abc` is the link `abc`, and so is `/abc`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// Whether `/ABC` and `/abc` are the same link. Codes on such a domain
    /// are stored in lowercase.
    #[serde(skip_serializing_if = "is_false")]
    pub case_insensitive: bool,
    /// The iOS and Android apps the domain belongs to, published in its
    /// association files ([`crate::deeplink`]). The Worker never reads
    /// them: the origin renders the files into the domain's `host:` record
    /// ([`crate::wire::EdgeDomain::files`]), so on wasm32 the field is not
    /// parsed and its parser stays out of the bundle.
    #[serde(skip_serializing_if = "Apps::is_empty")]
    #[cfg_attr(target_arch = "wasm32", serde(skip_deserializing))]
    pub apps: Apps,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Why settings were refused. Each names the field at fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsError {
    RootUrl(UrlError),
    Page { field: &'static str, reason: String },
    Prefix(String),
    Apps(AppError),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::RootUrl(e) => write!(f, "root_url: {e}"),
            SettingsError::Page { field, reason } => write!(f, "{field}: {reason}"),
            SettingsError::Prefix(reason) => write!(f, "prefixes: {reason}"),
            SettingsError::Apps(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SettingsError {}

fn check_page(field: &'static str, page: &str) -> Result<(), SettingsError> {
    let reason = if page.trim().is_empty() {
        "must not be empty (use null for the default page)".to_owned()
    } else if page.len() > MAX_PAGE_BYTES {
        format!("must be at most {MAX_PAGE_BYTES} bytes")
    } else if page.contains('\0') {
        "must not contain NUL characters".to_owned()
    } else {
        return Ok(());
    };
    Err(SettingsError::Page { field, reason })
}

/// Checks one prefix and returns it lowercased: 1 to 32 characters of
/// `[A-Za-z0-9_-]`, starting and ending with a letter or digit, and not a
/// reserved word (so `/v1/links` on a custom domain is still the API).
pub fn parse_prefix(raw: &str) -> Result<String, SettingsError> {
    let b = raw.as_bytes();
    let err = |why: &str| Err(SettingsError::Prefix(format!("{raw:?} {why}")));
    if b.is_empty() || b.len() > MAX_PREFIX_LEN {
        return err("must be 1 to 32 characters");
    }
    if !b
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return err("may only contain letters, digits, '-' and '_'");
    }
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return err("must start and end with a letter or digit");
    }
    if is_reserved(raw) {
        return err("is reserved");
    }
    Ok(raw.to_ascii_lowercase())
}

impl DomainSettings {
    /// Validates the settings and returns them in stored form: the root
    /// URL normalised like a destination under `policy`, prefixes
    /// lowercased, sorted and without duplicates.
    pub fn validated(mut self, policy: Policy) -> Result<DomainSettings, SettingsError> {
        if let Some(u) = &self.root_url {
            self.root_url = Some(normalize(u, policy).map_err(SettingsError::RootUrl)?);
        }
        if let Some(p) = &self.not_found_page {
            check_page("not_found_page", p)?;
        }
        if let Some(p) = &self.gone_page {
            check_page("gone_page", p)?;
        }
        let mut prefixes = self
            .prefixes
            .iter()
            .map(|p| parse_prefix(p))
            .collect::<Result<Vec<_>, _>>()?;
        prefixes.sort();
        prefixes.dedup();
        if prefixes.len() > MAX_PREFIXES {
            return Err(SettingsError::Prefix(format!(
                "at most {MAX_PREFIXES} prefixes"
            )));
        }
        self.prefixes = prefixes;
        self.apps = self.apps.validated("apps").map_err(SettingsError::Apps)?;
        Ok(self)
    }

    /// Whether these are the defaults, which change nothing.
    pub fn is_default(&self) -> bool {
        *self == DomainSettings::default()
    }
}

/// What a request path names on a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// `/`.
    Root,
    /// A code to look up, lowercased on a case-insensitive domain.
    Code(Cow<'a, str>),
    /// Nothing this domain could serve: answered with its 404 page and no
    /// lookup.
    Miss,
    /// One of the domain's app association files
    /// ([`crate::deeplink::app_file`]), answered from its settings.
    AppFile(AppFile),
}

/// Reads `path` (without the leading `/`, still percent-encoded) on a
/// domain with `settings`, or on the default domain when `None`. Codes are
/// plain ASCII, so a percent-encoded path never names one.
pub fn target<'a>(path: &'a str, settings: Option<&DomainSettings>) -> Target<'a> {
    if path.is_empty() {
        return Target::Root;
    }
    if settings.is_some()
        && let Some(file) = app_file_at(path)
    {
        return Target::AppFile(file);
    }
    let code = match (path.split_once('/'), settings) {
        (None, _) => path,
        (Some((prefix, code)), Some(s))
            if s.prefixes.iter().any(|p| p.eq_ignore_ascii_case(prefix)) =>
        {
            code
        }
        (Some(_), _) => return Target::Miss,
    };
    if !is_plausible_code(code) {
        return Target::Miss;
    }
    match settings {
        Some(s) if s.case_insensitive && code.bytes().any(|b| b.is_ascii_uppercase()) => {
            Target::Code(Cow::Owned(code.to_ascii_lowercase()))
        }
        _ => Target::Code(Cow::Borrowed(code)),
    }
}

/// Which error page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageKind {
    NotFound,
    Gone,
}

/// An error page to serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub status: u16,
    /// `text/html` for a domain's own page, `text/plain` otherwise.
    pub content_type: &'static str,
    pub body: String,
}

/// The `content-type` of a domain's own pages.
pub const HTML: &str = "text/html; charset=utf-8";

/// The `content-type` of the built-in pages.
pub const PLAIN: &str = "text/plain; charset=utf-8";

/// Sent with a domain's own pages: the HTML is the workspace's, served on
/// its own domain, but it may not run scripts, load anything but images
/// and styles, submit forms or be framed.
pub const PAGE_CSP: &str = "default-src 'none'; img-src https: data:; style-src 'unsafe-inline' \
                            https:; font-src https: data:; base-uri 'none'; form-action 'none'; \
                            frame-ancestors 'none'";

/// Text of the built-in 404 page.
pub const NOT_FOUND_TEXT: &str = "not found\n";

/// Text of the built-in 410 page for an expired link.
pub const EXPIRED_TEXT: &str = "this link has expired\n";

/// The page for `kind` on `host` with `settings`, for a request of `path`
/// (`""` for the root). Without a page of the domain's own, the built-in
/// plain-text one, whose text for 410 is `gone_text`.
pub fn page(
    kind: PageKind,
    settings: Option<&DomainSettings>,
    host: &str,
    path: &str,
    gone_text: &str,
) -> Page {
    let (status, own, text) = match kind {
        PageKind::NotFound => (
            404,
            settings.and_then(|s| s.not_found_page.as_deref()),
            NOT_FOUND_TEXT,
        ),
        PageKind::Gone => (
            410,
            settings.and_then(|s| s.gone_page.as_deref()),
            gone_text,
        ),
    };
    match own {
        Some(html) => Page {
            status,
            content_type: HTML,
            body: render(html, host, path),
        },
        None => Page {
            status,
            content_type: PLAIN,
            body: text.to_owned(),
        },
    }
}

/// `template` with its placeholders replaced, each value HTML-escaped. The
/// code shown is the path's last segment.
pub fn render(template: &str, host: &str, path: &str) -> String {
    let code = path.rsplit('/').next().unwrap_or(path);
    let (code, host) = (escape(code), escape(host));
    let mut out = String::with_capacity(template.len() + code.len() + host.len());
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(t) = tail.strip_prefix(CODE_PLACEHOLDER) {
            out.push_str(&code);
            rest = t;
        } else if let Some(t) = tail.strip_prefix(HOST_PLACEHOLDER) {
            out.push_str(&host);
            rest = t;
        } else {
            out.push_str("{{");
            rest = &tail[2..];
        }
    }
    out.push_str(rest);
    out
}

/// Escapes text for HTML element content and quoted attributes.
pub fn escape(s: &str) -> Cow<'_, str> {
    if !s
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'&' | b'"' | b'\''))
    {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> DomainSettings {
        DomainSettings {
            root_url: Some("https://example.com/".into()),
            not_found_page: Some("<h1>{{code}} is not on {{host}}</h1>".into()),
            gone_page: Some("<p>gone</p>".into()),
            prefixes: vec!["campaign".into()],
            case_insensitive: true,
            apps: Apps::default(),
        }
    }

    const POLICY: Policy = Policy {
        allow_ip_literals: false,
        allow_private: false,
    };

    #[test]
    fn settings_are_validated_into_stored_form() {
        let s = DomainSettings {
            root_url: Some("  HTTPS://Example.COM ".into()),
            prefixes: vec!["Promo".into(), "campaign".into(), "promo".into()],
            ..DomainSettings::default()
        }
        .validated(POLICY)
        .unwrap();
        assert_eq!(s.root_url.as_deref(), Some("https://example.com/"));
        assert_eq!(s.prefixes, ["campaign", "promo"]);
        assert!(DomainSettings::default().is_default());
        assert!(!s.is_default());

        let err = |s: DomainSettings| s.validated(POLICY).unwrap_err().to_string();
        let with_root = |u: &str| DomainSettings {
            root_url: Some(u.into()),
            ..DomainSettings::default()
        };
        assert!(err(with_root("http://10.0.0.1/")).starts_with("root_url:"));
        assert!(err(with_root("javascript:alert(1)")).starts_with("root_url:"));
        for (page, why) in [
            ("  ", "must not be empty"),
            ("a\0b", "NUL"),
            (&"x".repeat(MAX_PAGE_BYTES + 1), "at most"),
        ] {
            let nf = DomainSettings {
                not_found_page: Some(page.to_owned()),
                ..DomainSettings::default()
            };
            assert!(err(nf).contains(why), "{why}");
            let gone = DomainSettings {
                gone_page: Some(page.to_owned()),
                ..DomainSettings::default()
            };
            assert!(err(gone).starts_with("gone_page:"));
        }
        let ok_page = DomainSettings {
            not_found_page: Some("x".repeat(MAX_PAGE_BYTES)),
            ..DomainSettings::default()
        };
        assert!(ok_page.validated(POLICY).is_ok());
        let many = DomainSettings {
            prefixes: (0..=MAX_PREFIXES).map(|i| format!("p{i}")).collect(),
            ..DomainSettings::default()
        };
        assert!(err(many).contains("at most 8"));

        // Apps are validated with their path and kept in canonical form.
        let with_apps = |json: &str| DomainSettings {
            apps: serde_json::from_str(json).unwrap(),
            ..DomainSettings::default()
        };
        let s =
            with_apps(r#"{"ios": [{"team_id": "abcde12345", "bundle_id": "com.example.app"}]}"#)
                .validated(POLICY)
                .unwrap();
        assert_eq!(s.apps.ios[0].team_id, "ABCDE12345");
        assert!(!s.is_default());
        let e = err(with_apps(
            r#"{"ios": [{"team_id": "x", "bundle_id": "com.example.app"}]}"#,
        ));
        assert!(e.starts_with("apps.ios[0].team_id: "), "{e}");
        // Settings without apps leave them out of the wire form.
        let json = serde_json::to_string(&DomainSettings::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn prefixes() {
        assert_eq!(parse_prefix("Summer-2026").unwrap(), "summer-2026");
        assert_eq!(parse_prefix("a").unwrap(), "a");
        for (bad, why) in [
            ("", "1 to 32"),
            (&*"a".repeat(33), "1 to 32"),
            ("a/b", "may only"),
            ("a.b", "may only"),
            ("ü", "may only"),
            ("-a", "start and end"),
            ("a_", "start and end"),
            ("V1", "reserved"),
            ("api", "reserved"),
        ] {
            let e = parse_prefix(bad).unwrap_err().to_string();
            assert!(e.starts_with("prefixes:") && e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn paths_name_codes_roots_or_nothing() {
        let s = settings();
        let plain = DomainSettings::default();
        let code = |c: &str| Target::Code(Cow::Owned(c.to_owned()));
        for (path, on, want) in [
            ("", Some(&s), Target::Root),
            ("", None, Target::Root),
            ("abc", None, code("abc")),
            ("ABC", None, code("ABC")),
            ("ABC", Some(&plain), code("ABC")),
            ("ABC", Some(&s), code("abc")),
            ("abc", Some(&s), code("abc")),
            ("campaign/AbC", Some(&s), code("abc")),
            ("Campaign/abc", Some(&s), code("abc")),
            ("campaign/abc", Some(&plain), Target::Miss),
            ("campaign/abc", None, Target::Miss),
            ("other/abc", Some(&s), Target::Miss),
            ("campaign/", Some(&s), Target::Miss),
            ("campaign/a/b", Some(&s), Target::Miss),
            ("campaign/ab", Some(&s), Target::Miss),
            ("/abc", Some(&s), Target::Miss),
            ("ab", Some(&s), Target::Miss),
            ("a%62c", Some(&s), Target::Miss),
            ("abc.php", None, Target::Miss),
            // Association files exist only on custom domains.
            (
                ".well-known/apple-app-site-association",
                Some(&plain),
                Target::AppFile(AppFile::Apple),
            ),
            (
                "apple-app-site-association",
                Some(&s),
                Target::AppFile(AppFile::Apple),
            ),
            (
                ".well-known/assetlinks.json",
                Some(&s),
                Target::AppFile(AppFile::Android),
            ),
            (".well-known/assetlinks.json", None, Target::Miss),
            (
                "apple-app-site-association",
                None,
                code("apple-app-site-association"),
            ),
        ] {
            assert_eq!(target(path, on), want, "{path:?}");
        }
        // No allocation when nothing changes.
        assert!(matches!(
            target("abc", Some(&s)),
            Target::Code(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn pages_are_the_domains_own_or_built_in() {
        let s = settings();
        let p = page(PageKind::NotFound, Some(&s), "go.example.com", "x<y", "-");
        assert_eq!(p.status, 404);
        assert_eq!(p.content_type, HTML);
        assert_eq!(p.body, "<h1>x&lt;y is not on go.example.com</h1>");
        let p = page(PageKind::Gone, Some(&s), "go.example.com", "abc", "-");
        assert_eq!((p.status, p.body.as_str()), (410, "<p>gone</p>"));
        let plain = DomainSettings::default();
        let p = page(PageKind::Gone, Some(&plain), "h", "abc", EXPIRED_TEXT);
        assert_eq!((p.status, p.content_type), (410, PLAIN));
        assert_eq!(p.body, EXPIRED_TEXT);
        let p = page(PageKind::NotFound, None, "h", "abc", EXPIRED_TEXT);
        assert_eq!((p.status, p.body.as_str()), (404, NOT_FOUND_TEXT));
    }

    #[test]
    fn templates_escape_what_they_insert() {
        assert_eq!(
            render("{{code}}|{{host}}|{{other}}|{{", "h.example", "c/'\"&>"),
            "&#39;&quot;&amp;&gt;|h.example|{{other}}|{{"
        );
        assert_eq!(render("{{{{code}}", "h", "abc"), "{{abc");
        assert_eq!(render("no placeholders", "h", "abc"), "no placeholders");
        assert!(matches!(escape("plain"), Cow::Borrowed("plain")));
        assert_eq!(escape("ü<"), "ü&lt;");
    }

    #[test]
    fn settings_serialise_only_what_is_set() {
        assert_eq!(
            serde_json::to_string(&DomainSettings::default()).unwrap(),
            "{}"
        );
        let s = settings();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<DomainSettings>(&json).unwrap(), s);
        let later: DomainSettings =
            serde_json::from_str(r#"{"case_insensitive":true,"future":1}"#).unwrap();
        assert!(later.case_insensitive);
        assert!(SettingsError::Prefix("x".into()).to_string().contains('x'));
    }
}

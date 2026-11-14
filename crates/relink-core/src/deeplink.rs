//! Mobile deep links, decided the same way at the origin and the edge.
//!
//! Two halves:
//!
//! - **Domain association.** A custom domain names the apps it belongs to
//!   ([`Apps`], part of its settings). The domain then serves
//!   `/.well-known/apple-app-site-association` (and the legacy
//!   `/apple-app-site-association`) for iOS universal links and
//!   `/.well-known/assetlinks.json` for Android app links, built by
//!   [`app_file`]. With them, an installed app opens a link on that domain
//!   itself, before the request ever reaches relink.
//! - **Per-link app targets.** A link may say where phones go when the app
//!   did not open it ([`AppLink`]). An iOS visitor is sent to the App Store
//!   page; an Android visitor gets an `intent:` URL that opens the app at
//!   the link's deep link when it is installed and the store (or another
//!   fallback) when it is not. Desktops, other systems and crawlers follow
//!   the link's own destinations, so previews still show the web page.
//!
//! Everything a visitor or the stores can see is ASCII built from
//! validated parts, so it is safe in a `Location` header and in JSON.

use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::classify::{Device, Os, device_class, os_family};
use crate::destination::{Policy, normalize};

/// Most apps per platform a domain may name.
pub const MAX_APPS: usize = 8;

/// Most signing-certificate fingerprints per Android app.
pub const MAX_FINGERPRINTS: usize = 8;

/// Longest deep link URL.
pub const MAX_DEEP_LINK_LEN: usize = 1024;

/// Longest Android package name.
pub const MAX_PACKAGE_LEN: usize = 255;

/// Longest iOS bundle ID.
pub const MAX_BUNDLE_ID_LEN: usize = 155;

/// The `content-type` of both association files.
pub const JSON: &str = "application/json";

/// `Cache-Control` of both association files. Apple fetches them through
/// its own CDN and Android at install; five minutes keeps a settings change
/// quick to arrive without making relink answer every check.
pub const APP_FILE_CACHE: &str = "public, max-age=300";

/// The paths a domain serves association files at, without the leading
/// `/`, as sent.
pub const AASA_PATH: &str = ".well-known/apple-app-site-association";
pub const AASA_LEGACY_PATH: &str = "apple-app-site-association";
pub const ASSET_LINKS_PATH: &str = ".well-known/assetlinks.json";

/// Which association file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppFile {
    /// `apple-app-site-association`, for iOS universal links.
    Apple,
    /// `assetlinks.json`, for Android app links.
    Android,
}

/// The association file `path` (without the leading `/`) names, if any.
pub fn app_file_at(path: &str) -> Option<AppFile> {
    match path {
        AASA_PATH | AASA_LEGACY_PATH => Some(AppFile::Apple),
        ASSET_LINKS_PATH => Some(AppFile::Android),
        _ => None,
    }
}

/// One iOS app: its Apple team ID and bundle ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IosApp {
    pub team_id: String,
    pub bundle_id: String,
}

/// One Android app: its package name and the SHA-256 fingerprints of the
/// certificates it is signed with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidApp {
    pub package: String,
    pub sha256_cert_fingerprints: Vec<String>,
}

/// The apps a custom domain belongs to. Every path on the domain is
/// associated: the domain only serves links, and an app that does not
/// handle one can open it in the browser.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Apps {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ios: Vec<IosApp>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub android: Vec<AndroidApp>,
}

/// Why app settings were refused: the JSON path of the part at fault and
/// what is wrong with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppError {
    pub path: String,
    pub reason: String,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

impl std::error::Error for AppError {}

fn fail<T>(path: impl Into<String>, reason: impl Into<String>) -> Result<T, AppError> {
    Err(AppError {
        path: path.into(),
        reason: reason.into(),
    })
}

/// An Apple team ID: ten letters or digits, returned in uppercase.
pub fn parse_team_id(raw: &str) -> Option<String> {
    (raw.len() == 10 && raw.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| raw.to_ascii_uppercase())
}

/// A bundle ID: dot-separated labels of letters, digits and hyphens, at
/// least two of them, at most 155 characters.
pub fn is_bundle_id(s: &str) -> bool {
    s.len() <= MAX_BUNDLE_ID_LEN
        && s.split('.').count() >= 2
        && s.split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// An Android package name: at least two dot-separated segments, each a
/// letter followed by letters, digits and underscores, at most 255
/// characters.
pub fn is_package_name(s: &str) -> bool {
    s.len() <= MAX_PACKAGE_LEN
        && s.split('.').count() >= 2
        && s.split('.').all(|seg| {
            let b = seg.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_alphabetic()
                && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

/// A SHA-256 certificate fingerprint as 64 hex digits, with or without a
/// `:` between bytes, returned in the form `assetlinks.json` uses:
/// uppercase pairs joined by `:`.
pub fn parse_fingerprint(raw: &str) -> Option<String> {
    let hex: Vec<u8> = if raw.contains(':') {
        let pairs: Vec<&str> = raw.split(':').collect();
        if pairs.len() != 32 || pairs.iter().any(|p| p.len() != 2) {
            return None;
        }
        pairs.concat().into_bytes()
    } else {
        raw.as_bytes().to_vec()
    };
    if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = String::with_capacity(95);
    for (i, pair) in hex.chunks(2).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push(pair[0].to_ascii_uppercase() as char);
        out.push(pair[1].to_ascii_uppercase() as char);
    }
    Some(out)
}

impl Apps {
    /// Whether no app is named.
    pub fn is_empty(&self) -> bool {
        self.ios.is_empty() && self.android.is_empty()
    }

    /// Validates the apps and returns them in stored form: team IDs and
    /// fingerprints in canonical case. Errors name the part at fault under
    /// `path` (`apps.ios[1].team_id: ...`).
    pub fn validated(mut self, path: &str) -> Result<Apps, AppError> {
        if self.ios.len() > MAX_APPS {
            return fail(format!("{path}.ios"), format!("at most {MAX_APPS} apps"));
        }
        if self.android.len() > MAX_APPS {
            return fail(
                format!("{path}.android"),
                format!("at most {MAX_APPS} apps"),
            );
        }
        for (i, app) in self.ios.iter_mut().enumerate() {
            let at = format!("{path}.ios[{i}]");
            app.team_id = match parse_team_id(&app.team_id) {
                Some(t) => t,
                None => {
                    return fail(
                        format!("{at}.team_id"),
                        format!("{:?} must be 10 letters or digits", app.team_id),
                    );
                }
            };
            if !is_bundle_id(&app.bundle_id) {
                return fail(
                    format!("{at}.bundle_id"),
                    format!(
                        "{:?} must be at least two dot-separated labels of letters, digits and \
                         '-', at most {MAX_BUNDLE_ID_LEN} characters",
                        app.bundle_id
                    ),
                );
            }
        }
        for i in 1..self.ios.len() {
            let id = |a: &IosApp| (a.team_id.clone(), a.bundle_id.to_ascii_lowercase());
            if self.ios[..i].iter().any(|a| id(a) == id(&self.ios[i])) {
                return fail(format!("{path}.ios[{i}]"), "names the same app twice");
            }
        }
        for (i, app) in self.android.iter_mut().enumerate() {
            let at = format!("{path}.android[{i}]");
            if !is_package_name(&app.package) {
                return fail(
                    format!("{at}.package"),
                    format!(
                        "{:?} is not an Android package name (two or more segments like \
                         com.example.app)",
                        app.package
                    ),
                );
            }
            let prints = &mut app.sha256_cert_fingerprints;
            if prints.is_empty() || prints.len() > MAX_FINGERPRINTS {
                return fail(
                    format!("{at}.sha256_cert_fingerprints"),
                    format!("must list 1 to {MAX_FINGERPRINTS} fingerprints"),
                );
            }
            for j in 0..prints.len() {
                prints[j] = match parse_fingerprint(&prints[j]) {
                    Some(p) => p,
                    None => {
                        return fail(
                            format!("{at}.sha256_cert_fingerprints[{j}]"),
                            format!(
                                "{:?} is not a SHA-256 fingerprint (64 hex digits)",
                                prints[j]
                            ),
                        );
                    }
                };
                if prints[..j].contains(&prints[j]) {
                    return fail(
                        format!("{at}.sha256_cert_fingerprints[{j}]"),
                        "is listed twice",
                    );
                }
            }
        }
        for i in 1..self.android.len() {
            if self.android[..i]
                .iter()
                .any(|a| a.package == self.android[i].package)
            {
                return fail(
                    format!("{path}.android[{i}]"),
                    "names the same package twice",
                );
            }
        }
        Ok(self)
    }
}

/// A JSON string literal for `s`.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The body of `file` for a domain with `apps`, or `None` when the domain
/// names no app for that platform (the domain's 404 page answers instead).
///
/// The Apple file lists every app under both the current `appIDs` with
/// `components` (iOS 13 and later) and the older `appID` with `paths`, so
/// any iOS version associates every path on the domain.
pub fn app_file(file: AppFile, apps: &Apps) -> Option<String> {
    let mut out = String::new();
    match file {
        AppFile::Apple if !apps.ios.is_empty() => {
            out.push_str(r#"{"applinks":{"apps":[],"details":["#);
            for (i, app) in apps.ios.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let mut id = String::new();
                json_str(&mut id, &format!("{}.{}", app.team_id, app.bundle_id));
                let _ = write!(
                    out,
                    r#"{{"appID":{id},"appIDs":[{id}],"paths":["*"],"components":[{{"/":"*"}}]}}"#
                );
            }
            out.push_str("]}}");
        }
        AppFile::Android if !apps.android.is_empty() => {
            out.push('[');
            for (i, app) in apps.android.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    r#"{"relation":["delegate_permission/common.handle_all_urls"],"target":{"namespace":"android_app","package_name":"#,
                );
                json_str(&mut out, &app.package);
                out.push_str(r#","sha256_cert_fingerprints":["#);
                for (j, f) in app.sha256_cert_fingerprints.iter().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    json_str(&mut out, f);
                }
                out.push_str("]}}");
            }
            out.push(']');
        }
        _ => return None,
    }
    Some(out)
}

/// Where iOS visitors go when the app did not open the link: universal
/// links open an installed app before the request reaches relink, so a
/// visit that does arrive is from a phone without it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IosTarget {
    /// The app's App Store page.
    pub store_url: String,
}

/// What Android visitors get: an `intent:` URL that opens `package` at
/// `url` when it is installed, and sends the browser to `store_url` when it
/// is not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidTarget {
    pub package: String,
    /// The deep link the app is opened at: `myapp://item/42`, or an https
    /// app link.
    pub url: String,
    /// Where the browser goes without the app; the package's Play Store page
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_url: Option<String>,
}

/// Schemes a deep link may not use: ones a browser would run or read
/// itself rather than hand to the app, plain http, and `intent` itself.
const REFUSED_SCHEMES: &[&str] = &[
    "about",
    "blob",
    "data",
    "file",
    "filesystem",
    "http",
    "intent",
    "javascript",
    "vbscript",
];

/// Splits a deep link into its scheme and the part after `://`, if it is
/// one this module can carry: printable ASCII without spaces or `#`, at
/// most 1,024 bytes, with a lowercase RFC 3986 scheme that is not refused
/// and something after `://`.
pub fn split_deep_link(url: &str) -> Option<(&str, &str)> {
    if url.len() > MAX_DEEP_LINK_LEN || !url.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let b = scheme.as_bytes();
    let scheme_ok = !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'+' || c == b'-' || c == b'.'
        });
    (scheme_ok && !REFUSED_SCHEMES.contains(&scheme) && !rest.is_empty()).then_some((scheme, rest))
}

/// Whether a stored URL can be sent as a `Location` as it is: not empty,
/// printable ASCII. The API only stores normalised URLs, which are; a row
/// edited by hand into something else is ignored rather than served.
fn is_location(url: &str) -> bool {
    !url.is_empty() && url.bytes().all(|b| b.is_ascii_graphic())
}

/// The Play Store page of `package`.
pub fn play_store_url(package: &str) -> String {
    format!("https://play.google.com/store/apps/details?id={package}")
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode_component(out: &mut String, s: &str) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

impl AndroidTarget {
    /// The `intent:` URL Android visitors are sent to, or `None` for a
    /// target that breaks a rule the API checks (a row edited by hand):
    /// such a target is ignored rather than served.
    pub fn intent(&self) -> Option<String> {
        if !is_package_name(&self.package) {
            return None;
        }
        let (scheme, rest) = split_deep_link(&self.url)?;
        let package = &self.package;
        let fallback = match &self.store_url {
            Some(u) if is_location(u) => u.clone(),
            Some(_) => return None,
            None => play_store_url(package),
        };
        let mut intent = String::with_capacity(self.url.len() + fallback.len() * 3 + 96);
        let _ = write!(
            intent,
            "intent://{rest}#Intent;scheme={scheme};package={package};S.browser_fallback_url="
        );
        encode_component(&mut intent, &fallback);
        intent.push_str(";end");
        Some(intent)
    }
}

/// An [`IosTarget`] from the API: the store URL normalised like a
/// destination under `policy`. Errors are under `app.ios`.
pub fn ios_target(store_url: &str, policy: Policy) -> Result<IosTarget, AppError> {
    match normalize(store_url, policy) {
        Ok(store_url) => Ok(IosTarget { store_url }),
        Err(e) => fail("app.ios.store_url", e.to_string()),
    }
}

/// An [`AndroidTarget`] from the API, each part checked with its own path
/// under `app.android`; the store URL is normalised like a destination
/// under `policy`.
pub fn android_target(
    package: &str,
    url: &str,
    store_url: Option<&str>,
    policy: Policy,
) -> Result<AndroidTarget, AppError> {
    if !is_package_name(package) {
        return fail(
            "app.android.package",
            format!(
                "{package:?} is not an Android package name (two or more segments like \
                 com.example.app)"
            ),
        );
    }
    if split_deep_link(url).is_none() {
        return fail(
            "app.android.url",
            format!(
                "{url:?} must be scheme://... with a lowercase scheme other than http, \
                 javascript, data, file or intent, in at most {MAX_DEEP_LINK_LEN} printable \
                 ASCII characters without '#'"
            ),
        );
    }
    let store_url = match store_url {
        Some(u) => match normalize(u, policy) {
            Ok(n) => Some(n),
            Err(e) => return fail("app.android.store_url", e.to_string()),
        },
        None => None,
    };
    Ok(AndroidTarget {
        package: package.to_owned(),
        url: url.to_owned(),
        store_url,
    })
}

/// Where a link sends phones instead of its destinations, as written: what
/// the API takes and returns and the database stores. The redirect path
/// uses its compiled form, [`AppTargets`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ios: Option<IosTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android: Option<AndroidTarget>,
}

impl AppLink {
    /// Whether neither platform is set.
    pub fn is_empty(&self) -> bool {
        self.ios.is_none() && self.android.is_none()
    }

    /// The locations each platform is sent to.
    pub fn compile(&self) -> AppTargets {
        AppTargets {
            ios: self
                .ios
                .as_ref()
                .filter(|t| is_location(&t.store_url))
                .map(|t| t.store_url.clone()),
            android: self.android.as_ref().and_then(AndroidTarget::intent),
        }
    }
}

/// A link's app targets compiled to the `Location` each platform gets: the
/// App Store page for iOS, the `intent:` URL for Android. This is what a
/// cached link holds and what its KV record carries (`"app"`, left out when
/// empty), so the Worker reads two strings and never builds an intent.
///
/// On the wire it is the pair `[ios, android]`, with `""` for a platform
/// that is not set ([`pair`]): the Worker already parses lists of strings,
/// and a struct of its own would cost its bundle another parser.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<String>", into = "Vec<String>")]
pub struct AppTargets {
    pub ios: Option<String>,
    pub android: Option<String>,
}

impl From<Vec<String>> for AppTargets {
    fn from(v: Vec<String>) -> AppTargets {
        let (ios, android) = pair::from(v);
        AppTargets { ios, android }
    }
}

impl From<AppTargets> for Vec<String> {
    fn from(t: AppTargets) -> Vec<String> {
        pair::into(t.ios, t.android)
    }
}

/// Two optional strings as a list of two, `""` standing for `None`. A list
/// of another length reads its first two entries, so a later origin may
/// append more.
mod pair {
    pub fn from(mut v: Vec<String>) -> (Option<String>, Option<String>) {
        v.truncate(2);
        let mut it = v.into_iter().map(|s| (!s.is_empty()).then_some(s));
        (it.next().flatten(), it.next().flatten())
    }

    pub fn into(a: Option<String>, b: Option<String>) -> Vec<String> {
        vec![a.unwrap_or_default(), b.unwrap_or_default()]
    }
}

impl AppTargets {
    /// Whether neither platform is sent anywhere.
    pub fn is_empty(&self) -> bool {
        self.ios.is_none() && self.android.is_none()
    }

    /// Where a visitor with `user_agent` goes instead of the link's
    /// destinations, if anywhere. Crawlers never do: a preview should show
    /// the web page.
    pub fn target(&self, user_agent: Option<&[u8]>) -> Option<&str> {
        if self.is_empty() || device_class(user_agent) == Device::Bot {
            return None;
        }
        match os_family(user_agent) {
            Os::Ios => self.ios.as_deref(),
            Os::Android => self.android.as_deref(),
            _ => None,
        }
    }
}

/// A domain's association files, rendered by the origin into its `host:`
/// record ([`crate::wire::EdgeDomain`]) so the Worker serves them as they
/// are, without parsing the app list.
///
/// On the wire it is the pair `[apple, android]`, like [`AppTargets`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<String>", into = "Vec<String>")]
pub struct AppFiles {
    pub apple: Option<String>,
    pub android: Option<String>,
}

impl From<Vec<String>> for AppFiles {
    fn from(v: Vec<String>) -> AppFiles {
        let (apple, android) = pair::from(v);
        AppFiles { apple, android }
    }
}

impl From<AppFiles> for Vec<String> {
    fn from(f: AppFiles) -> Vec<String> {
        pair::into(f.apple, f.android)
    }
}

impl AppFiles {
    /// Both files for `apps`.
    pub fn render(apps: &Apps) -> AppFiles {
        AppFiles {
            apple: app_file(AppFile::Apple, apps),
            android: app_file(AppFile::Android, apps),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.apple.is_none() && self.android.is_none()
    }

    /// The body of `file`, if the domain has one.
    pub fn get(&self, file: AppFile) -> Option<&str> {
        match file {
            AppFile::Apple => self.apple.as_deref(),
            AppFile::Android => self.android.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPHONE: &[u8] = b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
        AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
    const PIXEL: &[u8] =
        b"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36";
    const DESKTOP: &[u8] = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36";
    const GOOGLEBOT: &[u8] = b"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) \
        AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; \
        +http://www.google.com/bot.html)";
    const PRINT: &str = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:\
                         A8:8A:04:96:B2:3F:CF:44:E5";

    fn policy() -> Policy {
        Policy::default()
    }

    fn apps() -> Apps {
        Apps {
            ios: vec![IosApp {
                team_id: "abcde12345".into(),
                bundle_id: "com.example.app".into(),
            }],
            android: vec![AndroidApp {
                package: "com.example.app".into(),
                sha256_cert_fingerprints: vec![PRINT.replace(':', "").to_ascii_lowercase()],
            }],
        }
    }

    #[test]
    fn paths_name_files() {
        assert_eq!(app_file_at(AASA_PATH), Some(AppFile::Apple));
        assert_eq!(app_file_at(AASA_LEGACY_PATH), Some(AppFile::Apple));
        assert_eq!(app_file_at(ASSET_LINKS_PATH), Some(AppFile::Android));
        assert_eq!(app_file_at(".well-known/assetlinks.json/"), None);
        assert_eq!(app_file_at(".well-known/Apple-App-Site-Association"), None);
        assert_eq!(app_file_at("abc"), None);
    }

    #[test]
    fn identifiers() {
        assert_eq!(parse_team_id("abcde12345").as_deref(), Some("ABCDE12345"));
        for bad in ["ABCDE1234", "ABCDE123456", "ABCDE-1234", "ABCDE 1234", ""] {
            assert_eq!(parse_team_id(bad), None, "{bad}");
        }
        assert!(is_bundle_id("com.example.app"));
        assert!(is_bundle_id("com.example-co.App2"));
        for bad in [
            "app",
            "com..app",
            ".com.app",
            "com.app.",
            "com.ex_ample",
            "com.ex ample",
        ] {
            assert!(!is_bundle_id(bad), "{bad}");
        }
        assert!(!is_bundle_id(&format!("com.{}", "a".repeat(152))));
        assert!(is_bundle_id(&format!("com.{}", "a".repeat(151))));
        assert!(is_package_name("com.example.app_2"));
        for bad in [
            "app",
            "com.1app",
            "com..app",
            "com.ex-ample",
            "com._app",
            "com.app.",
        ] {
            assert!(!is_package_name(bad), "{bad}");
        }
        assert!(!is_package_name(&format!("com.{}", "a".repeat(252))));
        assert_eq!(
            parse_fingerprint(&PRINT.replace(':', "").to_ascii_lowercase()).as_deref(),
            Some(PRINT)
        );
        assert_eq!(parse_fingerprint(PRINT).as_deref(), Some(PRINT));
        for bad in [
            &PRINT[..PRINT.len() - 3],
            &PRINT.replace("14:6D", "146:D"),
            &PRINT.replace("14", "1G"),
            &format!("{PRINT}:00"),
            "",
        ] {
            assert_eq!(parse_fingerprint(bad), None, "{bad}");
        }
    }

    #[test]
    fn apps_validate_into_canonical_form() {
        let v = apps().validated("apps").unwrap();
        assert_eq!(v.ios[0].team_id, "ABCDE12345");
        assert_eq!(v.android[0].sha256_cert_fingerprints, vec![PRINT]);
        assert!(Apps::default().validated("apps").unwrap().is_empty());
        assert!(!v.is_empty());
    }

    #[test]
    fn invalid_apps_name_their_path() {
        type Change = Box<dyn Fn(&mut Apps)>;
        let cases: Vec<(Change, &str)> = vec![
            (
                Box::new(|a| a.ios[0].team_id = "x".into()),
                "apps.ios[0].team_id: \"x\" must be 10 letters or digits",
            ),
            (
                Box::new(|a| a.ios[0].bundle_id = "app".into()),
                "apps.ios[0].bundle_id: \"app\" must be",
            ),
            (
                Box::new(|a| {
                    let mut dup = a.ios[0].clone();
                    dup.bundle_id = dup.bundle_id.to_uppercase();
                    a.ios.push(dup)
                }),
                "apps.ios[1]: names the same app twice",
            ),
            (
                Box::new(|a| a.ios = vec![a.ios[0].clone(); MAX_APPS + 1]),
                "apps.ios: at most 8 apps",
            ),
            (
                Box::new(|a| a.android = vec![a.android[0].clone(); MAX_APPS + 1]),
                "apps.android: at most 8 apps",
            ),
            (
                Box::new(|a| a.android[0].package = "app".into()),
                "apps.android[0].package: \"app\" is not an Android package name",
            ),
            (
                Box::new(|a| a.android[0].sha256_cert_fingerprints.clear()),
                "apps.android[0].sha256_cert_fingerprints: must list 1 to 8",
            ),
            (
                Box::new(|a| a.android[0].sha256_cert_fingerprints = vec![PRINT.into(); 9]),
                "apps.android[0].sha256_cert_fingerprints: must list 1 to 8",
            ),
            (
                Box::new(|a| a.android[0].sha256_cert_fingerprints.push("abc".into())),
                "apps.android[0].sha256_cert_fingerprints[1]: \"abc\" is not a SHA-256",
            ),
            (
                Box::new(|a| a.android[0].sha256_cert_fingerprints.push(PRINT.into())),
                "apps.android[0].sha256_cert_fingerprints[1]: is listed twice",
            ),
            (
                Box::new(|a| a.android.push(a.android[0].clone())),
                "apps.android[1]: names the same package twice",
            ),
        ];
        for (change, want) in cases {
            let mut a = apps();
            change(&mut a);
            let err = a.validated("apps").unwrap_err().to_string();
            assert!(err.starts_with(want), "{err} should start with {want}");
        }
    }

    #[test]
    fn association_files() {
        let a = apps().validated("apps").unwrap();
        let aasa = app_file(AppFile::Apple, &a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&aasa).unwrap();
        let detail = &v["applinks"]["details"][0];
        assert_eq!(detail["appID"], "ABCDE12345.com.example.app");
        assert_eq!(detail["appIDs"][0], "ABCDE12345.com.example.app");
        assert_eq!(detail["paths"][0], "*");
        assert_eq!(detail["components"][0]["/"], "*");
        assert_eq!(v["applinks"]["apps"], serde_json::json!([]));

        let links = app_file(AppFile::Android, &a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&links).unwrap();
        assert_eq!(
            v,
            serde_json::json!([{
                "relation": ["delegate_permission/common.handle_all_urls"],
                "target": {
                    "namespace": "android_app",
                    "package_name": "com.example.app",
                    "sha256_cert_fingerprints": [PRINT]
                }
            }])
        );

        // Several apps, and one platform without any.
        let mut two = a.clone();
        two.ios.push(IosApp {
            team_id: "ZZZZZ99999".into(),
            bundle_id: "org.example.other".into(),
        });
        two.android.clear();
        let v: serde_json::Value =
            serde_json::from_str(&app_file(AppFile::Apple, &two).unwrap()).unwrap();
        assert_eq!(v["applinks"]["details"].as_array().unwrap().len(), 2);
        assert_eq!(app_file(AppFile::Android, &two), None);
        assert_eq!(app_file(AppFile::Apple, &Apps::default()), None);

        // Strings are escaped even if a record was edited by hand.
        let mut odd = String::new();
        json_str(&mut odd, "a\"b\\c\n");
        assert_eq!(odd, r#""a\"b\\c\u000a""#);
    }

    #[test]
    fn deep_links_and_intents() {
        assert_eq!(
            split_deep_link("myapp://item/42?ref=x"),
            Some(("myapp", "item/42?ref=x"))
        );
        assert_eq!(
            split_deep_link("https://example.com/a"),
            Some(("https", "example.com/a"))
        );
        for bad in [
            "myapp:item",
            "myapp://",
            "MyApp://x",
            "1app://x",
            "my_app://x",
            "javascript://%0aalert(1)",
            "intent://x",
            "http://example.com/",
            "data://x",
            "file:///etc/passwd",
            "myapp://item#frag",
            "myapp://it em",
            "myapp://é",
            "://x",
        ] {
            assert_eq!(split_deep_link(bad), None, "{bad}");
        }
        assert!(split_deep_link(&format!("a://{}", "x".repeat(MAX_DEEP_LINK_LEN - 4))).is_some());
        assert!(split_deep_link(&format!("a://{}", "x".repeat(MAX_DEEP_LINK_LEN - 3))).is_none());

        let t = |package: &str, url: &str, store: Option<&str>| AndroidTarget {
            package: package.into(),
            url: url.into(),
            store_url: store.map(str::to_owned),
        };
        assert_eq!(
            t("com.example.app", "myapp://item/42?a=1", None)
                .intent()
                .unwrap(),
            "intent://item/42?a=1#Intent;scheme=myapp;package=com.example.app;\
             S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dcom.example.app;end"
        );
        assert_eq!(
            t(
                "com.example.app",
                "https://go.example.com/abc",
                Some("https://example.com/get-the-app?x=a%20b&y=~")
            )
            .intent()
            .unwrap(),
            "intent://go.example.com/abc#Intent;scheme=https;package=com.example.app;\
             S.browser_fallback_url=https%3A%2F%2Fexample.com%2Fget-the-app%3Fx%3Da%2520b%26y%3D~;end"
        );
        // Parts edited by hand into something the API refuses are ignored.
        assert_eq!(t("app", "myapp://x", None).intent(), None);
        assert_eq!(t("com.a.b", "javascript://x", None).intent(), None);
        assert_eq!(
            t("com.a.b", "myapp://x", Some("https://a b/")).intent(),
            None
        );
        assert_eq!(t("com.a.b", "myapp://x", Some("")).intent(), None);
        let odd: AppLink = serde_json::from_str(r#"{"ios": {"store_url": ""}}"#).unwrap();
        assert!(odd.compile().is_empty());
        let odd: AppLink =
            serde_json::from_str(r#"{"ios": {"store_url": "https://a\u0000/"}}"#).unwrap();
        assert!(odd.compile().is_empty());
    }

    fn app_link() -> AppLink {
        serde_json::from_str(
            r#"{"ios": {"store_url": "https://apps.apple.com/app/id1"},
                "android": {"package": "com.example.app", "url": "myapp://item/42"}}"#,
        )
        .unwrap()
    }

    #[test]
    fn written_and_compiled_forms() {
        let l = app_link();
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(
            json,
            r#"{"ios":{"store_url":"https://apps.apple.com/app/id1"},"android":{"package":"com.example.app","url":"myapp://item/42"}}"#
        );
        assert_eq!(serde_json::from_str::<AppLink>(&json).unwrap(), l);
        assert!(serde_json::from_str::<AppLink>("{}").unwrap().is_empty());

        let c = l.compile();
        assert_eq!(c.ios.as_deref(), Some("https://apps.apple.com/app/id1"));
        assert!(
            c.android
                .as_deref()
                .unwrap()
                .starts_with("intent://item/42#Intent;")
        );
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.starts_with(r#"["https://apps.apple.com/app/id1","intent://"#));
        assert_eq!(serde_json::from_str::<AppTargets>(&json).unwrap(), c);
        assert_eq!(
            serde_json::to_string(&AppTargets::default()).unwrap(),
            r#"["",""]"#
        );
        // Short and long lists read what they can.
        let one: AppTargets = serde_json::from_str(r#"["https://a.example/"]"#).unwrap();
        assert_eq!(
            (one.ios.as_deref(), one.android),
            (Some("https://a.example/"), None)
        );
        let three: AppTargets = serde_json::from_str(r#"["", "intent://x", "later"]"#).unwrap();
        assert_eq!(
            (three.ios, three.android.as_deref()),
            (None, Some("intent://x"))
        );
        assert!(AppLink::default().compile().is_empty());
    }

    #[test]
    fn rendered_files_are_served_as_they_are() {
        let files = AppFiles::render(&apps().validated("apps").unwrap());
        assert!(!files.is_empty());
        assert!(
            files
                .get(AppFile::Apple)
                .unwrap()
                .starts_with(r#"{"applinks":"#)
        );
        assert!(
            files
                .get(AppFile::Android)
                .unwrap()
                .starts_with(r#"[{"relation":"#)
        );
        let json = serde_json::to_string(&files).unwrap();
        assert_eq!(serde_json::from_str::<AppFiles>(&json).unwrap(), files);
        let none = AppFiles::render(&Apps::default());
        assert!(none.is_empty() && none.get(AppFile::Apple).is_none());
    }

    #[test]
    fn api_targets_are_checked_part_by_part() {
        let t = ios_target("HTTPS://Apps.Apple.com/app/id1", policy()).unwrap();
        assert_eq!(t.store_url, "https://apps.apple.com/app/id1");
        let err = ios_target("ftp://x", policy()).unwrap_err().to_string();
        assert!(err.starts_with("app.ios.store_url: "), "{err}");

        let t = android_target(
            "com.example.app",
            "myapp://a",
            Some("HTTPS://Example.com/get"),
            policy(),
        )
        .unwrap();
        assert_eq!(t.store_url.as_deref(), Some("https://example.com/get"));
        assert!(
            t.intent()
                .unwrap()
                .ends_with("https%3A%2F%2Fexample.com%2Fget;end")
        );
        for (package, url, store, want) in [
            ("app", "myapp://a", None, "app.android.package: "),
            (
                "com.example.app",
                "javascript://a",
                None,
                "app.android.url: ",
            ),
            ("com.example.app", "myapp:a", None, "app.android.url: "),
            (
                "com.example.app",
                "myapp://a",
                Some("https://localhost/"),
                "app.android.store_url: ",
            ),
        ] {
            let err = android_target(package, url, store, policy())
                .unwrap_err()
                .to_string();
            assert!(err.starts_with(want), "{err}");
        }
    }

    #[test]
    fn visitors_are_sent_by_platform() {
        let l = app_link().compile();
        assert_eq!(
            l.target(Some(IPHONE)),
            Some("https://apps.apple.com/app/id1")
        );
        assert!(
            l.target(Some(PIXEL))
                .unwrap()
                .starts_with("intent://item/42#Intent;")
        );
        assert_eq!(l.target(Some(DESKTOP)), None);
        assert_eq!(l.target(None), None);
        assert_eq!(l.target(Some(GOOGLEBOT)), None, "crawlers see the web page");
        let ios_only = AppLink {
            android: None,
            ..app_link()
        }
        .compile();
        assert_eq!(ios_only.target(Some(PIXEL)), None);
        assert_eq!(AppTargets::default().target(Some(IPHONE)), None);
    }
}

//! Short code rules shared by the server and the edge: the alphabet, alias
//! validation and the cheap plausibility check done before any lookup.

use std::fmt;

/// Base62 alphabet used for generated codes.
pub const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Bounds for generated code length (configurable within these).
pub const MIN_CODE_LEN: usize = 4;
pub const MAX_CODE_LEN: usize = 32;

/// Bounds for custom aliases.
pub const MIN_ALIAS_LEN: usize = 3;
pub const MAX_ALIAS_LEN: usize = 64;

/// Paths the service itself uses, or that are commonly expected to belong to
/// the site. Compared case-insensitively so `Metrics` is refused too.
pub const RESERVED: &[&str] = &[
    "admin",
    "api",
    "assets",
    "docs",
    "favicon",
    "health",
    "healthz",
    "help",
    "login",
    "logout",
    "metrics",
    "openapi",
    "readyz",
    "robots",
    "signin",
    "signup",
    "static",
    "status",
    "v1",
    "v2",
    "well-known",
    "www",
];

/// Whether `code` collides with a reserved path, ignoring case.
pub fn is_reserved(code: &str) -> bool {
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(code))
}

fn is_code_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Why an alias was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasError {
    Length,
    Charset,
    Edge,
    Reserved,
}

impl fmt::Display for AliasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AliasError::Length => "alias must be 3 to 64 characters",
            AliasError::Charset => "alias may only contain letters, digits, '-' and '_'",
            AliasError::Edge => "alias must start and end with a letter or digit",
            AliasError::Reserved => "alias is reserved",
        })
    }
}

impl std::error::Error for AliasError {}

/// Checks a custom alias: 3 to 64 characters of `[A-Za-z0-9_-]`, starting and
/// ending with a letter or digit, and not a reserved word.
pub fn validate_alias(alias: &str) -> Result<(), AliasError> {
    let bytes = alias.as_bytes();
    if !(MIN_ALIAS_LEN..=MAX_ALIAS_LEN).contains(&bytes.len()) {
        return Err(AliasError::Length);
    }
    if !bytes.iter().all(|&b| is_code_char(b)) {
        return Err(AliasError::Charset);
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(AliasError::Edge);
    }
    if is_reserved(alias) {
        return Err(AliasError::Reserved);
    }
    Ok(())
}

/// A cheap check on the redirect path: could this string be any stored code?
/// Anything else is answered with 404 without touching the cache or database.
pub fn is_plausible_code(s: &str) -> bool {
    let bytes = s.as_bytes();
    (MIN_ALIAS_LEN.min(MIN_CODE_LEN)..=MAX_ALIAS_LEN).contains(&bytes.len())
        && bytes.iter().all(|&b| is_code_char(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases() {
        assert!(validate_alias("summer-sale_2").is_ok());
        assert!(validate_alias("abc").is_ok());
        assert_eq!(validate_alias("ab"), Err(AliasError::Length));
        assert_eq!(validate_alias(&"a".repeat(65)), Err(AliasError::Length));
        assert_eq!(validate_alias("has space"), Err(AliasError::Charset));
        assert_eq!(validate_alias("ünï"), Err(AliasError::Charset));
        assert_eq!(validate_alias("a/b"), Err(AliasError::Charset));
        assert_eq!(validate_alias("-abc"), Err(AliasError::Edge));
        assert_eq!(validate_alias("abc_"), Err(AliasError::Edge));
        assert_eq!(validate_alias("Metrics"), Err(AliasError::Reserved));
        assert_eq!(validate_alias("well-known"), Err(AliasError::Reserved));
        for e in [
            AliasError::Length,
            AliasError::Charset,
            AliasError::Edge,
            AliasError::Reserved,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn plausible_codes() {
        assert!(is_plausible_code("abc"));
        assert!(!is_plausible_code("ab"));
        assert!(!is_plausible_code("abc.php"));
        assert!(!is_plausible_code(&"a".repeat(65)));
    }
}

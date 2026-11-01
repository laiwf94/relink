//! Argument parsing for the key administration commands of the binary
//! (`src/main.rs`), kept in the library so it is unit tested.
//!
//! ```text
//! relink create-key OWNER [NAME] [--workspace ID] [--scopes LIST] [--expires-in DURATION]
//! relink rotate-key ID [--overlap DURATION]
//! ```

use std::time::Duration;

use crate::auth::{
    DEFAULT_ROTATION_OVERLAP, MAX_KEY_LIFETIME, MAX_ROTATION_OVERLAP, Scopes, is_valid_owner,
    parse_duration,
};

/// `create-key` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateKey {
    pub owner: String,
    pub name: String,
    /// None: the owner's personal workspace.
    pub workspace_id: Option<i64>,
    pub scopes: Scopes,
    pub lifetime: Option<Duration>,
}

/// `rotate-key` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateKey {
    pub id: i64,
    pub overlap: Duration,
}

fn positive_id(what: &str, s: &str) -> Result<i64, String> {
    s.parse::<i64>()
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("{what} must be a positive integer"))
}

/// Positional words and `--flag value` pairs.
type Split<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>);

/// Splits `args` into positionals and `--flag value` pairs, refusing
/// unknown and repeated flags and flags without a value.
fn split<'a>(args: &[&'a str], known: &[&str]) -> Result<Split<'a>, String> {
    let mut positional = Vec::new();
    let mut flags: Vec<(&str, &str)> = Vec::new();
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if let Some(flag) = a.strip_prefix("--") {
            if !known.contains(&flag) {
                return Err(format!("unknown option --{flag}"));
            }
            if flags.iter().any(|(f, _)| *f == flag) {
                return Err(format!("--{flag} given twice"));
            }
            let value = it.next().ok_or_else(|| format!("--{flag} needs a value"))?;
            flags.push((flag, value));
        } else {
            positional.push(a);
        }
    }
    Ok((positional, flags))
}

impl CreateKey {
    /// Parses the words after `create-key`.
    pub fn parse(args: &[&str]) -> Result<CreateKey, String> {
        let (pos, flags) = split(args, &["workspace", "scopes", "expires-in"])?;
        let (owner, name) = match pos.as_slice() {
            [owner] => (*owner, ""),
            [owner, name] => (*owner, *name),
            _ => return Err("create-key takes OWNER and an optional NAME".into()),
        };
        if !is_valid_owner(owner) {
            return Err(
                "OWNER must be 1-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
                    .into(),
            );
        }
        if name.chars().count() > 100 {
            return Err("NAME must be at most 100 characters".into());
        }
        let mut key = CreateKey {
            owner: owner.to_owned(),
            name: name.to_owned(),
            workspace_id: None,
            scopes: Scopes::ALL,
            lifetime: None,
        };
        for (flag, value) in flags {
            match flag {
                "workspace" => key.workspace_id = Some(positive_id("--workspace", value)?),
                "scopes" => key.scopes = Scopes::parse_list(value)?,
                _ => {
                    let d = parse_duration(value)?;
                    if d.is_zero() || d > MAX_KEY_LIFETIME {
                        return Err("--expires-in must be between 1s and 3650d".into());
                    }
                    key.lifetime = Some(d);
                }
            }
        }
        Ok(key)
    }
}

impl RotateKey {
    /// Parses the words after `rotate-key`.
    pub fn parse(args: &[&str]) -> Result<RotateKey, String> {
        let (pos, flags) = split(args, &["overlap"])?;
        let [id] = pos.as_slice() else {
            return Err("rotate-key takes one key ID".into());
        };
        let mut rotate = RotateKey {
            id: positive_id("ID", id)?,
            overlap: DEFAULT_ROTATION_OVERLAP,
        };
        if let Some((_, value)) = flags.first() {
            let d = parse_duration(value)?;
            if d > MAX_ROTATION_OVERLAP {
                return Err("--overlap must be at most 30d".into());
            }
            rotate.overlap = d;
        }
        Ok(rotate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Scope;

    #[test]
    fn create_key_defaults() {
        assert_eq!(
            CreateKey::parse(&["alice"]),
            Ok(CreateKey {
                owner: "alice".into(),
                name: String::new(),
                workspace_id: None,
                scopes: Scopes::ALL,
                lifetime: None,
            })
        );
        assert_eq!(
            CreateKey::parse(&["alice", "laptop"]).unwrap().name,
            "laptop"
        );
    }

    #[test]
    fn create_key_options_in_any_order() {
        let k = CreateKey::parse(&[
            "--scopes",
            "links:read,stats:read",
            "carol",
            "--expires-in",
            "90d",
            "ci",
            "--workspace",
            "7",
        ])
        .unwrap();
        assert_eq!(k.owner, "carol");
        assert_eq!(k.name, "ci");
        assert_eq!(k.workspace_id, Some(7));
        assert_eq!(k.scopes, Scopes::from(Scope::LinksRead) | Scope::StatsRead);
        assert_eq!(k.lifetime, Some(Duration::from_secs(90 * 86_400)));
    }

    #[test]
    fn create_key_errors() {
        let err = |args: &[&str]| CreateKey::parse(args).unwrap_err();
        assert!(err(&[]).contains("OWNER"));
        assert!(err(&["a", "b", "c"]).contains("OWNER"));
        assert!(err(&["Bad Owner"]).contains("OWNER must be"));
        assert!(err(&["alice", &"n".repeat(101)]).contains("NAME"));
        assert!(err(&["alice", "--colour", "red"]).contains("unknown option --colour"));
        assert!(err(&["alice", "--scopes"]).contains("needs a value"));
        assert!(err(&["alice", "--scopes", "a", "--scopes", "b"]).contains("twice"));
        assert!(err(&["alice", "--scopes", "links:delete"]).contains("unknown scope"));
        assert!(err(&["alice", "--workspace", "0"]).contains("positive"));
        assert!(err(&["alice", "--workspace", "x"]).contains("positive"));
        assert!(err(&["alice", "--expires-in", "0s"]).contains("between"));
        assert!(err(&["alice", "--expires-in", "3651d"]).contains("between"));
        assert!(err(&["alice", "--expires-in", "soon"]).contains("duration"));
        assert!(CreateKey::parse(&["alice", "--expires-in", "3650d"]).is_ok());
    }

    #[test]
    fn rotate_key() {
        assert_eq!(
            RotateKey::parse(&["12"]),
            Ok(RotateKey {
                id: 12,
                overlap: DEFAULT_ROTATION_OVERLAP
            })
        );
        assert_eq!(
            RotateKey::parse(&["--overlap", "0s", "12"])
                .unwrap()
                .overlap,
            Duration::ZERO
        );
        assert_eq!(
            RotateKey::parse(&["12", "--overlap", "30d"])
                .unwrap()
                .overlap,
            MAX_ROTATION_OVERLAP
        );
        let err = |args: &[&str]| RotateKey::parse(args).unwrap_err();
        assert!(err(&[]).contains("one key ID"));
        assert!(err(&["1", "2"]).contains("one key ID"));
        assert!(err(&["-3"]).contains("unknown option") || err(&["-3"]).contains("positive"));
        assert!(err(&["abc"]).contains("positive"));
        assert!(err(&["1", "--overlap", "31d"]).contains("at most 30d"));
        assert!(err(&["1", "--overlap", "1w"]).contains("duration"));
        assert!(err(&["1", "--scopes", "links:read"]).contains("unknown option"));
    }
}

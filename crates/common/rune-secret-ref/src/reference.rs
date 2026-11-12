//! [`SecretRef`]: where a secret lives, and its `scheme:location` syntax.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::SecretError;

/// Where a secret lives. Parsed from a `scheme:location` string.
///
/// | Form | Meaning |
/// |---|---|
/// | `env:VAR` | the value of environment variable `VAR` |
/// | `file:PATH` | the contents of a file, one trailing newline stripped; relative paths join [`ResolveOptions::base_dir`] |
/// | `cmd:PROGRAM ARG…` | the standard output of a program, run without a shell; arguments split on whitespace |
/// | `keychain:SERVICE/ACCOUNT` | an OS keychain entry (parsed here, resolved by a secret provider) |
/// | `vault:PATH` | a secrets-manager path (parsed here, resolved by a secret provider) |
///
/// Any other text is treated as an inline secret and rejected with
/// [`SecretError::Inline`], so a credential pasted into a config file
/// fails loudly instead of being used (and later logged).
///
/// With the `serde` feature a reference also deserializes from a one-key
/// table, which lets command arguments contain spaces:
/// `{ cmd = ["pass", "show", "work/api token"] }`, `{ env = "VAR" }`.
///
/// [`ResolveOptions::base_dir`]: crate::ResolveOptions::base_dir
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretRef {
    /// An environment variable name (`[A-Za-z_][A-Za-z0-9_]*`).
    Env(String),
    /// A file path.
    File(PathBuf),
    /// A program and its arguments; its standard output is the secret.
    Command {
        /// The program, looked up on `PATH` when it has no separator.
        program: String,
        /// Its arguments, passed verbatim (no shell).
        args: Vec<String>,
    },
    /// An OS keychain entry.
    Keychain {
        /// Keychain service name (contains no `/`).
        service: String,
        /// Keychain account name.
        account: String,
    },
    /// A secrets-manager path.
    Vault(String),
}

impl SecretRef {
    /// The reference's scheme: `env`, `file`, `cmd`, `keychain` or `vault`.
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::File(_) => "file",
            Self::Command { .. } => "cmd",
            Self::Keychain { .. } => "keychain",
            Self::Vault(_) => "vault",
        }
    }

    /// Builds a reference from a scheme and its location, as written after
    /// the colon. `SecretRef::from_parts("env", "TOKEN")` equals
    /// `"env:TOKEN".parse()`.
    ///
    /// # Errors
    ///
    /// [`SecretError::Malformed`] for a bad location and
    /// [`SecretError::Inline`] for an unknown scheme.
    pub fn from_parts(scheme: &str, location: &str) -> Result<Self, SecretError> {
        match scheme {
            "env" => {
                if is_env_name(location) {
                    Ok(Self::Env(location.to_owned()))
                } else {
                    Err(SecretError::Malformed {
                        scheme: "env",
                        reason: "expected an environment variable name ([A-Za-z_][A-Za-z0-9_]*)",
                    })
                }
            }
            "file" => {
                if location.is_empty() {
                    Err(SecretError::Malformed {
                        scheme: "file",
                        reason: "expected a file path",
                    })
                } else {
                    Ok(Self::File(PathBuf::from(location)))
                }
            }
            "cmd" => Self::command(location.split_whitespace()),
            "keychain" => match location.split_once('/') {
                Some((service, account)) if !service.is_empty() && !account.is_empty() => {
                    Ok(Self::Keychain {
                        service: service.to_owned(),
                        account: account.to_owned(),
                    })
                }
                _ => Err(SecretError::Malformed {
                    scheme: "keychain",
                    reason: "expected `keychain:service/account`",
                }),
            },
            "vault" => {
                if location.is_empty() {
                    Err(SecretError::Malformed {
                        scheme: "vault",
                        reason: "expected a vault path",
                    })
                } else {
                    Ok(Self::Vault(location.to_owned()))
                }
            }
            _ => Err(SecretError::Inline),
        }
    }

    /// Builds a command reference from a program and its arguments, which
    /// may contain whitespace.
    ///
    /// # Errors
    ///
    /// [`SecretError::Malformed`] when `argv` is empty or the program name
    /// is blank.
    pub fn command<I, S>(argv: I) -> Result<Self, SecretError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut argv = argv.into_iter().map(Into::into);
        match argv.next() {
            Some(program) if !program.trim().is_empty() => Ok(Self::Command {
                program,
                args: argv.collect(),
            }),
            _ => Err(SecretError::Malformed {
                scheme: "cmd",
                reason: "expected a program name",
            }),
        }
    }

    /// Whether [`Display`](fmt::Display) output parses back to an equal
    /// reference. False only for a command whose program or arguments are
    /// empty or contain whitespace; serialize those in table form.
    #[must_use]
    pub fn has_string_form(&self) -> bool {
        match self {
            Self::Command { program, args } => std::iter::once(program)
                .chain(args)
                .all(|word| !word.is_empty() && !word.contains(char::is_whitespace)),
            _ => true,
        }
    }
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

impl FromStr for SecretRef {
    type Err = SecretError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (scheme, location) = text.split_once(':').ok_or(SecretError::Inline)?;
        Self::from_parts(scheme, location)
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => write!(f, "env:{name}"),
            Self::File(path) => write!(f, "file:{}", path.display()),
            Self::Command { program, args } => {
                write!(f, "cmd:{program}")?;
                args.iter().try_for_each(|arg| write!(f, " {arg}"))
            }
            Self::Keychain { service, account } => write!(f, "keychain:{service}/{account}"),
            Self::Vault(path) => write!(f, "vault:{path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_scheme() {
        assert_eq!(
            "env:API_KEY".parse::<SecretRef>().unwrap(),
            SecretRef::Env("API_KEY".into())
        );
        assert_eq!(
            "file:/run/secrets/token".parse::<SecretRef>().unwrap(),
            SecretRef::File("/run/secrets/token".into())
        );
        assert_eq!(
            "cmd:pass show  work/api".parse::<SecretRef>().unwrap(),
            SecretRef::Command {
                program: "pass".into(),
                args: vec!["show".into(), "work/api".into()]
            }
        );
        assert_eq!(
            "keychain:svc/acct/sub".parse::<SecretRef>().unwrap(),
            SecretRef::Keychain {
                service: "svc".into(),
                account: "acct/sub".into()
            }
        );
        assert_eq!(
            "vault:kv/app#key".parse::<SecretRef>().unwrap(),
            SecretRef::Vault("kv/app#key".into())
        );
    }

    #[test]
    fn rejects_inline_secrets_without_echoing_them() {
        for text in ["sk-live-0123456789", "hunter2:abc", "", ":", "ENV:FOO"] {
            let error = text.parse::<SecretRef>().unwrap_err();
            assert!(matches!(error, SecretError::Inline), "{text}");
            if text.len() > 4 {
                assert!(!error.to_string().contains(text));
            }
        }
    }

    #[test]
    fn rejects_malformed_locations() {
        for text in [
            "env:",
            "env:1ABC",
            "env:A-B",
            "file:",
            "cmd:",
            "cmd:   ",
            "keychain:svc",
            "keychain:/a",
            "keychain:s/",
            "vault:",
        ] {
            assert!(
                matches!(
                    text.parse::<SecretRef>(),
                    Err(SecretError::Malformed { .. })
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn display_round_trips() {
        for text in [
            "env:_X1",
            "file:relative/path",
            "cmd:op read op://vault/item",
            "keychain:a/b",
            "vault:secret/data/x",
        ] {
            let parsed: SecretRef = text.parse().unwrap();
            assert!(parsed.has_string_form());
            assert_eq!(parsed.to_string(), text);
        }
    }

    #[test]
    fn command_constructor_keeps_spaces() {
        let reference = SecretRef::command(["pass", "show", "a b"]).unwrap();
        assert!(!reference.has_string_form());
        assert_eq!(reference.scheme(), "cmd");
        assert!(SecretRef::command(Vec::<String>::new()).is_err());
        assert!(SecretRef::command([" "]).is_err());
    }
}

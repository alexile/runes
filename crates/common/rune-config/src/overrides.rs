//! Environment-variable and command-line override layers.

use toml::Value;

use crate::issue::{ConfigIssue, Source};
use crate::key::parse_key;
use crate::value::ValueKind;

/// One override: a value for a single key, from one variable or flag.
#[derive(Clone, Debug, PartialEq)]
pub struct Override {
    pub source: Source,
    pub key: Vec<String>,
    pub value: Value,
}

/// An explicit environment-variable mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvVar {
    name: String,
    key: Result<Vec<String>, String>,
    key_text: String,
    kind: ValueKind,
}

/// Maps environment variables onto config keys.
///
/// The library never reads the process environment itself: pass the
/// variables to [`ConfigLoader::with_env`] (for example
/// `std::env::vars()`), which keeps loading deterministic and testable.
///
/// Two kinds of mapping exist:
///
/// - **Explicit** ([`var`](Self::var), [`var_as`](Self::var_as)): one
///   variable, one key, one [`ValueKind`].
/// - **Prefix** ([`prefix`](Self::prefix)): every variable starting with
///   the prefix maps to a key made from the rest of its name, lower-cased,
///   with `__` separating key segments. With prefix `APP_`, `APP_SCAN__RATE_LIMIT`
///   sets `scan.rate_limit`. Values use [`ValueKind::Auto`].
///
/// Prefix matches apply first, in variable-name order; explicit mappings
/// apply after them, in the order they were added, so an explicit mapping
/// wins over a prefix match for the same key. A variable that has an
/// explicit mapping, or was passed to [`ignore`](Self::ignore), is not also
/// treated as a prefix match.
///
/// [`ConfigLoader::with_env`]: crate::ConfigLoader::with_env
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvMapping {
    vars: Vec<EnvVar>,
    prefix: Option<String>,
    ignored: Vec<String>,
}

impl EnvMapping {
    /// An empty mapping: no variable is used.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps variable `name` to the dotted `key`, guessing the type
    /// ([`ValueKind::Auto`]).
    #[must_use]
    pub fn var(self, name: impl Into<String>, key: impl Into<String>) -> Self {
        self.var_as(name, key, ValueKind::Auto)
    }

    /// Maps variable `name` to the dotted `key`, converting its value as
    /// `kind`. A value that does not convert is reported against the
    /// variable when the configuration loads.
    #[must_use]
    pub fn var_as(
        mut self,
        name: impl Into<String>,
        key: impl Into<String>,
        kind: ValueKind,
    ) -> Self {
        let key_text = key.into();
        self.vars.push(EnvVar {
            name: name.into(),
            key: parse_key(&key_text),
            key_text,
            kind,
        });
        self
    }

    /// Maps every variable starting with `prefix` (see the type docs).
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Excludes variable `name` from prefix matching, for variables that
    /// share the prefix but are not config keys (such as `APP_CONFIG`
    /// naming the config file).
    #[must_use]
    pub fn ignore(mut self, name: impl Into<String>) -> Self {
        self.ignored.push(name.into());
        self
    }

    /// Resolves `vars` into overrides and issues.
    pub fn resolve(&self, vars: &[(String, String)]) -> (Vec<Override>, Vec<ConfigIssue>) {
        let mut overrides = Vec::new();
        let mut issues = Vec::new();

        if let Some(prefix) = self.prefix.as_deref() {
            let mut matched: Vec<&(String, String)> = vars
                .iter()
                .filter(|(name, _)| {
                    name.starts_with(prefix)
                        && !self.ignored.contains(name)
                        && !self.vars.iter().any(|var| &var.name == name)
                })
                .collect();
            matched.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, raw) in matched {
                let source = Source::Env(name.clone());
                let rest = &name[prefix.len()..];
                let key: Vec<String> = rest.split("__").map(str::to_ascii_lowercase).collect();
                if key.iter().any(String::is_empty) {
                    issues.push(ConfigIssue::new(
                        source,
                        None,
                        format!("cannot derive a config key from `{name}`"),
                    ));
                    continue;
                }
                overrides.push(Override {
                    source,
                    key,
                    value: ValueKind::Auto.parse(raw).unwrap_or_else(Value::String),
                });
            }
        }

        for var in &self.vars {
            // The last occurrence wins, as it would in a real environment.
            let Some((_, raw)) = vars.iter().rev().find(|(name, _)| name == &var.name) else {
                continue;
            };
            let source = Source::Env(var.name.clone());
            match (&var.key, var.kind.parse(raw)) {
                (Err(message), _) => {
                    issues.push(ConfigIssue::new(
                        source,
                        Some(var.key_text.clone()),
                        message.clone(),
                    ));
                }
                (Ok(_), Err(message)) => {
                    issues.push(ConfigIssue::new(
                        source,
                        Some(var.key_text.clone()),
                        message,
                    ));
                }
                (Ok(key), Ok(value)) => overrides.push(Override {
                    source,
                    key: key.clone(),
                    value,
                }),
            }
        }
        (overrides, issues)
    }
}

/// Values from command-line flags, the highest-priority layer.
///
/// Typed values from an argument parser go in with [`set`](Self::set) or
/// [`set_opt`](Self::set_opt); free-form `--set key=value` arguments go in
/// with [`assign`](Self::assign). Problems (a malformed key or assignment)
/// are kept and reported, against the flag, when the configuration loads.
/// Later entries win over earlier ones for the same key.
///
/// ```
/// use rune_config::{CliOverrides, ValueKind};
///
/// let rps: Option<u32> = Some(20);
/// let cli = CliOverrides::new()
///     .set_opt("--rps", "scan.rate_limit", rps)
///     .set("--verbose", "log.verbose", true)
///     .assign("--set", "scan.profile=quick")
///     .assign_as("--set", "scan.tag=007", ValueKind::String);
/// assert_eq!(cli.len(), 4);
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct CliOverrides {
    entries: Vec<Override>,
    issues: Vec<ConfigIssue>,
}

impl CliOverrides {
    /// No overrides.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the dotted `key` to `value`, attributed to `flag`.
    #[must_use]
    pub fn set(mut self, flag: impl Into<String>, key: &str, value: impl Into<Value>) -> Self {
        let source = Source::Cli(flag.into());
        match parse_key(key) {
            Ok(key) => self.entries.push(Override {
                source,
                key,
                value: value.into(),
            }),
            Err(message) => {
                self.issues
                    .push(ConfigIssue::new(source, Some(key.to_owned()), message));
            }
        }
        self
    }

    /// Like [`set`](Self::set) when `value` is `Some`; does nothing for
    /// `None` (a flag the user did not pass).
    #[must_use]
    pub fn set_opt<V: Into<Value>>(
        self,
        flag: impl Into<String>,
        key: &str,
        value: Option<V>,
    ) -> Self {
        match value {
            Some(value) => self.set(flag, key, value),
            None => self,
        }
    }

    /// Parses `assignment` of the form `key=value`, guessing the value's
    /// type ([`ValueKind::Auto`]).
    #[must_use]
    pub fn assign(self, flag: impl Into<String>, assignment: &str) -> Self {
        self.assign_as(flag, assignment, ValueKind::Auto)
    }

    /// Parses `assignment` of the form `key=value`, converting the value as
    /// `kind`.
    #[must_use]
    pub fn assign_as(mut self, flag: impl Into<String>, assignment: &str, kind: ValueKind) -> Self {
        let source = Source::Cli(flag.into());
        let Some((key_text, raw)) = assignment.split_once('=') else {
            self.issues.push(ConfigIssue::new(
                source,
                None,
                format!("expected `key=value`, got `{assignment}`"),
            ));
            return self;
        };
        let key_text = key_text.trim();
        match (parse_key(key_text), kind.parse(raw)) {
            (Ok(key), Ok(value)) => self.entries.push(Override { source, key, value }),
            (Err(message), _) | (_, Err(message)) => {
                self.issues
                    .push(ConfigIssue::new(source, Some(key_text.to_owned()), message));
            }
        }
        self
    }

    /// Number of overrides and pending problems.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len() + self.issues.len()
    }

    /// Whether nothing was set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The overrides and the problems recorded so far.
    #[must_use]
    pub fn parts(&self) -> (&[Override], &[ConfigIssue]) {
        (&self.entries, &self.issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn explicit_mapping_types_and_reports_against_the_variable() {
        let mapping = EnvMapping::new()
            .var_as("APP_RPS", "scan.rate_limit", ValueKind::Integer)
            .var("APP_NAME", "name");
        let (overrides, issues) = mapping.resolve(&env(&[("APP_RPS", "fast"), ("APP_NAME", "x")]));
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].key, ["name"]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].source, Source::Env("APP_RPS".into()));
        assert_eq!(issues[0].key.as_deref(), Some("scan.rate_limit"));
    }

    #[test]
    fn prefix_mapping_derives_keys_and_respects_ignore() {
        let mapping = EnvMapping::new()
            .prefix("APP_")
            .ignore("APP_CONFIG")
            .var("APP_SPECIAL", "other.key");
        let (overrides, issues) = mapping.resolve(&env(&[
            ("APP_SCAN__RATE_LIMIT", "5"),
            ("APP_CONFIG", "/etc/app.toml"),
            ("APP_SPECIAL", "1"),
            ("APP_BAD____X", "1"),
            ("OTHER", "1"),
        ]));
        let keys: Vec<_> = overrides.iter().map(|o| o.key.join(".")).collect();
        assert_eq!(keys, ["scan.rate_limit", "other.key"]);
        assert_eq!(overrides[0].value, Value::Integer(5));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].source, Source::Env("APP_BAD____X".into()));
    }

    #[test]
    fn cli_collects_problems_against_the_flag() {
        let cli = CliOverrides::new()
            .set("--x", "a..b", 1)
            .assign("--set", "no-equals")
            .assign_as("--set", "n=abc", ValueKind::Integer)
            .assign("--set", " a.b = 2");
        let (entries, issues) = cli.parts();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, Value::String(" 2".into()));
        assert_eq!(issues.len(), 3);
        assert!(issues.iter().all(|i| matches!(i.source, Source::Cli(_))));
        assert_eq!(cli.len(), 4);
        assert!(
            CliOverrides::new()
                .set_opt::<i64>("--x", "a", None)
                .is_empty()
        );
    }
}

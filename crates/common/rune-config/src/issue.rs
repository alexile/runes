//! Where a value came from, and problems attributed to that place.

use std::fmt;
use std::path::PathBuf;

/// The layer that set a value, or in which a problem was found.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// Built-in defaults supplied by the application.
    Default,
    /// The per-user config file (see [`default_user_config_path`]).
    ///
    /// [`default_user_config_path`]: crate::default_user_config_path
    UserFile(PathBuf),
    /// The project config file, usually in the working directory or given
    /// with `--config`.
    ProjectFile(PathBuf),
    /// Any other config file.
    File(PathBuf),
    /// TOML text supplied in memory, under a caller-chosen name.
    Inline(String),
    /// An environment variable, by name.
    Env(String),
    /// A command-line flag, as the user typed it (for example `--rps`).
    Cli(String),
    /// The merged configuration as a whole, for problems no single layer
    /// owns (such as a required key that no layer sets).
    Merged,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("built-in default"),
            Self::UserFile(path) => write!(f, "user file {}", path.display()),
            Self::ProjectFile(path) => write!(f, "project file {}", path.display()),
            Self::File(path) => write!(f, "file {}", path.display()),
            Self::Inline(name) => write!(f, "{name}"),
            Self::Env(var) => write!(f, "environment variable {var}"),
            Self::Cli(flag) => write!(f, "command-line flag {flag}"),
            Self::Merged => f.write_str("merged configuration"),
        }
    }
}

/// One configuration problem, attributed to a layer and (when known) a key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigIssue {
    /// The layer the problem was found in.
    pub source: Source,
    /// Dotted key path such as `scan.rate_limit`; `None` for problems with
    /// a whole layer, such as a TOML syntax error or an unreadable file.
    pub key: Option<String>,
    /// What is wrong.
    pub message: String,
}

impl ConfigIssue {
    /// Creates an issue. Applications use this to report their own
    /// validation problems in the same shape as the loader's.
    #[must_use]
    pub fn new(source: Source, key: Option<String>, message: impl Into<String>) -> Self {
        Self {
            source,
            key,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{}: `{key}`: {}", self.source, self.message),
            None => write!(f, "{}: {}", self.source, self.message),
        }
    }
}

/// Every problem found while loading or deserializing a configuration.
///
/// The list is never empty when returned by this crate.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub struct ConfigErrors(Vec<ConfigIssue>);

impl ConfigErrors {
    /// Wraps a list of issues.
    #[must_use]
    pub const fn new(issues: Vec<ConfigIssue>) -> Self {
        Self(issues)
    }

    /// The individual problems, in the order they were found.
    #[must_use]
    pub fn issues(&self) -> &[ConfigIssue] {
        &self.0
    }

    /// Iterates over the individual problems.
    pub fn iter(&self) -> std::slice::Iter<'_, ConfigIssue> {
        self.0.iter()
    }

    /// Consumes the error, returning the individual problems.
    #[must_use]
    pub fn into_issues(self) -> Vec<ConfigIssue> {
        self.0
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.0.len();
        write!(
            f,
            "invalid configuration ({count} problem{}):",
            if count == 1 { "" } else { "s" }
        )?;
        for issue in &self.0 {
            write!(f, "\n  - {issue}")?;
        }
        Ok(())
    }
}

impl From<ConfigIssue> for ConfigErrors {
    fn from(issue: ConfigIssue) -> Self {
        Self(vec![issue])
    }
}

impl From<Vec<ConfigIssue>> for ConfigErrors {
    fn from(issues: Vec<ConfigIssue>) -> Self {
        Self(issues)
    }
}

impl IntoIterator for ConfigErrors {
    type Item = ConfigIssue;
    type IntoIter = std::vec::IntoIter<ConfigIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ConfigErrors {
    type Item = &'a ConfigIssue;
    type IntoIter = std::slice::Iter<'a, ConfigIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

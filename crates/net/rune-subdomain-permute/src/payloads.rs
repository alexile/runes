//! Named wordlists that pattern variables draw from.

use std::collections::{BTreeMap, HashSet};

use crate::Error;
use crate::seed::is_builtin;

/// Named payload lists: `word`, `number`, `region`, `env`, or any name a
/// pattern uses.
///
/// Values are trimmed and lowercased; empty values and duplicates (within
/// a list) are dropped, first occurrence kept, so order stays
/// deterministic.
///
/// ```
/// use rune_subdomain_permute::Payloads;
///
/// let mut payloads = Payloads::new();
/// payloads.insert("word", ["API", "dev", "api", ""])?;
/// assert_eq!(payloads.get("word"), Some(&["api".to_owned(), "dev".to_owned()][..]));
/// # Ok::<(), rune_subdomain_permute::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payloads {
    lists: BTreeMap<String, Vec<String>>,
}

impl Payloads {
    /// No payloads.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The built-in lists: [`DEFAULT_WORDS`] as `word`, `0`–`9` as
    /// `number`, [`DEFAULT_REGIONS`] as `region` and [`DEFAULT_ENVS`] as
    /// `env`.
    #[must_use]
    pub fn builtin() -> Self {
        let mut payloads = Self::new();
        for (name, values) in [
            ("word", DEFAULT_WORDS),
            (
                "number",
                &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][..],
            ),
            ("region", DEFAULT_REGIONS),
            ("env", DEFAULT_ENVS),
        ] {
            payloads.set(name, values.iter().copied());
        }
        payloads
    }

    /// Replaces the list called `name`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPayloadName`] if `name` is not `[a-z0-9_]+` or is a
    /// built-in variable (`sub`, `subN`, `suffix`, `root`, `sld`, `etld`,
    /// `tld`).
    pub fn insert<I, S>(&mut self, name: &str, values: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let invalid = |reason| Error::InvalidPayloadName {
            name: name.to_owned(),
            reason,
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid("names use only a-z, 0-9 and _"));
        }
        if is_builtin(name) {
            return Err(invalid("clashes with a built-in variable"));
        }
        self.set(name, values);
        Ok(())
    }

    /// Appends values to the list called `name` (creating it), skipping
    /// ones already present.
    ///
    /// # Errors
    ///
    /// As [`Payloads::insert`].
    pub fn extend<I, S>(&mut self, name: &str, values: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let existing = self.lists.get(name).cloned().unwrap_or_default();
        let mut combined: Vec<String> = existing;
        combined.extend(values.into_iter().map(|v| v.as_ref().to_owned()));
        self.insert(name, combined)
    }

    /// The list called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[String]> {
        self.lists.get(name).map(Vec::as_slice)
    }

    /// Removes the list called `name`.
    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        self.lists.remove(name)
    }

    /// The list names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.lists.keys().map(String::as_str)
    }

    fn set<I, S>(&mut self, name: &str, values: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let list = values
            .into_iter()
            .map(|v| v.as_ref().trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty() && seen.insert(v.clone()))
            .collect();
        self.lists.insert(name.to_owned(), list);
    }
}

/// The built-in `word` list: common service, infrastructure and
/// environment tokens.
pub const DEFAULT_WORDS: &[&str] = &[
    "api", "app", "admin", "auth", "beta", "cdn", "ci", "dev", "docs", "edge", "gateway", "git",
    "grafana", "internal", "jenkins", "lb", "mail", "media", "mgmt", "mobile", "monitor", "new",
    "old", "origin", "portal", "prod", "proxy", "qa", "sandbox", "secure", "sso", "stage",
    "staging", "static", "status", "test", "uat", "v1", "v2", "vpn", "web", "www",
];

/// The built-in `env` list: deployment environment tokens.
pub const DEFAULT_ENVS: &[&str] = &[
    "dev",
    "development",
    "test",
    "testing",
    "qa",
    "uat",
    "stage",
    "staging",
    "preprod",
    "prod",
    "production",
    "sandbox",
    "demo",
    "int",
];

/// The built-in `region` list: cloud region tokens.
pub const DEFAULT_REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "eu-north-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "sa-east-1",
    "ca-central-1",
    "us",
    "eu",
    "ap",
    "uk",
    "de",
    "fr",
    "jp",
    "in",
    "au",
    "east",
    "west",
    "north",
    "south",
    "central",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated() {
        let mut p = Payloads::new();
        assert!(p.insert("sub", ["x"]).is_err());
        assert!(p.insert("sub3", ["x"]).is_err());
        assert!(p.insert("Word", ["x"]).is_err());
        assert!(p.insert("", ["x"]).is_err());
        assert!(p.insert("my_list2", ["x"]).is_ok());
    }

    #[test]
    fn extend_keeps_order_and_dedups() {
        let mut p = Payloads::new();
        p.insert("word", ["a", "b"]).unwrap();
        p.extend("word", ["b", "c", "A"]).unwrap();
        assert_eq!(p.get("word").unwrap(), ["a", "b", "c"]);
        p.extend("fresh", ["x"]).unwrap();
        assert_eq!(p.names().collect::<Vec<_>>(), ["fresh", "word"]);
        assert_eq!(p.remove("fresh"), Some(vec!["x".to_owned()]));
    }

    #[test]
    fn builtin_lists_exist() {
        let p = Payloads::builtin();
        for name in ["word", "number", "region", "env"] {
            assert!(!p.get(name).unwrap().is_empty(), "{name}");
        }
    }
}

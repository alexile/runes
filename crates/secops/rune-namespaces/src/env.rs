//! Environment scrubbing: which variables the sandboxed process gets.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::Error;

/// Which environment variables the sandboxed process receives.
///
/// The default passes nothing: the child starts with an empty environment
/// plus whatever [`EnvPolicy::set`] adds. Variables named in
/// [`EnvPolicy::allow`] are copied from the host environment the caller
/// passes to [`EnvPolicy::resolve`]; a pattern ending in `*` matches by
/// prefix (`LC_*`).
///
/// `bwrap` itself adds `PWD`.
///
/// The environment reaches the child through the launcher's own
/// environment, never its command line, so passed-through secrets do not
/// show up in `/proc/<pid>/cmdline`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct EnvPolicy {
    /// Names (or `PREFIX*` patterns) to copy from the host environment.
    pub allow: Vec<OsString>,
    /// Variables to set, overriding anything allowed through.
    pub set: BTreeMap<OsString, OsString>,
}

/// Variables most programs need to behave sensibly, for
/// [`EnvPolicy::with_common`]. None of them usually carries a secret.
pub const COMMON_VARS: &[&str] = &[
    "PATH", "HOME", "LANG", "LC_*", "TERM", "TZ", "USER", "LOGNAME",
];

impl EnvPolicy {
    /// Allows `name` (or a `PREFIX*` pattern) through from the host.
    #[must_use]
    pub fn with_allow(mut self, name: impl Into<OsString>) -> Self {
        self.allow.push(name.into());
        self
    }

    /// Allows every name in [`COMMON_VARS`] through.
    #[must_use]
    pub fn with_common(self) -> Self {
        COMMON_VARS
            .iter()
            .fold(self, |env, name| env.with_allow(*name))
    }

    /// Sets `name` to `value` in the sandbox.
    #[must_use]
    pub fn with_set(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.set.insert(name.into(), value.into());
        self
    }

    /// Whether `name` is allowed through.
    #[must_use]
    pub fn allows(&self, name: &OsStr) -> bool {
        self.allow.iter().any(|pattern| {
            let pattern = pattern.as_bytes();
            pattern.strip_suffix(b"*").map_or_else(
                || pattern == name.as_bytes(),
                |prefix| name.as_bytes().starts_with(prefix),
            )
        })
    }

    /// Checks that every name to allow or set is non-empty and has no `=`
    /// or NUL (other than a trailing `*` on a pattern), and that no value
    /// contains NUL.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEnv`] naming the first bad variable.
    pub fn validate(&self) -> Result<(), Error> {
        let bad = |name: &OsStr, reason: &'static str| Error::InvalidEnv {
            name: name.to_owned(),
            reason,
        };
        for pattern in &self.allow {
            let bytes = pattern.as_bytes();
            let name = bytes.strip_suffix(b"*").unwrap_or(bytes);
            if bytes.is_empty() || name.contains(&b'*') {
                return Err(bad(pattern, "pattern must be a name or a `PREFIX*`"));
            }
            if name.contains(&b'=') || name.contains(&0) {
                return Err(bad(pattern, "name must not contain `=` or NUL"));
            }
        }
        for (name, value) in &self.set {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.contains(&b'=') || bytes.contains(&0) {
                return Err(bad(name, "name must be non-empty without `=` or NUL"));
            }
            if value.as_bytes().contains(&0) {
                return Err(bad(name, "value must not contain NUL"));
            }
        }
        Ok(())
    }

    /// The sandbox environment, sorted by name: the allowed subset of
    /// `host` (usually [`std::env::vars_os`]) overlaid with
    /// [`EnvPolicy::set`].
    pub fn resolve<I, K, V>(&self, host: I) -> Vec<(OsString, OsString)>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut env: BTreeMap<OsString, OsString> = host
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .filter(|(k, _)| self.allows(k))
            .collect();
        env.extend(self.set.iter().map(|(k, v)| (k.clone(), v.clone())));
        env.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Vec<(&'static str, &'static str)> {
        vec![
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("LC_ALL", "C"),
            ("LC_TIME", "en_GB"),
            ("AWS_SECRET_ACCESS_KEY", "s3cr3t"),
            ("LD_PRELOAD", "/evil.so"),
        ]
    }

    #[test]
    fn default_passes_nothing() {
        assert_eq!(EnvPolicy::default().resolve(host()), []);
    }

    #[test]
    fn allowlist_and_prefix_patterns() {
        let env = EnvPolicy::default()
            .with_allow("PATH")
            .with_allow("LC_*")
            .with_allow("MISSING")
            .resolve(host());
        let names: Vec<_> = env.iter().map(|(k, _)| k.to_str().unwrap()).collect();
        assert_eq!(names, ["LC_ALL", "LC_TIME", "PATH"]);
    }

    #[test]
    fn set_overrides_allowed() {
        let env = EnvPolicy::default()
            .with_common()
            .with_set("HOME", "/sandbox")
            .with_set("CI", "1")
            .resolve(host());
        let map: BTreeMap<_, _> = env.into_iter().collect();
        assert_eq!(map[OsStr::new("HOME")], "/sandbox");
        assert_eq!(map[OsStr::new("CI")], "1");
        assert!(!map.contains_key(OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert!(!map.contains_key(OsStr::new("LD_PRELOAD")));
    }

    #[test]
    fn exact_name_is_not_a_prefix() {
        let env = EnvPolicy::default().with_allow("PATH");
        assert!(env.allows(OsStr::new("PATH")));
        assert!(!env.allows(OsStr::new("PATHEXT")));
        assert!(!env.allows(OsStr::new("PAT")));
    }

    #[test]
    fn validate() {
        EnvPolicy::default()
            .with_common()
            .with_set("A", "b")
            .validate()
            .unwrap();
        for policy in [
            EnvPolicy::default().with_allow(""),
            EnvPolicy::default().with_allow("A*B*"),
            EnvPolicy::default().with_allow("A=B"),
            EnvPolicy::default().with_set("", "x"),
            EnvPolicy::default().with_set("A=B", "x"),
            EnvPolicy::default().with_set("A", "x\0y"),
        ] {
            assert!(
                matches!(policy.validate(), Err(Error::InvalidEnv { .. })),
                "{policy:?}"
            );
        }
    }
}

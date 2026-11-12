//! Known names, split into the parts patterns refer to.

use rune_psl::List;

use crate::Error;

/// A known host name, normalized and split at its registrable domain.
///
/// For `cloud.api.example.co.uk`:
///
/// | Variable     | Value                    |
/// |--------------|--------------------------|
/// | `{{sub}}`    | `cloud`                  |
/// | `{{sub1}}`   | `api`                    |
/// | `{{suffix}}` | `api.example.co.uk`      |
/// | `{{root}}`   | `example.co.uk`          |
/// | `{{sld}}`    | `example`                |
/// | `{{etld}}`   | `co.uk`                  |
/// | `{{tld}}`    | `uk`                     |
///
/// `{{sub}}` is the left-most label and `{{subN}}` the labels after it, up
/// to the registrable domain, as in alterx. A seed that is a registrable
/// domain itself has no `{{sub}}` (or `{{suffix}}`), and patterns that need
/// one skip it.
///
/// ```
/// use rune_subdomain_permute::Seed;
///
/// let seed = Seed::parse("Cloud.API.example.co.uk.")?;
/// assert_eq!(seed.name(), "cloud.api.example.co.uk");
/// assert_eq!(seed.root(), "example.co.uk");
/// assert_eq!(seed.sub_labels(), ["cloud", "api"]);
///
/// // Unicode is converted to A-labels.
/// assert_eq!(Seed::parse("www.bücher.example")?.root(), "xn--bcher-kva.example");
/// # Ok::<(), rune_subdomain_permute::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Seed {
    name: String,
    /// Labels left of the root, left-most first.
    sub: Vec<String>,
    root: String,
    etld: String,
}

impl Seed {
    /// Parses a host name, splitting it with the embedded Public Suffix
    /// List (private section included, so `app.herokuapp.com` is a root).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeed`] if IDNA processing rejects the name, it is an
    /// IP address, or it is itself a public suffix.
    pub fn parse(host: &str) -> Result<Self, Error> {
        Self::parse_with(host, &List::embedded())
    }

    /// As [`Seed::parse`], with a caller-supplied suffix list, for example
    /// `List::embedded().with_private_rules(false)`.
    ///
    /// # Errors
    ///
    /// As [`Seed::parse`].
    pub fn parse_with(host: &str, list: &List) -> Result<Self, Error> {
        let invalid = |reason: String| Error::InvalidSeed {
            seed: host.to_owned(),
            reason,
        };
        let ascii = rune_idna::to_ascii(host.trim(), &rune_idna::Options::default())
            .map_err(|e| invalid(e.to_string()))?;
        let domain = list.lookup(&ascii).map_err(|e| invalid(e.to_string()))?;
        let root = domain
            .registrable_domain()
            .ok_or_else(|| invalid("it is a public suffix".to_owned()))?
            .to_owned();
        let sub = domain
            .subdomain()
            .map(|s| s.split('.').map(str::to_owned).collect())
            .unwrap_or_default();
        Ok(Self {
            name: domain.as_str().to_owned(),
            sub,
            root,
            etld: domain.public_suffix().to_owned(),
        })
    }

    /// Splits `host` with an explicit root, for names the Public Suffix
    /// List does not describe well (internal zones such as `corp.internal`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeed`] if either name is invalid or `host` is not
    /// `root` or below it.
    pub fn with_root(host: &str, root: &str) -> Result<Self, Error> {
        let invalid = |reason: String| Error::InvalidSeed {
            seed: host.to_owned(),
            reason,
        };
        let options = rune_idna::Options::default();
        let name = normalize(
            &rune_idna::to_ascii(host.trim(), &options).map_err(|e| invalid(e.to_string()))?,
        );
        let root = normalize(
            &rune_idna::to_ascii(root.trim(), &options).map_err(|e| invalid(e.to_string()))?,
        );
        if root.is_empty() || name.is_empty() {
            return Err(invalid("empty name".to_owned()));
        }
        let sub = if name == root {
            Vec::new()
        } else {
            let prefix = name
                .strip_suffix(&root)
                .and_then(|p| p.strip_suffix('.'))
                .filter(|p| !p.is_empty())
                .ok_or_else(|| invalid(format!("not under root {root:?}")))?;
            prefix.split('.').map(str::to_owned).collect()
        };
        let etld = root
            .split_once('.')
            .map_or_else(|| root.clone(), |(_, rest)| rest.to_owned());
        Ok(Self {
            name,
            sub,
            root,
            etld,
        })
    }

    /// The whole name, lowercase A-labels, no trailing dot.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The labels left of the root, left-most first. Empty for a root.
    #[must_use]
    pub fn sub_labels(&self) -> &[String] {
        &self.sub
    }

    /// The registrable domain (`{{root}}`).
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The public suffix (`{{etld}}`).
    #[must_use]
    pub fn etld(&self) -> &str {
        &self.etld
    }

    /// Value of a built-in variable, or `None` if it is not built in or
    /// this seed has no value for it.
    pub(crate) fn var(&self, name: &str) -> Option<&str> {
        match name {
            "sub" => self.sub.first().map(String::as_str),
            "suffix" => {
                if self.sub.is_empty() {
                    None
                } else {
                    self.name.split_once('.').map(|(_, rest)| rest)
                }
            }
            "root" => Some(&self.root),
            "sld" => self.root.split('.').next(),
            "etld" => Some(&self.etld),
            "tld" => self.etld.rsplit('.').next(),
            _ => {
                let index: usize = name.strip_prefix("sub")?.parse().ok()?;
                if index == 0 {
                    return None;
                }
                self.sub.get(index).map(String::as_str)
            }
        }
    }
}

/// Whether `name` is a built-in variable (`sub`, `subN`, `suffix`, `root`,
/// `sld`, `etld`, `tld`).
pub fn is_builtin(name: &str) -> bool {
    matches!(name, "sub" | "suffix" | "root" | "sld" | "etld" | "tld")
        || name.strip_prefix("sub").is_some_and(|n| {
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0')
        })
}

fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables() {
        let seed = Seed::parse("cloud.api.example.co.uk").unwrap();
        assert_eq!(seed.var("sub"), Some("cloud"));
        assert_eq!(seed.var("sub1"), Some("api"));
        assert_eq!(seed.var("sub2"), None);
        assert_eq!(seed.var("sub0"), None);
        assert_eq!(seed.var("suffix"), Some("api.example.co.uk"));
        assert_eq!(seed.var("root"), Some("example.co.uk"));
        assert_eq!(seed.var("sld"), Some("example"));
        assert_eq!(seed.var("etld"), Some("co.uk"));
        assert_eq!(seed.var("tld"), Some("uk"));
        assert_eq!(seed.var("word"), None);
    }

    #[test]
    fn root_seed_has_no_sub_or_suffix() {
        let seed = Seed::parse("example.com").unwrap();
        assert_eq!(seed.sub_labels().len(), 0);
        assert_eq!(seed.var("sub"), None);
        assert_eq!(seed.var("suffix"), None);
        assert_eq!(seed.var("root"), Some("example.com"));
    }

    #[test]
    fn rejects_suffixes_and_addresses() {
        assert!(Seed::parse("co.uk").is_err());
        assert!(Seed::parse("192.0.2.1").is_err());
        assert!(Seed::parse("").is_err());
        assert!(Seed::parse("bad name.com").is_err());
    }

    #[test]
    fn explicit_root() {
        let seed = Seed::with_root("API.dev.corp.internal.", "corp.internal").unwrap();
        assert_eq!(seed.sub_labels(), ["api", "dev"]);
        assert_eq!(seed.var("etld"), Some("internal"));
        assert_eq!(seed.var("suffix"), Some("dev.corp.internal"));
        assert!(Seed::with_root("api.other.internal", "corp.internal").is_err());
        assert!(Seed::with_root("xcorp.internal", "corp.internal").is_err());
        assert_eq!(
            Seed::with_root("corp.internal", "corp.internal")
                .unwrap()
                .sub_labels()
                .len(),
            0
        );
    }

    #[test]
    fn builtin_names() {
        for name in [
            "sub", "sub1", "sub12", "suffix", "root", "sld", "etld", "tld",
        ] {
            assert!(is_builtin(name), "{name}");
        }
        for name in ["word", "sub0", "sub01", "subx", "number"] {
            assert!(!is_builtin(name), "{name}");
        }
    }
}

//! Validated, normalized hostnames.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// Longest name in bytes, without the trailing dot (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 253;
/// Longest label in bytes (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// A validated hostname in canonical form: ASCII lowercase, without a
/// trailing dot.
///
/// Accepted syntax is a relaxed RFC 1123 §2.1 hostname: dot-separated labels
/// of 1–63 letters, digits, `-` and `_`, at most 253 bytes in all. The
/// underscore is accepted because it is common in real names (`_dmarc`,
/// service records). One trailing dot (an absolute name) is dropped. The
/// right-most label must not be all digits, so IPv4 and IPv6 literals are
/// rejected: match addresses with `rune-cidr` instead. Internationalized
/// names must be converted to A-labels (`xn--…`) before parsing.
///
/// ```
/// use rune_host_match::Hostname;
///
/// let host = Hostname::parse("API.Example.COM.")?;
/// assert_eq!(host.as_str(), "api.example.com");
/// assert!(Hostname::parse("10.0.0.1").is_err());
/// # Ok::<(), rune_host_match::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Validates and normalizes `input`.
    ///
    /// # Errors
    ///
    /// Any syntax error described on [`Error`]; wildcards are rejected as
    /// [`Error::InvalidChar`].
    pub fn parse(input: &str) -> Result<Self, Error> {
        normalize(input, false).map(Self)
    }

    /// The canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels, left to right.
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('.')
    }

    /// Whether `self` is a strict subdomain of `parent`, at any depth.
    ///
    /// A name is not a subdomain of itself, and the comparison respects
    /// label boundaries: `evilexample.com` is not under `example.com`.
    ///
    /// ```
    /// use rune_host_match::Hostname;
    ///
    /// let parent = Hostname::parse("example.com")?;
    /// assert!(Hostname::parse("a.b.example.com")?.is_subdomain_of(&parent));
    /// assert!(!parent.is_subdomain_of(&parent));
    /// assert!(!Hostname::parse("evilexample.com")?.is_subdomain_of(&parent));
    /// # Ok::<(), rune_host_match::Error>(())
    /// ```
    #[must_use]
    pub fn is_subdomain_of(&self, parent: &Self) -> bool {
        is_strict_subdomain(&self.0, &parent.0)
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hostname {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        Self::parse(input)
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// `host` ends in `.{parent}` with at least one label in front.
pub fn is_strict_subdomain(host: &str, parent: &str) -> bool {
    host.strip_suffix(parent)
        .and_then(|front| front.strip_suffix('.'))
        .is_some_and(|front| !front.is_empty())
}

/// Shared syntax check for hostnames and patterns. With `allow_wildcard`, a
/// label may be exactly `*`; any other use of `*` is an error.
pub fn normalize(input: &str, allow_wildcard: bool) -> Result<String, Error> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty() {
        return Err(Error::Empty);
    }
    for (index, ch) in name.char_indices() {
        let allowed = ch.is_ascii_alphanumeric()
            || matches!(ch, '-' | '_' | '.')
            || (allow_wildcard && ch == '*');
        if !allowed {
            return Err(Error::InvalidChar { ch, index });
        }
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::TooLong { len: name.len() });
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(Error::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::LabelTooLong { len: label.len() });
        }
        if label != "*" && label.contains('*') {
            return Err(Error::PartialWildcard);
        }
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::NumericTld);
    }
    Ok(name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(
            Hostname::parse("WWW.Example.Com.").unwrap().as_str(),
            "www.example.com"
        );
        assert_eq!(Hostname::parse("localhost").unwrap().as_str(), "localhost");
        assert_eq!(
            Hostname::parse("_dmarc.example.com").unwrap().as_str(),
            "_dmarc.example.com"
        );
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(Hostname::parse(""), Err(Error::Empty));
        assert_eq!(Hostname::parse("."), Err(Error::Empty));
        assert_eq!(Hostname::parse("example.com.."), Err(Error::EmptyLabel));
        assert_eq!(Hostname::parse(".example.com"), Err(Error::EmptyLabel));
        assert_eq!(Hostname::parse("a..b"), Err(Error::EmptyLabel));
        assert_eq!(
            Hostname::parse("exa mple.com"),
            Err(Error::InvalidChar { ch: ' ', index: 3 })
        );
        assert_eq!(
            Hostname::parse("*.example.com"),
            Err(Error::InvalidChar { ch: '*', index: 0 })
        );
        assert_eq!(
            Hostname::parse("bücher.de"),
            Err(Error::InvalidChar { ch: 'ü', index: 1 })
        );
        assert_eq!(Hostname::parse("10.0.0.1"), Err(Error::NumericTld));
        assert!(matches!(
            Hostname::parse("::1"),
            Err(Error::InvalidChar { ch: ':', .. })
        ));
    }

    #[test]
    fn enforces_length_limits() {
        let label = "a".repeat(63);
        assert!(Hostname::parse(&format!("{label}.com")).is_ok());
        assert_eq!(
            Hostname::parse(&format!("a{label}.com")),
            Err(Error::LabelTooLong { len: 64 })
        );
        // 4 * 63 + 3 dots = 255 > 253.
        let long = [label.as_str(); 4].join(".");
        assert_eq!(Hostname::parse(&long), Err(Error::TooLong { len: 255 }));
        // 253 bytes plus the trailing dot is still fine.
        let max = format!("{}.{}", [label.as_str(); 3].join("."), "a".repeat(61));
        assert_eq!(max.len(), 253);
        assert!(Hostname::parse(&format!("{max}.")).is_ok());
    }

    #[test]
    fn subdomain_respects_label_boundaries() {
        assert!(is_strict_subdomain("a.example.com", "example.com"));
        assert!(!is_strict_subdomain("example.com", "example.com"));
        assert!(!is_strict_subdomain("aexample.com", "example.com"));
    }
}

//! Certificate name matching: the TLS semantics.

use std::fmt;
use std::str::FromStr;

use crate::hostname::normalize;
use crate::{Error, Hostname};

/// A DNS name presented in a TLS certificate.
///
/// That is a `dNSName` SAN entry, or a legacy subject CN. It is checked
/// against a server name per
/// [RFC 6125 §6.4](https://www.rfc-editor.org/rfc/rfc6125#section-6.4) as
/// tightened by [RFC 9525 §6.3](https://www.rfc-editor.org/rfc/rfc9525#section-6.3)
/// and the CA/Browser Forum Baseline Requirements:
///
/// - A wildcard is allowed only as the whole left-most label: `*.example.com`.
///   Partial wildcards (`f*.example.com`, `xn--*.example.com`) and wildcards
///   in any other position are rejected.
/// - The wildcard matches exactly one label: `*.example.com` covers
///   `api.example.com`, but neither `example.com` nor `a.b.example.com`.
/// - At least two labels must follow the wildcard, so `*.com` is rejected.
///   Public-suffix wildcards such as `*.co.uk` need the Public Suffix List:
///   [`CertName::parse`] accepts them, and the `psl` feature adds
///   `CertName::parse_with_psl` and `cert_names_match_with_psl`, which
///   reject them as browsers do.
/// - IP addresses never match: they belong in `iPAddress` SAN entries, and
///   [`Hostname`] rejects them.
///
/// Comparison is ASCII case-insensitive and ignores one trailing dot.
///
/// ```
/// use rune_host_match::CertName;
///
/// let name = CertName::parse("*.example.com")?;
/// assert!(name.matches("api.example.com"));
/// assert!(!name.matches("a.b.example.com"));
/// assert!(!name.matches("example.com"));
/// assert!(CertName::parse("*.com").is_err());
/// # Ok::<(), rune_host_match::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertName {
    /// Canonical text; starts with `*.` when `wildcard` is set.
    text: String,
    wildcard: bool,
}

impl CertName {
    /// Parses and normalizes a presented name.
    ///
    /// # Errors
    ///
    /// The [`Hostname`] syntax errors, plus [`Error::PartialWildcard`],
    /// [`Error::MisplacedWildcard`] and [`Error::WildcardTooBroad`].
    pub fn parse(input: &str) -> Result<Self, Error> {
        let text = normalize(input, true)?;
        let (wildcard, rest) = match text.strip_prefix("*.") {
            None if text == "*" => return Err(Error::WildcardTooBroad),
            None => (false, text.as_str()),
            Some(base) => {
                if base.split('.').count() < 2 {
                    return Err(Error::WildcardTooBroad);
                }
                (true, base)
            }
        };
        if rest.split('.').any(|label| label == "*") {
            return Err(Error::MisplacedWildcard);
        }
        Ok(Self { text, wildcard })
    }

    /// Parses a presented name like [`CertName::parse`], and also rejects
    /// a wildcard whose base is a public suffix of `list` (`*.co.uk`).
    ///
    /// Browsers check against the ICANN section only, so that private
    /// suffixes keep their certificates (`*.github.io` is GitHub's):
    /// pass `List::embedded().with_private_rules(false)` for that behaviour.
    ///
    /// ```
    /// use rune_host_match::{CertName, Error, rune_psl::List};
    ///
    /// let icann = List::embedded().with_private_rules(false);
    /// assert_eq!(
    ///     CertName::parse_with_psl("*.co.uk", &icann),
    ///     Err(Error::PublicSuffixWildcard)
    /// );
    /// assert!(CertName::parse_with_psl("*.example.co.uk", &icann).is_ok());
    /// assert!(CertName::parse_with_psl("*.github.io", &icann).is_ok());
    /// assert!(CertName::parse("*.co.uk").is_ok());
    /// # Ok::<(), rune_host_match::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Those of [`CertName::parse`], plus [`Error::PublicSuffixWildcard`].
    #[cfg(feature = "psl")]
    pub fn parse_with_psl(input: &str, list: &rune_psl::List) -> Result<Self, Error> {
        let name = Self::parse(input)?;
        if name.is_public_suffix_wildcard(list) {
            return Err(Error::PublicSuffixWildcard);
        }
        Ok(name)
    }

    /// Whether the name is a wildcard whose base is a public suffix of
    /// `list`: `*.co.uk`, or `*.github.io` when `list` includes private
    /// rules.
    #[cfg(feature = "psl")]
    #[must_use]
    pub fn is_public_suffix_wildcard(&self, list: &rune_psl::List) -> bool {
        self.wildcard && list.is_public_suffix(self.text.get(2..).unwrap_or_default())
    }

    /// Whether the name is a wildcard (`*.example.com`).
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the certificate name covers `server_name`. A server name
    /// that is not a valid [`Hostname`] never matches.
    #[must_use]
    pub fn matches(&self, server_name: &str) -> bool {
        Hostname::parse(server_name).is_ok_and(|host| self.matches_hostname(&host))
    }

    /// Whether the certificate name covers an already validated host.
    #[must_use]
    pub fn matches_hostname(&self, host: &Hostname) -> bool {
        let host = host.as_str();
        if self.wildcard {
            let base = self.text.get(2..).unwrap_or_default();
            host.split_once('.').is_some_and(|(_, rest)| rest == base)
        } else {
            host == self.text
        }
    }
}

impl fmt::Display for CertName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for CertName {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        Self::parse(input)
    }
}

impl AsRef<str> for CertName {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// Whether the presented certificate name `presented` covers `server_name`.
///
/// A malformed presented name, or an invalid server name, never matches.
/// See [`CertName`] for the rules.
///
/// ```
/// use rune_host_match::cert_name_matches;
///
/// assert!(cert_name_matches("*.example.com", "www.example.com"));
/// assert!(!cert_name_matches("*.example.com", "example.com"));
/// assert!(!cert_name_matches("w*.example.com", "www.example.com"));
/// ```
#[must_use]
pub fn cert_name_matches(presented: &str, server_name: &str) -> bool {
    CertName::parse(presented).is_ok_and(|name| name.matches(server_name))
}

/// Whether any of a certificate's presented names covers `server_name`.
///
/// Malformed presented names are skipped.
///
/// ```
/// use rune_host_match::cert_names_match;
///
/// let sans = ["example.com", "*.example.com"];
/// assert!(cert_names_match(sans, "example.com"));
/// assert!(cert_names_match(sans, "www.example.com"));
/// assert!(!cert_names_match(sans, "a.b.example.com"));
/// ```
#[must_use]
pub fn cert_names_match<I>(presented: I, server_name: &str) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let Ok(host) = Hostname::parse(server_name) else {
        return false;
    };
    presented
        .into_iter()
        .any(|name| CertName::parse(name.as_ref()).is_ok_and(|name| name.matches_hostname(&host)))
}

/// [`cert_names_match`], skipping presented names that
/// [`CertName::parse_with_psl`] rejects, such as `*.co.uk`.
///
/// ```
/// use rune_host_match::{cert_names_match, cert_names_match_with_psl, rune_psl::List};
///
/// let icann = List::embedded().with_private_rules(false);
/// assert!(cert_names_match(["*.co.uk"], "example.co.uk"));
/// assert!(!cert_names_match_with_psl(["*.co.uk"], "example.co.uk", &icann));
/// assert!(cert_names_match_with_psl(["*.co.uk", "*.example.co.uk"], "www.example.co.uk", &icann));
/// ```
#[cfg(feature = "psl")]
#[must_use]
pub fn cert_names_match_with_psl<I>(presented: I, server_name: &str, list: &rune_psl::List) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let Ok(host) = Hostname::parse(server_name) else {
        return false;
    };
    presented.into_iter().any(|name| {
        CertName::parse_with_psl(name.as_ref(), list).is_ok_and(|name| name.matches_hostname(&host))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The cases `network-tls-auditor`'s `host_matches` tests check.
    #[test]
    fn wildcard_matches_single_label() {
        assert!(cert_name_matches("*.example.com", "api.example.com"));
        assert!(!cert_name_matches("*.example.com", "a.b.example.com"));
        assert!(!cert_name_matches("*.example.com", "example.com"));
    }

    #[test]
    fn exact_names_fold_case_and_trailing_dot() {
        assert!(cert_name_matches("Example.COM", "example.com."));
        assert!(cert_name_matches("example.com.", "EXAMPLE.com"));
        assert!(!cert_name_matches("example.com", "www.example.com"));
        assert!(cert_name_matches("*.Example.com.", "WWW.example.COM."));
    }

    #[test]
    fn rejects_non_rfc_6125_wildcards() {
        assert_eq!(CertName::parse("*"), Err(Error::WildcardTooBroad));
        assert_eq!(CertName::parse("*.com"), Err(Error::WildcardTooBroad));
        assert_eq!(
            CertName::parse("f*.example.com"),
            Err(Error::PartialWildcard)
        );
        assert_eq!(
            CertName::parse("xn--*.example.com"),
            Err(Error::PartialWildcard)
        );
        assert_eq!(
            CertName::parse("www.*.example.com"),
            Err(Error::MisplacedWildcard)
        );
        assert_eq!(
            CertName::parse("*.*.example.com"),
            Err(Error::MisplacedWildcard)
        );
        assert_eq!(CertName::parse("example.*"), Err(Error::MisplacedWildcard));
        assert!(!cert_name_matches("www.*.example.com", "www.a.example.com"));
    }

    #[test]
    fn ip_addresses_never_match() {
        assert!(!cert_name_matches("10.0.0.1", "10.0.0.1"));
        assert!(!cert_name_matches("*.0.0.1", "10.0.0.1"));
    }

    #[test]
    fn any_of_several_names() {
        let sans = vec!["bad*.example.com".to_owned(), "*.example.org".to_owned()];
        assert!(cert_names_match(&sans, "www.example.org"));
        assert!(!cert_names_match(&sans, "bad.example.com"));
        assert!(!cert_names_match(&sans, "not a host"));
        assert!(!cert_names_match(Vec::<String>::new(), "example.org"));
    }

    #[cfg(feature = "psl")]
    #[test]
    fn public_suffix_wildcards() {
        let full = rune_psl::List::embedded();
        let icann = rune_psl::List::embedded().with_private_rules(false);
        for (name, with_icann, with_full) in [
            ("*.co.uk", true, true),
            ("*.github.io", false, true),
            ("*.example.com", false, false),
            ("*.test.ck", true, true),  // `*.ck`: every `x.ck` is a suffix
            ("*.www.ck", false, false), // except `!www.ck`
            ("*.example.internal", false, false), // unlisted TLD
            ("co.uk", false, false),    // not a wildcard
        ] {
            let parsed = CertName::parse(name).unwrap();
            assert_eq!(
                parsed.is_public_suffix_wildcard(&icann),
                with_icann,
                "{name}"
            );
            assert_eq!(parsed.is_public_suffix_wildcard(&full), with_full, "{name}");
        }
        assert_eq!(
            CertName::parse_with_psl("*.CO.UK.", &icann),
            Err(Error::PublicSuffixWildcard)
        );
        assert_eq!(
            CertName::parse_with_psl("*.com", &icann),
            Err(Error::WildcardTooBroad)
        );
        assert!(!cert_names_match_with_psl(["*.co.uk"], "x.co.uk", &icann));
        assert!(!cert_names_match_with_psl(
            ["*.example.com"],
            "not a host",
            &icann
        ));
        assert!(cert_names_match_with_psl(
            ["*.github.io"],
            "x.github.io",
            &icann
        ));
        assert!(!cert_names_match_with_psl(
            ["*.github.io"],
            "x.github.io",
            &full
        ));
    }

    #[test]
    fn reports_wildcardness() {
        assert!(CertName::parse("*.example.com").unwrap().is_wildcard());
        assert!(!CertName::parse("example.com").unwrap().is_wildcard());
    }
}

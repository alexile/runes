//! Allowlist patterns: the egress and scope semantics.

use std::fmt;
use std::str::FromStr;

use crate::hostname::{is_strict_subdomain, normalize};
use crate::{Error, Hostname};

/// Which rule a [`HostPattern`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PatternKind {
    /// `example.com`: only that exact name.
    Exact,
    /// `*.example.com`: any subdomain at any depth, never the apex.
    Subdomains,
    /// `api.*.example.com`: each `*` is exactly one label, and the host has
    /// as many labels as the pattern.
    Labels,
}

/// One allowlist entry, for egress proxies and scan scopes.
///
/// The syntax, after the same case folding and trailing-dot handling as
/// [`Hostname`]:
///
/// | Pattern             | Kind                        | Matches                                   | Does not match                     |
/// | ------------------- | --------------------------- | ----------------------------------------- | ---------------------------------- |
/// | `example.com`       | [`PatternKind::Exact`]      | `example.com`                             | `www.example.com`                  |
/// | `*.example.com`     | [`PatternKind::Subdomains`] | `api.example.com`, `a.b.example.com`      | `example.com`, `evilexample.com`   |
/// | `api.*.example.com` | [`PatternKind::Labels`]     | `api.eu.example.com`                      | `api.example.com`, `api.a.b.example.com` |
///
/// A single leading `*.` on an otherwise literal pattern is the common
/// allowlist convention: every subdomain, at any depth, but not the apex. Any
/// other wildcard, or a pattern with more than one, makes each `*` stand for
/// exactly one label (`*.*.example.com` matches four-label names only). A
/// wildcard must be a whole label, and the right-most label must be literal.
///
/// These are **not** certificate semantics: for a TLS certificate name use
/// [`CertName`](crate::CertName), where `*.example.com` covers one label only.
///
/// ```
/// use rune_host_match::HostPattern;
///
/// let pattern = HostPattern::parse("*.Example.com.")?;
/// assert_eq!(pattern.to_string(), "*.example.com");
/// assert!(pattern.matches("API.example.com"));
/// assert!(pattern.matches("a.b.example.com"));
/// assert!(!pattern.matches("example.com"));
/// assert!(!pattern.matches("evilexample.com"));
/// # Ok::<(), rune_host_match::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPattern {
    /// Canonical text; for `Subdomains` it starts with `*.`.
    text: String,
    kind: PatternKind,
}

impl HostPattern {
    /// Parses and normalizes a pattern.
    ///
    /// # Errors
    ///
    /// The [`Hostname`] syntax errors, plus [`Error::PartialWildcard`] and
    /// [`Error::UnanchoredWildcard`].
    pub fn parse(input: &str) -> Result<Self, Error> {
        let text = normalize(input, true)?;
        if text.rsplit('.').next() == Some("*") {
            return Err(Error::UnanchoredWildcard);
        }
        let wildcards = text.split('.').filter(|label| *label == "*").count();
        let kind = match wildcards {
            0 => PatternKind::Exact,
            1 if text.starts_with("*.") => PatternKind::Subdomains,
            _ => PatternKind::Labels,
        };
        Ok(Self { text, kind })
    }

    /// A pattern matching exactly `host`.
    #[must_use]
    pub fn exact(host: &Hostname) -> Self {
        Self {
            text: host.as_str().to_owned(),
            kind: PatternKind::Exact,
        }
    }

    /// A pattern matching every strict subdomain of `parent`, at any depth,
    /// but not `parent` itself: the pattern `*.{parent}`.
    #[must_use]
    pub fn subdomains_of(parent: &Hostname) -> Self {
        Self {
            text: format!("*.{parent}"),
            kind: PatternKind::Subdomains,
        }
    }

    /// The rule this pattern applies.
    #[must_use]
    pub const fn kind(&self) -> PatternKind {
        self.kind
    }

    /// Whether the pattern's wildcard covers a whole public suffix of
    /// `list`, so that it matches names registered by unrelated parties:
    /// `*.co.uk`, `api.*.co.uk`, or `*.github.io` when `list` includes
    /// private rules. The literal part right of the right-most `*` is the
    /// one checked. Exact patterns never cover a suffix.
    ///
    /// Use it to vet scan scopes and allowlists from configuration.
    ///
    /// ```
    /// use rune_host_match::{HostPattern, rune_psl::List};
    ///
    /// let list = List::embedded();
    /// assert!(HostPattern::parse("*.co.uk")?.is_public_suffix_wildcard(&list));
    /// assert!(HostPattern::parse("*.github.io")?.is_public_suffix_wildcard(&list));
    /// assert!(!HostPattern::parse("*.example.co.uk")?.is_public_suffix_wildcard(&list));
    /// # Ok::<(), rune_host_match::Error>(())
    /// ```
    #[cfg(feature = "psl")]
    #[must_use]
    pub fn is_public_suffix_wildcard(&self, list: &rune_psl::List) -> bool {
        self.text
            .rsplit_once("*.")
            .is_some_and(|(_, base)| list.is_public_suffix(base))
    }

    /// The canonical pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether `host` matches. A host that is not a valid [`Hostname`]
    /// (including IP literals) never matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        Hostname::parse(host).is_ok_and(|host| self.matches_hostname(&host))
    }

    /// Whether an already validated `host` matches.
    #[must_use]
    pub fn matches_hostname(&self, host: &Hostname) -> bool {
        let host = host.as_str();
        match self.kind {
            PatternKind::Exact => host == self.text,
            PatternKind::Subdomains => self
                .text
                .strip_prefix("*.")
                .is_some_and(|parent| is_strict_subdomain(host, parent)),
            PatternKind::Labels => {
                self.text.split('.').count() == host.split('.').count()
                    && self
                        .text
                        .split('.')
                        .zip(host.split('.'))
                        .all(|(want, got)| want == "*" || want == got)
            }
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for HostPattern {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        Self::parse(input)
    }
}

impl AsRef<str> for HostPattern {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// A list of [`HostPattern`]s; a host is allowed when any pattern matches.
///
/// An empty allowlist allows nothing.
///
/// ```
/// use rune_host_match::HostAllowlist;
///
/// let allow = HostAllowlist::parse_all(["api.anthropic.com", "*.github.com"])?;
/// assert!(allow.allows("api.anthropic.com"));
/// assert!(allow.allows("codeload.github.com"));
/// assert!(!allow.allows("github.com"));
/// assert!(!HostAllowlist::default().allows("api.anthropic.com"));
/// # Ok::<(), rune_host_match::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HostAllowlist {
    patterns: Vec<HostPattern>,
}

impl HostAllowlist {
    /// An empty allowlist.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Parses every pattern.
    ///
    /// # Errors
    ///
    /// The first pattern that fails [`HostPattern::parse`].
    pub fn parse_all<I>(patterns: I) -> Result<Self, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        patterns
            .into_iter()
            .map(|pattern| HostPattern::parse(pattern.as_ref()))
            .collect()
    }

    /// Adds a pattern.
    pub fn push(&mut self, pattern: HostPattern) {
        self.patterns.push(pattern);
    }

    /// Adds a pattern, builder style.
    #[must_use]
    pub fn with(mut self, pattern: HostPattern) -> Self {
        self.push(pattern);
        self
    }

    /// Whether any pattern matches `host`. Invalid hosts are never allowed.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        self.matching(host).is_some()
    }

    /// The first pattern that matches `host`, for logging why it was allowed.
    #[must_use]
    pub fn matching(&self, host: &str) -> Option<&HostPattern> {
        let host = Hostname::parse(host).ok()?;
        self.matching_hostname(&host)
    }

    /// The first pattern that matches an already validated `host`.
    #[must_use]
    pub fn matching_hostname(&self, host: &Hostname) -> Option<&HostPattern> {
        self.patterns
            .iter()
            .find(|pattern| pattern.matches_hostname(host))
    }

    /// The patterns, in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, HostPattern> {
        self.patterns.iter()
    }

    /// Number of patterns.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether there are no patterns (and so nothing is allowed).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

impl FromIterator<HostPattern> for HostAllowlist {
    fn from_iter<I: IntoIterator<Item = HostPattern>>(iter: I) -> Self {
        Self {
            patterns: iter.into_iter().collect(),
        }
    }
}

impl Extend<HostPattern> for HostAllowlist {
    fn extend<I: IntoIterator<Item = HostPattern>>(&mut self, iter: I) {
        self.patterns.extend(iter);
    }
}

impl<'a> IntoIterator for &'a HostAllowlist {
    type Item = &'a HostPattern;
    type IntoIter = std::slice::Iter<'a, HostPattern>;

    fn into_iter(self) -> Self::IntoIter {
        self.patterns.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> HostPattern {
        HostPattern::parse(text).unwrap()
    }

    #[cfg(feature = "psl")]
    #[test]
    fn public_suffix_wildcards() {
        let list = rune_psl::List::embedded();
        let icann = rune_psl::List::embedded().with_private_rules(false);
        let covers = |pattern: &str, list: &rune_psl::List| {
            HostPattern::parse(pattern)
                .unwrap()
                .is_public_suffix_wildcard(list)
        };
        assert!(covers("*.co.uk", &list));
        assert!(covers("api.*.co.uk", &list));
        assert!(covers("*.*.com", &list));
        assert!(covers("*.github.io", &list));
        assert!(!covers("*.github.io", &icann));
        assert!(!covers("*.example.com", &list));
        assert!(!covers("*.*.example.com", &list));
        assert!(!covers("co.uk", &list));
        assert!(!covers("*.example.internal", &list));
    }

    #[test]
    fn classifies_patterns() {
        assert_eq!(pattern("example.com").kind(), PatternKind::Exact);
        assert_eq!(pattern("*.example.com").kind(), PatternKind::Subdomains);
        assert_eq!(pattern("api.*.example.com").kind(), PatternKind::Labels);
        assert_eq!(pattern("*.*.example.com").kind(), PatternKind::Labels);
    }

    #[test]
    fn rejects_malformed_patterns() {
        assert_eq!(HostPattern::parse("*"), Err(Error::UnanchoredWildcard));
        assert_eq!(HostPattern::parse("*."), Err(Error::UnanchoredWildcard));
        assert_eq!(
            HostPattern::parse("example.*"),
            Err(Error::UnanchoredWildcard)
        );
        assert_eq!(
            HostPattern::parse("f*o.example.com"),
            Err(Error::PartialWildcard)
        );
        assert_eq!(
            HostPattern::parse("**.example.com"),
            Err(Error::PartialWildcard)
        );
        assert_eq!(HostPattern::parse(".example.com"), Err(Error::EmptyLabel));
        assert_eq!(HostPattern::parse("*.."), Err(Error::EmptyLabel));
        assert_eq!(HostPattern::parse(""), Err(Error::Empty));
        assert_eq!(HostPattern::parse("*.10.0.0.1"), Err(Error::NumericTld));
    }

    // The cases `rune-secops-warden`'s `domain_allowed` tests check.
    #[test]
    fn exact_match_only_matches_exact() {
        let allow = HostAllowlist::parse_all(["api.anthropic.com"]).unwrap();
        assert!(allow.allows("api.anthropic.com"));
        assert!(!allow.allows("evil.com"));
        assert!(!allow.allows("sub.api.anthropic.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let allow = HostAllowlist::parse_all(["*.anthropic.com"]).unwrap();
        assert!(allow.allows("api.anthropic.com"));
        assert!(allow.allows("deep.sub.anthropic.com"));
        assert!(!allow.allows("anthropic.com"), "never the apex");
        assert!(!allow.allows("evilanthropic.com"), "label boundary");
        assert!(!allow.allows("anthropic.com.evil.com"));
    }

    #[test]
    fn no_patterns_means_nothing_allowed() {
        assert!(!HostAllowlist::new().allows("api.anthropic.com"));
    }

    #[test]
    fn matching_folds_case_and_trailing_dot() {
        let exact = pattern("Example.COM.");
        assert!(exact.matches("example.com"));
        assert!(exact.matches("EXAMPLE.com."));
        assert!(!exact.matches("example.com.."));
    }

    #[test]
    fn label_wildcards_match_one_label_each() {
        let regional = pattern("api.*.example.com");
        assert!(regional.matches("api.eu.example.com"));
        assert!(!regional.matches("api.example.com"));
        assert!(!regional.matches("api.a.b.example.com"));
        assert!(!regional.matches("web.eu.example.com"));
        let two = pattern("*.*.example.com");
        assert!(two.matches("a.b.example.com"));
        assert!(!two.matches("b.example.com"));
        assert!(!two.matches("x.a.b.example.com"));
    }

    #[test]
    fn invalid_hosts_never_match() {
        let any = pattern("*.example.com");
        assert!(!any.matches(""));
        assert!(!any.matches("a b.example.com"));
        assert!(!any.matches("..example.com"));
        // IP literals are neither hosts nor patterns.
        assert!(!pattern("*.example.com").matches("127.0.0.1"));
        assert!(HostAllowlist::parse_all(["*.0.0.1"]).is_err());
    }

    #[test]
    fn constructors_match_parsed_patterns() {
        let host = Hostname::parse("Example.com").unwrap();
        assert_eq!(HostPattern::exact(&host), pattern("example.com"));
        assert_eq!(HostPattern::subdomains_of(&host), pattern("*.example.com"));
    }

    #[test]
    fn reports_the_matching_pattern() {
        let allow = HostAllowlist::new()
            .with(pattern("example.com"))
            .with(pattern("*.example.com"));
        assert_eq!(allow.len(), 2);
        assert_eq!(
            allow.matching("www.example.com").map(HostPattern::as_str),
            Some("*.example.com")
        );
        assert_eq!(allow.matching("example.org"), None);
    }
}

//! The result of a lookup.

use std::fmt;

use crate::{RuleKind, Section};

/// A domain name split at its public suffix, as returned by
/// [`List::lookup`](crate::List::lookup).
///
/// All parts borrow from the normalized name: lowercase, without a trailing
/// dot, and with each label in the form it was given (`xn--` A-labels stay
/// A-labels, Unicode labels stay Unicode).
///
/// ```
/// # #[cfg(feature = "embedded")] {
/// use rune_psl::{Section, lookup};
///
/// let domain = lookup("WWW.Example.CO.UK.")?;
/// assert_eq!(domain.as_str(), "www.example.co.uk");
/// assert_eq!(domain.public_suffix(), "co.uk");
/// assert_eq!(domain.registrable_domain(), Some("example.co.uk"));
/// assert_eq!(domain.subdomain(), Some("www"));
/// assert_eq!(domain.section(), Some(Section::Icann));
///
/// let suffix = lookup("github.io")?;
/// assert!(suffix.is_public_suffix());
/// assert!(suffix.is_private());
/// assert_eq!(suffix.registrable_domain(), None);
/// # }
/// # Ok::<(), rune_psl::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain {
    pub(crate) name: String,
    /// Byte offset of the public suffix in `name`.
    pub(crate) suffix_start: usize,
    /// Byte offset of the registrable domain in `name`, if there is one.
    pub(crate) registrable_start: Option<usize>,
    /// Section and kind of the prevailing rule; `None` for the implicit `*`.
    pub(crate) rule: Option<(Section, RuleKind)>,
}

impl Domain {
    /// The normalized name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The public suffix ("effective TLD"): `co.uk` for `www.example.co.uk`.
    ///
    /// A name under a top-level domain the list does not know gets that
    /// label as its suffix, by the list's implicit `*` rule.
    #[must_use]
    pub fn public_suffix(&self) -> &str {
        self.name.get(self.suffix_start..).unwrap_or_default()
    }

    /// The registrable domain (eTLD+1): the public suffix plus one label,
    /// `example.co.uk` for `www.example.co.uk`. `None` when the name is
    /// itself a public suffix.
    #[must_use]
    pub fn registrable_domain(&self) -> Option<&str> {
        self.registrable_start
            .and_then(|start| self.name.get(start..))
    }

    /// The labels left of the registrable domain, without the joining dot:
    /// `www` for `www.example.co.uk`. `None` when there are none.
    #[must_use]
    pub fn subdomain(&self) -> Option<&str> {
        self.registrable_start
            .and_then(|start| start.checked_sub(1))
            .and_then(|end| self.name.get(..end))
    }

    /// Whether the whole name is a public suffix (`co.uk`, `github.io`).
    #[must_use]
    pub const fn is_public_suffix(&self) -> bool {
        self.registrable_start.is_none()
    }

    /// The section of the rule that decided the suffix, or `None` when no
    /// rule of the list matched and the implicit `*` rule applied.
    #[must_use]
    pub fn section(&self) -> Option<Section> {
        self.rule.map(|(section, _)| section)
    }

    /// The kind of the rule that decided the suffix, or `None` for the
    /// implicit `*` rule.
    #[must_use]
    pub fn rule_kind(&self) -> Option<RuleKind> {
        self.rule.map(|(_, kind)| kind)
    }

    /// Whether the suffix comes from a rule of the list, rather than the
    /// implicit `*` rule for unknown top-level domains.
    #[must_use]
    pub const fn is_listed(&self) -> bool {
        self.rule.is_some()
    }

    /// Whether the suffix comes from the ICANN section.
    #[must_use]
    pub fn is_icann(&self) -> bool {
        self.section() == Some(Section::Icann)
    }

    /// Whether the suffix comes from the private section (`github.io`).
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.section() == Some(Section::Private)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

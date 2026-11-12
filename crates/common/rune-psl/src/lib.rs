//! [Public Suffix List](https://publicsuffix.org/) lookups: the public
//! suffix ("effective TLD") and the registrable domain (eTLD+1) of a name.
//!
//! `co.uk`, `github.io` and `kobe.jp`'s children are public suffixes: names
//! under which anyone can register. The registrable domain is the suffix
//! plus one label, the unit a site owner controls. It is what scopes a scan
//! to a site, groups subdomains, bounds cookie domains
//! ([RFC 6265 §5.3](https://www.rfc-editor.org/rfc/rfc6265#section-5.3)) and
//! rejects certificate wildcards such as `*.co.uk`.
//!
//! - [`List::embedded`] (feature `embedded`, default) is the list pinned in
//!   this release ([`EMBEDDED_VERSION`]), ICANN and private sections.
//!   [`List::parse`] (feature `runtime`) loads a newer or custom list.
//! - [`List::lookup`] returns a [`Domain`]: [`Domain::public_suffix`],
//!   [`Domain::registrable_domain`], and whether the deciding rule is ICANN
//!   or private ([`Domain::is_private`]).
//!   [`List::with_private_rules`] can restrict lookups to ICANN rules.
//! - Names may use A-labels (`xn--85x722f.com.cn`) or Unicode labels
//!   (`食狮.com.cn`): `xn--` labels are Punycode-decoded
//!   ([RFC 3492](https://www.rfc-editor.org/rfc/rfc3492)) before matching,
//!   and results keep the form they were given in.
//!
//! The algorithm is the list's
//! [formal algorithm](https://github.com/publicsuffix/list/wiki/Format#formal-algorithm),
//! and the crate passes the list's own test suite (`tests/tests.txt`).
//! Lookups are sans-I/O and do a binary search per label; the embedded list
//! is a sorted static table, so creating it costs nothing.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "embedded")] {
//! use rune_psl::{lookup, registrable_domain};
//!
//! assert_eq!(registrable_domain("www.example.co.uk").as_deref(), Some("example.co.uk"));
//! assert_eq!(registrable_domain("食狮.公司.cn").as_deref(), Some("食狮.公司.cn"));
//! assert_eq!(registrable_domain("co.uk"), None);
//!
//! let domain = lookup("docs.rune.github.io")?;
//! assert_eq!(domain.public_suffix(), "github.io");
//! assert_eq!(domain.registrable_domain(), Some("rune.github.io"));
//! assert!(domain.is_private());
//! # }
//! # Ok::<(), rune_psl::Error>(())
//! ```
//!
//! # Features
//!
//! - `embedded` (default): [`List::embedded`], [`EMBEDDED_VERSION`] and the
//!   free functions ([`lookup`], [`public_suffix`], [`registrable_domain`],
//!   [`is_public_suffix`]), which use the embedded list.
//! - `runtime`: [`List::parse`], to load a list at run time.
//! - `cli`: the `rune-psl` command-line tool.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "embedded")]
mod data;
mod domain;
mod error;
mod host;
mod list;
mod punycode;
mod rule;

pub use domain::Domain;
pub use error::Error;
pub use list::List;
pub use rule::{Rule, RuleKind, Section};

/// The source of the embedded list: the `publicsuffix/list` commit date and
/// hash it was generated from.
#[cfg(feature = "embedded")]
pub const EMBEDDED_VERSION: &str = data::VERSION;

/// Splits `host` at its public suffix, using the embedded list.
///
/// # Errors
///
/// See [`List::lookup`].
#[cfg(feature = "embedded")]
pub fn lookup(host: &str) -> Result<Domain, Error> {
    List::embedded().lookup(host)
}

/// The public suffix of `host`, using the embedded list. `None` if `host`
/// is invalid.
///
/// ```
/// assert_eq!(rune_psl::public_suffix("a.b.example.com").as_deref(), Some("com"));
/// assert_eq!(rune_psl::public_suffix("x.city.kobe.jp").as_deref(), Some("kobe.jp"));
/// ```
#[cfg(feature = "embedded")]
#[must_use]
pub fn public_suffix(host: &str) -> Option<String> {
    List::embedded().public_suffix(host)
}

/// The registrable domain (eTLD+1) of `host`, using the embedded list.
/// `None` if `host` is a public suffix or is invalid.
///
/// ```
/// assert_eq!(rune_psl::registrable_domain("a.b.example.com").as_deref(), Some("example.com"));
/// assert_eq!(rune_psl::registrable_domain("com"), None);
/// ```
#[cfg(feature = "embedded")]
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    List::embedded().registrable_domain(host)
}

/// Whether `host` is itself a public suffix, using the embedded list.
///
/// ```
/// assert!(rune_psl::is_public_suffix("co.uk"));
/// assert!(!rune_psl::is_public_suffix("example.co.uk"));
/// ```
#[cfg(feature = "embedded")]
#[must_use]
pub fn is_public_suffix(host: &str) -> bool {
    List::embedded().is_public_suffix(host)
}

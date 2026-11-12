//! The list and the lookup algorithm.

use std::borrow::Cow;
use std::fmt;

use crate::domain::Domain;
use crate::host::{Name, normalize};
#[cfg(feature = "runtime")]
use crate::rule::P;
use crate::rule::{Entry, N, W, X};
use crate::{Error, Rule, RuleKind, Section};

/// A Public Suffix List: a sorted set of rules, plus whether lookups use
/// the private section.
///
/// [`List::embedded`] (feature `embedded`, on by default) is the list
/// pinned in this release; it costs nothing to create. [`List::parse`]
/// (feature `runtime`) reads a list in the
/// [official format](https://github.com/publicsuffix/list/wiki/Format),
/// for example a newer copy fetched by the application.
///
/// Lookups follow the
/// [PSL algorithm](https://github.com/publicsuffix/list/wiki/Format#formal-algorithm):
/// the matching exception rule prevails, otherwise the matching rule with
/// the most labels, otherwise the implicit `*` rule (the top-level label is
/// the suffix).
///
/// ```
/// # #[cfg(feature = "embedded")] {
/// use rune_psl::List;
///
/// let list = List::embedded();
/// assert_eq!(list.registrable_domain("a.b.github.io").as_deref(), Some("b.github.io"));
///
/// // ICANN only: `github.io` is an ordinary registrable domain.
/// let icann = List::embedded().with_private_rules(false);
/// assert_eq!(icann.registrable_domain("a.b.github.io").as_deref(), Some("github.io"));
/// # }
/// ```
#[derive(Clone)]
pub struct List {
    entries: Cow<'static, [Entry]>,
    private: bool,
}

impl List {
    /// The list embedded in this release, private section included. See
    /// [`EMBEDDED_VERSION`](crate::EMBEDDED_VERSION) for its source.
    #[cfg(feature = "embedded")]
    #[must_use]
    pub const fn embedded() -> Self {
        Self {
            entries: Cow::Borrowed(crate::data::RULES),
            private: true,
        }
    }

    /// Parses a list in the official `public_suffix_list.dat` format.
    ///
    /// Each line is read up to its first whitespace; empty lines and `//`
    /// comments are skipped. Rules between `// ===BEGIN PRIVATE DOMAINS===`
    /// and `// ===END PRIVATE DOMAINS===` are private; all others are
    /// ICANN. Rule names are normalized like looked-up names, and `xn--`
    /// labels are decoded, so a rule matches in either form. Duplicate
    /// rules are merged.
    ///
    /// ```
    /// use rune_psl::List;
    ///
    /// let list = List::parse("com\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n")?;
    /// assert_eq!(list.len(), 4);
    /// assert_eq!(list.registrable_domain("a.b.ck").as_deref(), Some("a.b.ck"));
    /// assert_eq!(list.registrable_domain("www.ck").as_deref(), Some("www.ck"));
    /// assert!(list.lookup("x.github.io")?.is_private());
    /// # Ok::<(), rune_psl::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRule`] for the first malformed rule, with its line.
    #[cfg(feature = "runtime")]
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut private = false;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim_start();
            if let Some(comment) = line.strip_prefix("//") {
                match comment.trim() {
                    "===BEGIN PRIVATE DOMAINS===" => private = true,
                    "===END PRIVATE DOMAINS===" => private = false,
                    _ => {}
                }
                continue;
            }
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            let (name, flag) = parse_rule(rule).map_err(|reason| Error::InvalidRule {
                line: index + 1,
                rule: rule.to_owned(),
                reason: Box::new(reason),
            })?;
            entries.push(Entry {
                name: Cow::Owned(name),
                flags: flag | if private { P } else { 0 },
            });
        }
        entries.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        entries.dedup_by(|next, kept| {
            let same = sort_key(next) == sort_key(kept);
            if same {
                kept.flags |= next.flags;
            }
            same
        });
        Ok(Self {
            entries: Cow::Owned(entries),
            private: true,
        })
    }

    /// Whether lookups use the private section (on by default).
    ///
    /// With `false`, only ICANN rules apply: `github.io` is then an ordinary
    /// registrable domain under `io`. Browsers use the full list for cookie
    /// scoping, and the ICANN section alone to reject certificate wildcards
    /// such as `*.co.uk`.
    #[must_use]
    pub const fn with_private_rules(mut self, include: bool) -> Self {
        self.private = include;
        self
    }

    /// Whether lookups use the private section.
    #[must_use]
    pub const fn includes_private_rules(&self) -> bool {
        self.private
    }

    /// Number of rules, in both sections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| (entry.flags & (N | W | X)).count_ones() as usize)
            .sum()
    }

    /// Whether the list has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every rule, in both sections, sorted by name.
    pub fn rules(&self) -> impl Iterator<Item = Rule<'_>> {
        self.entries.iter().flat_map(Entry::rules)
    }

    /// Splits `host` at its public suffix.
    ///
    /// `host` may use A-labels (`xn--85x722f.com.cn`), Unicode labels
    /// (`食狮.com.cn`) or a mix. It is normalized first: one trailing dot is
    /// dropped and letters are lowercased.
    ///
    /// # Errors
    ///
    /// The name is empty, has an empty label (`.com`, `a..com`), exceeds the
    /// length limits, contains a character that is never valid in a domain
    /// name, has an `xn--` label that is not valid Punycode, or ends in an
    /// all-digit label (an IPv4 address).
    pub fn lookup(&self, host: &str) -> Result<Domain, Error> {
        let name = normalize(host, false)?;
        let (suffix_labels, rule) = self.suffix_labels(&name);
        let suffix_start = name.text_suffix_start(suffix_labels);
        let registrable_start =
            (name.labels() > suffix_labels).then(|| name.text_suffix_start(suffix_labels + 1));
        Ok(Domain {
            name: name.text,
            suffix_start,
            registrable_start,
            rule,
        })
    }

    /// The public suffix of `host`, or `None` if `host` is invalid (see
    /// [`List::lookup`]).
    #[must_use]
    pub fn public_suffix(&self, host: &str) -> Option<String> {
        self.lookup(host)
            .ok()
            .map(|domain| domain.public_suffix().to_owned())
    }

    /// The registrable domain (eTLD+1) of `host`, or `None` if `host` is
    /// itself a public suffix or is invalid (see [`List::lookup`]).
    #[must_use]
    pub fn registrable_domain(&self, host: &str) -> Option<String> {
        self.lookup(host)
            .ok()
            .and_then(|domain| domain.registrable_domain().map(str::to_owned))
    }

    /// Whether `host` is a valid name that is itself a public suffix.
    #[must_use]
    pub fn is_public_suffix(&self, host: &str) -> bool {
        self.lookup(host)
            .is_ok_and(|domain| domain.is_public_suffix())
    }

    /// The number of labels of the public suffix, and the prevailing rule.
    fn suffix_labels(&self, name: &Name) -> (usize, Option<(Section, RuleKind)>) {
        let mut best: Option<(usize, Section, RuleKind)> = None;
        let mut exception: Option<(usize, Section)> = None;
        let mut parent_wildcard: Option<Section> = None;
        for count in 1..=name.labels() {
            let hits = self.find(name.key_suffix(count));
            if let Some(section) = parent_wildcard {
                best = Some((count, section, RuleKind::Wildcard));
            }
            if let Some(section) = hits.normal {
                best = Some((count, section, RuleKind::Normal));
            }
            if let Some(section) = hits.exception {
                exception = Some((count, section));
            }
            parent_wildcard = hits.wildcard;
        }
        if let Some((count, section)) = exception {
            return (
                count.saturating_sub(1).max(1),
                Some((section, RuleKind::Exception)),
            );
        }
        match best {
            Some((count, section, kind)) => (count, Some((section, kind))),
            None => (1, None),
        }
    }

    /// The rules for exactly `key`, by kind, with ICANN taking precedence
    /// when both sections have one.
    fn find(&self, key: &str) -> Hits {
        let start = self
            .entries
            .partition_point(|entry| entry.name.as_ref() < key);
        let mut hits = Hits::default();
        for entry in self
            .entries
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|entry| entry.name == key)
        {
            let section = entry.section();
            if section == Section::Private && !self.private {
                continue;
            }
            for (flag, slot) in [
                (N, &mut hits.normal),
                (W, &mut hits.wildcard),
                (X, &mut hits.exception),
            ] {
                if entry.flags & flag != 0 && slot.is_none() {
                    *slot = Some(section);
                }
            }
        }
        hits
    }
}

impl fmt::Debug for List {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("rules", &self.len())
            .field("private", &self.private)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "runtime")]
impl std::str::FromStr for List {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

#[derive(Default)]
struct Hits {
    normal: Option<Section>,
    wildcard: Option<Section>,
    exception: Option<Section>,
}

/// Entries sort by name, ICANN before private.
#[cfg(feature = "runtime")]
fn sort_key(entry: &Entry) -> (&str, u8) {
    (entry.name.as_ref(), entry.flags & P)
}

/// Parses one rule into its canonical name and kind flag.
#[cfg(feature = "runtime")]
fn parse_rule(rule: &str) -> Result<(String, u8), Error> {
    let (body, flag) = match (rule.strip_prefix('!'), rule.strip_prefix("*.")) {
        (Some(name), _) => (name, X),
        (None, Some(name)) => (name, W),
        (None, None) => (rule, N),
    };
    if body.contains('*') {
        return Err(Error::MisplacedWildcard);
    }
    let name = normalize(body, true)?;
    if flag == X && name.labels() < 2 {
        return Err(Error::ExceptionTooShort);
    }
    Ok((name.key, flag))
}

#[cfg(all(test, feature = "runtime"))]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
*.ck
!www.ck
jp
*.kobe.jp
!city.kobe.jp
公司.cn
cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
*.compute.example.com  trailing text is ignored
// ===END PRIVATE DOMAINS===
";

    fn sample() -> Result<List, Error> {
        List::parse(SAMPLE)
    }

    #[test]
    fn parses_sections_and_kinds() {
        let list = sample().unwrap();
        assert_eq!(list.len(), 12);
        assert!(
            list.rules()
                .any(|rule| rule.to_string() == "*.compute.example.com")
        );
        let private: Vec<String> = list
            .rules()
            .filter(|rule| rule.section() == Section::Private)
            .map(|rule| rule.to_string())
            .collect();
        assert_eq!(private, ["*.compute.example.com", "github.io"]);
    }

    #[test]
    fn exception_and_wildcard_rules() {
        let list = sample().unwrap();
        assert_eq!(list.public_suffix("a.b.ck").as_deref(), Some("b.ck"));
        assert_eq!(list.registrable_domain("b.ck"), None);
        assert_eq!(list.registrable_domain("www.ck").as_deref(), Some("www.ck"));
        assert_eq!(
            list.registrable_domain("a.www.ck").as_deref(),
            Some("www.ck")
        );
        let city = list.lookup("x.city.kobe.jp").unwrap();
        assert_eq!(city.public_suffix(), "kobe.jp");
        assert_eq!(city.rule_kind(), Some(RuleKind::Exception));
        // The wildcard needs a label to cover.
        assert_eq!(list.public_suffix("ck").as_deref(), Some("ck"));
        assert!(!list.lookup("ck").unwrap().is_listed());
    }

    #[test]
    fn private_rules_can_be_excluded() {
        let list = sample().unwrap();
        let host = "a.b.compute.example.com";
        assert_eq!(
            list.public_suffix(host).as_deref(),
            Some("b.compute.example.com")
        );
        assert!(list.lookup(host).unwrap().is_private());
        let icann = sample().unwrap().with_private_rules(false);
        assert!(!icann.includes_private_rules());
        assert_eq!(icann.public_suffix(host).as_deref(), Some("com"));
        assert!(icann.lookup(host).unwrap().is_icann());
        assert_eq!(
            icann.registrable_domain("x.github.io").as_deref(),
            Some("github.io")
        );
        assert!(!icann.lookup("x.github.io").unwrap().is_listed());
    }

    #[test]
    fn a_labels_and_u_labels_match_alike() {
        let list = sample().unwrap();
        assert_eq!(
            list.public_suffix("x.xn--55qx5d.cn").as_deref(),
            Some("xn--55qx5d.cn")
        );
        assert_eq!(list.public_suffix("x.公司.cn").as_deref(), Some("公司.cn"));
        let punycoded = List::parse("xn--55qx5d.cn").unwrap();
        assert_eq!(
            punycoded.rules().next().map(|rule| rule.name()),
            Some("公司.cn")
        );
        assert!(punycoded.is_public_suffix("公司.CN."));
    }

    #[test]
    fn duplicates_merge_and_sections_stay_apart() {
        let list =
            List::parse("a.com\na.com\n*.a.com\n// ===BEGIN PRIVATE DOMAINS===\na.com\n").unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list.entries.len(), 2);
        // The ICANN rule wins when both sections have one.
        assert!(list.lookup("x.a.com").unwrap().is_icann());
    }

    #[test]
    fn rejects_malformed_rules() {
        let error = |text: &str| match List::parse(text) {
            Err(Error::InvalidRule { reason, .. }) => *reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(error("a.*.com"), Error::MisplacedWildcard);
        assert_eq!(error("*"), Error::MisplacedWildcard);
        assert_eq!(error("!*.com"), Error::MisplacedWildcard);
        assert_eq!(error("f*.com"), Error::MisplacedWildcard);
        assert_eq!(error("!com"), Error::ExceptionTooShort);
        assert_eq!(error(".com"), Error::EmptyLabel);
        assert!(matches!(
            List::parse("com\n\nbad/rule"),
            Err(Error::InvalidRule { line: 3, .. })
        ));
    }

    #[test]
    fn empty_list_uses_the_implicit_rule() {
        let list = List::parse("// nothing\n\n").unwrap();
        assert!(list.is_empty());
        assert_eq!(
            list.registrable_domain("a.b.example").as_deref(),
            Some("b.example")
        );
        assert_eq!(list.registrable_domain("example"), None);
    }
}

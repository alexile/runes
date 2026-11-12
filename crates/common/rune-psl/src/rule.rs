//! Rules of the list and their compact storage.

use std::borrow::Cow;
use std::fmt;

/// The kind of a Public Suffix List rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RuleKind {
    /// `co.uk`: the name itself is a public suffix.
    Normal,
    /// `*.ck`: every direct child of the name is a public suffix.
    Wildcard,
    /// `!www.ck`: the name is not a public suffix, although a wildcard rule
    /// covers it; its parent is.
    Exception,
}

/// The section of the list a rule comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Section {
    /// `===BEGIN ICANN DOMAINS===`: suffixes operated by registries under
    /// ICANN's authority (`com`, `co.uk`).
    Icann,
    /// `===BEGIN PRIVATE DOMAINS===`: suffixes that a company offers to its
    /// customers (`github.io`, `blogspot.com`).
    Private,
}

/// One rule of a [`List`](crate::List), borrowed from it.
///
/// `name` is canonical: lowercase, without the `*.` or `!` prefix, and with
/// internationalized labels as Unicode (U-labels). [`Display`](fmt::Display)
/// writes the rule in list syntax.
///
/// ```
/// # #[cfg(feature = "embedded")] {
/// use rune_psl::{List, RuleKind};
///
/// let list = List::embedded();
/// let rule = list.rules().find(|rule| rule.kind() == RuleKind::Exception).unwrap();
/// assert!(rule.to_string().starts_with('!'));
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule<'a> {
    name: &'a str,
    kind: RuleKind,
    section: Section,
}

impl<'a> Rule<'a> {
    /// The name the rule is about, without `*.` or `!`.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The kind of rule.
    #[must_use]
    pub const fn kind(&self) -> RuleKind {
        self.kind
    }

    /// The section the rule comes from.
    #[must_use]
    pub const fn section(&self) -> Section {
        self.section
    }
}

impl fmt::Display for Rule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RuleKind::Normal => f.write_str(self.name),
            RuleKind::Wildcard => write!(f, "*.{}", self.name),
            RuleKind::Exception => write!(f, "!{}", self.name),
        }
    }
}

/// Flag: a normal rule for the name.
pub const N: u8 = 1;
/// Flag: a wildcard rule `*.name`.
pub const W: u8 = 2;
/// Flag: an exception rule `!name`.
pub const X: u8 = 4;
/// Flag: the rules of this entry are in the private section.
pub const P: u8 = 8;

/// All rules for one name in one section. A list is a slice of entries
/// sorted by `(name, flags & P)`, so a name has at most two entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: Cow<'static, str>,
    pub flags: u8,
}

impl Entry {
    /// An entry of the embedded list.
    #[cfg(any(feature = "embedded", test))]
    pub const fn new(name: &'static str, flags: u8) -> Self {
        Self {
            name: Cow::Borrowed(name),
            flags,
        }
    }

    pub const fn section(&self) -> Section {
        if self.flags & P == 0 {
            Section::Icann
        } else {
            Section::Private
        }
    }

    /// The rules this entry holds, in [`RuleKind`] order.
    pub fn rules(&self) -> impl Iterator<Item = Rule<'_>> {
        let section = self.section();
        [
            (N, RuleKind::Normal),
            (W, RuleKind::Wildcard),
            (X, RuleKind::Exception),
        ]
        .into_iter()
        .filter(move |(flag, _)| self.flags & flag != 0)
        .map(move |(_, kind)| Rule {
            name: &self.name,
            kind,
            section,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_expands_to_rules_in_list_syntax() {
        let entry = Entry::new("ck", W | X | P);
        let rules: Vec<String> = entry.rules().map(|rule| rule.to_string()).collect();
        assert_eq!(rules, ["*.ck", "!ck"]);
        assert!(entry.rules().all(|rule| rule.section() == Section::Private));
        assert_eq!(Entry::new("com", N).section(), Section::Icann);
    }
}

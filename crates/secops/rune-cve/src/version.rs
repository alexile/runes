//! Version comparison and the version ranges of NVD match criteria.

use core::cmp::Ordering;

/// Words that mark a pre-release when they follow the release number
/// (`2.0-rc1 < 2.0`, `1.0.beta < 1.0`), earliest first: among themselves
/// they order by this list, so `2.0-dev < 2.0-alpha < 2.0-beta < 2.0-rc`.
///
/// Single letters are deliberately not here: `1.1.1a` is a later OpenSSL
/// release than `1.1.1`, and OpenSSH-style suffixes (`7.4p1`) are later
/// too.
const PRE_RELEASE: [&str; 11] = [
    "dev",
    "snapshot",
    "nightly",
    "alpha",
    "beta",
    "milestone",
    "ea",
    "pre",
    "preview",
    "cr",
    "rc",
];

/// One run of a version, ranked so that comparing ranks is a total order:
/// pre-release words < `0` (and the end of the version) < other words <
/// numbers from 1 up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Token<'a> {
    /// A [`PRE_RELEASE`] word, by its index there.
    Pre(usize),
    /// Zero, or nothing: `1.0 == 1.0.0 == 1`.
    Zero,
    /// Any other run of ASCII letters, lowercased byte by byte on compare.
    Word(Word<'a>),
    /// A positive number: digits without leading zeros.
    Num(Digits<'a>),
}

/// ASCII letters, ordered case-insensitively.
#[derive(Debug, Clone, Copy)]
struct Word<'a>(&'a str);

impl PartialEq for Word<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}
impl Eq for Word<'_> {}
impl PartialOrd for Word<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Word<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.0.bytes().map(|c| c.to_ascii_lowercase());
        let b = other.0.bytes().map(|c| c.to_ascii_lowercase());
        a.cmp(b)
    }
}

/// Digits without leading zeros, ordered numerically at any length: a
/// longer number is larger, equal lengths compare digit by digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Digits<'a>(&'a str);

impl PartialOrd for Digits<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Digits<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(other.0))
    }
}

fn tokens(version: &str) -> impl Iterator<Item = Token<'_>> {
    let v = version.trim();
    // A leading `v` before a digit (`v1.2.3`) is a prefix, not a word.
    let v = match v.as_bytes() {
        [b'v' | b'V', d, ..] if d.is_ascii_digit() => &v[1..],
        _ => v,
    };
    let bytes = v.as_bytes();
    let mut i = 0;
    core::iter::from_fn(move || {
        while i < bytes.len() && !bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let start = i;
        if bytes[i].is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let digits = v[start..i].trim_start_matches('0');
            Some(if digits.is_empty() {
                Token::Zero
            } else {
                Token::Num(Digits(digits))
            })
        } else {
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let word = &v[start..i];
            Some(
                PRE_RELEASE
                    .iter()
                    .position(|p| p.eq_ignore_ascii_case(word))
                    .map_or(Token::Word(Word(word)), Token::Pre),
            )
        }
    })
}

/// Compares two product version strings the way vulnerability databases
/// need: numerically per component, and tolerant of the many formats
/// vendors use.
///
/// The versions split into runs of digits and runs of letters; any other
/// character (`.`, `-`, `_`, `+`, `~`, …) only separates runs. The runs
/// compare pairwise, and the shorter version is padded with zeros:
///
/// - numbers numerically, of any length (`1.10 > 1.9`, `01 == 1`), so
///   trailing zeros change nothing (`2.0 == 2.0.0`);
/// - a pre-release word (`dev`, `snapshot`, `nightly`, `alpha`, `beta`,
///   `milestone`, `ea`, `pre`, `preview`, `cr`, `rc`, in that order) is
///   earlier than zero, so `2.0-rc1 < 2.0` and `2.0-beta9 < 2.0-rc1`;
/// - any other word is later than zero but earlier than 1, so
///   `1.1.1k > 1.1.1`, `7.4p1 > 7.4` and `1.0.1 > 1.0.a`; such words
///   compare case-insensitively among themselves.
///
/// A leading `v` before a digit is ignored. The relation is a total
/// preorder (reflexive, transitive, and antisymmetric up to equality):
/// versions that differ only in separators, case or leading zeros compare
/// equal.
///
/// # Examples
///
/// ```
/// use core::cmp::Ordering;
/// use rune_cve::compare_versions;
///
/// assert_eq!(compare_versions("2.14.1", "2.15.0"), Ordering::Less);
/// assert_eq!(compare_versions("1.10", "1.9"), Ordering::Greater);
/// assert_eq!(compare_versions("2.0", "v2.0.0"), Ordering::Equal);
/// assert_eq!(compare_versions("2.0.0-rc1", "2.0.0"), Ordering::Less);
/// assert_eq!(compare_versions("1.0.1g", "1.0.1"), Ordering::Greater);
/// ```
#[must_use]
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let mut a = tokens(a);
    let mut b = tokens(b);
    loop {
        let (x, y) = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (x, y) => (x.unwrap_or(Token::Zero), y.unwrap_or(Token::Zero)),
        };
        match x.cmp(&y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
}

/// One end of a [`VersionRange`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bound {
    /// The version itself is in the range.
    Including(String),
    /// The version itself is not in the range.
    Excluding(String),
}

impl Bound {
    /// The bound's version.
    #[must_use]
    pub fn version(&self) -> &str {
        match self {
            Self::Including(v) | Self::Excluding(v) => v,
        }
    }
}

/// A range of versions, as NVD match criteria give it with
/// `versionStartIncluding`/`versionStartExcluding` and
/// `versionEndIncluding`/`versionEndExcluding`. A missing end is unbounded.
///
/// Versions compare with [`compare_versions`].
///
/// # Examples
///
/// ```
/// use rune_cve::{Bound, VersionRange};
///
/// // Log4Shell: 2.0-beta9 up to, but not including, 2.15.0.
/// let range = VersionRange::new(
///     Some(Bound::Including("2.0-beta9".into())),
///     Some(Bound::Excluding("2.15.0".into())),
/// );
/// assert!(range.contains("2.14.1"));
/// assert!(range.contains("2.0-beta9"));
/// assert!(!range.contains("2.15.0"));
/// assert!(!range.contains("1.2.17"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VersionRange {
    /// The lower end, or `None` for no lower limit.
    pub start: Option<Bound>,
    /// The upper end, or `None` for no upper limit.
    pub end: Option<Bound>,
}

impl VersionRange {
    /// A range between `start` and `end`.
    #[must_use]
    pub const fn new(start: Option<Bound>, end: Option<Bound>) -> Self {
        Self { start, end }
    }

    /// Whether the range has neither end, so it contains every version.
    #[must_use]
    pub const fn is_unbounded(&self) -> bool {
        self.start.is_none() && self.end.is_none()
    }

    /// Whether `version` is in the range.
    #[must_use]
    pub fn contains(&self, version: &str) -> bool {
        let above = match &self.start {
            None => true,
            Some(Bound::Including(v)) => compare_versions(version, v).is_ge(),
            Some(Bound::Excluding(v)) => compare_versions(version, v).is_gt(),
        };
        let below = match &self.end {
            None => true,
            Some(Bound::Including(v)) => compare_versions(version, v).is_le(),
            Some(Bound::Excluding(v)) => compare_versions(version, v).is_lt(),
        };
        above && below
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    #[test]
    fn known_orderings() {
        let cases = [
            ("1.0", "1.0", Equal),
            ("1.0", "1.0.0", Equal),
            ("1.0.0.0", "1", Equal),
            ("01.002", "1.2", Equal),
            ("1.2", "1.10", Less),
            ("2.14.1", "2.15.0", Less),
            ("2.0-beta9", "2.0", Less),
            ("2.0-beta9", "2.0-beta10", Less),
            ("2.0-alpha1", "2.0-beta1", Less),
            ("2.0-dev", "2.0-alpha", Less),
            ("2.0-beta9", "2.0-rc1", Less),
            ("1.0", "1.0a", Less),
            ("1.0a", "1.0rc1", Greater),
            ("1.0.0", "1.0.a", Less),
            ("1.0.a", "1.0.1", Less),
            ("2.0-rc1", "2.0-rc2", Less),
            ("2.0.rc2", "2.0.0", Less),
            ("2.0-rc2", "2.0.1", Less),
            ("1.0.1", "1.0.1a", Less),
            ("1.0.1f", "1.0.1g", Less),
            ("1.0.1g", "1.0.2", Less),
            ("7.4", "7.4p1", Less),
            ("v3.1", "3.1.0", Equal),
            ("V3", "3", Equal),
            ("1.0RC1", "1.0rc1", Equal),
            ("1_2_3", "1.2.3", Equal),
            ("", "0", Equal),
            ("", "1", Less),
            ("5.15.0-91", "5.15.0-100", Less),
            (
                "99999999999999999999999999999",
                "100000000000000000000000000000",
                Less,
            ),
        ];
        for (a, b, want) in cases {
            assert_eq!(compare_versions(a, b), want, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn ranges() {
        let r = VersionRange::new(
            Some(Bound::Excluding("1.0".into())),
            Some(Bound::Including("1.4".into())),
        );
        assert!(!r.contains("1.0"));
        assert!(!r.contains("1.0.0"));
        assert!(r.contains("1.0.1"));
        assert!(r.contains("1.4"));
        assert!(r.contains("1.4.0"));
        assert!(!r.contains("1.4.1"));
        assert!(VersionRange::default().contains("anything"));
        assert!(VersionRange::default().is_unbounded());
        assert_eq!(Bound::Including("1".into()).version(), "1");
    }
}

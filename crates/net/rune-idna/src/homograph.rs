//! IDN homograph detection for whole domain names.

use std::collections::HashMap;

use crate::Error;
use crate::confusable::skeleton;
use crate::script::{RestrictionLevel, ScriptSet, resolved_script_set, restriction_level};
use crate::uts46::{Options, to_ascii, to_unicode};

/// When a label counts as a spoofing risk; see [`LabelReport::is_suspicious`].
///
/// The default follows the practice of browsers: labels up to
/// [`RestrictionLevel::ModeratelyRestrictive`] are fine, and so are
/// single-script labels unless they could pass for an ASCII label.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpoofPolicy {
    /// The least restrictive [`RestrictionLevel`] a label may have.
    pub max_restriction_level: RestrictionLevel,
    /// Flag non-ASCII labels whose [`skeleton`] is all ASCII: labels made
    /// entirely of look-alikes of ASCII characters, such as Cyrillic
    /// `аррӏе`. This is what catches whole-script confusables, which pass
    /// every mixed-script check.
    pub flag_ascii_lookalikes: bool,
}

impl Default for SpoofPolicy {
    fn default() -> Self {
        Self {
            max_restriction_level: RestrictionLevel::ModeratelyRestrictive,
            flag_ascii_lookalikes: true,
        }
    }
}

impl SpoofPolicy {
    /// Sets [`SpoofPolicy::max_restriction_level`].
    #[must_use]
    pub const fn with_max_restriction_level(mut self, level: RestrictionLevel) -> Self {
        self.max_restriction_level = level;
        self
    }

    /// Sets [`SpoofPolicy::flag_ascii_lookalikes`].
    #[must_use]
    pub const fn with_flag_ascii_lookalikes(mut self, flag: bool) -> Self {
        self.flag_ascii_lookalikes = flag;
        self
    }
}

/// The analysis of one label of a domain name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LabelReport {
    /// The ASCII form of the label (`xn--…` for an internationalized label).
    pub ascii: String,
    /// The Unicode form of the label, after UTS #46 mapping.
    pub unicode: String,
    /// The [resolved script set](crate::resolved_script_set) of the label.
    pub scripts: ScriptSet,
    /// The [restriction level](crate::restriction_level) of the label.
    pub restriction_level: RestrictionLevel,
    /// The [`skeleton`] of the Unicode form.
    pub skeleton: String,
    /// The label is not ASCII, but its skeleton is: every character looks
    /// like an ASCII one.
    pub ascii_lookalike: bool,
    /// The Unicode form converts back to the same ASCII label on its own.
    /// It does not for odd labels such as `xn--xn--…`, whose Unicode form
    /// still starts with `xn--`; such a label is always suspicious, so
    /// [`DomainReport::display`] never shows a form that does not convert
    /// back.
    pub round_trips: bool,
}

impl LabelReport {
    fn new(ascii: &str, unicode: &str, options: &Options) -> Self {
        let skeleton = skeleton(unicode);
        let options = options.clone().with_verify_dns_length(false);
        let round_trips =
            ascii == unicode || to_ascii(unicode, &options).is_ok_and(|again| again == ascii);
        Self {
            ascii: ascii.to_owned(),
            unicode: unicode.to_owned(),
            scripts: resolved_script_set(unicode),
            restriction_level: restriction_level(unicode),
            ascii_lookalike: !unicode.is_ascii() && skeleton.is_ascii(),
            round_trips,
            skeleton,
        }
    }

    /// Whether the label breaks `policy`, or does not
    /// [round-trip](Self::round_trips).
    #[must_use]
    pub fn is_suspicious(&self, policy: &SpoofPolicy) -> bool {
        !self.round_trips
            || self.restriction_level > policy.max_restriction_level
            || (policy.flag_ascii_lookalikes && self.ascii_lookalike)
    }
}

/// The homograph analysis of a domain name.
///
/// ```
/// use rune_idna::{DomainReport, Options, RestrictionLevel, SpoofPolicy};
///
/// let policy = SpoofPolicy::default();
///
/// // Cyrillic а, р and ӏ: every label is single-script, but the first
/// // one passes for ASCII `apple`.
/// let report = DomainReport::analyze("аррӏе.com", &Options::default())?;
/// assert_eq!(report.ascii, "xn--80ak6aa92e.com");
/// assert_eq!(report.skeleton, rune_idna::skeleton("apple.com"));
/// assert!(report.is_suspicious(&policy));
/// assert_eq!(report.display(&policy), "xn--80ak6aa92e.com");
///
/// let report = DomainReport::analyze("xn--bcher-kva.de", &Options::default())?;
/// assert_eq!(report.restriction_level(), RestrictionLevel::SingleScript);
/// assert!(!report.is_suspicious(&policy));
/// assert_eq!(report.display(&policy), "bücher.de");
/// # Ok::<(), rune_idna::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DomainReport {
    /// The ASCII form ([`to_ascii`]).
    pub ascii: String,
    /// The Unicode form ([`to_unicode`]).
    pub unicode: String,
    /// The [`skeleton`] of the Unicode form, for comparison with other
    /// domains.
    pub skeleton: String,
    /// One report per label, in order. A trailing root dot adds no label.
    pub labels: Vec<LabelReport>,
}

impl DomainReport {
    /// Processes `domain` with `options` and analyses every label.
    ///
    /// # Errors
    ///
    /// Any error of [`to_ascii`] or [`to_unicode`].
    pub fn analyze(domain: &str, options: &Options) -> Result<Self, Error> {
        let ascii = to_ascii(domain, options)?;
        let unicode = to_unicode(&ascii, options)?;
        let labels = ascii
            .strip_suffix('.')
            .unwrap_or(&ascii)
            .split('.')
            .zip(unicode.strip_suffix('.').unwrap_or(&unicode).split('.'))
            .map(|(a, u)| LabelReport::new(a, u, options))
            .collect();
        Ok(Self {
            skeleton: skeleton(&unicode),
            ascii,
            unicode,
            labels,
        })
    }

    /// The least restrictive [`RestrictionLevel`] of any label.
    #[must_use]
    pub fn restriction_level(&self) -> RestrictionLevel {
        self.labels
            .iter()
            .map(|l| l.restriction_level)
            .max()
            .unwrap_or(RestrictionLevel::AsciiOnly)
    }

    /// Whether any label breaks `policy`.
    #[must_use]
    pub fn is_suspicious(&self, policy: &SpoofPolicy) -> bool {
        self.labels.iter().any(|l| l.is_suspicious(policy))
    }

    /// The form to show a user: Unicode labels, except that every label
    /// that breaks `policy` stays in its `xn--` form, as browsers do.
    #[must_use]
    pub fn display(&self, policy: &SpoofPolicy) -> String {
        let mut out = String::with_capacity(self.unicode.len());
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                out.push('.');
            }
            if label.is_suspicious(policy) {
                out.push_str(&label.ascii);
            } else {
                out.push_str(&label.unicode);
            }
        }
        if self.ascii.ends_with('.') {
            out.push('.');
        }
        out
    }
}

/// Finds look-alikes of a set of known domain names: brand names,
/// customer domains, the hosts of an allow list.
///
/// Each known name is stored by the [`skeleton`] of its Unicode form, so a
/// lookup is one hash probe.
///
/// ```
/// use rune_idna::{LookalikeIndex, Options};
///
/// let mut index = LookalikeIndex::new(Options::default());
/// index.insert("paypal.com")?;
/// index.insert("example.org")?;
///
/// assert_eq!(index.find("pаypal.com")?, ["paypal.com"]); // Cyrillic а
/// assert_eq!(index.find("PAYPAL.com")?, Vec::<&str>::new()); // the same domain
/// assert_eq!(index.find("paypa1.com")?, ["paypal.com"]);
/// # Ok::<(), rune_idna::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct LookalikeIndex {
    options: Options,
    by_skeleton: HashMap<String, Vec<String>>,
}

impl LookalikeIndex {
    /// An empty index that processes names with `options`.
    #[must_use]
    pub fn new(options: Options) -> Self {
        Self {
            options,
            by_skeleton: HashMap::new(),
        }
    }

    /// The ASCII form and skeleton of `domain`, without a trailing dot.
    fn key(&self, domain: &str) -> Result<(String, String), Error> {
        let mut ascii = to_ascii(domain, &self.options)?;
        if ascii.ends_with('.') {
            ascii.pop();
        }
        let unicode = to_unicode(&ascii, &self.options)?;
        Ok((ascii, skeleton(&unicode)))
    }

    /// Adds a known domain name. Adding a name twice has no effect.
    ///
    /// # Errors
    ///
    /// Any error of [`to_ascii`] or [`to_unicode`] on `domain`.
    pub fn insert(&mut self, domain: &str) -> Result<(), Error> {
        let (ascii, skeleton) = self.key(domain)?;
        let names = self.by_skeleton.entry(skeleton).or_default();
        if !names.contains(&ascii) {
            names.push(ascii);
        }
        Ok(())
    }

    /// The number of distinct known names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_skeleton.values().map(Vec::len).sum()
    }

    /// Whether no names are known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_skeleton.is_empty()
    }

    /// The known names that `domain` is confusable with, by their ASCII
    /// form, in insertion order. `domain` itself is not reported, so a
    /// known name finds nothing unless another known name looks like it.
    ///
    /// # Errors
    ///
    /// Any error of [`to_ascii`] or [`to_unicode`] on `domain`.
    pub fn find(&self, domain: &str) -> Result<Vec<&str>, Error> {
        let (ascii, skeleton) = self.key(domain)?;
        Ok(self
            .by_skeleton
            .get(&skeleton)
            .into_iter()
            .flatten()
            .filter(|known| **known != ascii)
            .map(String::as_str)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(domain: &str) -> DomainReport {
        DomainReport::analyze(domain, &Options::default()).unwrap()
    }

    #[test]
    fn ascii_domain_is_clean() {
        let r = report("Example.COM.");
        assert_eq!(r.ascii, "example.com.");
        assert_eq!(r.unicode, "example.com.");
        assert_eq!(r.labels.len(), 2);
        assert_eq!(r.restriction_level(), RestrictionLevel::AsciiOnly);
        assert!(!r.is_suspicious(&SpoofPolicy::default()));
        assert_eq!(r.display(&SpoofPolicy::default()), "example.com.");
    }

    #[test]
    fn mixed_script_label_is_suspicious() {
        let policy = SpoofPolicy::default();
        let r = report("pаypal.com");
        assert_eq!(
            r.labels[0].restriction_level,
            RestrictionLevel::MinimallyRestrictive
        );
        assert!(r.labels[0].scripts.is_empty());
        assert!(r.is_suspicious(&policy));
        assert!(!r.labels[1].is_suspicious(&policy));
        assert_eq!(r.display(&policy), format!("{}.com", r.labels[0].ascii));
        // `m` has the prototype `rn`.
        assert_eq!(r.skeleton, "paypal.corn");
    }

    #[test]
    fn whole_script_lookalike_is_suspicious() {
        let r = report("ѕсоре.com");
        assert_eq!(
            r.labels[0].restriction_level,
            RestrictionLevel::SingleScript
        );
        assert!(r.labels[0].ascii_lookalike);
        assert!(r.is_suspicious(&SpoofPolicy::default()));
        let lenient = SpoofPolicy::default().with_flag_ascii_lookalikes(false);
        assert!(!r.is_suspicious(&lenient));
    }

    #[test]
    fn legitimate_idns_are_clean() {
        let policy = SpoofPolicy::default();
        for domain in [
            "bücher.de",
            "яндекс.рф",
            "例え.テスト",
            "日本語.jp",
            "παράδειγμα.ελ",
        ] {
            let r = report(domain);
            assert!(!r.is_suspicious(&policy), "{domain}: {r:?}");
            assert_eq!(r.display(&policy), r.unicode, "{domain}");
        }
    }

    #[test]
    fn policy_level() {
        let r = report("abcไทย.com");
        assert_eq!(
            r.restriction_level(),
            RestrictionLevel::ModeratelyRestrictive
        );
        assert!(!r.is_suspicious(&SpoofPolicy::default()));
        let strict =
            SpoofPolicy::default().with_max_restriction_level(RestrictionLevel::HighlyRestrictive);
        assert!(r.is_suspicious(&strict));
    }

    // Regression: found by the fuzzer. The Unicode form of
    // `xn--xn--xn--bcva` starts with `xn--` and is not valid input, so it
    // must not be displayed.
    #[test]
    fn label_that_does_not_round_trip_is_suspicious() {
        let options = Options::default();
        let r = DomainReport::analyze("xn--xn--xn--bcva.cg", &options).unwrap();
        assert!(r.labels[0].unicode.starts_with("xn--"));
        assert!(!r.labels[0].round_trips);
        assert!(r.labels[1].round_trips);
        assert!(r.is_suspicious(&SpoofPolicy::default()));
        let display = r.display(&SpoofPolicy::default());
        assert_eq!(display, r.ascii);
        assert_eq!(to_ascii(&display, &options).unwrap(), r.ascii);
    }

    #[test]
    fn analyze_propagates_errors() {
        assert_eq!(
            DomainReport::analyze("a b.com", &Options::default()),
            Err(Error::Uts46)
        );
    }

    #[test]
    fn lookalike_index() {
        let mut index = LookalikeIndex::new(Options::default());
        assert!(index.is_empty());
        index.insert("apple.com").unwrap();
        index.insert("APPLE.com.").unwrap();
        index.insert("rnicrosoft.com").unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index.find("аррӏе.com").unwrap(), ["apple.com"]);
        assert_eq!(index.find("xn--80ak6aa92e.com").unwrap(), ["apple.com"]);
        assert_eq!(index.find("apple.com.").unwrap(), Vec::<&str>::new());
        assert_eq!(index.find("microsoft.com").unwrap(), ["rnicrosoft.com"]);
        assert_eq!(index.find("unrelated.org").unwrap(), Vec::<&str>::new());
        assert_eq!(index.find("a b"), Err(Error::Uts46));
        assert_eq!(index.insert("a b"), Err(Error::Uts46));
    }
}

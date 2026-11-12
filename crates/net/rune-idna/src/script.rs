//! Script sets, mixed-script detection and restriction levels
//! ([UTS #39](https://www.unicode.org/reports/tr39/) sections 5.1 and 5.2).

use std::collections::BTreeSet;

use icu_properties::PropertyNamesShort;
use icu_properties::props::Script;
use icu_properties::script::ScriptWithExtensions;

use crate::data;

/// A set of scripts, named by their ISO 15924 codes (`Latn`, `Cyrl`, …).
///
/// This is the *resolved script set* of UTS #39: characters of the Common
/// and Inherited scripts belong to every script, so the set of a string
/// made only of such characters (digits, `-`) is [`ScriptSet::is_all`].
/// Han characters also count as `Hanb`, `Jpan` and `Kore`, Hiragana and
/// Katakana as `Jpan`, Hangul as `Kore` and Bopomofo as `Hanb`, so that
/// Japanese, Korean and Chinese text resolve to one script each.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScriptSet {
    all: bool,
    scripts: BTreeSet<&'static str>,
}

impl ScriptSet {
    /// The set of every script.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            all: true,
            scripts: BTreeSet::new(),
        }
    }

    /// The empty set: the scripts of a mixed-script string.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            all: false,
            scripts: BTreeSet::new(),
        }
    }

    /// Whether this is the set of every script.
    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.all
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.all && self.scripts.is_empty()
    }

    /// Whether the set contains the script with ISO 15924 code `code`.
    #[must_use]
    pub fn contains(&self, code: &str) -> bool {
        self.all || self.scripts.contains(code)
    }

    /// The scripts in the set, by ISO 15924 code in ascending order.
    /// Empty when the set [`is_all`](Self::is_all).
    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.scripts.iter().copied()
    }

    /// Whether the two sets have a script in common.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        match (self.all, other.all) {
            (true, _) => !other.is_empty(),
            (_, true) => !self.is_empty(),
            _ => self.scripts.intersection(&other.scripts).next().is_some(),
        }
    }

    fn intersect_with(&mut self, other: &Self) {
        if other.all {
            return;
        }
        if self.all {
            self.clone_from(other);
            return;
        }
        self.scripts.retain(|s| other.scripts.contains(s));
    }
}

impl core::fmt::Display for ScriptSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.all {
            return f.write_str("ALL");
        }
        let mut first = true;
        for s in &self.scripts {
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(s)?;
            first = false;
        }
        if first {
            f.write_str("∅")?;
        }
        Ok(())
    }
}

/// The augmented script set of one character (UTS #39 section 5.1).
fn augmented(c: char) -> ScriptSet {
    let swe = ScriptWithExtensions::new();
    let names = PropertyNamesShort::<Script>::new();
    let mut set = ScriptSet::empty();
    for script in swe.get_script_extensions_val(c).iter() {
        if script == Script::Common || script == Script::Inherited {
            return ScriptSet::all();
        }
        let extra: &[&'static str] = match script {
            Script::Han => &["Hanb", "Jpan", "Kore"],
            Script::Hiragana | Script::Katakana => &["Jpan"],
            Script::Hangul => &["Kore"],
            Script::Bopomofo => &["Hanb"],
            _ => &[],
        };
        set.scripts.extend(extra);
        if let Some(name) = names.get(script) {
            set.scripts.insert(name);
        }
    }
    set
}

/// The resolved script set of `s` (UTS #39 section 5.1): the intersection
/// of the augmented script sets of its characters.
///
/// ```
/// use rune_idna::resolved_script_set;
///
/// assert_eq!(resolved_script_set("paypal").iter().collect::<Vec<_>>(), ["Latn"]);
/// // The first `а` is Cyrillic: no script covers the whole string.
/// assert!(resolved_script_set("pаypal").is_empty());
/// assert!(resolved_script_set("123-456").is_all());
/// // Kanji and kana resolve to Japanese.
/// assert!(resolved_script_set("日本語のテキスト").contains("Jpan"));
/// ```
#[must_use]
pub fn resolved_script_set(s: &str) -> ScriptSet {
    let mut set = ScriptSet::all();
    for c in s.chars() {
        set.intersect_with(&augmented(c));
        if set.is_empty() {
            break;
        }
    }
    set
}

/// Whether `s` is mixed-script: its [resolved script set] is empty
/// (UTS #39 section 5.1).
///
/// [resolved script set]: resolved_script_set
///
/// ```
/// use rune_idna::is_mixed_script;
///
/// assert!(!is_mixed_script("apple"));
/// assert!(!is_mixed_script("яблоко"));
/// assert!(is_mixed_script("аpple")); // Cyrillic а + Latin
/// ```
#[must_use]
pub fn is_mixed_script(s: &str) -> bool {
    resolved_script_set(s).is_empty()
}

/// Whether `c` has `Identifier_Status=Allowed` in the UTS #39 general
/// security profile.
#[must_use]
pub fn is_identifier_allowed(c: char) -> bool {
    crate::in_ranges(data::IDENTIFIER_ALLOWED, c)
}

/// UTS #39 restriction levels (section 5.2), from most to least
/// restrictive. Levels compare by restrictiveness: `AsciiOnly` is the
/// smallest, `Unrestricted` the largest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RestrictionLevel {
    /// Only ASCII characters.
    AsciiOnly,
    /// All characters are from a single script (Common and Inherited
    /// characters go with any script).
    SingleScript,
    /// Covered by Latin plus Han, Hiragana and Katakana; Latin plus Han and
    /// Bopomofo; or Latin plus Han and Hangul.
    HighlyRestrictive,
    /// Covered by Latin plus one other script, other than Cyrillic or Greek.
    ModeratelyRestrictive,
    /// Any mix of scripts, with every character in the identifier profile.
    MinimallyRestrictive,
    /// Some character is outside the UTS #39 identifier profile
    /// (`Identifier_Status=Restricted`): an obsolete or limited-use script,
    /// a symbol, an invisible character, and so on.
    Unrestricted,
}

impl RestrictionLevel {
    /// The UTS #39 name of the level, such as `"Highly Restrictive"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsciiOnly => "ASCII-Only",
            Self::SingleScript => "Single Script",
            Self::HighlyRestrictive => "Highly Restrictive",
            Self::ModeratelyRestrictive => "Moderately Restrictive",
            Self::MinimallyRestrictive => "Minimally Restrictive",
            Self::Unrestricted => "Unrestricted",
        }
    }
}

impl core::fmt::Display for RestrictionLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The UTS #39 restriction level of `s` (section 5.2).
///
/// Apply it to one label at a time: the `.` between labels is Common and
/// does not change the result, but mixing scripts across labels
/// (`яндекс.com`) is ordinary.
///
/// ```
/// use rune_idna::{RestrictionLevel, restriction_level};
///
/// assert_eq!(restriction_level("paypal"), RestrictionLevel::AsciiOnly);
/// assert_eq!(restriction_level("bücher"), RestrictionLevel::SingleScript);
/// assert_eq!(restriction_level("abc日本"), RestrictionLevel::HighlyRestrictive);
/// assert_eq!(restriction_level("pаypal"), RestrictionLevel::MinimallyRestrictive);
/// ```
#[must_use]
pub fn restriction_level(s: &str) -> RestrictionLevel {
    if s.is_ascii() {
        return RestrictionLevel::AsciiOnly;
    }
    if !s.chars().all(is_identifier_allowed) {
        return RestrictionLevel::Unrestricted;
    }
    if !resolved_script_set(s).is_empty() {
        return RestrictionLevel::SingleScript;
    }
    // The resolved set of everything that is not (also) Latin.
    let mut rest = ScriptSet::all();
    for c in s.chars() {
        let set = augmented(c);
        if !set.contains("Latn") {
            rest.intersect_with(&set);
        }
    }
    if rest.is_empty() {
        return RestrictionLevel::MinimallyRestrictive;
    }
    if ["Hanb", "Jpan", "Kore"].iter().any(|s| rest.contains(s)) {
        return RestrictionLevel::HighlyRestrictive;
    }
    if rest.iter().any(|s| s != "Cyrl" && s != "Grek") {
        return RestrictionLevel::ModeratelyRestrictive;
    }
    RestrictionLevel::MinimallyRestrictive
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(set: &ScriptSet) -> Vec<&'static str> {
        set.iter().collect()
    }

    #[test]
    fn resolved_sets() {
        assert_eq!(codes(&resolved_script_set("abc")), ["Latn"]);
        assert_eq!(codes(&resolved_script_set("яблоко")), ["Cyrl"]);
        assert_eq!(codes(&resolved_script_set("한국어")), ["Hang", "Kore"]);
        assert_eq!(
            codes(&resolved_script_set("中文")),
            ["Hanb", "Hani", "Jpan", "Kore"]
        );
        assert_eq!(codes(&resolved_script_set("ひらがなカタカナ")), ["Jpan"]);
        assert!(resolved_script_set("").is_all());
        assert!(resolved_script_set("0-9").is_all());
        assert!(resolved_script_set("aя").is_empty());
        // U+0660 ARABIC-INDIC DIGIT ZERO has Script_Extensions {Arab, Thaa, Yezi}.
        assert!(resolved_script_set("\u{0660}").contains("Arab"));
        assert!(!resolved_script_set("\u{0660}").is_all());
    }

    #[test]
    fn script_set_operations() {
        let latn = resolved_script_set("a");
        let cyrl = resolved_script_set("я");
        let all = ScriptSet::all();
        let empty = ScriptSet::empty();
        assert!(latn.intersects(&all) && all.intersects(&latn) && all.intersects(&all));
        assert!(!latn.intersects(&cyrl));
        assert!(!empty.intersects(&all) && !all.intersects(&empty));
        assert!(all.contains("Zzzz"));
        assert_eq!(all.to_string(), "ALL");
        assert_eq!(empty.to_string(), "∅");
        assert_eq!(resolved_script_set("中").to_string(), "Hanb Hani Jpan Kore");
    }

    #[test]
    fn mixed_script() {
        assert!(!is_mixed_script("example"));
        assert!(!is_mixed_script("ex-123"));
        assert!(is_mixed_script("exаmple"));
        assert!(!is_mixed_script("日本のカタカナ"));
    }

    #[test]
    fn restriction_levels() {
        use RestrictionLevel as L;
        let cases = [
            ("abc-123", L::AsciiOnly),
            ("", L::AsciiOnly),
            ("bücher", L::SingleScript),
            ("яндекс", L::SingleScript),
            ("ελληνικά", L::SingleScript),
            ("中文", L::SingleScript),
            ("abc中文", L::HighlyRestrictive),
            ("abcカタカナ", L::HighlyRestrictive),
            ("abc한국", L::HighlyRestrictive),
            ("abcไทย", L::ModeratelyRestrictive),
            ("abcяндекс", L::MinimallyRestrictive),
            ("abcαβγ", L::MinimallyRestrictive),
            ("яα", L::MinimallyRestrictive),
            ("a\u{2615}", L::Unrestricted),
            ("a\u{0300}", L::SingleScript),
        ];
        for (s, level) in cases {
            assert_eq!(restriction_level(s), level, "{s}");
        }
        assert!(L::AsciiOnly < L::SingleScript && L::MinimallyRestrictive < L::Unrestricted);
        assert_eq!(L::HighlyRestrictive.to_string(), "Highly Restrictive");
    }

    #[test]
    fn identifier_profile() {
        assert!(is_identifier_allowed('a'));
        assert!(is_identifier_allowed('-'));
        assert!(is_identifier_allowed('ü'));
        assert!(!is_identifier_allowed('\u{2615}'));
        assert!(!is_identifier_allowed(' '));
    }
}

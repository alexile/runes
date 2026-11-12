//! Confusable detection with the UTS #39 skeleton
//! ([UTS #39](https://www.unicode.org/reports/tr39/#Confusable_Detection)
//! section 4).

use icu_normalizer::DecomposingNormalizerBorrowed;
use icu_properties::CodePointSetData;
use icu_properties::props::DefaultIgnorableCodePoint;

use crate::data;
use crate::script::resolved_script_set;

/// The confusable prototype of `c`, if `confusables.txt` maps it.
fn prototype(c: char) -> Option<&'static str> {
    data::CONFUSABLES
        .binary_search_by_key(&c, |&(src, _)| src)
        .ok()
        .and_then(|i| data::CONFUSABLES.get(i))
        .map(|&(_, target)| target)
}

/// The UTS #39 skeleton of `s`.
///
/// Two strings are confusable exactly when their skeletons are equal. The
/// skeleton is `NFD(map(remove_default_ignorables(NFD(s))))`, where `map`
/// replaces each character with its prototype from `confusables.txt`. It is
/// meant for comparison only, not for display: `m` becomes `rn` and
/// Cyrillic `а` becomes Latin `a`.
///
/// The skeleton is case sensitive. Compare domain names after UTS #46
/// mapping ([`to_unicode`](crate::to_unicode)), which lowercases them;
/// [`DomainReport`](crate::DomainReport) does that for you.
///
/// ```
/// use rune_idna::skeleton;
///
/// assert_eq!(skeleton("pаypаl"), "paypal"); // Cyrillic а
/// assert_eq!(skeleton("modern"), skeleton("rnodern"));
/// assert_eq!(skeleton("g00gle"), skeleton("gOOgle"));
/// ```
#[must_use]
pub fn skeleton(s: &str) -> String {
    let nfd = DecomposingNormalizerBorrowed::new_nfd();
    let ignorable = CodePointSetData::new::<DefaultIgnorableCodePoint>();
    let mut mapped = String::with_capacity(s.len());
    for c in nfd.normalize(s).chars() {
        if ignorable.contains(c) {
            continue;
        }
        match prototype(c) {
            Some(p) => mapped.push_str(p),
            None => mapped.push(c),
        }
    }
    nfd.normalize(&mapped).into_owned()
}

/// Whether `a` and `b` are confusable: they have the same [`skeleton`].
///
/// Identical strings are confusable with each other.
///
/// ```
/// use rune_idna::is_confusable_with;
///
/// assert!(is_confusable_with("paypal", "pаypal"));
/// assert!(is_confusable_with("rn", "m"));
/// assert!(!is_confusable_with("paypal", "paypa1x"));
/// ```
#[must_use]
pub fn is_confusable_with(a: &str, b: &str) -> bool {
    a == b || skeleton(a) == skeleton(b)
}

/// How two confusable strings relate by script (UTS #39 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfusableKind {
    /// Their resolved script sets have a script in common, as in `rn` and
    /// `m`.
    SingleScript,
    /// Their resolved script sets have no script in common, and at least
    /// one of them is mixed-script, as in `paypal` and `pаypal`.
    MixedScript,
    /// Mixed-script confusables that are each single-script, as in Latin
    /// `scope` and Cyrillic `ѕсоре`: the most deceptive kind, because no
    /// mixed-script check catches either one.
    WholeScript,
}

/// Classifies `a` and `b` if they are confusable, or returns `None` if
/// they are not.
///
/// ```
/// use rune_idna::{ConfusableKind, confusable_kind};
///
/// assert_eq!(confusable_kind("scope", "ѕсоре"), Some(ConfusableKind::WholeScript));
/// assert_eq!(confusable_kind("paypal", "pаypal"), Some(ConfusableKind::MixedScript));
/// assert_eq!(confusable_kind("rn", "m"), Some(ConfusableKind::SingleScript));
/// assert_eq!(confusable_kind("abc", "xyz"), None);
/// ```
#[must_use]
pub fn confusable_kind(a: &str, b: &str) -> Option<ConfusableKind> {
    if !is_confusable_with(a, b) {
        return None;
    }
    let (sa, sb) = (resolved_script_set(a), resolved_script_set(b));
    Some(if sa.intersects(&sb) {
        ConfusableKind::SingleScript
    } else if !sa.is_empty() && !sb.is_empty() {
        ConfusableKind::WholeScript
    } else {
        ConfusableKind::MixedScript
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_known_answers() {
        assert_eq!(skeleton(""), "");
        assert_eq!(skeleton("abc"), "abc");
        assert_eq!(skeleton("m"), "rn");
        assert_eq!(skeleton("0"), "O");
        assert_eq!(skeleton("1"), "l");
        assert_eq!(skeleton("I"), "l");
        assert_eq!(skeleton("ѕсоре"), "scope");
        assert_eq!(skeleton("аррӏе"), "apple");
        // Fullwidth forms.
        assert_eq!(skeleton("ａｂｃ"), "abc");
    }

    #[test]
    fn skeleton_drops_default_ignorables() {
        // ZERO WIDTH SPACE, ZWJ, SOFT HYPHEN.
        assert_eq!(skeleton("pay\u{200b}pal"), "paypal");
        assert_eq!(skeleton("pay\u{200d}pal"), "paypal");
        assert_eq!(skeleton("pay\u{ad}pal"), "paypal");
    }

    #[test]
    fn skeleton_is_nfd() {
        // Precomposed and decomposed é agree.
        assert_eq!(skeleton("caf\u{e9}"), skeleton("cafe\u{301}"));
        assert!(is_confusable_with("caf\u{e9}", "cafe\u{301}"));
    }

    #[test]
    fn skeleton_is_idempotent_on_samples() {
        for s in [
            "paypal",
            "аррӏе",
            "ѕсоре",
            "日本",
            "ǉ",
            "ﬃ",
            "Å",
            "\u{212b}",
        ] {
            let k = skeleton(s);
            assert_eq!(skeleton(&k), k, "{s}");
        }
    }

    #[test]
    fn confusable_kinds() {
        assert_eq!(
            confusable_kind("a", "a"),
            Some(ConfusableKind::SingleScript)
        );
        assert_eq!(
            confusable_kind("apple", "аррӏе"),
            Some(ConfusableKind::WholeScript)
        );
        assert_eq!(
            confusable_kind("apple", "аpple"),
            Some(ConfusableKind::MixedScript)
        );
        assert_eq!(
            confusable_kind("1", "l"),
            Some(ConfusableKind::SingleScript)
        );
        assert_eq!(confusable_kind("a", "b"), None);
    }

    #[test]
    fn data_is_sorted() {
        assert!(data::CONFUSABLES.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(data::IDENTIFIER_ALLOWED.windows(2).all(|w| w[0].1 < w[1].0));
        assert!(data::IDNA2008_EXCLUDED.windows(2).all(|w| w[0].1 < w[1].0));
        assert_eq!(data::UNICODE_VERSION, "18.0.0");
    }
}

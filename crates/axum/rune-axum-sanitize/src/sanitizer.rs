//! The per-string cleaning pipeline: character filtering, Unicode
//! normalisation, then the markup mode.

use std::{borrow::Cow, fmt};

#[cfg(feature = "allowlist")]
use std::sync::Arc;

use icu_normalizer::ComposingNormalizerBorrowed;

use crate::{json, strip::strip_html_cow, urlencoded};

/// What to do with markup in a string value.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::{Mode, Sanitizer};
///
/// let strip = Sanitizer::new().mode(Mode::StripTags);
/// assert_eq!(strip.clean("<b>hi</b>"), "hi");
///
/// let escape = Sanitizer::new().mode(Mode::Escape);
/// assert_eq!(escape.clean("<b>hi</b>"), "&lt;b&gt;hi&lt;/b&gt;");
/// ```
#[derive(Clone, Default)]
#[non_exhaustive]
pub enum Mode {
    /// Remove tags, comments and script/style content and keep the text. See
    /// [`strip_html`](crate::strip_html).
    #[default]
    StripTags,
    /// HTML-encode `& < > " '`, keeping everything the user typed. Not
    /// idempotent: running it twice double-encodes.
    Escape,
    /// Parse the value as HTML and keep only allowlisted tags and attributes,
    /// using an [`ammonia::Builder`]. The output is HTML, with text
    /// entity-encoded. Meant for rich-text fields, usually via
    /// [`SanitizeConfig::field_mode`](crate::SanitizeConfig::field_mode).
    #[cfg(feature = "allowlist")]
    Allowlist(Arc<ammonia::Builder<'static>>),
}

impl Mode {
    /// [`Mode::Allowlist`] with ammonia's default allowlist: common
    /// formatting tags, safe link schemes, no scripts, styles or event
    /// handlers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Mode, Sanitizer};
    ///
    /// let rich = Sanitizer::new().mode(Mode::allowlist());
    /// assert_eq!(
    ///     rich.clean("<b onclick=x()>hi</b><script>x()</script>"),
    ///     "<b>hi</b>"
    /// );
    /// ```
    #[cfg(feature = "allowlist")]
    #[must_use]
    pub fn allowlist() -> Self {
        Self::Allowlist(Arc::new(ammonia::Builder::default()))
    }

    fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match self {
            Self::StripTags => strip_html_cow(input),
            Self::Escape => {
                if input.contains(['&', '<', '>', '"', '\'']) {
                    Cow::Owned(rune_html_encode::encode(input))
                } else {
                    Cow::Borrowed(input)
                }
            }
            #[cfg(feature = "allowlist")]
            Self::Allowlist(builder) => {
                let cleaned = builder.clean(input).to_string();
                if cleaned == input {
                    Cow::Borrowed(input)
                } else {
                    Cow::Owned(cleaned)
                }
            }
        }
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StripTags => formatter.write_str("StripTags"),
            Self::Escape => formatter.write_str("Escape"),
            #[cfg(feature = "allowlist")]
            Self::Allowlist(_) => formatter.write_str("Allowlist(..)"),
        }
    }
}

/// Unicode normalisation form applied before markup handling.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::{Normalization, Sanitizer};
///
/// // NFKC folds fullwidth brackets to ASCII, so they are then stripped.
/// let sanitizer = Sanitizer::new().normalization(Some(Normalization::Nfkc));
/// assert_eq!(sanitizer.clean("＜b＞hi＜/b＞"), "hi");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Normalization {
    /// Canonical composition. Changes no meaning; makes equal-looking strings
    /// byte-equal for comparison and storage.
    Nfc,
    /// Compatibility composition. Also folds lookalikes such as fullwidth
    /// `＜` to `<` and ligatures to letters. Lossy for some scripts and
    /// typography; use it when values are identifiers or will be compared.
    Nfkc,
}

/// Cleans individual strings, query strings and JSON documents.
///
/// The pipeline, in order:
///
/// 1. drop control characters (on by default) and, optionally, bidi controls
///    and invisible formatting characters;
/// 2. optionally normalise to NFC or NFKC;
/// 3. apply the [`Mode`] (strip tags by default).
///
/// Normalisation runs before the mode so lookalikes that NFKC folds into `<`
/// are handled. All steps work on `&str`, so valid UTF-8 always comes out.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::Sanitizer;
///
/// let sanitizer = Sanitizer::new().strip_invisible(true);
/// assert_eq!(sanitizer.clean("pay\u{200B}pal\0<b>!</b>"), "paypal!");
/// ```
#[derive(Clone, Debug)]
pub struct Sanitizer {
    mode: Mode,
    normalization: Option<Normalization>,
    strip_control_chars: bool,
    strip_invisible: bool,
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self {
            mode: Mode::StripTags,
            normalization: None,
            strip_control_chars: true,
            strip_invisible: false,
        }
    }
}

impl Sanitizer {
    /// Strip tags and control characters; no normalisation, invisible
    /// characters kept.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// assert_eq!(Sanitizer::new().clean("a\0<i>b</i>"), "ab");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the markup [`Mode`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Mode, Sanitizer};
    ///
    /// let sanitizer = Sanitizer::new().mode(Mode::Escape);
    /// assert_eq!(sanitizer.clean("<"), "&lt;");
    /// ```
    #[must_use]
    #[cfg_attr(
        not(feature = "allowlist"),
        expect(
            clippy::missing_const_for_fn,
            reason = "not const once `Mode` can hold an allowlist"
        )
    )]
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the Unicode normalisation form, or `None` to leave text as is.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Normalization, Sanitizer};
    ///
    /// let sanitizer = Sanitizer::new().normalization(Some(Normalization::Nfc));
    /// assert_eq!(sanitizer.clean("e\u{301}"), "\u{e9}");
    /// ```
    #[must_use]
    pub const fn normalization(mut self, normalization: Option<Normalization>) -> Self {
        self.normalization = normalization;
        self
    }

    /// Whether to remove C0 controls other than tab, LF and CR, plus DEL and
    /// the C1 controls (U+0080 to U+009F). This covers null bytes. On by
    /// default.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// assert_eq!(Sanitizer::new().clean("a\0b\x07c\td"), "abc\td");
    /// let keep = Sanitizer::new().strip_control_chars(false);
    /// assert_eq!(keep.clean("a\0b"), "a\0b");
    /// ```
    #[must_use]
    pub const fn strip_control_chars(mut self, strip: bool) -> Self {
        self.strip_control_chars = strip;
        self
    }

    /// Whether to remove bidi controls (U+202A to U+202E, U+2066 to U+2069,
    /// LRM, RLM, ALM) and invisible formatting characters (zero-width space,
    /// word joiner and friends, BOM, soft hyphen, Hangul fillers). Off by
    /// default.
    ///
    /// ZWJ and ZWNJ are kept because emoji sequences and several scripts
    /// need them; variation selectors and tag characters are kept for the
    /// same reason.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// let sanitizer = Sanitizer::new().strip_invisible(true);
    /// assert_eq!(sanitizer.clean("abc\u{202E}fed"), "abcfed");
    /// assert_eq!(sanitizer.clean("👩\u{200D}💻"), "👩\u{200D}💻");
    /// ```
    #[must_use]
    pub const fn strip_invisible(mut self, strip: bool) -> Self {
        self.strip_invisible = strip;
        self
    }

    /// Cleans one string. Borrows when nothing changes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::borrow::Cow;
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// let sanitizer = Sanitizer::new();
    /// assert!(matches!(sanitizer.clean("plain"), Cow::Borrowed(_)));
    /// assert_eq!(sanitizer.clean("<script>x</script>plain"), "plain");
    /// ```
    #[must_use]
    pub fn clean<'a>(&self, input: &'a str) -> Cow<'a, str> {
        self.clean_with(input, &self.mode)
    }

    /// Cleans a URL query string or `application/x-www-form-urlencoded`
    /// body.
    ///
    /// Each name and value is percent-decoded exactly as axum's `Query` and
    /// `Form` extractors decode it, cleaned, and re-encoded only if it
    /// changed. Pairs that need no change keep their original encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// let sanitizer = Sanitizer::new();
    /// assert_eq!(
    ///     sanitizer.clean_urlencoded("q=%3Cscript%3Ealert(1)%3C%2Fscript%3Ehi&page=2"),
    ///     "q=hi&page=2"
    /// );
    /// assert_eq!(sanitizer.clean_urlencoded("a=1&b=x%20y"), "a=1&b=x%20y");
    /// ```
    #[must_use]
    pub fn clean_urlencoded<'a>(&self, input: &'a str) -> Cow<'a, str> {
        urlencoded::clean(input, |_, _, value| self.clean(value))
    }

    /// Cleans every string (object keys included) in a JSON document.
    ///
    /// Only string literals that change are rewritten; numbers, whitespace
    /// and key order are left byte for byte. The document must be valid
    /// JSON and nest at most `max_depth` arrays and objects.
    ///
    /// # Errors
    ///
    /// [`JsonError::Syntax`](crate::JsonError::Syntax) for invalid JSON
    /// (including lone surrogate escapes),
    /// [`JsonError::TooDeep`](crate::JsonError::TooDeep) past `max_depth`, and
    /// [`JsonError::DuplicateKey`](crate::JsonError::DuplicateKey) when a
    /// cleaned object key ends up equal to another key of the same object.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::Sanitizer;
    ///
    /// let sanitizer = Sanitizer::new();
    /// let cleaned = sanitizer
    ///     .clean_json(r#"{"name": "<b>Ann</b>", "tags": ["<i>x</i>"], "n": 1.50}"#, 32)
    ///     .unwrap();
    /// assert_eq!(cleaned, r#"{"name": "Ann", "tags": ["x"], "n": 1.50}"#);
    /// ```
    pub fn clean_json<'a>(
        &self,
        input: &'a str,
        max_depth: usize,
    ) -> Result<Cow<'a, str>, crate::JsonError> {
        json::clean(input, max_depth, |_, _, value| self.clean(value))
    }

    /// Runs the pipeline with `mode` in place of the configured one.
    #[must_use]
    pub(crate) fn clean_with<'a>(&self, input: &'a str, mode: &Mode) -> Cow<'a, str> {
        let filtered = self.filter_chars(input);
        let normalised = match self.normalization {
            None => filtered,
            Some(form) => {
                let normalizer = match form {
                    Normalization::Nfc => ComposingNormalizerBorrowed::new_nfc(),
                    Normalization::Nfkc => ComposingNormalizerBorrowed::new_nfkc(),
                };
                match normalizer.normalize(&filtered) {
                    Cow::Borrowed(_) => filtered,
                    Cow::Owned(owned) => Cow::Owned(owned),
                }
            }
        };
        match mode.apply(&normalised) {
            Cow::Borrowed(_) => normalised,
            Cow::Owned(owned) => Cow::Owned(owned),
        }
    }

    fn filter_chars<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let removed = |character: char| {
            (self.strip_control_chars && is_stripped_control(character))
                || (self.strip_invisible && is_invisible(character))
        };
        if input.chars().any(removed) {
            Cow::Owned(
                input
                    .chars()
                    .filter(|&character| !removed(character))
                    .collect(),
            )
        } else {
            Cow::Borrowed(input)
        }
    }
}

const fn is_stripped_control(character: char) -> bool {
    matches!(character, '\0'..='\x08' | '\x0B' | '\x0C' | '\x0E'..='\x1F' | '\x7F'..='\u{9F}')
}

const fn is_invisible(character: char) -> bool {
    matches!(
        character,
        '\u{AD}'
            | '\u{61C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180E}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_chars() {
        let sanitizer = Sanitizer::new().mode(Mode::Escape);
        assert_eq!(sanitizer.clean("a\0\x1b[31m\u{85}b\r\n"), "a[31mb\r\n");
    }

    #[test]
    fn nfkc_before_strip() {
        let sanitizer = Sanitizer::new().normalization(Some(Normalization::Nfkc));
        assert_eq!(sanitizer.clean("﹤script﹥x﹤/script﹥ok"), "ok");
        // Without NFKC the lookalikes are just text, which browsers don't parse as markup.
        assert_eq!(Sanitizer::new().clean("＜b＞"), "＜b＞");
    }

    #[test]
    fn invisible_keeps_joiners() {
        let sanitizer = Sanitizer::new().strip_invisible(true);
        assert_eq!(
            sanitizer.clean("\u{FEFF}a\u{200C}b\u{2066}c"),
            "a\u{200C}bc"
        );
    }

    #[test]
    fn escape_borrows_clean_input() {
        let sanitizer = Sanitizer::new().mode(Mode::Escape);
        assert!(matches!(sanitizer.clean("plain text"), Cow::Borrowed(_)));
    }
}

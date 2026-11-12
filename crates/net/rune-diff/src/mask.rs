//! Masking volatile content (dates, ids, tokens, nonces, CSRF values)
//! before comparing.

use std::borrow::Cow;

use regex::{Captures, Regex};

use crate::Error;

const MONTH: &str = "(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?";

/// Which kinds of volatile content a [`Masker`] replaces with placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent on/off switches per kind"
)]
pub struct MaskOptions {
    /// Dates, times and 10/13-digit Unix epochs → `[time]`. Default on.
    pub timestamps: bool,
    /// UUIDs → `[uuid]`. Default on.
    pub uuids: bool,
    /// Hex runs of 16+ digits and mixed letter/digit tokens of
    /// [`min_token_len`](Self::min_token_len)+ characters → `[token]`. Default on.
    pub tokens: bool,
    /// Minimum length of a letters-and-digits token. Default 20.
    pub min_token_len: usize,
    /// `value`/`content` of hidden inputs and CSRF-like inputs and meta
    /// tags → `[hidden]`. Default on.
    pub hidden_inputs: bool,
    /// `nonce` attribute values → `[nonce]`. Default on.
    pub nonces: bool,
    /// Literal strings (such as injected payloads) → `[literal]`, matched
    /// longest first. Default empty.
    pub literals: Vec<String>,
    /// Extra regexes; each match → `[masked]`. Default empty.
    pub patterns: Vec<String>,
}

impl Default for MaskOptions {
    fn default() -> Self {
        Self {
            timestamps: true,
            uuids: true,
            tokens: true,
            min_token_len: 20,
            hidden_inputs: true,
            nonces: true,
            literals: Vec::new(),
            patterns: Vec::new(),
        }
    }
}

impl MaskOptions {
    /// Masks nothing; enable kinds with the builder methods.
    #[must_use]
    pub fn none() -> Self {
        Self {
            timestamps: false,
            uuids: false,
            tokens: false,
            hidden_inputs: false,
            nonces: false,
            ..Self::default()
        }
    }

    /// Sets [`timestamps`](Self::timestamps).
    #[must_use]
    pub const fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    /// Sets [`uuids`](Self::uuids).
    #[must_use]
    pub const fn with_uuids(mut self, on: bool) -> Self {
        self.uuids = on;
        self
    }

    /// Sets [`tokens`](Self::tokens).
    #[must_use]
    pub const fn with_tokens(mut self, on: bool) -> Self {
        self.tokens = on;
        self
    }

    /// Sets [`min_token_len`](Self::min_token_len).
    #[must_use]
    pub const fn with_min_token_len(mut self, len: usize) -> Self {
        self.min_token_len = len;
        self
    }

    /// Sets [`hidden_inputs`](Self::hidden_inputs).
    #[must_use]
    pub const fn with_hidden_inputs(mut self, on: bool) -> Self {
        self.hidden_inputs = on;
        self
    }

    /// Sets [`nonces`](Self::nonces).
    #[must_use]
    pub const fn with_nonces(mut self, on: bool) -> Self {
        self.nonces = on;
        self
    }

    /// Adds a literal to mask.
    #[must_use]
    pub fn with_literal(mut self, literal: impl Into<String>) -> Self {
        self.literals.push(literal.into());
        self
    }

    /// Adds a regex to mask.
    #[must_use]
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.patterns.push(pattern.into());
        self
    }
}

/// Compiled masking rules. Build once, reuse for every comparison.
///
/// ```
/// use rune_diff::{MaskOptions, Masker};
///
/// let masker = Masker::new(&MaskOptions::default())?;
/// let a = masker.mask(r#"<input type="hidden" name="csrf" value="a8f3k2"> at 2026-11-12T10:00:00Z"#);
/// let b = masker.mask(r#"<input type="hidden" name="csrf" value="zz91qq"> at 2026-11-12T10:00:07Z"#);
/// assert_eq!(a, b);
/// assert_eq!(a, r#"<input type="hidden" name="csrf" value="[hidden]"> at [time]"#);
/// # Ok::<(), rune_diff::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Masker {
    literals: Vec<String>,
    patterns: Vec<Regex>,
    hidden: Option<HiddenRules>,
    nonce: Option<Regex>,
    timestamps: Vec<Regex>,
    uuid: Option<Regex>,
    tokens: Option<TokenRules>,
}

#[derive(Debug, Clone)]
struct HiddenRules {
    input: Regex,
    meta: Regex,
    hidden_type: Regex,
    secret_name: Regex,
    value: Regex,
    content: Regex,
}

#[derive(Debug, Clone)]
struct TokenRules {
    hex: Regex,
    word: Regex,
    min_len: usize,
}

fn compile(pattern: &str) -> Result<Regex, Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 22)
        .build()
        .map_err(|e| Error::Pattern {
            pattern: pattern.to_owned(),
            reason: e.to_string(),
        })
}

impl Masker {
    /// Compiles `options`. Fails only on an invalid custom pattern.
    pub fn new(options: &MaskOptions) -> Result<Self, Error> {
        let mut literals: Vec<String> = options
            .literals
            .iter()
            .filter(|l| !l.is_empty())
            .cloned()
            .collect();
        literals.sort_by_key(|l| std::cmp::Reverse(l.len()));
        literals.dedup();
        let patterns = options
            .patterns
            .iter()
            .map(|p| compile(p))
            .collect::<Result<_, _>>()?;
        let attr = |name: &str| {
            compile(&format!(
                r#"(?i)(\b{name}\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>"']+)"#
            ))
        };
        let hidden = if options.hidden_inputs {
            Some(HiddenRules {
                input: compile(r"(?is)<input\b[^>]*>")?,
                meta: compile(r"(?is)<meta\b[^>]*>")?,
                hidden_type: compile(r#"(?i)\btype\s*=\s*["']?hidden\b"#)?,
                secret_name: compile(
                    r#"(?i)\bname\s*=\s*["']?[^"'\s>]*(?:csrf|xsrf|token|nonce|authenticity|viewstate|eventvalidation)"#,
                )?,
                value: attr("value")?,
                content: attr("content")?,
            })
        } else {
            None
        };
        let timestamps = if options.timestamps {
            [
                format!(
                    r"(?i)\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+\d{{1,2}}[\s-]{MONTH}[\s-]\d{{2,4}}\s+\d{{1,2}}:\d{{2}}(?::\d{{2}})?(?:\s*(?:gmt|utc|[+-]\d{{4}}))?"
                ),
                r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?".to_owned(),
                format!(r"(?i)\b\d{{1,2}}\s+{MONTH}\s+\d{{4}}\b"),
                format!(r"(?i)\b{MONTH}\s+\d{{1,2}},?\s+\d{{4}}\b"),
                r"\b\d{1,2}/\d{1,2}/\d{2,4}\b".to_owned(),
                r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b".to_owned(),
                r"\b1\d{9}(?:\d{3})?\b".to_owned(),
            ]
            .iter()
            .map(|p| compile(p))
            .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        Ok(Self {
            literals,
            patterns,
            hidden,
            nonce: if options.nonces {
                Some(attr("nonce")?)
            } else {
                None
            },
            timestamps,
            uuid: if options.uuids {
                Some(compile(
                    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                )?)
            } else {
                None
            },
            tokens: if options.tokens {
                Some(TokenRules {
                    hex: compile(r"\b[0-9a-fA-F]{16,}\b")?,
                    word: compile(r"[A-Za-z0-9_\-+/]+={0,2}")?,
                    min_len: options.min_token_len.max(1),
                })
            } else {
                None
            },
        })
    }

    /// A masker that changes nothing.
    #[must_use]
    pub const fn noop() -> Self {
        Self {
            literals: Vec::new(),
            patterns: Vec::new(),
            hidden: None,
            nonce: None,
            timestamps: Vec::new(),
            uuid: None,
            tokens: None,
        }
    }

    /// Whether this masker changes nothing.
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.literals.is_empty()
            && self.patterns.is_empty()
            && self.hidden.is_none()
            && self.nonce.is_none()
            && self.timestamps.is_empty()
            && self.uuid.is_none()
            && self.tokens.is_none()
    }

    /// Replaces volatile content in `text` with placeholders. Order:
    /// literals, custom patterns, hidden inputs, nonces, timestamps, UUIDs,
    /// tokens.
    #[must_use]
    pub fn mask<'t>(&self, text: &'t str) -> Cow<'t, str> {
        let mut text = Cow::Borrowed(text);
        for literal in &self.literals {
            if text.contains(literal.as_str()) {
                text = Cow::Owned(text.replace(literal.as_str(), "[literal]"));
            }
        }
        for p in &self.patterns {
            text = replace(text, p, |_| "[masked]".to_owned());
        }
        if let Some(h) = &self.hidden {
            text = replace(text, &h.input, |c| {
                let tag = &c[0];
                if h.hidden_type.is_match(tag) || h.secret_name.is_match(tag) {
                    h.value.replace_all(tag, "${1}\"[hidden]\"").into_owned()
                } else {
                    tag.to_owned()
                }
            });
            text = replace(text, &h.meta, |c| {
                let tag = &c[0];
                if h.secret_name.is_match(tag) {
                    h.content.replace_all(tag, "${1}\"[hidden]\"").into_owned()
                } else {
                    tag.to_owned()
                }
            });
        }
        if let Some(n) = &self.nonce {
            text = replace(text, n, |c| format!("{}\"[nonce]\"", &c[1]));
        }
        for t in &self.timestamps {
            text = replace(text, t, |_| "[time]".to_owned());
        }
        if let Some(u) = &self.uuid {
            text = replace(text, u, |_| "[uuid]".to_owned());
        }
        if let Some(t) = &self.tokens {
            text = replace(text, &t.hex, |_| "[token]".to_owned());
            text = replace(text, &t.word, |c| {
                let word = &c[0];
                if looks_like_token(word, t.min_len) {
                    "[token]".to_owned()
                } else {
                    word.to_owned()
                }
            });
        }
        text
    }
}

/// A token needs the minimum length, at least one digit and one letter.
/// Base64-looking words (with `+` or `/`) also need both cases and 24+
/// characters, so ordinary URL paths are left alone.
fn looks_like_token(word: &str, min_len: usize) -> bool {
    let has = |f: fn(&u8) -> bool| word.as_bytes().iter().any(f);
    let base = word.len() >= min_len && has(u8::is_ascii_digit) && has(u8::is_ascii_alphabetic);
    if word.contains(['+', '/']) {
        base && word.len() >= min_len.max(24)
            && has(u8::is_ascii_lowercase)
            && has(u8::is_ascii_uppercase)
    } else {
        base
    }
}

fn replace<'t>(
    text: Cow<'t, str>,
    re: &Regex,
    f: impl Fn(&Captures<'_>) -> String,
) -> Cow<'t, str> {
    match re.replace_all(&text, |c: &Captures<'_>| f(c)) {
        Cow::Borrowed(_) => text,
        Cow::Owned(s) => Cow::Owned(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(text: &str) -> String {
        Masker::new(&MaskOptions::default())
            .unwrap()
            .mask(text)
            .into_owned()
    }

    #[test]
    fn masks_kinds() {
        assert_eq!(m("Date: Tue, 15 Nov 1994 08:12:31 GMT"), "Date: [time]");
        assert_eq!(m("at 1731400000 and 1731400000123"), "at [time] and [time]");
        assert_eq!(m("id 123e4567-e89b-12d3-a456-426614174000."), "id [uuid].");
        assert_eq!(m("etag 0123456789abcdef0123"), "etag [token]");
        assert_eq!(m("sess=eyJhbGciOiJIUzI1NiJ9abc123XYZ"), "sess=[token]");
        assert_eq!(
            m(r#"<script nonce="r4nd0m">"#),
            r#"<script nonce="[nonce]">"#
        );
        assert_eq!(
            m(r#"<meta name="csrf-token" content="abc">"#),
            r#"<meta name="csrf-token" content="[hidden]">"#
        );
        assert_eq!(
            m(r#"<input name="q" value="keep">"#),
            r#"<input name="q" value="keep">"#
        );
        assert_eq!(
            m("/assets/images/logo2x/x.png"),
            "/assets/images/logo2x/x.png"
        );
        // Ordinary words and numbers survive.
        assert_eq!(
            m("page 2 of 10, total 4521 items"),
            "page 2 of 10, total 4521 items"
        );
    }

    #[test]
    fn literals_and_patterns() {
        let masker = Masker::new(
            &MaskOptions::none()
                .with_literal("<x>")
                .with_literal("<x>y")
                .with_pattern(r"req-\d+"),
        )
        .unwrap();
        assert_eq!(
            masker.mask("a <x>y b <x> req-42"),
            "a [literal] b [literal] [masked]"
        );
        assert!(Masker::new(&MaskOptions::none().with_pattern("(")).is_err());
        assert!(Masker::new(&MaskOptions::none()).unwrap().is_noop());
        assert!(matches!(
            Masker::new(&MaskOptions::none()).unwrap().mask("x"),
            Cow::Borrowed(_)
        ));
    }
}

//! The evasion techniques as [`rune_transform::Transform`]s.
//!
//! Techniques that already exist in the `rune-transform` built-ins (URL,
//! double URL, `\uXXXX`, `\xNN`, `0x…` hex) wrap the registry's transform;
//! the rewrites use its parameterised [`MatchReplaceTransform`] and
//! [`SuffixTransform`]. Only the mutations with no equivalent there (case
//! toggling, mixed HTML entities, `CHAR(…)`, concatenation) are written here.

use std::fmt::Write as _;
use std::str;
use std::sync::Arc;

use rune_transform::{
    Category, Error as TransformError, MatchReplaceTransform, SuffixTransform, Transform,
    TransformChain, TransformRegistry,
};

use crate::{Context, Error, Technique};

/// One [`Technique`] in one [`Context`], as a registrable transform.
///
/// Its id is [`Technique::transform_id`], and it is reversible exactly when
/// [`Technique::is_reversible`] says so.
///
/// ```
/// use rune_payload_encode::{Context, EvasionTransform, Technique};
/// use rune_transform::{Transform, TransformRegistry};
///
/// let registry = TransformRegistry::builtin();
/// let hex = EvasionTransform::new(Technique::HexEncode, Context::Sql, &registry)?;
/// assert_eq!(hex.id(), "evade_hex_encode_sql");
/// assert_eq!(hex.encode(b"ab")?, b"0x6162");
/// assert_eq!(hex.decode(b"0x6162")?, b"ab");
/// # Ok::<(), rune_payload_encode::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct EvasionTransform {
    /// The technique applied.
    technique: Technique,
    /// The context it was built for.
    context: Context,
    /// The transform doing the work.
    inner: Arc<dyn Transform>,
}

impl EvasionTransform {
    /// Build `technique` for `context`, taking the codecs it reuses from
    /// `registry`.
    ///
    /// # Errors
    /// Returns [`Error::Transform`] with an unknown-transform error when
    /// `registry` lacks a built-in this technique wraps (`url`,
    /// `double_url`, `js_unicode_escape`, `js_hex_escape` or `hex_0x`).
    pub fn new(
        technique: Technique,
        context: Context,
        registry: &TransformRegistry,
    ) -> Result<Self, Error> {
        let builtin = |id: &str| {
            registry
                .get(id)
                .ok_or_else(|| TransformError::UnknownTransform { id: id.to_owned() })
        };
        let replace = |from: &str, to: &str| -> Arc<dyn Transform> {
            Arc::new(MatchReplaceTransform::new(from, to))
        };
        let sql = matches!(context, Context::Sql);
        let inner: Arc<dyn Transform> = match technique {
            Technique::CaseToggle => Arc::new(CaseToggle),
            Technique::UrlEncode => builtin("url")?,
            Technique::DoubleUrlEncode => builtin("double_url")?,
            Technique::UnicodeEscape => builtin("js_unicode_escape")?,
            Technique::HtmlEntityEncode => Arc::new(HtmlEntityMixed),
            Technique::HexEncode if sql => builtin("hex_0x")?,
            Technique::HexEncode => builtin("js_hex_escape")?,
            Technique::SqlInlineComment => replace(" ", "/**/"),
            Technique::SqlWhitespaceAlt => replace(" ", "%09"),
            Technique::SqlCharEncode => Arc::new(SqlChar),
            Technique::NullByte => Arc::new(SuffixTransform::new("%00")),
            Technique::PathDotSlashObfuscation => replace("../", "....//"),
            Technique::OsCommandSeparatorAlt => Arc::new(TransformChain::new(vec![
                replace(";", "|"),
                replace(" ", "${IFS}"),
            ])),
            Technique::TabNewlineInsertion => replace(" ", "\t"),
            Technique::Concatenation => Arc::new(Concat { sql }),
        };
        Ok(Self {
            technique,
            context,
            inner,
        })
    }

    /// The technique applied.
    #[must_use]
    pub const fn technique(&self) -> Technique {
        self.technique
    }

    /// The context the transform was built for.
    #[must_use]
    pub const fn context(&self) -> Context {
        self.context
    }
}

impl Transform for EvasionTransform {
    fn id(&self) -> &str {
        self.technique.transform_id(self.context)
    }

    fn description(&self) -> &str {
        self.technique.description()
    }

    fn category(&self) -> Category {
        self.inner.category()
    }

    fn is_reversible(&self) -> bool {
        self.inner.is_reversible()
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        self.inner.encode(input)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        if !self.inner.is_reversible() {
            return Err(TransformError::not_reversible(self.id()));
        }
        self.inner.decode(input)
    }
}

/// Register every evasion transform in `registry`: one per technique, plus
/// the SQL forms of the context-sensitive ones (16 in all, ids
/// `evade_*`), after the built-ins they wrap.
///
/// Nothing is registered when an error is returned.
///
/// ```
/// use rune_payload_encode::register;
/// use rune_transform::TransformRegistry;
///
/// let mut registry = TransformRegistry::builtin();
/// register(&mut registry)?;
/// // Evasion transforms chain with everything else in the registry.
/// let chain = registry.parse_chain("evade_case_toggle | evade_sql_inline_comment | url")?;
/// assert_eq!(chain.encode(b"union select")?, b"UnIoN%2F%2A%2A%2FsElEcT");
/// # Ok::<(), rune_payload_encode::Error>(())
/// ```
///
/// # Errors
/// Returns [`Error::Transform`] when `registry` lacks a built-in the
/// techniques wrap, or already holds one of the `evade_*` ids.
pub fn register(registry: &mut TransformRegistry) -> Result<(), Error> {
    let mut transforms = Vec::with_capacity(16);
    for technique in Technique::ALL {
        transforms.push(EvasionTransform::new(
            technique,
            Context::Generic,
            registry,
        )?);
        if technique.is_context_sensitive() {
            transforms.push(EvasionTransform::new(technique, Context::Sql, registry)?);
        }
    }
    if let Some(taken) = transforms.iter().find(|t| registry.contains(t.id())) {
        return Err(TransformError::DuplicateId {
            id: taken.id().to_owned(),
        }
        .into());
    }
    for transform in transforms {
        registry.register(transform)?;
    }
    Ok(())
}

// --- transforms with no rune-transform equivalent ----------------------------

/// Alternate the case of ASCII letters, starting upper. Non-letters pass
/// through and do not advance the alternation. One-way.
#[derive(Debug)]
struct CaseToggle;

impl Transform for CaseToggle {
    fn id(&self) -> &'static str {
        "case_toggle"
    }

    fn description(&self) -> &'static str {
        Technique::CaseToggle.description()
    }

    fn category(&self) -> Category {
        Category::Text
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let mut upper = true;
        Ok(input
            .iter()
            .map(|&byte| {
                if !byte.is_ascii_alphabetic() {
                    return byte;
                }
                let out = if upper {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                };
                upper = !upper;
                out
            })
            .collect())
    }
}

/// HTML entities for every character: named for the five specials,
/// `&#xNN;` otherwise. Reversible.
#[derive(Debug)]
struct HtmlEntityMixed;

impl Transform for HtmlEntityMixed {
    fn id(&self) -> &'static str {
        "html_entity_mixed"
    }

    fn description(&self) -> &'static str {
        Technique::HtmlEntityEncode.description()
    }

    fn category(&self) -> Category {
        Category::Encoding
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let text = str::from_utf8(input).map_err(|_| TransformError::not_utf8(self.id()))?;
        let mut out = String::with_capacity(text.len() * 6);
        for ch in text.chars() {
            match ch {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                _ => {
                    let _ = write!(out, "&#x{:x};", u32::from(ch));
                }
            }
        }
        Ok(out.into_bytes())
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let text = str::from_utf8(input).map_err(|_| TransformError::not_utf8(self.id()))?;
        Ok(rune_html_encode::decode(text).into_bytes())
    }
}

/// `CHAR(b1,b2,…)` of the byte values. Reversible.
#[derive(Debug)]
struct SqlChar;

impl Transform for SqlChar {
    fn id(&self) -> &'static str {
        "sql_char"
    }

    fn description(&self) -> &'static str {
        Technique::SqlCharEncode.description()
    }

    fn category(&self) -> Category {
        Category::Numeric
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let mut out = String::with_capacity(6 + input.len() * 4);
        out.push_str("CHAR(");
        for (index, byte) in input.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(out, "{byte}");
        }
        out.push(')');
        Ok(out.into_bytes())
    }

    /// Accepts `CHAR(…)` in any case, with ASCII whitespace around the
    /// numbers.
    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let text = str::from_utf8(input).map_err(|_| TransformError::not_utf8(self.id()))?;
        let inner = text
            .get(..5)
            .filter(|head| head.eq_ignore_ascii_case("CHAR("))
            .and_then(|_| text.get(5..))
            .and_then(|rest| rest.strip_suffix(')'))
            .ok_or_else(|| TransformError::malformed(self.id(), "expected CHAR(...)"))?;
        if inner.trim_ascii().is_empty() {
            return Ok(Vec::new());
        }
        inner
            .split(',')
            .map(|token| {
                let token = token.trim_ascii();
                if !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()) {
                    token
                        .parse::<u8>()
                        .map_err(|_| TransformError::malformed(self.id(), "byte value over 255"))
                } else {
                    Err(TransformError::malformed(
                        self.id(),
                        format!("not a byte value: {token:?}"),
                    ))
                }
            })
            .collect()
    }
}

/// Split the text at its middle character and re-join as two string
/// literals: `'left'+'right'` for SQL, `"left""right"` otherwise.
/// Reversible: the split point follows from the length.
#[derive(Debug)]
struct Concat {
    /// SQL form (`'…'+'…'`) rather than adjacent double-quoted literals.
    sql: bool,
}

impl Concat {
    /// Opening quote, separator, closing quote.
    const fn parts(&self) -> (&'static str, &'static str, &'static str) {
        if self.sql {
            ("'", "'+'", "'")
        } else {
            ("\"", "\"\"", "\"")
        }
    }
}

impl Transform for Concat {
    fn id(&self) -> &'static str {
        if self.sql { "concat_sql" } else { "concat" }
    }

    fn description(&self) -> &'static str {
        Technique::Concatenation.description()
    }

    fn category(&self) -> Category {
        Category::Framing
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let text = str::from_utf8(input).map_err(|_| TransformError::not_utf8(self.id()))?;
        let mid = text
            .char_indices()
            .nth(text.chars().count() / 2)
            .map_or(text.len(), |(at, _)| at);
        let (left, right) = text.split_at(mid);
        let (open, sep, close) = self.parts();
        Ok(format!("{open}{left}{sep}{right}{close}").into_bytes())
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, TransformError> {
        let text = str::from_utf8(input).map_err(|_| TransformError::not_utf8(self.id()))?;
        let (open, sep, close) = self.parts();
        let malformed =
            || TransformError::malformed(self.id(), "not a concatenation of two halves");
        let inner = text
            .strip_prefix(open)
            .and_then(|rest| rest.strip_suffix(close))
            .ok_or_else(malformed)?;
        let total = inner
            .chars()
            .count()
            .checked_sub(sep.len())
            .ok_or_else(malformed)?;
        let mid = inner
            .char_indices()
            .nth(total / 2)
            .map_or(inner.len(), |(at, _)| at);
        let (left, rest) = inner.split_at(mid);
        let right = rest.strip_prefix(sep).ok_or_else(malformed)?;
        let mut out = String::with_capacity(left.len() + right.len());
        out.push_str(left);
        out.push_str(right);
        Ok(out.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(technique: Technique, context: Context) -> EvasionTransform {
        EvasionTransform::new(technique, context, &TransformRegistry::builtin())
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn reversibility_flags_agree_with_techniques() {
        for technique in Technique::ALL {
            for context in [Context::Generic, Context::Sql] {
                let transform = build(technique, context);
                assert_eq!(
                    transform.is_reversible(),
                    technique.is_reversible(),
                    "{technique}"
                );
                assert_eq!(transform.id(), technique.transform_id(context));
                assert_eq!(transform.technique(), technique);
                assert_eq!(transform.context(), context);
            }
        }
    }

    #[test]
    fn one_way_decode_names_the_evasion_transform() {
        let error = build(Technique::CaseToggle, Context::Generic)
            .decode(b"x")
            .err();
        assert_eq!(
            error,
            Some(TransformError::not_reversible("evade_case_toggle"))
        );
    }

    #[test]
    fn concat_split_points() {
        let sql = Concat { sql: true };
        assert_eq!(sql.encode(b"").ok(), Some(b"''+''".to_vec()));
        assert_eq!(sql.encode(b"a").ok(), Some(b"''+'a'".to_vec()));
        assert_eq!(sql.encode(b"ab").ok(), Some(b"'a'+'b'".to_vec()));
        assert_eq!(sql.decode(b"''+'a'").ok(), Some(b"a".to_vec()));
        // The separator inside a half is not mistaken for the split.
        let tricky = "'+''+'";
        let encoded = sql.encode(tricky.as_bytes()).unwrap_or_default();
        assert_eq!(sql.decode(&encoded).ok(), Some(tricky.as_bytes().to_vec()));
        for bad in [&b""[..], b"'", b"''", b"'ab'", b"\"a\"\"b\""] {
            assert!(sql.decode(bad).is_err(), "{bad:?}");
        }
        let plain = Concat { sql: false };
        assert_eq!(
            plain.encode("héllo".as_bytes()).ok(),
            Some("\"hé\"\"llo\"".as_bytes().to_vec())
        );
        assert_eq!(
            plain.decode("\"hé\"\"llo\"".as_bytes()).ok(),
            Some("héllo".as_bytes().to_vec())
        );
    }

    #[test]
    fn sql_char_decode_is_lenient_but_strict_on_values() {
        assert_eq!(SqlChar.encode(b"").ok(), Some(b"CHAR()".to_vec()));
        assert_eq!(SqlChar.decode(b"CHAR()").ok(), Some(Vec::new()));
        assert_eq!(SqlChar.decode(b"char( 97, 98 )").ok(), Some(b"ab".to_vec()));
        for bad in [
            &b"CHAR(256)"[..],
            b"CHAR(1,,2)",
            b"CHAR(-1)",
            b"CHAR(1",
            b"CHR(1)",
            b"CH",
        ] {
            assert!(SqlChar.decode(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn register_is_atomic_and_rejects_duplicates() {
        let mut registry = TransformRegistry::builtin();
        let before = registry.len();
        assert!(register(&mut registry).is_ok());
        assert_eq!(registry.len(), before + 16);
        assert!(matches!(
            register(&mut registry),
            Err(Error::Transform(TransformError::DuplicateId { .. }))
        ));
        assert_eq!(registry.len(), before + 16);

        // Without the built-ins it wraps, nothing is registered.
        let mut empty = TransformRegistry::new();
        assert!(matches!(
            register(&mut empty),
            Err(Error::Transform(TransformError::UnknownTransform { .. }))
        ));
        assert!(empty.is_empty());
    }
}

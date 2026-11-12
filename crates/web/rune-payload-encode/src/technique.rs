//! Injection contexts and evasion techniques.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// The injection context a payload is destined for.
///
/// The context decides which techniques apply (SQL comments make no sense in
/// a path) and tunes the context-sensitive ones: [`Technique::HexEncode`]
/// renders `0x…` for SQL and `\xNN` elsewhere, and
/// [`Technique::Concatenation`] joins with `'…'+'…'` for SQL and `"…""…"`
/// elsewhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Context {
    /// No specific context: every technique applies.
    #[default]
    Generic,
    /// SQL injection (query strings, `WHERE` clauses, `UNION` payloads).
    Sql,
    /// Cross-site scripting (HTML or JavaScript injection).
    Xss,
    /// Path traversal and local file inclusion.
    Path,
    /// OS command injection.
    OsCommand,
    /// An HTML attribute or element body.
    Html,
}

impl Context {
    /// Every context, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Generic,
        Self::Sql,
        Self::Xss,
        Self::Path,
        Self::OsCommand,
        Self::Html,
    ];

    /// Stable `snake_case` name, such as `"os_command"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Sql => "sql",
            Self::Xss => "xss",
            Self::Path => "path",
            Self::OsCommand => "os_command",
            Self::Html => "html",
        }
    }

    /// The default technique set for this context, in output order.
    ///
    /// These are the techniques used when none are named.
    #[must_use]
    pub const fn default_techniques(self) -> &'static [Technique] {
        use Technique as T;
        match self {
            Self::Generic => &[
                T::CaseToggle,
                T::UrlEncode,
                T::DoubleUrlEncode,
                T::HtmlEntityEncode,
                T::HexEncode,
                T::UnicodeEscape,
                T::TabNewlineInsertion,
            ],
            Self::Sql => &[
                T::CaseToggle,
                T::SqlInlineComment,
                T::SqlWhitespaceAlt,
                T::SqlCharEncode,
                T::HexEncode,
                T::UrlEncode,
                T::Concatenation,
            ],
            Self::Xss => &[
                T::CaseToggle,
                T::HtmlEntityEncode,
                T::UrlEncode,
                T::UnicodeEscape,
                T::Concatenation,
            ],
            Self::Path => &[
                T::PathDotSlashObfuscation,
                T::UrlEncode,
                T::DoubleUrlEncode,
                T::NullByte,
            ],
            Self::OsCommand => &[
                T::OsCommandSeparatorAlt,
                T::TabNewlineInsertion,
                T::UrlEncode,
                T::NullByte,
            ],
            Self::Html => &[
                T::HtmlEntityEncode,
                T::UnicodeEscape,
                T::UrlEncode,
                T::CaseToggle,
            ],
        }
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

impl FromStr for Context {
    type Err = Error;

    /// Parse a [`name`](Context::name); `-` is accepted for `_`.
    fn from_str(text: &str) -> Result<Self, Error> {
        let wanted = text.trim().replace('-', "_");
        Self::ALL
            .into_iter()
            .find(|context| context.name().eq_ignore_ascii_case(&wanted))
            .ok_or_else(|| Error::UnknownContext(text.to_owned()))
    }
}

/// One evasion mutation of a payload, in the style of a sqlmap tamper
/// script.
///
/// Each technique is backed by a [`rune_transform::Transform`]; see
/// [`Encoder::transform`](crate::Encoder::transform) and
/// [`register`](crate::register). Some are reversible encodings, the rest
/// are lossy rewrites ([`is_reversible`](Technique::is_reversible)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Technique {
    /// Alternate the case of ASCII letters, starting upper (`SeLeCt`).
    CaseToggle,
    /// Percent-encode everything outside the RFC 3986 unreserved set.
    UrlEncode,
    /// Percent-encode twice.
    DoubleUrlEncode,
    /// Render every UTF-16 code unit as a `\uXXXX` escape.
    UnicodeEscape,
    /// HTML entities: named for `<>&"'`, `&#xNN;` for everything else.
    HtmlEntityEncode,
    /// Hex-encode the bytes: `0x…` for SQL, `\xNN` per byte otherwise.
    HexEncode,
    /// Replace spaces with SQL inline comments (`/**/`).
    SqlInlineComment,
    /// Replace spaces with an encoded tab (`%09`).
    SqlWhitespaceAlt,
    /// Rewrite the payload as a `CHAR(…)` list of byte values.
    SqlCharEncode,
    /// Append an encoded null byte (`%00`).
    NullByte,
    /// Obfuscate `../` traversal sequences as `....//`.
    PathDotSlashObfuscation,
    /// Swap `;` for `|` and spaces for `${IFS}`.
    OsCommandSeparatorAlt,
    /// Replace spaces with literal tab characters.
    TabNewlineInsertion,
    /// Split at the midpoint and re-join with string concatenation.
    Concatenation,
}

impl Technique {
    /// Every technique, in declaration order.
    pub const ALL: [Self; 14] = [
        Self::CaseToggle,
        Self::UrlEncode,
        Self::DoubleUrlEncode,
        Self::UnicodeEscape,
        Self::HtmlEntityEncode,
        Self::HexEncode,
        Self::SqlInlineComment,
        Self::SqlWhitespaceAlt,
        Self::SqlCharEncode,
        Self::NullByte,
        Self::PathDotSlashObfuscation,
        Self::OsCommandSeparatorAlt,
        Self::TabNewlineInsertion,
        Self::Concatenation,
    ];

    /// Stable `snake_case` name, such as `"case_toggle"`. Variants are
    /// labelled with it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CaseToggle => "case_toggle",
            Self::UrlEncode => "url_encode",
            Self::DoubleUrlEncode => "double_url_encode",
            Self::UnicodeEscape => "unicode_escape",
            Self::HtmlEntityEncode => "html_entity_encode",
            Self::HexEncode => "hex_encode",
            Self::SqlInlineComment => "sql_inline_comment",
            Self::SqlWhitespaceAlt => "sql_whitespace_alt",
            Self::SqlCharEncode => "sql_char_encode",
            Self::NullByte => "null_byte",
            Self::PathDotSlashObfuscation => "path_dot_slash_obfuscation",
            Self::OsCommandSeparatorAlt => "os_command_separator_alt",
            Self::TabNewlineInsertion => "tab_newline_insertion",
            Self::Concatenation => "concatenation",
        }
    }

    /// Short human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::CaseToggle => "Alternate the case of alphabetic characters",
            Self::UrlEncode => "Percent-encode the payload once",
            Self::DoubleUrlEncode => "Percent-encode the payload twice",
            Self::UnicodeEscape => "Render characters as \\uXXXX unicode escapes",
            Self::HtmlEntityEncode => "Encode characters as HTML entities",
            Self::HexEncode => "Hex-encode the payload for the context",
            Self::SqlInlineComment => "Insert SQL inline comments in place of spaces",
            Self::SqlWhitespaceAlt => "Replace spaces with alternate SQL whitespace",
            Self::SqlCharEncode => "Rewrite the payload as a CHAR() code-point list",
            Self::NullByte => "Append a null byte",
            Self::PathDotSlashObfuscation => "Obfuscate ../ traversal sequences",
            Self::OsCommandSeparatorAlt => "Swap OS command separators and spaces",
            Self::TabNewlineInsertion => "Replace spaces with literal tab characters",
            Self::Concatenation => "Split and re-join string literals with concat",
        }
    }

    /// Whether this technique is meaningful in `context`. Techniques tied to
    /// one syntax (SQL comments, traversal, command separators) apply only
    /// in that context and in [`Context::Generic`].
    #[must_use]
    pub const fn applies_to(self, context: Context) -> bool {
        use Context as C;
        match self {
            Self::SqlInlineComment | Self::SqlWhitespaceAlt | Self::SqlCharEncode => {
                matches!(context, C::Sql | C::Generic)
            }
            Self::PathDotSlashObfuscation => matches!(context, C::Path | C::Generic),
            Self::OsCommandSeparatorAlt => matches!(context, C::OsCommand | C::Generic),
            Self::HtmlEntityEncode => matches!(context, C::Html | C::Xss | C::Generic),
            Self::Concatenation => matches!(context, C::Sql | C::Xss | C::Html | C::Generic),
            Self::CaseToggle
            | Self::UrlEncode
            | Self::DoubleUrlEncode
            | Self::UnicodeEscape
            | Self::HexEncode
            | Self::NullByte
            | Self::TabNewlineInsertion => true,
        }
    }

    /// Whether the output reverses exactly: the backing transform's
    /// `decode` gives back the original payload.
    #[must_use]
    pub const fn is_reversible(self) -> bool {
        matches!(
            self,
            Self::UrlEncode
                | Self::DoubleUrlEncode
                | Self::UnicodeEscape
                | Self::HtmlEntityEncode
                | Self::HexEncode
                | Self::SqlCharEncode
                | Self::NullByte
                | Self::Concatenation
        )
    }

    /// Whether `context` changes the output: true for
    /// [`HexEncode`](Self::HexEncode) and
    /// [`Concatenation`](Self::Concatenation), which have a SQL form.
    #[must_use]
    pub const fn is_context_sensitive(self) -> bool {
        matches!(self, Self::HexEncode | Self::Concatenation)
    }

    /// Id of the registered transform that implements this technique in
    /// `context`: `evade_<name>`, plus `_sql` for the SQL form of a
    /// context-sensitive technique.
    ///
    /// ```
    /// use rune_payload_encode::{Context, Technique};
    ///
    /// assert_eq!(Technique::CaseToggle.transform_id(Context::Sql), "evade_case_toggle");
    /// assert_eq!(Technique::HexEncode.transform_id(Context::Sql), "evade_hex_encode_sql");
    /// assert_eq!(Technique::HexEncode.transform_id(Context::Xss), "evade_hex_encode");
    /// ```
    #[must_use]
    pub const fn transform_id(self, context: Context) -> &'static str {
        let sql = matches!(context, Context::Sql);
        match self {
            Self::CaseToggle => "evade_case_toggle",
            Self::UrlEncode => "evade_url_encode",
            Self::DoubleUrlEncode => "evade_double_url_encode",
            Self::UnicodeEscape => "evade_unicode_escape",
            Self::HtmlEntityEncode => "evade_html_entity_encode",
            Self::HexEncode if sql => "evade_hex_encode_sql",
            Self::HexEncode => "evade_hex_encode",
            Self::SqlInlineComment => "evade_sql_inline_comment",
            Self::SqlWhitespaceAlt => "evade_sql_whitespace_alt",
            Self::SqlCharEncode => "evade_sql_char_encode",
            Self::NullByte => "evade_null_byte",
            Self::PathDotSlashObfuscation => "evade_path_dot_slash_obfuscation",
            Self::OsCommandSeparatorAlt => "evade_os_command_separator_alt",
            Self::TabNewlineInsertion => "evade_tab_newline_insertion",
            Self::Concatenation if sql => "evade_concatenation_sql",
            Self::Concatenation => "evade_concatenation",
        }
    }
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

impl FromStr for Technique {
    type Err = Error;

    /// Parse a [`name`](Technique::name); `-` is accepted for `_`.
    fn from_str(text: &str) -> Result<Self, Error> {
        let wanted = text.trim().replace('-', "_");
        Self::ALL
            .into_iter()
            .find(|technique| technique.name().eq_ignore_ascii_case(&wanted))
            .ok_or_else(|| Error::UnknownTechnique(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_through_from_str() {
        for context in Context::ALL {
            assert_eq!(context.name().parse::<Context>(), Ok(context));
            assert_eq!(context.to_string(), context.name());
        }
        for technique in Technique::ALL {
            assert_eq!(technique.name().parse::<Technique>(), Ok(technique));
        }
        assert_eq!("OS-Command".parse::<Context>(), Ok(Context::OsCommand));
        assert_eq!(
            "nope".parse::<Technique>(),
            Err(Error::UnknownTechnique("nope".into()))
        );
        assert!("nope".parse::<Context>().is_err());
    }

    #[test]
    fn applicability_per_context() {
        assert!(!Technique::SqlInlineComment.applies_to(Context::Xss));
        assert!(Technique::SqlInlineComment.applies_to(Context::Generic));
        assert!(!Technique::PathDotSlashObfuscation.applies_to(Context::Sql));
        assert!(!Technique::HtmlEntityEncode.applies_to(Context::Path));
        assert!(!Technique::Concatenation.applies_to(Context::OsCommand));
        // Every technique applies in the generic context, and every default
        // applies to its own context.
        for technique in Technique::ALL {
            assert!(technique.applies_to(Context::Generic));
        }
        for context in Context::ALL {
            for technique in context.default_techniques() {
                assert!(technique.applies_to(context), "{technique} in {context}");
            }
        }
    }

    #[test]
    fn transform_ids_are_unique_per_form() {
        let mut ids: Vec<&str> = Technique::ALL
            .iter()
            .flat_map(|t| {
                [
                    t.transform_id(Context::Generic),
                    t.transform_id(Context::Sql),
                ]
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 16);
    }
}

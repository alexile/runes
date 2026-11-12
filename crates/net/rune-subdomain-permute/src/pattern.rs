//! Patterns such as `{{word}}-{{sub}}.{{suffix}}`.

use core::fmt;
use core::str::FromStr;

use crate::Error;
use crate::seed::is_builtin;

/// One piece of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Token {
    Literal(String),
    Var(String),
}

/// A permutation pattern: literal text and `{{variable}}` placeholders.
///
/// Built-in variables come from the seed (see [`Seed`](crate::Seed)):
/// `sub`, `sub1`, `sub2`, …, `suffix`, `root`, `sld`, `etld`, `tld`. Any
/// other variable names a payload (a wordlist such as `word`, `number`,
/// `region` or `env`), and the pattern expands to every combination of
/// payload values. A variable used twice takes the same value both times.
///
/// Literal text may contain lowercase letters, digits, `-` and `.`.
///
/// ```
/// use rune_subdomain_permute::Pattern;
///
/// let pattern: Pattern = "{{word}}-{{sub}}.{{suffix}}".parse()?;
/// assert_eq!(pattern.payload_vars().collect::<Vec<_>>(), ["word"]);
/// assert_eq!(pattern.to_string(), "{{word}}-{{sub}}.{{suffix}}");
/// # Ok::<(), rune_subdomain_permute::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pattern {
    source: String,
    tokens: Vec<Token>,
    /// Distinct payload variables, in order of first use.
    payload_vars: Vec<String>,
}

impl Pattern {
    /// Parses a pattern.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPattern`] for an unclosed or empty `{{…}}`, a
    /// variable name outside `[a-z0-9_]`, a stray `{` or `}`, or literal
    /// text outside `[a-z0-9.-]`; an empty pattern or one with no variable.
    pub fn parse(source: &str) -> Result<Self, Error> {
        let invalid = |reason| Error::InvalidPattern {
            pattern: source.to_owned(),
            reason,
        };
        let mut tokens = Vec::new();
        let mut payload_vars: Vec<String> = Vec::new();
        let mut rest = source;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix("{{") {
                let end = after.find("}}").ok_or_else(|| invalid("unclosed `{{`"))?;
                let name = after.get(..end).unwrap_or_default().trim();
                if name.is_empty() {
                    return Err(invalid("empty variable"));
                }
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(invalid("variable names use only a-z, 0-9 and _"));
                }
                if !is_builtin(name) && !payload_vars.iter().any(|v| v == name) {
                    payload_vars.push(name.to_owned());
                }
                tokens.push(Token::Var(name.to_owned()));
                rest = after.get(end + 2..).unwrap_or_default();
            } else {
                let end = rest.find("{{").unwrap_or(rest.len());
                let literal = rest.get(..end).unwrap_or_default();
                if literal.contains(['{', '}']) {
                    return Err(invalid("stray brace"));
                }
                if !literal
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
                {
                    return Err(invalid("literal text uses only a-z, 0-9, - and ."));
                }
                tokens.push(Token::Literal(literal.to_owned()));
                rest = rest.get(end..).unwrap_or_default();
            }
        }
        if !tokens.iter().any(|t| matches!(t, Token::Var(_))) {
            return Err(invalid("no variable"));
        }
        Ok(Self {
            source: source.to_owned(),
            tokens,
            payload_vars,
        })
    }

    /// The pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The distinct payload (non-built-in) variables, in order of first use.
    pub fn payload_vars(&self) -> impl ExactSizeIterator<Item = &str> {
        self.payload_vars.iter().map(String::as_str)
    }

    pub(crate) fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub(crate) fn payload_index(&self, name: &str) -> Option<usize> {
        self.payload_vars.iter().position(|v| v == name)
    }
}

impl FromStr for Pattern {
    type Err = Error;

    fn from_str(source: &str) -> Result<Self, Error> {
        Self::parse(source)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

/// The default patterns, after alterx's: dash, dot and concatenation
/// insertion of words, environment and region tokens, and numbered
/// variants.
pub const DEFAULT_PATTERNS: &[&str] = &[
    "{{word}}-{{sub}}.{{suffix}}",
    "{{sub}}-{{word}}.{{suffix}}",
    "{{word}}.{{sub}}.{{suffix}}",
    "{{sub}}.{{word}}.{{suffix}}",
    "{{word}}{{sub}}.{{suffix}}",
    "{{sub}}{{word}}.{{suffix}}",
    "{{sub}}-{{env}}.{{suffix}}",
    "{{env}}-{{sub}}.{{suffix}}",
    "{{env}}.{{sub}}.{{suffix}}",
    "{{sub}}.{{env}}.{{suffix}}",
    "{{region}}.{{sub}}.{{suffix}}",
    "{{sub}}.{{region}}.{{suffix}}",
    "{{sub}}{{number}}.{{suffix}}",
    "{{sub}}-{{number}}.{{suffix}}",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_vars() {
        let p = Pattern::parse("{{word}}-{{sub}}.{{word}}{{n}}.{{root}}").unwrap();
        assert_eq!(p.payload_vars().collect::<Vec<_>>(), ["word", "n"]);
        assert_eq!(p.tokens().len(), 8);
        assert_eq!(p.payload_index("n"), Some(1));
        assert_eq!(p.payload_index("sub"), None);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "plain.example.com",
            "{{word",
            "{{}}.x",
            "{{Word}}.x",
            "{{word}}}.x",
            "{word}.x",
            "{{word}}_x",
            "{{word}}.X",
        ] {
            assert!(
                matches!(Pattern::parse(bad), Err(Error::InvalidPattern { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn spaces_inside_braces_are_trimmed() {
        let p = Pattern::parse("{{ word }}.{{root}}").unwrap();
        assert_eq!(p.payload_vars().collect::<Vec<_>>(), ["word"]);
    }

    #[test]
    fn defaults_parse() {
        for p in DEFAULT_PATTERNS {
            Pattern::parse(p).unwrap();
        }
    }
}

//! `Strict-Transport-Security` header grammar (RFC 6797 §6.1).

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A parsed `Strict-Transport-Security` header value.
///
/// Parsing follows [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797#section-6.1)
/// and the user-agent rules of §8.1: directive names are case-insensitive,
/// `max-age` is required, `max-age` and `includeSubDomains` may appear only
/// once, `includeSubDomains` takes no value, and unknown directives are
/// kept but otherwise ignored. A header that breaks these rules is ignored
/// by browsers, so [`Hsts::parse`] returns an [`Error`] for it.
///
/// `preload` is not part of RFC 6797; it is the opt-in token of the
/// [HSTS preload list](https://hstspreload.org/). Only a valueless,
/// first `preload` sets [`Hsts::preload`]; a repeated or valued one is kept
/// in [`Hsts::extensions`].
///
/// [`Display`](fmt::Display) writes the canonical form:
/// `max-age=N; includeSubDomains; preload` followed by extensions with
/// lowercase names, separated by `"; "`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Hsts {
    /// `max-age` in seconds. `0` tells the browser to forget the host.
    pub max_age: u64,
    /// `includeSubDomains` is present.
    pub include_subdomains: bool,
    /// A valueless `preload` token is present.
    pub preload: bool,
    /// Every other directive, in header order, with lowercase names.
    pub extensions: Vec<Extension>,
}

/// A directive [`Hsts`] does not interpret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Extension {
    /// Lowercase directive name.
    pub name: String,
    /// The value, unquoted, if the directive has one.
    pub value: Option<String>,
}

impl Extension {
    /// Creates an extension directive. The name is lowercased.
    #[must_use]
    pub fn new(name: &str, value: Option<String>) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
            value,
        }
    }
}

impl Hsts {
    /// A policy with the given `max-age` and no other directives.
    #[must_use]
    pub const fn new(max_age: u64) -> Self {
        Self {
            max_age,
            include_subdomains: false,
            preload: false,
            extensions: Vec::new(),
        }
    }

    /// Sets [`Hsts::include_subdomains`].
    #[must_use]
    pub const fn with_include_subdomains(mut self, include: bool) -> Self {
        self.include_subdomains = include;
        self
    }

    /// Sets [`Hsts::preload`].
    #[must_use]
    pub const fn with_preload(mut self, preload: bool) -> Self {
        self.preload = preload;
        self
    }

    /// Appends an extension directive.
    #[must_use]
    pub fn with_extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// Parses a header value.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when browsers would ignore the header: a syntax
    /// error, a missing or malformed `max-age`, a repeated `max-age` or
    /// `includeSubDomains`, or a valued `includeSubDomains`.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let directives = tokenize(value)?;
        if directives.is_empty() {
            return Err(Error::Empty);
        }
        let mut max_age = None;
        let mut include_subdomains = false;
        let mut preload = false;
        let mut extensions = Vec::new();
        for Raw { name, value } in directives {
            let lower = name.to_ascii_lowercase();
            match lower.as_str() {
                "max-age" => {
                    if max_age.is_some() {
                        return Err(Error::DuplicateDirective { name: lower });
                    }
                    let Some(value) = value else {
                        return Err(Error::MissingValue { name: lower });
                    };
                    max_age = Some(parse_max_age(&value)?);
                }
                "includesubdomains" => {
                    if include_subdomains {
                        return Err(Error::DuplicateDirective { name: lower });
                    }
                    if value.is_some() {
                        return Err(Error::UnexpectedValue { name: lower });
                    }
                    include_subdomains = true;
                }
                "preload" if value.is_none() && !preload => preload = true,
                _ => extensions.push(Extension { name: lower, value }),
            }
        }
        let max_age = max_age.ok_or(Error::MissingMaxAge)?;
        Ok(Self {
            max_age,
            include_subdomains,
            preload,
            extensions,
        })
    }
}

impl FromStr for Hsts {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Hsts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "max-age={}", self.max_age)?;
        if self.include_subdomains {
            f.write_str("; includeSubDomains")?;
        }
        if self.preload {
            f.write_str("; preload")?;
        }
        for ext in &self.extensions {
            write!(f, "; {ext}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        match &self.value {
            None => Ok(()),
            Some(v) if !v.is_empty() && v.bytes().all(is_tchar) => write!(f, "={v}"),
            Some(v) => {
                f.write_str("=\"")?;
                for c in v.chars() {
                    if c == '"' || c == '\\' {
                        f.write_str("\\")?;
                    }
                    write!(f, "{c}")?;
                }
                f.write_str("\"")
            }
        }
    }
}

/// `max-age` value: delta-seconds, optionally quoted (already unquoted
/// here). Large values saturate rather than fail, as for delta-seconds.
fn parse_max_age(value: &str) -> Result<u64, Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidMaxAge {
            value: value.to_owned(),
        });
    }
    Ok(value.bytes().fold(0u64, |acc, b| {
        acc.saturating_mul(10).saturating_add(u64::from(b - b'0'))
    }))
}

/// One directive as written.
struct Raw {
    name: String,
    value: Option<String>,
}

/// RFC 9110 `tchar`.
const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

/// `[ directive ] *( ";" [ directive ] )` with optional whitespace.
fn tokenize(input: &str) -> Result<Vec<Raw>, Error> {
    let mut p = Cursor { s: input, pos: 0 };
    let mut out = Vec::new();
    loop {
        p.skip_ows();
        match p.peek() {
            None => break,
            Some(';') => {
                p.pos += 1;
                continue;
            }
            Some(_) => {}
        }
        let name = p.token();
        if name.is_empty() {
            return Err(p.unexpected());
        }
        p.skip_ows();
        let value = if p.peek() == Some('=') {
            p.pos += 1;
            p.skip_ows();
            let v = if p.peek() == Some('"') {
                p.quoted()?
            } else {
                let token = p.token();
                if token.is_empty() {
                    return Err(Error::MissingValue {
                        name: name.to_ascii_lowercase(),
                    });
                }
                token.to_owned()
            };
            p.skip_ows();
            Some(v)
        } else {
            None
        };
        match p.peek() {
            None | Some(';') => {}
            Some(_) => return Err(p.unexpected()),
        }
        out.push(Raw {
            name: name.to_owned(),
            value,
        });
    }
    Ok(out)
}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<char> {
        self.s[self.pos..].chars().next()
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.pos += 1;
        }
    }

    fn token(&mut self) -> &'a str {
        let start = self.pos;
        let rest = &self.s.as_bytes()[start..];
        let len = rest.iter().take_while(|b| is_tchar(**b)).count();
        self.pos += len;
        &self.s[start..self.pos]
    }

    /// A quoted-string starting at the opening quote; returns the unescaped
    /// content.
    fn quoted(&mut self) -> Result<String, Error> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        let mut escaped = false;
        for (i, c) in self.s[self.pos..].char_indices() {
            if c.is_control() && c != '\t' {
                self.pos += i;
                return Err(self.unexpected());
            }
            if escaped {
                out.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                self.pos += i + 1;
                return Ok(out);
            } else {
                out.push(c);
            }
        }
        Err(Error::UnterminatedQuote { offset: start })
    }

    fn unexpected(&self) -> Error {
        Error::UnexpectedChar {
            offset: self.pos,
            found: self.peek().unwrap_or('\0'),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_examples() {
        // RFC 6797 §6.2.
        let h = Hsts::parse("max-age=31536000").unwrap();
        assert_eq!(h, Hsts::new(31_536_000));
        let h = Hsts::parse("max-age=15768000 ; includeSubDomains").unwrap();
        assert_eq!(h, Hsts::new(15_768_000).with_include_subdomains(true));
        let h = Hsts::parse("max-age=\"31536000\"").unwrap();
        assert_eq!(h.max_age, 31_536_000);
        assert_eq!(Hsts::parse("max-age=0").unwrap().max_age, 0);
    }

    #[test]
    fn case_order_and_empty_directives() {
        let h = Hsts::parse(";; PRELOAD; INCLUDESUBDOMAINS ;Max-Age=10;").unwrap();
        assert_eq!(
            h,
            Hsts::new(10)
                .with_include_subdomains(true)
                .with_preload(true)
        );
        assert_eq!(h.to_string(), "max-age=10; includeSubDomains; preload");
    }

    #[test]
    fn extensions_and_quoting() {
        let h = Hsts::parse("max-age=1; Foo=\"a b\\\"c\"; bar; preload=yes").unwrap();
        assert!(!h.preload);
        assert_eq!(
            h.extensions,
            [
                Extension::new("foo", Some("a b\"c".into())),
                Extension::new("bar", None),
                Extension::new("preload", Some("yes".into())),
            ]
        );
        assert_eq!(
            h.to_string(),
            "max-age=1; foo=\"a b\\\"c\"; bar; preload=yes"
        );
        assert_eq!(Hsts::parse(&h.to_string()).unwrap(), h);
    }

    #[test]
    fn errors() {
        assert_eq!(Hsts::parse(""), Err(Error::Empty));
        assert_eq!(Hsts::parse(" ; "), Err(Error::Empty));
        assert_eq!(Hsts::parse("includeSubDomains"), Err(Error::MissingMaxAge));
        assert!(matches!(
            Hsts::parse("max-age=1; max-age=2"),
            Err(Error::DuplicateDirective { .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=1; includeSubDomains; includesubdomains"),
            Err(Error::DuplicateDirective { .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=1; includeSubDomains=true"),
            Err(Error::UnexpectedValue { .. })
        ));
        for bad in ["max-age=-1", "max-age=1d", "max-age=\"\"", "max-age=+5"] {
            assert!(
                matches!(
                    Hsts::parse(bad),
                    Err(Error::InvalidMaxAge { .. } | Error::UnexpectedChar { .. })
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            Hsts::parse("max-age"),
            Err(Error::MissingValue { .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age="),
            Err(Error::MissingValue { .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=1, max-age=2"),
            Err(Error::UnexpectedChar { found: ',', .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=1 2"),
            Err(Error::UnexpectedChar { found: '2', .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=\"1"),
            Err(Error::UnterminatedQuote { .. })
        ));
        assert!(matches!(
            Hsts::parse("max-age=1; x=\"a\u{1}\""),
            Err(Error::UnexpectedChar { .. })
        ));
    }

    #[test]
    fn duplicate_preload_is_kept_as_extension() {
        let h = Hsts::parse("max-age=1; preload; preload").unwrap();
        assert!(h.preload);
        assert_eq!(h.extensions, [Extension::new("preload", None)]);
    }

    #[test]
    fn huge_max_age_saturates() {
        let h = Hsts::parse("max-age=99999999999999999999999999").unwrap();
        assert_eq!(h.max_age, u64::MAX);
    }
}

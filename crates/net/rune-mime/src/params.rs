//! Shared grammar: tokens, quoted strings and `; name=value` parameter
//! lists ([RFC 9110 §5.6], [RFC 2045 §5.1]) with [RFC 8187] extended
//! values (`name*=UTF-8''%e2%82%ac`).
//!
//! [RFC 9110 §5.6]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6
//! [RFC 2045 §5.1]: https://www.rfc-editor.org/rfc/rfc2045#section-5.1
//! [RFC 8187]: https://www.rfc-editor.org/rfc/rfc8187

use std::fmt::{self, Write as _};

use crate::MimeError;

/// One `name=value` parameter of a media type or disposition.
///
/// Names are stored in ASCII lowercase and without the trailing `*` of an
/// extended parameter; values are stored decoded (quotes and escapes
/// removed, percent-encoding of extended values resolved).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Param {
    /// Lowercase parameter name, without a trailing `*`.
    pub name: String,
    /// Decoded value.
    pub value: String,
    /// `true` if the parameter is (or will be written as) an RFC 8187
    /// extended value, `name*=UTF-8''…`.
    pub extended: bool,
}

impl Param {
    /// A parameter. The name must be a non-empty token not ending in `*`;
    /// it is lowercased.
    /// Values that a quoted string cannot carry (control characters) are
    /// marked [`extended`](Self::extended) so they survive formatting.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if the name is not a token or ends in
    /// `*`.
    pub fn new(name: &str, value: impl Into<String>) -> Result<Self, MimeError> {
        let value = value.into();
        let extended = !is_quotable(&value);
        Ok(Self {
            name: checked_param_name(name)?,
            value,
            extended,
        })
    }

    /// An RFC 8187 extended parameter, always written as
    /// `name*=UTF-8''percent-encoded`. Use it for non-ASCII file names that
    /// old recipients would mangle in a quoted string.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if the name is not a token or ends in
    /// `*`.
    pub fn extended(name: &str, value: impl Into<String>) -> Result<Self, MimeError> {
        Ok(Self {
            name: checked_param_name(name)?,
            value: value.into(),
            extended: true,
        })
    }
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.extended || !is_quotable(&self.value) {
            write!(f, "{}*=UTF-8''", self.name)?;
            for byte in self.value.bytes() {
                if is_attr_char(byte) {
                    f.write_char(char::from(byte))?;
                } else {
                    write!(f, "%{byte:02X}")?;
                }
            }
            Ok(())
        } else {
            write!(f, "{}=", self.name)?;
            write_value(f, &self.value)
        }
    }
}

/// Looks a parameter up by case-insensitive name. An extended parameter
/// (`name*`) wins over a plain one, as RFC 8187 §4.2 and RFC 6266 §4.3
/// require; among equals the first one wins.
pub fn find_param<'a>(params: &'a [Param], name: &str) -> Option<&'a str> {
    let mut plain = None;
    for param in params {
        if param.name.eq_ignore_ascii_case(name) {
            if param.extended {
                return Some(&param.value);
            }
            plain = plain.or(Some(param.value.as_str()));
        }
    }
    plain
}

/// Writes `; name=value` for every parameter.
pub fn write_params(f: &mut fmt::Formatter<'_>, params: &[Param]) -> fmt::Result {
    for param in params {
        write!(f, "; {param}")?;
    }
    Ok(())
}

/// `tchar` of RFC 9110 §5.6.2.
pub const fn is_tchar(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// `true` if `text` is a non-empty token.
pub fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(is_tchar)
}

/// Checks a parameter name: a token that does not end in `*` (that suffix
/// marks an extended value on the wire).
fn checked_param_name(name: &str) -> Result<String, MimeError> {
    if name.ends_with('*') {
        return Err(MimeError::InvalidValue {
            what: "parameter name",
            value: name.to_owned(),
        });
    }
    checked_token("parameter name", name)
}

/// Lowercases `text` after checking that it is a token.
pub fn checked_token(what: &'static str, text: &str) -> Result<String, MimeError> {
    if is_token(text) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(MimeError::InvalidValue {
            what,
            value: text.to_owned(),
        })
    }
}

/// `attr-char` of RFC 8187 §3.2.1.
const fn is_attr_char(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// `true` if a quoted string can carry `value`: HTAB, SP, VCHAR and
/// non-ASCII (`obs-text`) only.
fn is_quotable(value: &str) -> bool {
    value
        .chars()
        .all(|c| c == '\t' || c == ' ' || ('!'..='~').contains(&c) || !c.is_ascii())
}

/// Writes `value` as a token if it is one, else as a quoted string.
fn write_value(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    if is_token(value) {
        return f.write_str(value);
    }
    f.write_char('"')?;
    for c in value.chars() {
        if c == '"' || c == '\\' {
            f.write_char('\\')?;
        }
        f.write_char(c)?;
    }
    f.write_char('"')
}

/// A position in a header value.
pub struct Cursor<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub const fn new(text: &'a str) -> Self {
        Self { text, pos: 0 }
    }

    pub fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    pub const fn at_end(&self) -> bool {
        self.pos >= self.text.len()
    }

    pub const fn error(&self, expected: &'static str) -> MimeError {
        MimeError::Syntax {
            offset: self.pos,
            expected,
        }
    }

    /// Skips optional whitespace (SP / HTAB).
    pub fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Consumes `byte` if it comes next.
    pub fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes a (possibly empty) run of token characters.
    pub fn token(&mut self) -> &'a str {
        let start = self.pos;
        while self.peek().is_some_and(is_tchar) {
            self.pos += 1;
        }
        self.text.get(start..self.pos).unwrap_or_default()
    }

    /// Consumes a non-empty token, or fails with `expected`.
    pub fn required_token(&mut self, expected: &'static str) -> Result<&'a str, MimeError> {
        let token = self.token();
        if token.is_empty() {
            Err(self.error(expected))
        } else {
            Ok(token)
        }
    }

    /// Consumes a quoted string (the opening quote is next) and returns its
    /// unescaped content.
    fn quoted_string(&mut self) -> Result<String, MimeError> {
        let rest = self.text.get(self.pos + 1..).unwrap_or_default();
        let mut out = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += 1 + i + 1;
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, escaped)) if escaped == '\t' || !escaped.is_control() => {
                        out.push(escaped);
                    }
                    _ => {
                        self.pos += 1 + i;
                        return Err(self.error("a quoted-pair"));
                    }
                },
                c if c == '\t' || !c.is_control() => out.push(c),
                _ => {
                    self.pos += 1 + i;
                    return Err(self.error("a quoted-string character"));
                }
            }
        }
        self.pos = self.text.len();
        Err(self.error("a closing quote"))
    }

    /// Parses `*( OWS ";" OWS [ parameter ] )` up to the end of the input.
    ///
    /// Empty parameters (`;;`, a trailing `;`) are tolerated, as is
    /// whitespace around `=`, which real-world senders emit.
    pub fn params(&mut self) -> Result<Vec<Param>, MimeError> {
        let mut params = Vec::new();
        loop {
            self.skip_ows();
            if self.at_end() {
                return Ok(params);
            }
            if !self.eat(b';') {
                return Err(self.error("`;` or the end of the value"));
            }
            self.skip_ows();
            if self.at_end() || self.peek() == Some(b';') {
                continue;
            }
            params.push(self.param()?);
        }
    }

    fn param(&mut self) -> Result<Param, MimeError> {
        let raw_name = self.required_token("a parameter name")?;
        self.skip_ows();
        if !self.eat(b'=') {
            return Err(self.error("`=` after the parameter name"));
        }
        self.skip_ows();
        let value = if self.peek() == Some(b'"') {
            self.quoted_string()?
        } else {
            let token = self.token();
            if token.is_empty() {
                return Err(self.error("a parameter value"));
            }
            token.to_owned()
        };
        match raw_name.strip_suffix('*') {
            Some(name) if !name.is_empty() => Ok(Param {
                name: name.to_ascii_lowercase(),
                value: decode_ext_value(name, &value)?,
                extended: true,
            }),
            _ => Ok(Param {
                name: raw_name.to_ascii_lowercase(),
                value,
                extended: false,
            }),
        }
    }
}

/// Decodes an RFC 8187 `ext-value`: `charset "'" [ language ] "'" value-chars`.
fn decode_ext_value(name: &str, raw: &str) -> Result<String, MimeError> {
    let invalid = || MimeError::InvalidExtValue {
        name: name.to_ascii_lowercase(),
    };
    let mut pieces = raw.splitn(3, '\'');
    let (Some(charset), Some(_language), Some(encoded)) =
        (pieces.next(), pieces.next(), pieces.next())
    else {
        return Err(invalid());
    };
    let bytes = percent_decode(encoded).ok_or_else(invalid)?;
    if charset.eq_ignore_ascii_case("utf-8") {
        String::from_utf8(bytes).map_err(|_| invalid())
    } else if charset.eq_ignore_ascii_case("iso-8859-1") || charset.eq_ignore_ascii_case("us-ascii")
    {
        if charset.eq_ignore_ascii_case("us-ascii") && !bytes.is_ascii() {
            return Err(invalid());
        }
        Ok(bytes.into_iter().map(char::from).collect())
    } else {
        Err(invalid())
    }
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            let hi = hex_value(*bytes.get(i + 1)?)?;
            let lo = hex_value(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    Some(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Vec<Param>, MimeError> {
        Cursor::new(text).params()
    }

    #[test]
    fn quoted_and_token_values() {
        let params = parse(r#"; a=b ; c="d \"e\" \\f";;"#).unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].value, "b");
        assert_eq!(params[1].value, r#"d "e" \f"#);
    }

    #[test]
    fn extended_value_wins() {
        let params = parse("; filename=\"euro.txt\"; filename*=UTF-8''%e2%82%ac.txt").unwrap();
        assert_eq!(find_param(&params, "FILENAME"), Some("€.txt"));
        let latin = parse("; title*=iso-8859-1'en'%A3%20rates").unwrap();
        assert_eq!(find_param(&latin, "title"), Some("£ rates"));
    }

    #[test]
    fn rejects_bad_ext_values() {
        assert!(parse("; a*=UTF-8''%zz").is_err());
        assert!(parse("; a*=koi8-r''abc").is_err());
        assert!(parse("; a*=UTF-8''%ff").is_err());
        assert!(parse("; a*=nolang").is_err());
    }

    #[test]
    fn rejects_broken_syntax() {
        assert!(parse("; a").is_err());
        assert!(parse("; a=").is_err());
        assert!(parse("; a=\"open").is_err());
        assert!(parse("junk").is_err());
        assert!(parse("; a=b c").is_err());
    }

    #[test]
    fn display_quotes_and_extends() {
        assert_eq!(Param::new("A", "b").unwrap().to_string(), "a=b");
        assert_eq!(Param::new("a", "b c").unwrap().to_string(), "a=\"b c\"");
        assert_eq!(Param::new("a", "").unwrap().to_string(), "a=\"\"");
        assert_eq!(
            Param::extended("f", "€ x").unwrap().to_string(),
            "f*=UTF-8''%E2%82%AC%20x"
        );
        assert_eq!(
            Param::new("f", "a\nb").unwrap().to_string(),
            "f*=UTF-8''a%0Ab"
        );
        assert!(Param::new("bad name", "x").is_err());
        assert!(Param::new("star*", "x").is_err());
    }
}

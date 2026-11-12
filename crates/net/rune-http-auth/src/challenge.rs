//! The shared grammar of `WWW-Authenticate`, `Proxy-Authenticate` and
//! `Authorization` ([RFC 9110 §11]).
//!
//! [RFC 9110 §11]: https://www.rfc-editor.org/rfc/rfc9110#section-11

use std::fmt;

use crate::AuthError;

/// One challenge (`WWW-Authenticate`) or one set of credentials
/// (`Authorization`): `auth-scheme [ 1*SP ( token68 / #auth-param ) ]`.
///
/// ```
/// use rune_http_auth::Challenge;
///
/// let challenges =
///     Challenge::parse_list("Basic realm=\"simple\", Newauth realm=\"apps\", type=1, title=\"Login\"")
///         .unwrap();
/// assert_eq!(challenges.len(), 2);
/// assert!(challenges[0].is_scheme("basic"));
/// assert_eq!(challenges[1].param("TITLE"), Some("Login"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Challenge {
    /// The scheme as sent (compare with [`is_scheme`](Self::is_scheme)).
    pub scheme: String,
    /// The token68 form (`Negotiate YIIG…`, `Basic dXNlcjpwYXNz`).
    pub token68: Option<String>,
    /// The auth-param form, in order. Names are lowercased; values are
    /// unquoted.
    pub params: Vec<(String, String)>,
}

impl Challenge {
    /// A challenge with a scheme and nothing else.
    #[must_use]
    pub fn new(scheme: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            token68: None,
            params: Vec::new(),
        }
    }

    /// Sets the token68.
    #[must_use]
    pub fn with_token68(mut self, token68: impl Into<String>) -> Self {
        self.token68 = Some(token68.into());
        self
    }

    /// Adds a parameter (the name is lowercased).
    #[must_use]
    pub fn with_param(mut self, name: &str, value: impl Into<String>) -> Self {
        self.params.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    /// `true` if the scheme is `scheme`, ignoring case.
    #[must_use]
    pub fn is_scheme(&self, scheme: &str) -> bool {
        self.scheme.eq_ignore_ascii_case(scheme)
    }

    /// The first parameter called `name`, ignoring case.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parses a comma-separated list of challenges (one
    /// `WWW-Authenticate` header value).
    ///
    /// # Errors
    ///
    /// [`AuthError::Empty`] or [`AuthError::Syntax`].
    pub fn parse_list(text: &str) -> Result<Vec<Self>, AuthError> {
        let mut cursor = Cursor { text, pos: 0 };
        let mut out = Vec::new();
        loop {
            cursor.skip_list_separators();
            if cursor.at_end() {
                break;
            }
            out.push(cursor.challenge()?);
            cursor.skip_ows();
            if !cursor.at_end() && cursor.peek() != Some(b',') {
                return Err(cursor.error("`,` between challenges"));
            }
        }
        if out.is_empty() {
            return Err(AuthError::Empty);
        }
        Ok(out)
    }

    /// Parses exactly one challenge or set of credentials (an
    /// `Authorization` header value).
    ///
    /// # Errors
    ///
    /// [`AuthError::Empty`] or [`AuthError::Syntax`] (also when the value
    /// holds more than one).
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let mut cursor = Cursor { text, pos: 0 };
        cursor.skip_ows();
        if cursor.at_end() {
            return Err(AuthError::Empty);
        }
        let challenge = cursor.challenge()?;
        cursor.skip_ows();
        if cursor.at_end() {
            Ok(challenge)
        } else {
            Err(cursor.error("the end of the value"))
        }
    }
}

impl fmt::Display for Challenge {
    /// Writes the scheme, then the token68 or the parameters. Values are
    /// written as tokens when they are tokens and quoted otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.scheme)?;
        if let Some(token68) = &self.token68 {
            return write!(f, " {token68}");
        }
        for (i, (name, value)) in self.params.iter().enumerate() {
            f.write_str(if i == 0 { " " } else { ", " })?;
            write!(f, "{name}=")?;
            if is_token(value) {
                f.write_str(value)?;
            } else {
                write_quoted(f, value)?;
            }
        }
        Ok(())
    }
}

/// Writes `value` as a quoted string, escaping `"` and `\`.
pub fn write_quoted(out: &mut impl fmt::Write, value: &str) -> fmt::Result {
    out.write_char('"')?;
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.write_char('\\')?;
        }
        out.write_char(c)?;
    }
    out.write_char('"')
}

/// `tchar` of RFC 9110 §5.6.2.
const fn is_tchar(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// `true` for a non-empty token.
pub fn is_token(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(is_tchar)
}

/// `true` for a non-empty `token68` (RFC 9110 §11.2), which is also RFC
/// 6750's `b64token`.
pub fn is_token68(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

struct Cursor<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn peek_at(&self, pos: usize) -> Option<u8> {
        self.text.as_bytes().get(pos).copied()
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.text.len()
    }

    const fn error(&self, expected: &'static str) -> AuthError {
        AuthError::Syntax {
            offset: self.pos,
            expected,
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn skip_list_separators(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b',')) {
            self.pos += 1;
        }
    }

    /// Index after the run of bytes matching `pred` starting at `from`.
    fn scan(&self, from: usize, pred: impl Fn(u8) -> bool) -> usize {
        let mut end = from;
        while self.peek_at(end).is_some_and(&pred) {
            end += 1;
        }
        end
    }

    fn slice(&self, from: usize, to: usize) -> &'a str {
        self.text.get(from..to).unwrap_or_default()
    }

    fn challenge(&mut self) -> Result<Challenge, AuthError> {
        let end = self.scan(self.pos, is_tchar);
        if end == self.pos {
            return Err(self.error("an auth-scheme"));
        }
        let mut challenge = Challenge::new(self.slice(self.pos, end));
        self.pos = end;
        if !matches!(self.peek(), Some(b' ' | b'\t')) {
            return Ok(challenge);
        }
        self.skip_ows();

        // token68: its characters, then `=` padding, then the end of this
        // list element.
        let body_end = self.scan(self.pos, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        });
        if body_end > self.pos {
            let token_end = self.scan(body_end, |b| b == b'=');
            let after = self.scan(token_end, |b| b == b' ' || b == b'\t');
            if matches!(self.peek_at(after), None | Some(b',')) {
                challenge.token68 = Some(self.slice(self.pos, token_end).to_owned());
                self.pos = after;
                return Ok(challenge);
            }
        }

        // Otherwise zero or more auth-params; a list element that is not
        // `name =` starts the next challenge.
        while self.param_ahead() {
            let name_end = self.scan(self.pos, is_tchar);
            let name = self.slice(self.pos, name_end).to_ascii_lowercase();
            self.pos = name_end;
            self.skip_ows();
            self.pos += 1; // `=`, checked by `param_ahead`
            self.skip_ows();
            let value = if self.peek() == Some(b'"') {
                self.quoted_string()?
            } else {
                let end = self.scan(self.pos, is_tchar);
                if end == self.pos {
                    return Err(self.error("a parameter value"));
                }
                let value = self.slice(self.pos, end).to_owned();
                self.pos = end;
                value
            };
            challenge.params.push((name, value));
            self.skip_ows();
            match self.peek() {
                None => break,
                Some(b',') => {
                    let save = self.pos;
                    self.skip_list_separators();
                    if !self.param_ahead() {
                        self.pos = save;
                        break;
                    }
                }
                Some(_) => return Err(self.error("`,` or the end of the value")),
            }
        }
        Ok(challenge)
    }

    /// `true` if `token BWS "="` comes next.
    fn param_ahead(&self) -> bool {
        let end = self.scan(self.pos, is_tchar);
        if end == self.pos {
            return false;
        }
        let eq = self.scan(end, |b| b == b' ' || b == b'\t');
        self.peek_at(eq) == Some(b'=')
    }

    fn quoted_string(&mut self) -> Result<String, AuthError> {
        let rest = self.text.get(self.pos + 1..).unwrap_or_default();
        let mut out = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += i + 2;
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, escaped)) if escaped == '\t' || !escaped.is_control() => {
                        out.push(escaped);
                    }
                    _ => {
                        self.pos += i + 1;
                        return Err(self.error("a quoted-pair"));
                    }
                },
                c if c == '\t' || !c.is_control() => out.push(c),
                _ => {
                    self.pos += i + 1;
                    return Err(self.error("a quoted-string character"));
                }
            }
        }
        self.pos = self.text.len();
        Err(self.error("a closing quote"))
    }
}

/// Appends `, name=value` (or ` name=value` for the first parameter),
/// quoting the value when `quote` is set. Scheme modules use it where the
/// RFC fixes which parameters are quoted.
pub fn push_param(out: &mut String, first: &mut bool, name: &str, value: &str, quote: bool) {
    out.push_str(if *first { " " } else { ", " });
    *first = false;
    out.push_str(name);
    out.push('=');
    if quote {
        let _ = write_quoted(out, value);
    } else {
        out.push_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9110_example() {
        // RFC 9110 §11.6.1.
        let list = Challenge::parse_list(
            "Basic realm=\"simple\", Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"",
        )
        .unwrap();
        assert_eq!(list[0].param("realm"), Some("simple"));
        assert_eq!(list[1].scheme, "Newauth");
        assert_eq!(list[1].param("type"), Some("1"));
        assert_eq!(list[1].param("title"), Some("Login to \"apps\""));
    }

    #[test]
    fn token68_and_bare_schemes() {
        let list = Challenge::parse_list("Negotiate, NTLM TlRMTVNTUAABAAAA==, Bearer").unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].token68, None);
        assert_eq!(list[1].token68.as_deref(), Some("TlRMTVNTUAABAAAA=="));
        assert!(list[2].is_scheme("BEARER"));

        let one = Challenge::parse("Basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ==  ").unwrap();
        assert_eq!(one.token68.as_deref(), Some("QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
    }

    #[test]
    fn whitespace_around_equals() {
        let c = Challenge::parse("Digest realm = \"r\" , nonce=abc").unwrap();
        assert_eq!(c.param("realm"), Some("r"));
        assert_eq!(c.param("nonce"), Some("abc"));
    }

    #[test]
    fn errors() {
        assert_eq!(Challenge::parse_list(" , "), Err(AuthError::Empty));
        assert!(Challenge::parse("Basic a b").is_err());
        assert!(Challenge::parse("Digest realm=\"open").is_err());
        assert!(Challenge::parse("Basic x, Bearer").is_err());
        assert!(Challenge::parse("=").is_err());
        assert!(Challenge::parse_list("Basic a b").is_err());
    }

    #[test]
    fn display_round_trips() {
        let c = Challenge::new("Digest")
            .with_param("realm", "a b")
            .with_param("qop", "auth");
        assert_eq!(c.to_string(), "Digest realm=\"a b\", qop=auth");
        assert_eq!(Challenge::parse(&c.to_string()).unwrap(), c);
        let t = Challenge::new("NTLM").with_token68("abc=");
        assert_eq!(Challenge::parse(&t.to_string()).unwrap(), t);
    }
}

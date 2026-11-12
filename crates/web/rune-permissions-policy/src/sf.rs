//! The subset of [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941)
//! Structured Field Values that a `Permissions-Policy` header uses: a
//! Dictionary whose members are Items or Inner Lists, with Parameters.
//!
//! Parsing is strict, as in browsers: any syntax error fails the whole
//! field.

use std::fmt;

use crate::Error;

/// A bare item (RFC 8941 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareItem {
    Integer(i64),
    /// A decimal, in thousandths.
    Decimal(i64),
    String(String),
    Token(String),
    /// Base64 content between the colons, as written.
    ByteSeq(String),
    Boolean(bool),
}

/// An item with its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub bare: BareItem,
    pub params: Vec<(String, BareItem)>,
}

/// A dictionary member value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Item(BareItem),
    InnerList(Vec<Item>),
}

/// One dictionary member, in the order written; duplicates are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: String,
    pub value: Value,
    pub params: Vec<(String, BareItem)>,
}

/// Parses a Dictionary, keeping every member (also repeated keys).
pub fn parse_dictionary(input: &str) -> Result<Vec<Member>, Error> {
    let mut p = Parser {
        s: input.as_bytes(),
        pos: 0,
    };
    p.skip(|b| b == b' ');
    // Header values arrive with OWS trimmed; be tolerant of trailing SP/HTAB.
    let end = input.trim_end_matches([' ', '\t']).len();
    p.s = &input.as_bytes()[..end];
    let mut out = Vec::new();
    while !p.at_end() {
        let key = p.key()?;
        let (value, params) = if p.peek() == Some(b'=') {
            p.pos += 1;
            if p.peek() == Some(b'(') {
                let items = p.inner_list()?;
                (Value::InnerList(items), p.params()?)
            } else {
                let bare = p.bare_item()?;
                (Value::Item(bare), p.params()?)
            }
        } else {
            (Value::Item(BareItem::Boolean(true)), p.params()?)
        };
        out.push(Member { key, value, params });
        p.skip(|b| b == b' ' || b == b'\t');
        if p.at_end() {
            break;
        }
        p.expect(b',')?;
        p.skip(|b| b == b' ' || b == b'\t');
        if p.at_end() {
            return Err(p.unexpected());
        }
    }
    Ok(out)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    const fn at_end(&self) -> bool {
        self.pos >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn skip(&mut self, f: impl Fn(u8) -> bool) {
        while self.peek().is_some_and(&f) {
            self.pos += 1;
        }
    }

    fn unexpected(&self) -> Error {
        let found = std::str::from_utf8(&self.s[self.pos.min(self.s.len())..])
            .ok()
            .and_then(|r| r.chars().next())
            .unwrap_or('\0');
        // Non-UTF-8 boundaries cannot happen: `s` comes from a `&str` and
        // the parser only advances over ASCII.
        Error::UnexpectedChar {
            offset: self.pos,
            found,
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), Error> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn key(&mut self) -> Result<String, Error> {
        match self.peek() {
            Some(b) if b.is_ascii_lowercase() || b == b'*' => {}
            _ => return Err(self.unexpected()),
        }
        let start = self.pos;
        self.skip(is_key_char);
        Ok(ascii(&self.s[start..self.pos]))
    }

    fn inner_list(&mut self) -> Result<Vec<Item>, Error> {
        self.expect(b'(')?;
        let mut items = Vec::new();
        loop {
            self.skip(|b| b == b' ');
            if self.peek() == Some(b')') {
                self.pos += 1;
                return Ok(items);
            }
            let bare = self.bare_item()?;
            let params = self.params()?;
            items.push(Item { bare, params });
            match self.peek() {
                Some(b' ' | b')') => {}
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn params(&mut self) -> Result<Vec<(String, BareItem)>, Error> {
        let mut params: Vec<(String, BareItem)> = Vec::new();
        while self.peek() == Some(b';') {
            self.pos += 1;
            self.skip(|b| b == b' ');
            let key = self.key()?;
            let value = if self.peek() == Some(b'=') {
                self.pos += 1;
                self.bare_item()?
            } else {
                BareItem::Boolean(true)
            };
            // RFC 8941 §4.2.3.2: a repeated key overwrites the value.
            if let Some(slot) = params.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = value;
            } else {
                params.push((key, value));
            }
        }
        Ok(params)
    }

    fn bare_item(&mut self) -> Result<BareItem, Error> {
        match self.peek() {
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'"') => self.string(),
            Some(b'*') => Ok(self.token()),
            Some(b) if b.is_ascii_alphabetic() => Ok(self.token()),
            Some(b':') => self.byte_seq(),
            Some(b'?') => self.boolean(),
            _ => Err(self.unexpected()),
        }
    }

    fn number(&mut self) -> Result<BareItem, Error> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
            return Err(self.unexpected());
        }
        let int_start = self.pos;
        self.skip(|b| b.is_ascii_digit());
        let int_digits = self.pos - int_start;
        let mut frac_digits = 0;
        let mut frac = 0i64;
        let decimal = self.peek() == Some(b'.');
        if decimal {
            if int_digits > 12 {
                return Err(Error::NumberOutOfRange { offset: start });
            }
            self.pos += 1;
            let frac_start = self.pos;
            self.skip(|b| b.is_ascii_digit());
            frac_digits = self.pos - frac_start;
            if frac_digits == 0 || frac_digits > 3 {
                return Err(Error::NumberOutOfRange { offset: start });
            }
            for &d in &self.s[frac_start..self.pos] {
                frac = frac * 10 + i64::from(d - b'0');
            }
        } else if int_digits > 15 {
            return Err(Error::NumberOutOfRange { offset: start });
        }
        let mut int = 0i64;
        for &d in &self.s[int_start..int_start + int_digits] {
            int = int * 10 + i64::from(d - b'0');
        }
        let sign = if negative { -1 } else { 1 };
        if decimal {
            for _ in frac_digits..3 {
                frac *= 10;
            }
            Ok(BareItem::Decimal(sign * (int * 1000 + frac)))
        } else {
            Ok(BareItem::Integer(sign * int))
        }
    }

    fn string(&mut self) -> Result<BareItem, Error> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(Error::UnterminatedString { offset: start }),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(BareItem::String(out));
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => {
                            out.push(char::from(c));
                            self.pos += 1;
                        }
                        None => return Err(Error::UnterminatedString { offset: start }),
                        _ => return Err(self.unexpected()),
                    }
                }
                Some(c @ 0x20..=0x7e) => {
                    out.push(char::from(c));
                    self.pos += 1;
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn token(&mut self) -> BareItem {
        let start = self.pos;
        self.pos += 1;
        self.skip(|b| is_tchar(b) || b == b':' || b == b'/');
        BareItem::Token(ascii(&self.s[start..self.pos]))
    }

    fn byte_seq(&mut self) -> Result<BareItem, Error> {
        self.pos += 1;
        let start = self.pos;
        self.skip(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        let content = ascii(&self.s[start..self.pos]);
        self.expect(b':')?;
        Ok(BareItem::ByteSeq(content))
    }

    fn boolean(&mut self) -> Result<BareItem, Error> {
        self.pos += 1;
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                Ok(BareItem::Boolean(false))
            }
            Some(b'1') => {
                self.pos += 1;
                Ok(BareItem::Boolean(true))
            }
            _ => Err(self.unexpected()),
        }
    }
}

/// The bytes are all ASCII (checked by the caller's character classes).
fn ascii(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

/// `lcalpha / DIGIT / "_" / "-" / "." / "*"`.
pub const fn is_key_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'*')
}

/// RFC 9110 `tchar`.
pub const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
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
        )
}

/// Whether `s` is a valid SF key.
pub fn is_key(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'*')
        && s.bytes().all(is_key_char)
}

/// Whether `s` is a valid SF token.
pub fn is_token(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'*')
        && s.bytes().all(|b| is_tchar(b) || b == b':' || b == b'/')
}

/// Writes `s` as an SF string (quotes, `\"` and `\\` escapes).
pub fn write_string(out: &mut impl fmt::Write, s: &str) -> fmt::Result {
    out.write_char('"')?;
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.write_char('\\')?;
        }
        out.write_char(c)?;
    }
    out.write_char('"')
}

impl fmt::Display for BareItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(i) => write!(f, "{i}"),
            Self::Decimal(d) => {
                let sign = if *d < 0 { "-" } else { "" };
                let abs = d.unsigned_abs();
                let mut frac = format!("{:03}", abs % 1000);
                while frac.len() > 1 && frac.ends_with('0') {
                    frac.pop();
                }
                write!(f, "{sign}{}.{frac}", abs / 1000)
            }
            Self::String(s) => write_string(f, s),
            Self::Token(t) => f.write_str(t),
            Self::ByteSeq(b) => write!(f, ":{b}:"),
            Self::Boolean(b) => f.write_str(if *b { "?1" } else { "?0" }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(s: &str) -> Vec<String> {
        parse_dictionary(s)
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect()
    }

    #[test]
    fn dictionary_shapes() {
        assert_eq!(keys("a=(), b=*, c=self , d"), ["a", "b", "c", "d"]);
        assert_eq!(keys(""), Vec::<String>::new());
        assert_eq!(keys("  a=1\t"), ["a"]);
        let m = parse_dictionary("a=(self \"https://x\";p=1);report-to=ep").unwrap();
        assert_eq!(
            m[0].params,
            [("report-to".to_owned(), BareItem::Token("ep".into()))]
        );
        let Value::InnerList(items) = &m[0].value else {
            panic!("inner list expected")
        };
        assert_eq!(items[1].bare, BareItem::String("https://x".into()));
        assert_eq!(items[1].params.len(), 1);
    }

    #[test]
    fn bare_items() {
        let m = parse_dictionary("a=-12, b=1.50, c=:AQ==:, d=?0, e=\"q\\\"\\\\\"").unwrap();
        let v: Vec<String> = m
            .iter()
            .map(|m| match &m.value {
                Value::Item(b) => b.to_string(),
                Value::InnerList(_) => String::new(),
            })
            .collect();
        assert_eq!(v, ["-12", "1.5", ":AQ==:", "?0", "\"q\\\"\\\\\""]);
    }

    #[test]
    fn errors() {
        for bad in [
            "A=1",
            "a=1,",
            "a=1 b=2",
            "a=(1",
            "a=(1,2)",
            "a='self'",
            "a=\"x",
            "a=\"\\x\"",
            "a=1234567890123456",
            "a=1.2345",
            "a=?2",
            "a=:abc",
            "a=\"é\"",
            ",",
        ] {
            assert!(parse_dictionary(bad).is_err(), "{bad}");
        }
    }
}

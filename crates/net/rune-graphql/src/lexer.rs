//! GraphQL lexer ([spec §2.1](https://spec.graphql.org/October2021/#sec-Language.Source-Text)).

use crate::GraphQlError;

/// A token kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bang,
    Dollar,
    Amp,
    LParen,
    RParen,
    Spread,
    Colon,
    Equals,
    At,
    LBracket,
    RBracket,
    LBrace,
    Pipe,
    RBrace,
    Name,
    Int,
    Float,
    String,
    Eof,
}

impl Kind {
    /// How the token is shown in error messages.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Bang => "`!`",
            Self::Dollar => "`$`",
            Self::Amp => "`&`",
            Self::LParen => "`(`",
            Self::RParen => "`)`",
            Self::Spread => "`...`",
            Self::Colon => "`:`",
            Self::Equals => "`=`",
            Self::At => "`@`",
            Self::LBracket => "`[`",
            Self::RBracket => "`]`",
            Self::LBrace => "`{`",
            Self::Pipe => "`|`",
            Self::RBrace => "`}`",
            Self::Name => "a name",
            Self::Int => "an integer",
            Self::Float => "a float",
            Self::String => "a string",
            Self::Eof => "end of input",
        }
    }
}

/// One token. `text` is the raw source slice; `value` holds the decoded
/// value of string tokens.
#[derive(Debug, Clone)]
pub struct Token<'a> {
    pub kind: Kind,
    pub text: &'a str,
    pub value: Option<String>,
    pub offset: usize,
}

/// A pull lexer over GraphQL source text.
pub struct Lexer<'a> {
    source: &'a str,
    position: usize,
}

/// Converts a byte offset to a 1-based line and column.
pub fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    let mut previous_cr = false;
    for (index, character) in source.char_indices() {
        if index >= offset {
            break;
        }
        match character {
            '\n' if previous_cr => {}
            '\n' | '\r' => {
                line += 1;
                column = 1;
            }
            _ => column += 1,
        }
        previous_cr = character == '\r';
    }
    (line, column)
}

/// Builds a syntax error at `offset`.
pub fn syntax_error(source: &str, offset: usize, message: impl Into<String>) -> GraphQlError {
    let (line, column) = line_column(source, offset);
    GraphQlError::Syntax {
        line,
        column,
        message: message.into(),
    }
}

const fn is_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

const fn is_name_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

impl<'a> Lexer<'a> {
    pub const fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn byte(&self, offset: usize) -> Option<u8> {
        self.source.as_bytes().get(self.position + offset).copied()
    }

    fn rest(&self) -> &'a str {
        self.source.get(self.position..).unwrap_or_default()
    }

    fn error(&self, offset: usize, message: impl Into<String>) -> GraphQlError {
        syntax_error(self.source, offset, message)
    }

    fn skip_ignored(&mut self) {
        while let Some(byte) = self.byte(0) {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' | b',' => self.position += 1,
                b'#' => {
                    while let Some(byte) = self.byte(0) {
                        if byte == b'\n' || byte == b'\r' {
                            break;
                        }
                        self.position += 1;
                    }
                }
                0xEF if self.rest().starts_with('\u{FEFF}') => self.position += 3,
                _ => break,
            }
        }
    }

    /// Lexes the next token.
    pub fn next_token(&mut self) -> Result<Token<'a>, GraphQlError> {
        self.skip_ignored();
        let start = self.position;
        let Some(byte) = self.byte(0) else {
            return Ok(Token {
                kind: Kind::Eof,
                text: "",
                value: None,
                offset: start,
            });
        };
        let single = |kind| Some(kind);
        let punctuator = match byte {
            b'!' => single(Kind::Bang),
            b'$' => single(Kind::Dollar),
            b'&' => single(Kind::Amp),
            b'(' => single(Kind::LParen),
            b')' => single(Kind::RParen),
            b':' => single(Kind::Colon),
            b'=' => single(Kind::Equals),
            b'@' => single(Kind::At),
            b'[' => single(Kind::LBracket),
            b']' => single(Kind::RBracket),
            b'{' => single(Kind::LBrace),
            b'|' => single(Kind::Pipe),
            b'}' => single(Kind::RBrace),
            _ => None,
        };
        let mut value = None;
        let kind = if let Some(kind) = punctuator {
            self.position += 1;
            kind
        } else if byte == b'.' {
            if !self.rest().starts_with("...") {
                return Err(self.error(start, "unexpected `.`; did you mean `...`?"));
            }
            self.position += 3;
            Kind::Spread
        } else if byte == b'"' {
            value = Some(if self.rest().starts_with("\"\"\"") {
                self.block_string()?
            } else {
                self.string()?
            });
            Kind::String
        } else if byte == b'-' || byte.is_ascii_digit() {
            self.number()?
        } else if is_name_start(byte) {
            while self.byte(0).is_some_and(is_name_continue) {
                self.position += 1;
            }
            Kind::Name
        } else {
            let character = self.rest().chars().next().unwrap_or('\u{FFFD}');
            return Err(self.error(start, format!("unexpected character {character:?}")));
        };
        Ok(Token {
            kind,
            text: self.source.get(start..self.position).unwrap_or_default(),
            value,
            offset: start,
        })
    }

    fn digits(&mut self) -> usize {
        let start = self.position;
        while self.byte(0).is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        self.position - start
    }

    fn number(&mut self) -> Result<Kind, GraphQlError> {
        let start = self.position;
        if self.byte(0) == Some(b'-') {
            self.position += 1;
        }
        match self.byte(0) {
            Some(b'0') => {
                self.position += 1;
                if self.byte(0).is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(self.error(start, "numbers may not have leading zeros"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error(start, "expected a digit")),
        }
        let fraction = self.byte(0) == Some(b'.');
        if fraction {
            self.position += 1;
            if self.digits() == 0 {
                return Err(self.error(start, "expected a digit after `.`"));
            }
        }
        let exponent = matches!(self.byte(0), Some(b'e' | b'E'));
        if exponent {
            self.position += 1;
            if matches!(self.byte(0), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if self.digits() == 0 {
                return Err(self.error(start, "expected a digit in the exponent"));
            }
        }
        if self
            .byte(0)
            .is_some_and(|byte| byte == b'.' || is_name_start(byte))
        {
            return Err(self.error(start, "invalid number"));
        }
        Ok(if fraction || exponent {
            Kind::Float
        } else {
            Kind::Int
        })
    }

    fn next_char(&mut self) -> Option<char> {
        let character = self.rest().chars().next()?;
        self.position += character.len_utf8();
        Some(character)
    }

    fn hex(&mut self, start: usize, count: usize) -> Result<u32, GraphQlError> {
        let text = self
            .source
            .get(self.position..self.position + count)
            .ok_or_else(|| self.error(start, "unterminated unicode escape"))?;
        let code = u32::from_str_radix(text, 16)
            .ok()
            .filter(|_| text.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| self.error(start, "invalid unicode escape"))?;
        self.position += count;
        Ok(code)
    }

    fn unicode_escape(&mut self, start: usize) -> Result<char, GraphQlError> {
        if self.byte(0) == Some(b'{') {
            self.position += 1;
            let digits = self
                .rest()
                .bytes()
                .take_while(u8::is_ascii_hexdigit)
                .count();
            if digits == 0 || digits > 6 || self.byte(digits) != Some(b'}') {
                return Err(self.error(start, "invalid unicode escape"));
            }
            let code = self.hex(start, digits)?;
            self.position += 1;
            return char::from_u32(code).ok_or_else(|| self.error(start, "invalid code point"));
        }
        let code = self.hex(start, 4)?;
        if (0xD800..0xDC00).contains(&code) && self.rest().starts_with("\\u") {
            let saved = self.position;
            self.position += 2;
            let low = self.hex(start, 4)?;
            if (0xDC00..0xE000).contains(&low) {
                let combined = 0x1_0000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                return char::from_u32(combined)
                    .ok_or_else(|| self.error(start, "invalid surrogate pair"));
            }
            self.position = saved;
        }
        char::from_u32(code).ok_or_else(|| self.error(start, "invalid code point"))
    }

    fn string(&mut self) -> Result<String, GraphQlError> {
        let start = self.position;
        self.position += 1;
        let mut value = String::new();
        loop {
            match self.next_char() {
                None | Some('\n' | '\r') => return Err(self.error(start, "unterminated string")),
                Some('"') => return Ok(value),
                Some('\\') => {
                    let escape_start = self.position - 1;
                    let escaped = match self.next_char() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('/') => '/',
                        Some('b') => '\u{8}',
                        Some('f') => '\u{c}',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        Some('u') => self.unicode_escape(escape_start)?,
                        _ => return Err(self.error(escape_start, "invalid escape sequence")),
                    };
                    value.push(escaped);
                }
                Some(character) => value.push(character),
            }
        }
    }

    fn block_string(&mut self) -> Result<String, GraphQlError> {
        let start = self.position;
        self.position += 3;
        let mut raw = String::new();
        loop {
            let rest = self.rest();
            if rest.starts_with("\\\"\"\"") {
                raw.push_str("\"\"\"");
                self.position += 4;
            } else if rest.starts_with("\"\"\"") {
                self.position += 3;
                return Ok(block_string_value(&raw));
            } else if let Some(character) = self.next_char() {
                raw.push(character);
            } else {
                return Err(self.error(start, "unterminated block string"));
            }
        }
    }
}

/// The spec's `BlockStringValue()`: strips common indentation and leading
/// and trailing blank lines.
fn block_string_value(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let indent_of = |line: &str| line.len() - line.trim_start_matches([' ', '\t']).len();
    let common = lines
        .iter()
        .skip(1)
        .filter(|line| !line.trim_start_matches([' ', '\t']).is_empty())
        .map(|line| indent_of(line))
        .min();
    let mut out: Vec<&str> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| match common {
            Some(common) if index > 0 => line.get(common.min(line.len())..).unwrap_or_default(),
            _ => line,
        })
        .collect();
    let blank = |line: &&str| line.trim_start_matches([' ', '\t']).is_empty();
    while out.first().is_some_and(blank) {
        out.remove(0);
    }
    while out.last().is_some_and(blank) {
        out.pop();
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<Kind> {
        let mut lexer = Lexer::new(source);
        let mut out = Vec::new();
        loop {
            let token = lexer.next_token().unwrap();
            if token.kind == Kind::Eof {
                return out;
            }
            out.push(token.kind);
        }
    }

    fn first_value(source: &str) -> String {
        Lexer::new(source).next_token().unwrap().value.unwrap()
    }

    #[test]
    fn punctuators_and_ignored() {
        assert_eq!(
            kinds("\u{FEFF}{ a(b: $c) @d ... } # comment\n, [!]=|&:"),
            vec![
                Kind::LBrace,
                Kind::Name,
                Kind::LParen,
                Kind::Name,
                Kind::Colon,
                Kind::Dollar,
                Kind::Name,
                Kind::RParen,
                Kind::At,
                Kind::Name,
                Kind::Spread,
                Kind::RBrace,
                Kind::LBracket,
                Kind::Bang,
                Kind::RBracket,
                Kind::Equals,
                Kind::Pipe,
                Kind::Amp,
                Kind::Colon,
            ]
        );
    }

    #[test]
    fn numbers() {
        assert_eq!(kinds("0 -12 1.5 2e3 -0.1E-2"), {
            vec![Kind::Int, Kind::Int, Kind::Float, Kind::Float, Kind::Float]
        });
        for bad in ["01", "1.", "1e", "1.5x", "1a", "-", "1..2"] {
            assert!(Lexer::new(bad).next_token().is_err(), "{bad}");
        }
    }

    #[test]
    fn strings() {
        assert_eq!(first_value(r#""a\"b\\\/\nA\u{1F600}""#), "a\"b\\/\nA😀");
        assert_eq!(first_value(r#""😀""#), "😀");
        assert!(Lexer::new("\"abc").next_token().is_err());
        assert!(Lexer::new("\"a\nb\"").next_token().is_err());
        assert!(Lexer::new(r#""\q""#).next_token().is_err());
        assert!(Lexer::new(r#""\u12""#).next_token().is_err());
        assert!(Lexer::new(r#""\u{110000}""#).next_token().is_err());
    }

    #[test]
    fn block_strings() {
        assert_eq!(
            first_value("\"\"\"\n    Hello,\n      World!\n\n    Yours \\\"\"\"\n  \"\"\""),
            "Hello,\n  World!\n\nYours \"\"\""
        );
        assert_eq!(first_value("\"\"\"one line\"\"\""), "one line");
        assert!(Lexer::new("\"\"\"open").next_token().is_err());
    }

    #[test]
    fn positions() {
        assert_eq!(line_column("ab\ncd", 4), (2, 2));
        assert_eq!(line_column("a\r\nb", 3), (2, 1));
        let error = Lexer::new("\n  ?").next_token().unwrap_err();
        assert_eq!(
            error.to_string(),
            "syntax error at 2:3: unexpected character '?'"
        );
    }
}

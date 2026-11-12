//! Tokenizer for the master-file format (RFC 1035 §5.1): entries, comments,
//! parentheses and quoted strings.

use crate::Error;

/// One word of an entry. Escapes (`\X`, `\DDD`) are kept as written; the
/// field parsers interpret them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The text, without quotes.
    pub text: String,
    /// Whether it was written as a `"quoted string"`.
    pub quoted: bool,
}

/// One logical entry: a line, or several joined by parentheses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based line on which the entry starts.
    pub line: usize,
    /// Whether the entry starts with blank space (the owner is omitted).
    pub blank_owner: bool,
    /// The words of the entry.
    pub tokens: Vec<Token>,
}

impl Entry {
    const fn new(line: usize) -> Self {
        Self {
            line,
            blank_owner: false,
            tokens: Vec::new(),
        }
    }
}

/// Splits `text` into entries, dropping comments and empty lines.
pub fn entries(text: &str) -> Result<Vec<Entry>, Error> {
    let mut out = Vec::new();
    let mut line = 1;
    let mut depth = 0usize;
    let mut entry = Entry::new(line);
    let mut word: Option<String> = None;
    let mut line_start = true;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if line_start {
            line_start = false;
            entry.blank_owner = matches!(c, ' ' | '\t');
        }
        match c {
            '\n' => {
                flush(&mut word, &mut entry);
                line += 1;
                if depth == 0 {
                    let done = core::mem::replace(&mut entry, Entry::new(line));
                    if !done.tokens.is_empty() {
                        out.push(done);
                    }
                    line_start = true;
                }
            }
            ' ' | '\t' | '\r' => flush(&mut word, &mut entry),
            ';' => {
                flush(&mut word, &mut entry);
                while chars.next_if(|&next| next != '\n').is_some() {}
            }
            '(' => {
                flush(&mut word, &mut entry);
                depth += 1;
            }
            ')' => {
                flush(&mut word, &mut entry);
                depth = depth.checked_sub(1).ok_or(Error::Syntax {
                    line,
                    reason: "unbalanced ')'",
                })?;
            }
            '"' => {
                flush(&mut word, &mut entry);
                let mut text = String::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            text.push('\\');
                            text.push(escaped(chars.next(), line)?);
                        }
                        Some('\n') | None => {
                            return Err(Error::Syntax {
                                line,
                                reason: "unterminated quoted string",
                            });
                        }
                        Some(other) => text.push(other),
                    }
                }
                entry.tokens.push(Token { text, quoted: true });
            }
            '\\' => {
                let next = escaped(chars.next(), line)?;
                let word = word.get_or_insert_with(String::new);
                word.push('\\');
                word.push(next);
            }
            _ => word.get_or_insert_with(String::new).push(c),
        }
    }
    if depth > 0 {
        return Err(Error::Syntax {
            line,
            reason: "unbalanced '('",
        });
    }
    flush(&mut word, &mut entry);
    if !entry.tokens.is_empty() {
        out.push(entry);
    }
    Ok(out)
}

/// The character after a backslash; a line break or the end of input there
/// is an error.
fn escaped(next: Option<char>, line: usize) -> Result<char, Error> {
    next.filter(|&c| c != '\n').ok_or(Error::Syntax {
        line,
        reason: "backslash at the end of a line",
    })
}

fn flush(word: &mut Option<String>, entry: &mut Entry) {
    if let Some(text) = word.take() {
        entry.tokens.push(Token {
            text,
            quoted: false,
        });
    }
}

/// Decodes `\X` and `\DDD` escapes into bytes (RFC 1035 §5.1).
pub fn unescape(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        let first = bytes.next()?;
        if !first.is_ascii_digit() {
            out.push(first);
            continue;
        }
        let mut value = u32::from(first - b'0');
        for _ in 0..2 {
            let digit = bytes.next().filter(u8::is_ascii_digit)?;
            value = value * 10 + u32::from(digit - b'0');
        }
        out.push(u8::try_from(value).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(entry: &Entry) -> Vec<&str> {
        entry.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    #[test]
    fn splits_entries() {
        let text =
            "a 1 IN A 1.2.3.4 ; comment\n\n  ; only a comment\n\tIN TXT \"x ; (y)\" \\; z\r\n";
        let entries = entries(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(words(&entries[0]), ["a", "1", "IN", "A", "1.2.3.4"]);
        assert!(!entries[0].blank_owner);
        assert_eq!(entries[1].line, 4);
        assert!(entries[1].blank_owner);
        assert_eq!(words(&entries[1]), ["IN", "TXT", "x ; (y)", "\\;", "z"]);
        assert!(entries[1].tokens[2].quoted);
    }

    #[test]
    fn joins_parentheses() {
        let text = "@ SOA ns host (\n 1 ; serial\n 2 3 4\n 5 )\nnext A 1.1.1.1";
        let entries = entries(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(words(&entries[0]).len(), 9);
        assert_eq!(entries[1].line, 5);
    }

    #[test]
    fn rejects_bad_structure() {
        for bad in ["a (", "a )", "a \"open", "a \"x\ny\"", "a b\\"] {
            assert!(entries(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unescapes() {
        assert_eq!(unescape("a\\\"b\\092\\255").unwrap(), b"a\"b\\\xff");
        assert_eq!(unescape("\\256"), None);
        assert_eq!(unescape("\\1x"), None);
        assert_eq!(unescape("x\\"), None);
    }
}

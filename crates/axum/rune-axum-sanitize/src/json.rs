//! A strict JSON scanner that rewrites string literals in place.
//!
//! Parsing into `serde_json::Value` and back would reorder keys (unless the
//! global `preserve_order` feature is on) and reformat numbers, so instead
//! this walks the raw text, hands each decoded string to a callback and
//! splices in a re-encoded literal only where the callback changed it.
//! Everything else is copied byte for byte.
//!
//! The scanner is iterative, so deep input cannot overflow the stack, and it
//! enforces a nesting limit. It accepts exactly the JSON grammar (no
//! comments, no trailing commas), so it agrees with `serde_json` on where
//! every string starts and ends.

use std::{borrow::Cow, collections::HashMap, fmt};

/// Why a JSON body could not be cleaned.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::{JsonError, Sanitizer};
///
/// let sanitizer = Sanitizer::new();
/// assert!(matches!(sanitizer.clean_json("[1,]", 8), Err(JsonError::Syntax { .. })));
/// assert_eq!(
///     sanitizer.clean_json("[[[]]]", 2),
///     Err(JsonError::TooDeep { max_depth: 2 })
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonError {
    /// The input is not valid JSON; `offset` is the byte where scanning
    /// stopped.
    Syntax {
        /// Byte offset of the problem.
        offset: usize,
    },
    /// Arrays and objects nest deeper than allowed.
    TooDeep {
        /// The configured limit.
        max_depth: usize,
    },
    /// Cleaning an object key made it equal to another key of the same
    /// object, e.g. `{"a<b>": 1, "a": 2}`. Parsers disagree on which
    /// duplicate wins, so the document is refused rather than guessed at.
    /// Duplicates the client sent verbatim are left alone.
    DuplicateKey {
        /// Byte offset of the key that collided.
        offset: usize,
    },
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { offset } => write!(formatter, "invalid JSON at byte {offset}"),
            Self::TooDeep { max_depth } => {
                write!(formatter, "JSON nests deeper than {max_depth} levels")
            }
            Self::DuplicateKey { offset } => {
                write!(
                    formatter,
                    "JSON object key at byte {offset} duplicates another once cleaned"
                )
            }
        }
    }
}

impl std::error::Error for JsonError {}

enum Container {
    /// The keys seen so far, as cleaned, and whether any of them was
    /// changed by cleaning.
    Object(HashMap<String, bool>),
    Array(usize),
}

#[derive(Clone, Copy)]
enum Expect {
    Value,
    ObjectKeyOrEnd,
    ObjectKey,
    Colon,
    ObjectCommaOrEnd,
    ArrayValueOrEnd,
    ArrayCommaOrEnd,
    End,
}

struct Rewriter<'a> {
    input: &'a str,
    out: Option<String>,
    copied: usize,
}

impl Rewriter<'_> {
    fn replace(&mut self, start: usize, end: usize, value: &str) -> Result<(), JsonError> {
        let encoded =
            serde_json::to_string(value).map_err(|_| JsonError::Syntax { offset: start })?;
        let out = self
            .out
            .get_or_insert_with(|| String::with_capacity(self.input.len()));
        out.push_str(&self.input[self.copied..start]);
        out.push_str(&encoded);
        self.copied = end;
        Ok(())
    }
}

/// Cleans every string in `input` with `clean(path, is_key, text)`.
///
/// `path` holds the object keys (as decoded from the input) and array
/// indices leading to the string; for a key, it ends with that key.
pub fn clean<'a, F>(
    input: &'a str,
    max_depth: usize,
    mut clean: F,
) -> Result<Cow<'a, str>, JsonError>
where
    F: for<'s> FnMut(&[String], bool, &'s str) -> Cow<'s, str>,
{
    let bytes = input.as_bytes();
    let mut rewriter = Rewriter {
        input,
        out: None,
        copied: 0,
    };
    let mut stack: Vec<Container> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut expect = Expect::Value;
    let mut index = 0;

    loop {
        while bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            index += 1;
        }
        let syntax = JsonError::Syntax { offset: index };
        if matches!(expect, Expect::End) {
            if index == bytes.len() {
                break;
            }
            return Err(syntax);
        }
        let Some(&byte) = bytes.get(index) else {
            return Err(syntax);
        };

        expect = match expect {
            Expect::Value => match byte {
                b'{' | b'[' => {
                    if stack.len() >= max_depth {
                        return Err(JsonError::TooDeep { max_depth });
                    }
                    index += 1;
                    if byte == b'{' {
                        stack.push(Container::Object(HashMap::new()));
                        Expect::ObjectKeyOrEnd
                    } else {
                        stack.push(Container::Array(0));
                        path.push("0".to_owned());
                        Expect::ArrayValueOrEnd
                    }
                }
                b'"' => {
                    let end = scan_string(bytes, index)?;
                    let decoded = decode_string(input, index, end)?;
                    if let Cow::Owned(cleaned) = clean(&path, false, &decoded) {
                        rewriter.replace(index, end, &cleaned)?;
                    }
                    index = end;
                    after_value(&stack)
                }
                _ => {
                    index = scan_literal(bytes, index)?;
                    after_value(&stack)
                }
            },
            Expect::ObjectKeyOrEnd if byte == b'}' => {
                index += 1;
                stack.pop();
                after_value(&stack)
            }
            Expect::ObjectKeyOrEnd | Expect::ObjectKey => {
                if byte != b'"' {
                    return Err(syntax);
                }
                let end = scan_string(bytes, index)?;
                let decoded = decode_string(input, index, end)?;
                path.push(decoded.clone().into_owned());
                let (key, rewritten) = match clean(&path, true, &decoded) {
                    Cow::Owned(cleaned) => {
                        rewriter.replace(index, end, &cleaned)?;
                        (cleaned, true)
                    }
                    Cow::Borrowed(_) => (decoded.into_owned(), false),
                };
                if let Some(Container::Object(keys)) = stack.last_mut() {
                    match keys.get(&key) {
                        // Two untouched keys are the client's own duplicate;
                        // any other pairing is a collision cleaning created.
                        Some(&earlier) if earlier || rewritten => {
                            return Err(JsonError::DuplicateKey { offset: index });
                        }
                        Some(_) => {}
                        None => {
                            keys.insert(key, rewritten);
                        }
                    }
                }
                index = end;
                Expect::Colon
            }
            Expect::Colon => {
                if byte != b':' {
                    return Err(syntax);
                }
                index += 1;
                Expect::Value
            }
            Expect::ObjectCommaOrEnd => {
                path.pop();
                index += 1;
                match byte {
                    b',' => Expect::ObjectKey,
                    b'}' => {
                        stack.pop();
                        after_value(&stack)
                    }
                    _ => return Err(syntax),
                }
            }
            Expect::ArrayValueOrEnd if byte == b']' => {
                index += 1;
                path.pop();
                stack.pop();
                after_value(&stack)
            }
            Expect::ArrayValueOrEnd => Expect::Value,
            Expect::ArrayCommaOrEnd => {
                index += 1;
                match byte {
                    b',' => {
                        if let (Some(Container::Array(position)), Some(segment)) =
                            (stack.last_mut(), path.last_mut())
                        {
                            *position += 1;
                            *segment = position.to_string();
                        }
                        Expect::Value
                    }
                    b']' => {
                        path.pop();
                        stack.pop();
                        after_value(&stack)
                    }
                    _ => return Err(syntax),
                }
            }
            Expect::End => return Err(syntax),
        };
    }

    Ok(match rewriter.out {
        None => Cow::Borrowed(input),
        Some(mut out) => {
            out.push_str(&input[rewriter.copied..]);
            Cow::Owned(out)
        }
    })
}

const fn after_value(stack: &[Container]) -> Expect {
    match stack.last() {
        None => Expect::End,
        Some(Container::Object(_)) => Expect::ObjectCommaOrEnd,
        Some(Container::Array(_)) => Expect::ArrayCommaOrEnd,
    }
}

/// Returns the index just past the closing quote of the string at `start`.
fn scan_string(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let mut index = start + 1;
    loop {
        let syntax = JsonError::Syntax { offset: index };
        match bytes.get(index).copied() {
            None => return Err(syntax),
            Some(b'"') => return Ok(index + 1),
            Some(b'\\') => match bytes.get(index + 1).copied() {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => index += 2,
                Some(b'u') => {
                    let hex = bytes
                        .get(index + 2..index + 6)
                        .ok_or_else(|| syntax.clone())?;
                    if !hex.iter().all(u8::is_ascii_hexdigit) {
                        return Err(syntax);
                    }
                    index += 6;
                }
                _ => return Err(syntax),
            },
            Some(byte) if byte < 0x20 => return Err(syntax),
            Some(_) => index += 1,
        }
    }
}

/// Decodes the literal `input[start..end]` (quotes included).
fn decode_string(input: &str, start: usize, end: usize) -> Result<Cow<'_, str>, JsonError> {
    let literal = &input[start..end];
    let body = &literal[1..literal.len() - 1];
    if body.contains('\\') {
        // serde_json rejects lone surrogates, as the handler's extractor will.
        serde_json::from_str::<String>(literal)
            .map(Cow::Owned)
            .map_err(|_| JsonError::Syntax { offset: start })
    } else {
        Ok(Cow::Borrowed(body))
    }
}

/// Skips `true`, `false`, `null` or a number. Numbers are checked for
/// shape only; `serde_json` gives the precise verdict later.
fn scan_literal(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let rest = &bytes[start..];
    for keyword in [&b"true"[..], b"false", b"null"] {
        if rest.starts_with(keyword) {
            return Ok(start + keyword.len());
        }
    }
    let syntax = JsonError::Syntax { offset: start };
    if !rest
        .first()
        .is_some_and(|byte| *byte == b'-' || byte.is_ascii_digit())
    {
        return Err(syntax);
    }
    let length = rest
        .iter()
        .position(|byte| {
            !(byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E'))
        })
        .unwrap_or(rest.len());
    Ok(start + length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upper(input: &str) -> Result<Cow<'_, str>, JsonError> {
        clean(input, 16, |_, _, text| {
            if text.chars().any(char::is_lowercase) {
                Cow::Owned(text.to_uppercase())
            } else {
                Cow::Borrowed(text)
            }
        })
    }

    #[test]
    fn rewrites_only_changed_strings() {
        let input = "{ \"a\" : [1e5, \"x\", true, null, {\"B\": \"Y\"}] }";
        assert_eq!(
            upper(input).unwrap(),
            "{ \"A\" : [1e5, \"X\", true, null, {\"B\": \"Y\"}] }"
        );
        assert!(matches!(upper("[\"A\", 1]").unwrap(), Cow::Borrowed(_)));
    }

    #[test]
    fn escapes_are_decoded_and_reencoded() {
        assert_eq!(upper(r#"["\u0061\n"]"#).unwrap(), r#"["A\n"]"#);
    }

    #[test]
    fn rejects_invalid_json() {
        for bad in [
            "",
            "[",
            "[1,]",
            "{\"a\"}",
            "{\"a\":1,}",
            "{'a':1}",
            "[1 2]",
            "\"\\x\"",
            "\"\u{1}\"",
            "[\"\\ud800\"]",
            "1 2",
            "nul",
            "{\"a\":1]",
            "[}",
        ] {
            assert!(
                matches!(upper(bad), Err(JsonError::Syntax { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn depth_limit() {
        assert!(upper(&format!("{}{}", "[".repeat(16), "]".repeat(16))).is_ok());
        let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
        assert_eq!(upper(&deep), Err(JsonError::TooDeep { max_depth: 16 }));
        let huge = "[".repeat(1_000_000);
        assert_eq!(upper(&huge), Err(JsonError::TooDeep { max_depth: 16 }));
    }

    #[test]
    fn paths_are_tracked() {
        let mut seen = Vec::new();
        clean(
            r#"{"a":[{"b":"x"},"y"],"c":"z"}"#,
            8,
            |path, is_key, text| {
                seen.push((path.join("/"), is_key, text.to_owned()));
                Cow::Borrowed(text)
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            [
                ("a".to_owned(), true, "a".to_owned()),
                ("a/0/b".to_owned(), true, "b".to_owned()),
                ("a/0/b".to_owned(), false, "x".to_owned()),
                ("a/1".to_owned(), false, "y".to_owned()),
                ("c".to_owned(), true, "c".to_owned()),
                ("c".to_owned(), false, "z".to_owned()),
            ]
        );
    }
}

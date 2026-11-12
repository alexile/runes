//! Partial parsing of incomplete JSON, for progressive (streaming) UIs.
//!
//! While a model streams a JSON answer, every prefix of it is invalid JSON.
//! [`parse_partial`] turns such a prefix into the most complete *valid*
//! value it implies: open strings are closed (so long text fields grow
//! character by character), open arrays and objects are closed, and anything
//! that cannot be completed honestly — a half-written key, a key with no
//! value yet, a literal such as `tru`, a number such as `1.` or `-` — is
//! dropped until more text arrives.
//!
//! [`PartialJsonParser`] wraps this in a chunk accumulator that yields a
//! [`Partial`] each time the value grows, deserialized into `T` when it fits.
//! Give `T` `#[serde(default)]` fields (or `Option`s) to see typed values
//! before every field has arrived.
//!
//! The scanner is iterative, honours [`MAX_NESTING`] and
//! [`MAX_INPUT_BYTES`], and never panics.

use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::extract::remove_trailing_commas;
use crate::{MAX_INPUT_BYTES, MAX_NESTING};

/// Parse a possibly incomplete JSON document into the most complete valid
/// value it implies.
///
/// Leading prose and an opening Markdown fence are skipped (the value starts
/// at the first `{` or `[`; a bare scalar document is accepted only once it
/// parses as is). Text after the end of the top-level value is ignored.
/// Returns `None` when nothing usable has arrived yet, the text is malformed
/// (not merely incomplete), nests deeper than [`MAX_NESTING`], or is longer
/// than [`MAX_INPUT_BYTES`].
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::parse_partial;
/// use serde_json::json;
///
/// assert_eq!(parse_partial(r#"{"title": "Rust in Act"#), Some(json!({"title": "Rust in Act"})));
/// assert_eq!(parse_partial(r#"{"tags": ["a", "b"#), Some(json!({"tags": ["a", "b"]})));
/// // A key without a value yet, and an unfinished literal, are held back.
/// assert_eq!(parse_partial(r#"{"a": 1, "b""#), Some(json!({"a": 1})));
/// assert_eq!(parse_partial(r#"{"a": 1, "ok": tr"#), Some(json!({"a": 1})));
/// assert_eq!(parse_partial("Sure! ```json\n[1, 2"), Some(json!([1, 2])));
/// ```
#[must_use]
pub fn parse_partial(text: &str) -> Option<Value> {
    parse_partial_inner(text).map(|(v, _)| v)
}

/// [`parse_partial`], plus whether the top-level value was closed.
fn parse_partial_inner(text: &str) -> Option<(Value, bool)> {
    if text.len() > MAX_INPUT_BYTES {
        return None;
    }
    let Some(start) = text.find(['{', '[']) else {
        return serde_json::from_str(text.trim()).ok().map(|v| (v, true));
    };
    let (candidate, complete) = complete_prefix(&text[start..])?;
    serde_json::from_str(&candidate)
        .or_else(|_| serde_json::from_str(&remove_trailing_commas(&candidate)))
        .ok()
        .map(|v| (v, complete))
}

/// What the scanner expects next inside a container.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// An object key (or `}`).
    Key,
    /// The `:` after a key.
    Colon,
    /// A value (after `:` in an object, or after `[` / `,` in an array).
    Value,
    /// A `,` or the closer.
    CommaOrEnd,
}

struct Frame {
    closer: u8,
    expect: Expect,
}

impl Frame {
    /// What an empty container expects first.
    const fn first(&self) -> Expect {
        if self.closer == b'}' {
            Expect::Key
        } else {
            Expect::Value
        }
    }
}

/// Turn the prefix `s` (starting at `{` or `[`) into a complete JSON text,
/// and say whether the model closed the top-level value itself.
fn complete_prefix(s: &str) -> Option<(String, bool)> {
    let bytes = s.as_bytes();
    let mut stack: Vec<Frame> = Vec::new();
    // Byte offset up to which `s` can be cut and closed with the current
    // stack's closers. Every push and pop is itself a safe point, so the
    // stack never differs from the one at the last safe point.
    let mut safe = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let expect = stack.last().map_or(Expect::Value, |f| f.expect);
        match b {
            b'{' | b'[' if expect == Expect::Value => {
                if stack.len() >= MAX_NESTING {
                    return None;
                }
                stack.push(Frame {
                    closer: if b == b'{' { b'}' } else { b']' },
                    expect: if b == b'{' {
                        Expect::Key
                    } else {
                        Expect::Value
                    },
                });
                i += 1;
                safe = i;
            }
            b'}' | b']' => {
                let frame = stack.pop()?;
                // A value just ended, the container is empty (`{}`, `[]`),
                // or a trailing comma (`[1, ]`, removed below).
                let closable = frame.closer == b
                    && (frame.expect == Expect::CommaOrEnd || frame.expect == frame.first());
                if !closable {
                    return None;
                }
                i += 1;
                value_done(&mut stack);
                if stack.is_empty() {
                    return Some((s[..i].to_owned(), true));
                }
                safe = i;
            }
            b',' if expect == Expect::CommaOrEnd => {
                if let Some(f) = stack.last_mut() {
                    f.expect = f.first();
                }
                i += 1;
            }
            b':' if expect == Expect::Colon => {
                if let Some(f) = stack.last_mut() {
                    f.expect = Expect::Value;
                }
                i += 1;
            }
            b'"' if matches!(expect, Expect::Key | Expect::Value) => {
                let (end, escape_at) = scan_string(bytes, i + 1);
                let Some(end) = end else {
                    // Unterminated string: show a partial value, never a
                    // partial key.
                    if expect == Expect::Key {
                        break;
                    }
                    let cut = escape_at.unwrap_or(bytes.len());
                    let mut out = String::with_capacity(cut + 1 + stack.len());
                    out.push_str(s.get(..cut)?);
                    out.push('"');
                    close(&mut out, &stack);
                    return Some((out, false));
                };
                i = end;
                if expect == Expect::Key {
                    if let Some(f) = stack.last_mut() {
                        f.expect = Expect::Colon;
                    }
                } else {
                    value_done(&mut stack);
                    safe = i;
                }
            }
            _ if expect == Expect::Value => {
                // A number or literal: runs until a delimiter.
                let end = bytes[i..]
                    .iter()
                    .position(|c| {
                        matches!(c, b',' | b'}' | b']' | b':' | b'"') || c.is_ascii_whitespace()
                    })
                    .map_or(bytes.len(), |n| i + n);
                let token = s.get(i..end)?;
                if serde_json::from_str::<Value>(token).is_err() {
                    // Incomplete at the end of input (`tru`, `1.`): stop
                    // here. Anywhere else it is malformed.
                    if end == bytes.len() {
                        break;
                    }
                    return None;
                }
                i = end;
                value_done(&mut stack);
                // A number at the very end may still grow (`12` → `123`),
                // but it is a valid value now.
                safe = i;
            }
            _ => return None,
        }
    }
    if stack.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(safe + stack.len());
    out.push_str(s.get(..safe)?);
    close(&mut out, &stack);
    Some((out, false))
}

/// A value just finished inside the top frame.
const fn value_done(stack: &mut [Frame]) {
    if let Some(f) = stack.last_mut() {
        f.expect = Expect::CommaOrEnd;
    }
}

fn close(out: &mut String, stack: &[Frame]) {
    out.extend(stack.iter().rev().map(|f| char::from(f.closer)));
}

/// Scan a string body starting just after its opening quote. Returns the
/// offset just past the closing quote (or `None` if unterminated) and, when
/// unterminated, where an incomplete trailing escape sequence begins.
fn scan_string(bytes: &[u8], mut i: usize) -> (Option<usize>, Option<usize>) {
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return (Some(i + 1), None),
            b'\\' => {
                let escape_len = if bytes.get(i + 1) == Some(&b'u') {
                    6
                } else {
                    2
                };
                if i + escape_len > bytes.len() {
                    return (None, Some(i));
                }
                i += escape_len;
            }
            _ => i += 1,
        }
    }
    (None, None)
}

/// A progressively parsed value from a stream of chunks.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Partial<T> {
    /// The most complete valid JSON value seen so far.
    pub json: Value,
    /// `json` deserialized into `T`, when it fits (give `T` defaulted or
    /// optional fields to get typed values early).
    pub value: Option<T>,
    /// `true` once the top-level value has been closed by the model.
    pub complete: bool,
}

/// Accumulates streamed chunks and parses the growing text with
/// [`parse_partial`].
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::PartialJsonParser;
/// use serde::Deserialize;
///
/// #[derive(Debug, Default, Deserialize, PartialEq)]
/// #[serde(default)]
/// struct Story { title: String, words: u32 }
///
/// let mut p = PartialJsonParser::<Story>::new();
/// assert!(p.push("Here: ").is_none()); // nothing usable yet
/// let s = p.push("{\"tit").unwrap(); // a half-written key is held back
/// assert_eq!(s.value.unwrap(), Story::default());
/// let s = p.push("le\": \"Once upon").unwrap();
/// assert_eq!(s.value.unwrap().title, "Once upon");
/// let s = p.push(" a time\", \"words\": 4}").unwrap();
/// assert!(s.complete);
/// assert_eq!(s.value.unwrap(), Story { title: "Once upon a time".into(), words: 4 });
/// ```
#[derive(Debug)]
pub struct PartialJsonParser<T> {
    buffer: String,
    last: Option<(Value, bool)>,
    max_bytes: usize,
    overflowed: bool,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Default for PartialJsonParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PartialJsonParser<T> {
    /// Create an empty parser that accepts up to [`MAX_INPUT_BYTES`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: String::new(),
            last: None,
            max_bytes: MAX_INPUT_BYTES,
            overflowed: false,
            _phantom: PhantomData,
        }
    }

    /// Lower the accumulated-size cap (it can never exceed
    /// [`MAX_INPUT_BYTES`]). Once exceeded, [`push`](Self::push) returns
    /// `None` for good and [`is_overflowed`](Self::is_overflowed) is `true`.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes.min(MAX_INPUT_BYTES);
        self
    }

    /// The text received so far.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.buffer
    }

    /// `true` once the stream exceeded the size cap.
    #[must_use]
    pub const fn is_overflowed(&self) -> bool {
        self.overflowed
    }
}

impl<T: DeserializeOwned> PartialJsonParser<T> {
    /// Append `chunk` and return the new partial value, or `None` when the
    /// value has not changed (or nothing usable has arrived yet).
    ///
    /// Each call re-scans the whole buffer (linear in its size), so a stream
    /// of many tiny chunks costs O(n²) overall; the size cap bounds it.
    pub fn push(&mut self, chunk: &str) -> Option<Partial<T>> {
        if self.overflowed {
            return None;
        }
        if self.buffer.len().saturating_add(chunk.len()) > self.max_bytes {
            self.overflowed = true;
            return None;
        }
        self.buffer.push_str(chunk);
        let latest = parse_partial_inner(&self.buffer)?;
        if self.last.as_ref() == Some(&latest) {
            return None;
        }
        self.last = Some(latest.clone());
        Some(snapshot(latest))
    }

    /// The latest partial value, if any.
    #[must_use]
    pub fn current(&self) -> Option<Partial<T>> {
        self.last.clone().map(snapshot)
    }
}

fn snapshot<T: DeserializeOwned>((json, complete): (Value, bool)) -> Partial<T> {
    Partial {
        value: T::deserialize(&json).ok(),
        complete,
        json,
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[test]
    fn complete_documents() {
        assert_eq!(
            parse_partial(r#"{"a": [1, {"b": null}]}"#),
            Some(json!({"a": [1, {"b": null}]}))
        );
        assert_eq!(parse_partial("[]"), Some(json!([])));
        assert_eq!(parse_partial("{} trailing prose"), Some(json!({})));
        assert_eq!(parse_partial("42"), Some(json!(42)));
    }

    #[test]
    fn every_prefix_is_valid_or_none() {
        let doc = r#"{"name": "Ada \"L\" é", "n": -12.5e3, "ok": true, "x": null, "list": [1, [2, {}], "s"]}"#;
        for end in 1..=doc.len() {
            if doc.is_char_boundary(end) {
                assert!(parse_partial(&doc[..end]).is_some(), "{}", &doc[..end]);
            }
        }
        assert_eq!(parse_partial(doc), serde_json::from_str(doc).ok());
    }

    #[test]
    fn holds_back_incomplete_pieces() {
        assert_eq!(parse_partial("{"), Some(json!({})));
        assert_eq!(parse_partial(r#"{"ke"#), Some(json!({})));
        assert_eq!(parse_partial(r#"{"key""#), Some(json!({})));
        assert_eq!(parse_partial(r#"{"key":"#), Some(json!({})));
        assert_eq!(parse_partial(r#"{"a": 1,"#), Some(json!({"a": 1})));
        assert_eq!(parse_partial(r"[1, -"), Some(json!([1])));
        assert_eq!(parse_partial(r"[1, 2."), Some(json!([1])));
        assert_eq!(parse_partial(r"[nul"), Some(json!([])));
        assert_eq!(parse_partial(r#"["a\"#), Some(json!(["a"])));
        assert_eq!(parse_partial(r#"["a\u00"#), Some(json!(["a"])));
        assert_eq!(parse_partial(r#"["a\n"#), Some(json!(["a\n"])));
    }

    #[test]
    fn malformed_is_none() {
        assert_eq!(parse_partial(""), None);
        assert_eq!(parse_partial("no json"), None);
        assert_eq!(parse_partial("{]"), None);
        assert_eq!(parse_partial("[1 2]"), None);
        assert_eq!(parse_partial("{\"a\" 1}"), None);
        assert_eq!(parse_partial("[tru, 1]"), None);
        assert_eq!(parse_partial("{\"a\":}"), None);
        assert_eq!(parse_partial("[1,]"), Some(json!([1])));
        assert_eq!(parse_partial("[,]"), None);
        assert_eq!(parse_partial(&"[".repeat(MAX_NESTING + 1)), None);
    }

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(default)]
    struct Doc {
        title: String,
        items: Vec<u32>,
    }

    #[test]
    fn accumulator_yields_changes_only() {
        let mut p = PartialJsonParser::<Doc>::new();
        assert!(p.push("```json\n").is_none());
        let a = p.push("{\"title\": \"T\"").unwrap();
        assert!(!a.complete);
        assert_eq!(a.value.unwrap().title, "T");
        assert!(p.push(", ").is_none()); // nothing new
        let b = p.push("\"items\": [1, 2]}\n```").unwrap();
        assert!(b.complete);
        assert_eq!(b.value.unwrap().items, [1, 2]);
        assert!(p.current().unwrap().complete);
    }

    #[test]
    fn accumulator_size_cap() {
        let mut p = PartialJsonParser::<Value>::new().with_max_bytes(8);
        assert!(p.push("[1, 2").is_some());
        assert!(p.push(", 3, 4, 5").is_none());
        assert!(p.is_overflowed());
        assert!(p.push("]").is_none());
    }
}

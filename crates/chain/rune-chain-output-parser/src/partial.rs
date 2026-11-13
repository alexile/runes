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
use serde_json::{Map, Value};

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
    let mut scanner = Scanner::new();
    scanner.advance(text);
    scanner.view(text)
}

/// What the scanner expects next inside a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A container being built.
#[derive(Debug)]
enum Container {
    Array(Vec<Value>),
    Object(Map<String, Value>),
}

/// An open container: what it holds so far and what comes next.
#[derive(Debug)]
struct Frame {
    container: Container,
    expect: Expect,
    /// The key waiting for its value (objects only).
    key: Option<String>,
    /// The pending key is not valid JSON. That only matters once a value
    /// for it shows up: until then the key is not part of the value.
    bad_key: bool,
}

impl Frame {
    fn new(open: u8) -> Self {
        if open == b'{' {
            Self {
                container: Container::Object(Map::new()),
                expect: Expect::Key,
                key: None,
                bad_key: false,
            }
        } else {
            Self {
                container: Container::Array(Vec::new()),
                expect: Expect::Value,
                key: None,
                bad_key: false,
            }
        }
    }

    const fn closer(&self) -> u8 {
        match self.container {
            Container::Array(_) => b']',
            Container::Object(_) => b'}',
        }
    }

    /// What an empty container (or one right after a comma) expects.
    const fn first(&self) -> Expect {
        match self.container {
            Container::Array(_) => Expect::Value,
            Container::Object(_) => Expect::Key,
        }
    }

    /// Store a finished value under the pending key, or at the end.
    fn add(&mut self, value: Value) {
        match &mut self.container {
            Container::Array(items) => items.push(value),
            Container::Object(map) => {
                if let Some(key) = self.key.take() {
                    map.insert(key, value);
                }
            }
        }
        self.expect = Expect::CommaOrEnd;
    }

    /// A copy of the container with `child` (an unfinished value) added.
    fn snapshot(&self, child: Option<Value>) -> Value {
        match &self.container {
            Container::Array(items) => {
                let mut items = items.clone();
                items.extend(child);
                Value::Array(items)
            }
            Container::Object(map) => {
                let mut map = map.clone();
                if let (Some(key), Some(child)) = (&self.key, child) {
                    map.insert(key.clone(), child);
                }
                Value::Object(map)
            }
        }
    }

    fn into_value(self) -> Value {
        match self.container {
            Container::Array(items) => Value::Array(items),
            Container::Object(map) => Value::Object(map),
        }
    }
}

/// A string whose closing quote has not been seen yet.
#[derive(Debug)]
struct OpenString {
    is_key: bool,
    /// Where scanning resumes (always on an escape boundary).
    scanned: usize,
    /// Where the undecoded content starts. Keys are decoded only once
    /// closed (an unfinished key is never shown, so it is not checked yet).
    decoded_to: usize,
    /// The content decoded so far.
    decoded: String,
}

/// Fingerprint of the most recent visible piece of the value.
#[derive(Debug, Clone, PartialEq)]
enum Atom {
    Container,
    Scalar(Value),
    /// A string, by decoded length: strings only ever grow, so equal
    /// lengths mean equal content.
    Str(usize),
}

/// Cheap fingerprint of the value [`Scanner::view`] would build. Two equal
/// fingerprints taken from the same growing text mean equal values.
#[derive(Debug, Clone, PartialEq)]
enum Fingerprint {
    /// A bare scalar document (no container yet).
    Scalar(Value),
    /// The value of a container document.
    Body {
        /// Visible pieces: containers opened plus finished and shown
        /// unfinished values.
        atoms: u64,
        last: Option<Atom>,
        complete: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Looking for the first `{` or `[`.
    Prelude,
    /// Inside the top-level container.
    Body,
    /// The top-level container was closed; later text is ignored.
    Done,
    /// The text is malformed; nothing more will parse.
    Failed,
}

/// A bare scalar document seen before any container.
#[derive(Debug)]
struct Prelude {
    /// Bytes already searched for `{` / `[`.
    searched: usize,
    /// For a document starting with `"`: where the string scan resumes, and
    /// where it ended once closed.
    string_scan: usize,
    string_end: Option<usize>,
}

/// Resumable partial-JSON scanner. Every byte is looked at a bounded number
/// of times, so feeding a document in chunks costs time linear in its size.
#[derive(Debug)]
struct Scanner {
    phase: Phase,
    prelude: Prelude,
    /// Next unconsumed byte of the body.
    pos: usize,
    stack: Vec<Frame>,
    open: Option<OpenString>,
    /// Visible pieces committed so far (see [`Fingerprint::Body`]).
    atoms: u64,
    last: Option<Atom>,
    /// The finished top-level value.
    root: Option<Value>,
    /// The unfinished value at the end of the text (an open string or a
    /// number or literal that may still grow), recomputed on each advance.
    tail: Option<Value>,
    /// The text ends inside a surrogate pair: there is no valid value until
    /// the low half arrives (a lone surrogate is not valid JSON).
    split_surrogate: bool,
}

/// JSON whitespace (form feed is not JSON whitespace).
const fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

const fn is_delimiter(b: u8) -> bool {
    matches!(b, b',' | b'}' | b']' | b':' | b'"') || b.is_ascii_whitespace()
}

impl Scanner {
    const fn new() -> Self {
        Self {
            phase: Phase::Prelude,
            prelude: Prelude {
                searched: 0,
                string_scan: 0,
                string_end: None,
            },
            pos: 0,
            stack: Vec::new(),
            open: None,
            atoms: 0,
            last: None,
            root: None,
            tail: None,
            split_surrogate: false,
        }
    }

    /// Consume `text` (the whole buffer so far: it only ever grows).
    fn advance(&mut self, text: &str) {
        if self.phase == Phase::Prelude {
            let from = self.prelude.searched;
            let Some(offset) = text.get(from..).and_then(|rest| rest.find(['{', '['])) else {
                self.prelude.searched = text.len();
                self.track_prelude_string(text);
                return;
            };
            self.phase = Phase::Body;
            self.pos = from + offset;
        }
        if self.phase == Phase::Body && self.scan(text).is_none() {
            self.fail();
        }
    }

    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.tail = None;
    }

    /// Scan the body from `self.pos`. `None` means the text is malformed.
    fn scan(&mut self, text: &str) -> Option<()> {
        let bytes = text.as_bytes();
        self.tail = None;
        self.split_surrogate = false;
        loop {
            if self.open.is_some() {
                if !self.scan_open_string(text)? {
                    return Some(());
                }
                continue;
            }
            while self.pos < bytes.len() && is_ws(bytes[self.pos]) {
                self.pos += 1;
            }
            let Some(&b) = bytes.get(self.pos) else {
                return Some(());
            };
            let expect = self.stack.last().map_or(Expect::Value, |f| f.expect);
            // A value is about to show up under a malformed key.
            let bad_key = self.stack.last().is_some_and(|f| f.bad_key);
            match b {
                b'{' | b'[' if expect == Expect::Value => {
                    if bad_key || self.stack.len() >= MAX_NESTING {
                        return None;
                    }
                    self.stack.push(Frame::new(b));
                    self.pos += 1;
                    self.commit_atom(Atom::Container);
                }
                b'}' | b']' => {
                    // A value just ended, the container is empty, or a
                    // trailing comma (`[1, ]`) is being tolerated.
                    let top = self.stack.last()?;
                    if top.closer() != b
                        || (top.expect != Expect::CommaOrEnd && top.expect != top.first())
                    {
                        return None;
                    }
                    let value = self.stack.pop()?.into_value();
                    self.pos += 1;
                    let Some(parent) = self.stack.last_mut() else {
                        self.root = Some(value);
                        self.phase = Phase::Done;
                        return Some(());
                    };
                    parent.add(value);
                }
                b',' if expect == Expect::CommaOrEnd => {
                    let top = self.stack.last_mut()?;
                    top.expect = top.first();
                    self.pos += 1;
                }
                b':' if expect == Expect::Colon => {
                    self.stack.last_mut()?.expect = Expect::Value;
                    self.pos += 1;
                }
                b'"' if matches!(expect, Expect::Key | Expect::Value) => {
                    if expect == Expect::Value && bad_key {
                        return None;
                    }
                    self.pos += 1;
                    self.open = Some(OpenString {
                        is_key: expect == Expect::Key,
                        scanned: self.pos,
                        decoded_to: self.pos,
                        decoded: String::new(),
                    });
                }
                _ if expect == Expect::Value => {
                    // A number or literal: runs until a delimiter.
                    let rest = &bytes[self.pos..];
                    let Some(len) = rest.iter().position(|&c| is_delimiter(c)) else {
                        // It may still grow; show it only if it is valid now.
                        self.tail = serde_json::from_str::<Value>(text.get(self.pos..)?).ok();
                        if bad_key && self.tail.is_some() {
                            return None;
                        }
                        return Some(());
                    };
                    let token = text.get(self.pos..self.pos + len)?;
                    let value = serde_json::from_str::<Value>(token).ok()?;
                    if bad_key {
                        return None;
                    }
                    self.pos += len;
                    self.commit_value(value);
                }
                _ => return None,
            }
        }
    }

    /// Continue the open string. Returns `Some(true)` when it closed,
    /// `Some(false)` when the text ran out first, `None` when malformed.
    fn scan_open_string(&mut self, text: &str) -> Option<bool> {
        let open = self.open.as_mut()?;
        let scan = scan_string(text.as_bytes(), open.scanned);
        open.scanned = scan.resume;
        if open.is_key && scan.end.is_none() {
            return Some(false);
        }
        let upto = scan.end.map_or(scan.resume, |end| end - 1);
        let decoded = decode_into(&mut open.decoded, text.get(open.decoded_to..upto)?);
        if decoded.is_none() && !open.is_key {
            return None;
        }
        open.decoded_to = upto;
        let Some(end) = scan.end else {
            self.split_surrogate = scan.held_surrogate;
            if !open.is_key {
                self.tail = Some(Value::String(open.decoded.clone()));
            }
            return Some(false);
        };
        let open = self.open.take()?;
        self.pos = end;
        if open.is_key {
            let top = self.stack.last_mut()?;
            top.bad_key = decoded.is_none();
            top.key = decoded.map(|()| open.decoded);
            top.expect = Expect::Colon;
        } else {
            self.commit_value(Value::String(open.decoded));
        }
        Some(true)
    }

    fn commit_atom(&mut self, atom: Atom) {
        self.atoms += 1;
        self.last = Some(atom);
    }

    fn commit_value(&mut self, value: Value) {
        self.commit_atom(atom_of(&value));
        if let Some(top) = self.stack.last_mut() {
            top.add(value);
        }
    }

    /// The fingerprint of the current value, or `None` if there is none.
    fn fingerprint(&self, text: &str) -> Option<Fingerprint> {
        if self.split_surrogate {
            return None;
        }
        match self.phase {
            Phase::Prelude => self.prelude_scalar(text).map(Fingerprint::Scalar),
            Phase::Body | Phase::Done => Some(self.tail.as_ref().map_or_else(
                || Fingerprint::Body {
                    atoms: self.atoms,
                    last: self.last.clone(),
                    complete: self.phase == Phase::Done,
                },
                |tail| Fingerprint::Body {
                    atoms: self.atoms + 1,
                    last: Some(atom_of(tail)),
                    complete: false,
                },
            )),
            Phase::Failed => None,
        }
    }

    /// Build the current value. Linear in its size.
    fn view(&self, text: &str) -> Option<(Value, bool)> {
        if self.split_surrogate {
            return None;
        }
        match self.phase {
            Phase::Prelude => self.prelude_scalar(text).map(|v| (v, true)),
            Phase::Done => self.root.clone().map(|v| (v, true)),
            Phase::Body => self.body_view(),
            Phase::Failed => None,
        }
    }

    /// After malformed text: the value as far as it parsed.
    fn view_parsed(&self) -> Option<(Value, bool)> {
        match self.phase {
            Phase::Failed => self.body_view(),
            _ => None,
        }
    }

    fn body_view(&self) -> Option<(Value, bool)> {
        let mut child = self.tail.clone();
        for frame in self.stack.iter().rev() {
            child = Some(frame.snapshot(child));
        }
        child.map(|v| (v, false))
    }

    /// A bare scalar document: accepted only once the whole (trimmed) text
    /// parses. Strings are tracked incrementally so a long one is not
    /// re-read on every chunk.
    fn prelude_scalar(&self, text: &str) -> Option<Value> {
        let trimmed = text.trim();
        if trimmed.starts_with('"') {
            let end = self.prelude.string_end?;
            if !text[end..].trim().is_empty() {
                return None;
            }
        }
        serde_json::from_str(trimmed).ok()
    }

    /// Track a bare string document so [`prelude_scalar`](Self::prelude_scalar)
    /// knows whether it is closed.
    fn track_prelude_string(&mut self, text: &str) {
        if self.phase != Phase::Prelude || self.prelude.string_end.is_some() {
            return;
        }
        let Some(quote) = text.find(|c: char| !c.is_whitespace()) else {
            return;
        };
        if text.as_bytes()[quote] != b'"' {
            return;
        }
        let from = self.prelude.string_scan.max(quote + 1);
        let scan = scan_string(text.as_bytes(), from);
        self.prelude.string_scan = scan.resume;
        self.prelude.string_end = scan.end;
    }
}

fn atom_of(value: &Value) -> Atom {
    match value {
        Value::String(s) => Atom::Str(s.len()),
        Value::Array(_) | Value::Object(_) => Atom::Container,
        other => Atom::Scalar(other.clone()),
    }
}

/// Result of scanning a string body.
struct StringScan {
    /// Offset just past the closing quote, if it was found.
    end: Option<usize>,
    /// Where to resume next time: the end of the text, or the start of an
    /// incomplete trailing escape (or of a trailing `\u` high surrogate
    /// whose low half has not arrived).
    resume: usize,
    /// The text ends in a high surrogate escape waiting for its low half.
    held_surrogate: bool,
}

/// Scan a string body from `i` (just after the opening quote, or a
/// previous resume point).
fn scan_string(bytes: &[u8], mut i: usize) -> StringScan {
    // Start of the `\u` escape just before `i`, if the previous token was one.
    let mut last_unicode: Option<usize> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                return StringScan {
                    end: Some(i + 1),
                    resume: i,
                    held_surrogate: false,
                };
            }
            b'\\' => {
                let unicode = bytes.get(i + 1) == Some(&b'u');
                let len = if unicode { 6 } else { 2 };
                if i + len > bytes.len() {
                    break;
                }
                last_unicode = unicode.then_some(i);
                i += len;
            }
            _ => {
                last_unicode = None;
                i += 1;
            }
        }
    }
    // A high surrogate needs its low half to decode; wait for it.
    match last_unicode {
        Some(at) if is_high_surrogate(&bytes[at + 2..at + 6]) => StringScan {
            end: None,
            resume: at,
            held_surrogate: true,
        },
        _ => StringScan {
            end: None,
            resume: i,
            held_surrogate: false,
        },
    }
}

fn is_high_surrogate(hex: &[u8]) -> bool {
    std::str::from_utf8(hex)
        .ok()
        .and_then(|h| u16::from_str_radix(h, 16).ok())
        .is_some_and(|v| (0xD800..=0xDBFF).contains(&v))
}

/// Decode a run of JSON string content (complete escapes only) onto `out`.
fn decode_into(out: &mut String, raw: &str) -> Option<()> {
    if !raw.bytes().any(|b| b == b'\\' || b < 0x20) {
        out.push_str(raw);
        return Some(());
    }
    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('"');
    quoted.push_str(raw);
    quoted.push('"');
    out.push_str(&serde_json::from_str::<String>(&quoted).ok()?);
    Some(())
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
/// [`parse_partial`] semantics.
///
/// Parsing is incremental: each chunk is scanned once and the value is built
/// up as it arrives, so feeding a document costs time linear in its length
/// however small the chunks are. Producing a [`Partial`] copies the value
/// (and deserializes `T`), so:
///
/// - [`push`](Self::push) returns a [`Partial`] each time the value
///   changes — the right choice for a UI that redraws on every change;
/// - [`feed`](Self::feed) only reports whether it changed, and
///   [`current`](Self::current) builds the value on demand — the right
///   choice for large documents or when you redraw at your own pace.
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
    scanner: Scanner,
    /// Fingerprint of the value last reported by `push` or `feed`.
    reported: Option<Fingerprint>,
    /// The last value built, and the fingerprint it was built at.
    last: Option<(Value, bool)>,
    last_at: Option<Fingerprint>,
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
            scanner: Scanner::new(),
            reported: None,
            last: None,
            last_at: None,
            max_bytes: MAX_INPUT_BYTES,
            overflowed: false,
            _phantom: PhantomData,
        }
    }

    /// Lower the accumulated-size cap (it can never exceed
    /// [`MAX_INPUT_BYTES`]). Once exceeded, [`push`](Self::push) returns
    /// `None` and [`feed`](Self::feed) `false` for good, and
    /// [`is_overflowed`](Self::is_overflowed) is `true`.
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

    /// Append `chunk` and say whether the value changed since the last
    /// change [`push`](Self::push) or `feed` reported. Costs time
    /// proportional to the chunk, not to the text so far; build the value
    /// with [`current`](Self::current) when you need it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_output_parser::PartialJsonParser;
    /// use serde_json::{Value, json};
    ///
    /// let mut p = PartialJsonParser::<Value>::new();
    /// assert!(!p.feed("Sure: "));
    /// assert!(p.feed("[1, 2"));
    /// assert!(!p.feed(", ")); // nothing new yet
    /// assert!(p.feed("3]"));
    /// let done = p.current().unwrap();
    /// assert!(done.complete);
    /// assert_eq!(done.json, json!([1, 2, 3]));
    /// ```
    pub fn feed(&mut self, chunk: &str) -> bool {
        if self.overflowed {
            return false;
        }
        if self.buffer.len().saturating_add(chunk.len()) > self.max_bytes {
            self.overflowed = true;
            return false;
        }
        self.buffer.push_str(chunk);
        self.scanner.advance(&self.buffer);
        let Some(now) = self.scanner.fingerprint(&self.buffer) else {
            return false;
        };
        if self.reported.as_ref() == Some(&now) {
            return false;
        }
        self.reported = Some(now);
        true
    }

    /// The current value: the remembered one when nothing changed since it
    /// was built, a freshly built one otherwise, and after malformed text
    /// the last good one.
    fn latest(&self) -> Option<(Value, bool)> {
        match self.scanner.fingerprint(&self.buffer) {
            Some(now) if self.last_at.as_ref() == Some(&now) => self.last.clone(),
            Some(_) => self.scanner.view(&self.buffer),
            None if self.scanner.phase == Phase::Failed => {
                self.last.clone().or_else(|| self.scanner.view_parsed())
            }
            None => self.last.clone(),
        }
    }
}

impl<T: DeserializeOwned> PartialJsonParser<T> {
    /// Append `chunk` and return the new partial value, or `None` when the
    /// value has not changed (or nothing usable has arrived yet).
    ///
    /// Scanning is incremental, but each returned [`Partial`] is a full copy
    /// of the value; for very large documents prefer [`feed`](Self::feed).
    pub fn push(&mut self, chunk: &str) -> Option<Partial<T>> {
        if !self.feed(chunk) {
            return None;
        }
        let latest = self.scanner.view(&self.buffer)?;
        self.last = Some(latest.clone());
        self.last_at.clone_from(&self.reported);
        Some(snapshot(latest))
    }

    /// The latest partial value, if any, built on demand. After malformed
    /// text it stays at the last value that parsed.
    #[must_use]
    pub fn current(&self) -> Option<Partial<T>> {
        self.latest().map(snapshot)
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

    /// The previous whole-buffer implementation, kept as the reference the
    /// incremental scanner must agree with.
    mod reference {
        #![allow(clippy::all, clippy::pedantic, clippy::nursery)]

        use serde_json::Value;

        use crate::extract::remove_trailing_commas;
        use crate::{MAX_INPUT_BYTES, MAX_NESTING};

        /// [`parse_partial`], plus whether the top-level value was closed.
        pub(super) fn parse_partial_inner(text: &str) -> Option<(Value, bool)> {
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
                            && (frame.expect == Expect::CommaOrEnd
                                || frame.expect == frame.first());
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
                                matches!(c, b',' | b'}' | b']' | b':' | b'"')
                                    || c.is_ascii_whitespace()
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
    }

    /// What the old `push` returned for each chunk.
    fn reference_pushes(chunks: &[String]) -> Vec<Option<(Value, bool)>> {
        let mut buffer = String::new();
        let mut last: Option<(Value, bool)> = None;
        chunks
            .iter()
            .map(|chunk| {
                buffer.push_str(chunk);
                let latest = reference::parse_partial_inner(&buffer)?;
                if last.as_ref() == Some(&latest) {
                    return None;
                }
                last = Some(latest.clone());
                Some(latest)
            })
            .collect()
    }

    fn pushes(chunks: &[String]) -> Vec<Option<(Value, bool)>> {
        let mut p = PartialJsonParser::<Value>::new();
        chunks
            .iter()
            .map(|c| p.push(c).map(|x| (x.json, x.complete)))
            .collect()
    }

    fn chunked(text: &str, size: usize) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        chars.chunks(size).map(|c| c.iter().collect()).collect()
    }

    #[test]
    fn agrees_with_the_reference_on_tricky_streams() {
        let docs = [
            r#"Sure! ```json
{"a": [1, [2, {}], "x\"y"], "b": {"c": null}, "d": -1.5e3}
``` done"#,
            r"[1, 2., 3, tru, 4]",
            r#"{"a": 1, "a": 2, "b": [1,], "c": {},}"#,
            r"42",
            r"4 then [1, 2]",
            r#""bare string" and [1]"#,
            r#"{"s": "\u00e9\n\t\\", "e": "\ud83d\ude00!"}"#,
            r#"{"a" 1}"#,
            r#"[[[]], [[1]], {"k": [true, false]}] trailing { junk"#,
            r#"{"x": 12345678901234567890, "y": 0.000001}"#,
        ];
        for doc in docs {
            for size in 1..=7 {
                let chunks = chunked(doc, size);
                assert_eq!(pushes(&chunks), reference_pushes(&chunks), "{doc} / {size}");
            }
            for end in 0..=doc.len() {
                if doc.is_char_boundary(end) {
                    assert_eq!(
                        parse_partial_inner(&doc[..end]),
                        reference::parse_partial_inner(&doc[..end]),
                        "{}",
                        &doc[..end]
                    );
                }
            }
        }
    }

    fn arb_json() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            (-1e6f64..1e6).prop_map(Value::from),
            "[a-z \\\\\"{}\\[\\],:\u{e9}\u{1F600}\n]{0,10}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 32, 5, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                prop::collection::btree_map("[a-z]{1,4}", inner, 0..5)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest::proptest! {
        #[test]
        fn chunked_pushes_match_the_reference(
            v in arb_json(),
            pretty in proptest::bool::ANY,
            prefix in "[a-z !:`\n]{0,8}",
            suffix in "[a-z !\\]}]{0,6}",
            size in 1usize..9,
        ) {
            let body = if pretty { format!("{v:#}") } else { v.to_string() };
            let text = format!("{prefix}{body}{suffix}");
            let chunks = chunked(&text, size);
            proptest::prop_assert_eq!(pushes(&chunks), reference_pushes(&chunks));
        }

        #[test]
        fn json_ish_noise_matches_the_reference(
            text in "[{}\\[\\]\",:\\\\a1eE.+\\-tru \n`]{0,80}",
            size in 1usize..5,
        ) {
            let chunks = chunked(&text, size);
            proptest::prop_assert_eq!(pushes(&chunks), reference_pushes(&chunks));
            proptest::prop_assert_eq!(
                parse_partial_inner(&text),
                reference::parse_partial_inner(&text)
            );
        }
    }

    #[test]
    fn feed_reports_changes_and_current_builds_on_demand() {
        let mut p = PartialJsonParser::<Doc>::new();
        assert!(!p.feed("noise "));
        assert!(p.current().is_none());
        assert!(p.feed("{\"title\": \"a"));
        assert!(p.feed("b"));
        assert!(!p.feed("\""));
        assert_eq!(p.current().unwrap().value.unwrap().title, "ab");
        assert!(p.feed(", \"items\": [7]}"));
        let done = p.current().unwrap();
        assert!(done.complete);
        assert_eq!(done.value.unwrap().items, [7]);
        assert!(!p.feed(" more text"));
    }

    #[test]
    fn malformed_text_keeps_the_last_good_value() {
        let mut p = PartialJsonParser::<Value>::new();
        assert!(p.push("[1, 2").is_some());
        assert!(p.push(" x]").is_none());
        assert_eq!(p.current().unwrap().json, json!([1, 2]));
        assert!(p.push("[3]").is_none());

        let mut fed = PartialJsonParser::<Value>::new();
        assert!(fed.feed("[1, [2"));
        assert!(!fed.feed(", 3 x"));
        assert!(!fed.feed(","));
        assert_eq!(fed.current().unwrap().json, json!([1, [2, 3]]));
    }

    #[test]
    fn split_surrogate_pairs_wait_for_the_low_half() {
        let mut p = PartialJsonParser::<Value>::new();
        assert_eq!(p.push(r#"["a"#).unwrap().json, json!(["a"]));
        assert!(p.push(r"\ud83d").is_none());
        assert_eq!(p.push(r"\ude00").unwrap().json, json!(["a\u{1F600}"]));
    }

    /// One mebibyte in 4-byte chunks: linear time, not quadratic.
    #[test]
    fn large_streams_in_tiny_chunks_are_linear() {
        use std::fmt::Write as _;

        let mut doc = String::from("{\"items\": [");
        let mut i = 0u32;
        while doc.len() < (1 << 20) - 64 {
            if i > 0 {
                doc.push_str(", ");
            }
            let _ = write!(doc, "{{\"id\": {i}, \"text\": \"line {i} \\u00e9 ok\"}}");
            i += 1;
        }
        doc.push_str("], \"note\": \"");
        doc.push_str(&"x".repeat((1 << 20) - doc.len() - 2));
        doc.push_str("\"}");
        assert_eq!(doc.len(), 1 << 20);

        let started = std::time::Instant::now();
        let mut p = PartialJsonParser::<Value>::new();
        let mut changes = 0usize;
        for chunk in doc.as_bytes().chunks(4) {
            changes += usize::from(p.feed(std::str::from_utf8(chunk).unwrap()));
        }
        let elapsed = started.elapsed();
        let done = p.current().unwrap();
        assert!(done.complete);
        assert_eq!(done.json, serde_json::from_str::<Value>(&doc).unwrap());
        assert!(changes > 100_000, "{changes}");
        if !cfg!(debug_assertions) {
            assert!(elapsed.as_millis() < 500, "took {elapsed:?}");
        }
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

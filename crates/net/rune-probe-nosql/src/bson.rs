//! A minimal, bounded [BSON](https://bsonspec.org/spec.html) reader and
//! writer: enough to send MongoDB commands and read their replies.

use crate::Error;
use crate::wire::{Reader, text};

const WHAT: &str = "bson document";

/// Deepest nesting accepted.
const MAX_DEPTH: usize = 16;
/// Most elements accepted in one document.
const MAX_ELEMENTS: usize = 1024;

/// A BSON value. Types the probes never look at are kept only by type
/// byte.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Bson {
    /// `0x01` double.
    Double(f64),
    /// `0x02` UTF-8 string, printable and bounded.
    String(String),
    /// `0x03` embedded document.
    Document(Document),
    /// `0x04` array.
    Array(Vec<Self>),
    /// `0x08` boolean.
    Bool(bool),
    /// `0x0A` null.
    Null,
    /// `0x10` 32-bit integer.
    Int32(i32),
    /// `0x12` 64-bit integer.
    Int64(i64),
    /// Any other type, by type byte; its value is skipped.
    Other(u8),
}

impl Bson {
    /// The value as a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The value as an integer, converting doubles with no fraction.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked: the double is integral and in range"
    )]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Int32(v) => Some(i64::from(v)),
            Self::Int64(v) => Some(v),
            Self::Double(v) if v.fract() == 0.0 && v.abs() < 9.0e15 => Some(v as i64),
            _ => None,
        }
    }

    /// The value as a boolean; numbers are true when non-zero (MongoDB
    /// replies use `ok: 1.0`).
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            other => other.as_i64().map(|v| v != 0),
        }
    }

    /// The value as an embedded document.
    #[must_use]
    pub const fn as_document(&self) -> Option<&Document> {
        match self {
            Self::Document(d) => Some(d),
            _ => None,
        }
    }

    /// The value as an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// A BSON document: elements in order.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Document {
    /// The elements, in the order they appear.
    pub elements: Vec<(String, Bson)>,
}

impl Document {
    /// The first element named `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Bson> {
        self.elements.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Parse a document from the start of `bytes`, returning it and its
    /// length.
    ///
    /// ```
    /// use rune_probe_nosql::bson::{Bson, Document};
    ///
    /// let bytes = Document::encode(&[("ok", Bson::Double(1.0))]);
    /// let (doc, used) = Document::parse(&bytes)?;
    /// assert_eq!(used, bytes.len());
    /// assert_eq!(doc.get("ok").and_then(Bson::as_bool), Some(true));
    /// # Ok::<(), rune_probe_nosql::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when `bytes` ends inside the document, and
    /// [`Error::Malformed`] when it is not valid BSON or nests too deep.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), Error> {
        parse_document(bytes, 0)
    }

    /// Encode a document of doubles, integers, strings and booleans.
    /// Other value types are skipped.
    #[must_use]
    pub fn encode(elements: &[(&str, Bson)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, value) in elements {
            let (kind, bytes): (u8, Vec<u8>) = match value {
                Bson::Double(v) => (0x01, v.to_le_bytes().to_vec()),
                Bson::String(s) => {
                    let len = i32::try_from(s.len() + 1).unwrap_or(i32::MAX);
                    let mut b = len.to_le_bytes().to_vec();
                    b.extend_from_slice(s.as_bytes());
                    b.push(0);
                    (0x02, b)
                }
                Bson::Bool(v) => (0x08, vec![u8::from(*v)]),
                Bson::Int32(v) => (0x10, v.to_le_bytes().to_vec()),
                Bson::Int64(v) => (0x12, v.to_le_bytes().to_vec()),
                _ => continue,
            };
            body.push(kind);
            body.extend(key.bytes().filter(|&b| b != 0));
            body.push(0);
            body.extend_from_slice(&bytes);
        }
        let len = i32::try_from(body.len() + 5).unwrap_or(i32::MAX);
        let mut out = len.to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out.push(0);
        out
    }
}

fn parse_document(bytes: &[u8], depth: usize) -> Result<(Document, usize), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::malformed(WHAT, "nested too deep"));
    }
    let mut r = Reader::new(bytes, WHAT);
    let len = usize::try_from(r.u32_le()?).unwrap_or(usize::MAX);
    if len < 5 {
        return Err(Error::malformed(WHAT, format!("length {len}")));
    }
    let body = r.take(len - 4)?;
    let Some((&0, body)) = body.split_last() else {
        return Err(Error::malformed(WHAT, "missing terminator"));
    };
    // Inside a complete document, running out of bytes is malformed.
    let malformed = |e: Error| match e {
        Error::Truncated { .. } => Error::malformed(WHAT, "element overruns the document"),
        other => other,
    };
    let mut r = Reader::new(body, WHAT);
    let mut doc = Document::default();
    while !r.is_empty() {
        if doc.elements.len() >= MAX_ELEMENTS {
            return Err(Error::malformed(WHAT, "too many elements"));
        }
        let kind = r.u8().map_err(malformed)?;
        let key = text(r.cstr().map_err(malformed)?);
        let value = parse_value(kind, &mut r, depth).map_err(malformed)?;
        doc.elements.push((key, value));
    }
    Ok((doc, len))
}

fn string(r: &mut Reader<'_>) -> Result<String, Error> {
    let len = usize::try_from(r.u32_le()?).unwrap_or(usize::MAX);
    if len == 0 {
        return Err(Error::malformed(WHAT, "zero string length"));
    }
    let bytes = r.take(len)?;
    Ok(text(bytes.get(..len - 1).unwrap_or_default()))
}

fn parse_value(kind: u8, r: &mut Reader<'_>, depth: usize) -> Result<Bson, Error> {
    Ok(match kind {
        0x01 => Bson::Double(f64::from_le_bytes(r.array()?)),
        0x02 => Bson::String(string(r)?),
        0x03 | 0x04 => {
            let (doc, used) = parse_document(r.rest(), depth + 1)?;
            r.take(used)?;
            if kind == 0x03 {
                Bson::Document(doc)
            } else {
                Bson::Array(doc.elements.into_iter().map(|(_, v)| v).collect())
            }
        }
        0x05 => {
            let len = usize::try_from(r.u32_le()?).unwrap_or(usize::MAX);
            r.take(1)?;
            r.take(len)?;
            Bson::Other(kind)
        }
        0x06 | 0x7f | 0xff => Bson::Other(kind),
        0x07 => {
            r.take(12)?;
            Bson::Other(kind)
        }
        0x08 => Bson::Bool(r.u8()? != 0),
        0x09 | 0x11 => {
            r.take(8)?;
            Bson::Other(kind)
        }
        0x0a => Bson::Null,
        0x0b => {
            r.cstr()?;
            r.cstr()?;
            Bson::Other(kind)
        }
        0x0c => {
            string(r)?;
            r.take(12)?;
            Bson::Other(kind)
        }
        0x0d | 0x0e => {
            string(r)?;
            Bson::Other(kind)
        }
        0x0f => {
            let len = usize::try_from(r.u32_le()?).unwrap_or(usize::MAX);
            r.take(len.saturating_sub(4))?;
            Bson::Other(kind)
        }
        0x10 => Bson::Int32(i32::from_le_bytes(r.array()?)),
        0x12 => Bson::Int64(i64::from_le_bytes(r.array()?)),
        0x13 => {
            r.take(16)?;
            Bson::Other(kind)
        }
        other => return Err(Error::malformed(WHAT, format!("element type {other:#04x}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_hello_doc() {
        // {"hello": 1} from the BSON spec examples' layout.
        assert_eq!(
            Document::encode(&[("hello", Bson::Int32(1))]),
            [
                16, 0, 0, 0, 0x10, b'h', b'e', b'l', b'l', b'o', 0, 1, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn round_trips_and_nests() {
        let inner = Document::encode(&[("a", Bson::String("x".into()))]);
        let mut outer = vec![0, 0, 0, 0, 0x03, b'd', 0];
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&[0x04, b'l', 0]);
        outer.extend_from_slice(&Document::encode(&[
            ("0", Bson::Int64(7)),
            ("1", Bson::Bool(true)),
        ]));
        outer.extend_from_slice(&[0x07, b'o', 0]);
        outer.extend_from_slice(&[0; 12]);
        outer.push(0);
        let len = u32::try_from(outer.len()).unwrap();
        outer[..4].copy_from_slice(&len.to_le_bytes());
        let (doc, used) = Document::parse(&outer).unwrap();
        assert_eq!(used, outer.len());
        let d = doc.get("d").and_then(Bson::as_document).unwrap();
        assert_eq!(d.get("a").and_then(Bson::as_str), Some("x"));
        let l = doc.get("l").and_then(Bson::as_array).unwrap();
        assert_eq!(l, [Bson::Int64(7), Bson::Bool(true)]);
        assert_eq!(doc.get("o"), Some(&Bson::Other(0x07)));
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(Document::parse(&[5, 0, 0]).unwrap_err().is_truncated());
        assert!(matches!(
            Document::parse(&[4, 0, 0, 0]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            Document::parse(&[5, 0, 0, 0, 1]),
            Err(Error::Malformed { .. })
        ));
        // An int32 element cut short inside a complete document.
        assert!(matches!(
            Document::parse(&[9, 0, 0, 0, 0x10, b'a', 0, 1, 0]),
            Err(Error::Malformed { .. })
        ));
        // Deep nesting.
        let mut deep = Document::encode(&[]);
        for _ in 0..40 {
            let mut d = vec![0, 0, 0, 0, 0x03, b'x', 0];
            d.extend_from_slice(&deep);
            d.push(0);
            let len = u32::try_from(d.len()).unwrap();
            d[..4].copy_from_slice(&len.to_le_bytes());
            deep = d;
        }
        assert!(matches!(
            Document::parse(&deep),
            Err(Error::Malformed { .. })
        ));
    }
}

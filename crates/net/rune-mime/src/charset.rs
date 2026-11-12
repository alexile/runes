//! Charset labels, detection and decoding of the common single-byte and
//! Unicode charsets.
//!
//! Detection follows the precedence of the [WHATWG encoding sniffing
//! algorithm]: a byte order mark, then the transport-declared charset
//! (`Content-Type`), then an in-document declaration (HTML `<meta>`, XML
//! declaration, CSS `@charset`), then content heuristics.
//!
//! [WHATWG encoding sniffing algorithm]: https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding

use std::borrow::Cow;
use std::fmt;

/// How many leading bytes the in-document prescan looks at.
const PRESCAN_BYTES: usize = 1024;

/// A character encoding, identified by label.
///
/// Labels normalise to one variant (`latin1`, `ISO_8859-1` and `l1` are all
/// [`Charset::Iso8859_1`]); anything unknown is kept, lowercased, in
/// [`Charset::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Charset {
    /// UTF-8.
    Utf8,
    /// UTF-16, little-endian.
    Utf16Le,
    /// UTF-16, big-endian.
    Utf16Be,
    /// US-ASCII.
    UsAscii,
    /// ISO-8859-1 (Latin-1), decoded byte-for-byte to U+0000..U+00FF.
    Iso8859_1,
    /// Windows-1252.
    Windows1252,
    /// Any other label, trimmed and lowercased. Not decodable here.
    Other(String),
}

impl Charset {
    /// Normalises a charset label (case-insensitive, surrounding whitespace
    /// and quotes ignored).
    ///
    /// ```
    /// use rune_mime::Charset;
    ///
    /// assert_eq!(Charset::from_label(" UTF8 "), Charset::Utf8);
    /// assert_eq!(Charset::from_label("latin1"), Charset::Iso8859_1);
    /// assert_eq!(Charset::from_label("Shift_JIS"), Charset::Other("shift_jis".into()));
    /// ```
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let label = label
            .trim_matches(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'')
            .to_ascii_lowercase();
        match label.as_str() {
            "utf-8" | "utf8" | "unicode-1-1-utf-8" | "x-unicode20utf8" => Self::Utf8,
            "utf-16le" | "utf-16" | "ucs-2" | "unicode" | "csunicode" | "unicodefeff" => {
                Self::Utf16Le
            }
            "utf-16be" | "unicodefffe" => Self::Utf16Be,
            "us-ascii" | "ascii" | "ansi_x3.4-1968" | "iso646-us" | "us" | "cp367" | "ibm367"
            | "csascii" | "iso-ir-6" => Self::UsAscii,
            "iso-8859-1" | "iso8859-1" | "iso_8859-1" | "iso_8859-1:1987" | "latin1" | "l1"
            | "cp819" | "ibm819" | "iso-ir-100" | "csisolatin1" | "iso88591" => Self::Iso8859_1,
            "windows-1252" | "cp1252" | "x-cp1252" | "win-1252" => Self::Windows1252,
            _ => Self::Other(label),
        }
    }

    /// The canonical (IANA) name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Utf16Be => "utf-16be",
            Self::UsAscii => "us-ascii",
            Self::Iso8859_1 => "iso-8859-1",
            Self::Windows1252 => "windows-1252",
            Self::Other(label) => label,
        }
    }

    /// `true` if [`decode`](Self::decode) supports this charset.
    #[must_use]
    pub const fn is_decodable(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Decodes `bytes` to text. Malformed sequences (invalid UTF-8, a lone
    /// surrogate, non-ASCII bytes in US-ASCII, an odd trailing byte in
    /// UTF-16) become U+FFFD. A leading BOM of the same encoding is
    /// dropped. Returns `None` for [`Charset::Other`].
    ///
    /// ```
    /// use rune_mime::Charset;
    ///
    /// assert_eq!(Charset::Windows1252.decode(b"\x93hi\x94").unwrap(), "\u{201c}hi\u{201d}");
    /// assert_eq!(Charset::Utf16Be.decode(b"\xfe\xff\x00h\x00i").unwrap(), "hi");
    /// ```
    #[must_use]
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Option<Cow<'a, str>> {
        Some(match self {
            Self::Utf8 => String::from_utf8_lossy(bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes)),
            Self::Utf16Le => Cow::Owned(decode_utf16(
                bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes),
                u16::from_le_bytes,
            )),
            Self::Utf16Be => Cow::Owned(decode_utf16(
                bytes.strip_prefix(&[0xFE, 0xFF]).unwrap_or(bytes),
                u16::from_be_bytes,
            )),
            Self::UsAscii => match std::str::from_utf8(bytes) {
                Ok(text) if bytes.is_ascii() => Cow::Borrowed(text),
                _ => Cow::Owned(
                    bytes
                        .iter()
                        .map(|&b| {
                            if b.is_ascii() {
                                char::from(b)
                            } else {
                                '\u{FFFD}'
                            }
                        })
                        .collect(),
                ),
            },
            Self::Iso8859_1 => latin(bytes, char::from),
            Self::Windows1252 => latin(bytes, windows_1252),
            Self::Other(_) => return None,
        })
    }
}

impl fmt::Display for Charset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let (pairs, rest) = bytes.as_chunks::<2>();
    let mut text: String = char::decode_utf16(pairs.iter().map(|&pair| unit(pair)))
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !rest.is_empty() {
        text.push(char::REPLACEMENT_CHARACTER);
    }
    text
}

fn latin(bytes: &[u8], map: fn(u8) -> char) -> Cow<'_, str> {
    if bytes.is_ascii() {
        // ASCII bytes are valid UTF-8.
        String::from_utf8_lossy(bytes)
    } else {
        Cow::Owned(bytes.iter().map(|&b| map(b)).collect())
    }
}

/// Windows-1252, per the WHATWG index (0x81, 0x8D, 0x8F, 0x90 and 0x9D map
/// to the C1 controls).
fn windows_1252(byte: u8) -> char {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}',
        '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    ];
    match byte {
        0x80..=0x9F => HIGH
            .get(usize::from(byte - 0x80))
            .copied()
            .unwrap_or(char::REPLACEMENT_CHARACTER),
        _ => char::from(byte),
    }
}

/// Where a detected charset came from, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CharsetSource {
    /// A byte order mark at the start of the body.
    Bom,
    /// The charset the caller passed in (normally the `Content-Type`
    /// `charset` parameter).
    Declared,
    /// An in-document declaration: HTML `<meta>`, the XML declaration or CSS
    /// `@charset`.
    Document,
    /// The body is valid UTF-8 and not plain ASCII.
    Utf8Valid,
    /// The body is plain ASCII.
    Ascii,
    /// Nothing matched; Windows-1252 is assumed, as browsers do.
    Fallback,
}

/// The result of [`detect_charset`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CharsetMatch {
    /// The detected charset.
    pub charset: Charset,
    /// What the detection is based on.
    pub source: CharsetSource,
}

/// Detects the charset of `body`, given the charset declared by the
/// transport (the `Content-Type` `charset` parameter), if any.
///
/// ```
/// use rune_mime::{Charset, CharsetSource, detect_charset};
///
/// let html = b"<html><head><meta charset='iso-8859-1'></head>";
/// let found = detect_charset(html, None);
/// assert_eq!(found.charset, Charset::Iso8859_1);
/// assert_eq!(found.source, CharsetSource::Document);
///
/// // A BOM beats the header.
/// let found = detect_charset(b"\xef\xbb\xbfhi", Some("latin1"));
/// assert_eq!((found.charset, found.source), (Charset::Utf8, CharsetSource::Bom));
/// ```
#[must_use]
pub fn detect_charset(body: &[u8], declared: Option<&str>) -> CharsetMatch {
    let found = |charset, source| CharsetMatch { charset, source };
    if let Some(charset) = bom(body) {
        return found(charset, CharsetSource::Bom);
    }
    if let Some(label) = declared.filter(|label| !label.trim().is_empty()) {
        return found(Charset::from_label(label), CharsetSource::Declared);
    }
    if let Some(label) = prescan(body) {
        return found(Charset::from_label(&label), CharsetSource::Document);
    }
    if body.is_ascii() {
        found(Charset::UsAscii, CharsetSource::Ascii)
    } else if std::str::from_utf8(body).is_ok() {
        found(Charset::Utf8, CharsetSource::Utf8Valid)
    } else {
        found(Charset::Windows1252, CharsetSource::Fallback)
    }
}

/// The charset a byte order mark at the start of `body` names.
#[must_use]
pub fn bom(body: &[u8]) -> Option<Charset> {
    if body.starts_with(UTF8_BOM) {
        Some(Charset::Utf8)
    } else if body.starts_with(&[0xFE, 0xFF]) {
        Some(Charset::Utf16Be)
    } else if body.starts_with(&[0xFF, 0xFE]) {
        Some(Charset::Utf16Le)
    } else {
        None
    }
}

/// Looks for an in-document charset declaration in the first
/// [`PRESCAN_BYTES`] bytes: `@charset "…";`, `<?xml … encoding="…"?>`, or a
/// `<meta>` tag with `charset=` (both `<meta charset>` and the
/// `http-equiv` / `content` form).
fn prescan(body: &[u8]) -> Option<String> {
    let head = body.get(..PRESCAN_BYTES).unwrap_or(body);
    let lower = head.to_ascii_lowercase();

    if let Some(rest) = lower.strip_prefix(b"@charset \"") {
        let end = rest.iter().position(|&b| b == b'"')?;
        return label(rest.get(..end)?);
    }
    if let Some(decl) = lower.strip_prefix(b"<?xml") {
        let decl = decl.get(..find(decl, b"?>")?)?;
        let at = find(decl, b"encoding")?;
        return attribute_value(decl.get(at + b"encoding".len()..)?);
    }
    let mut from = 0;
    while let Some(at) = lower.get(from..).and_then(|rest| find(rest, b"<meta")) {
        let tag_start = from + at + b"<meta".len();
        let tag = lower.get(tag_start..)?;
        let tag = tag.get(..tag.iter().position(|&b| b == b'>').unwrap_or(tag.len()))?;
        if let Some(at) = find(tag, b"charset")
            && let Some(value) = tag.get(at + b"charset".len()..).and_then(attribute_value)
        {
            return Some(value);
        }
        from = tag_start;
    }
    None
}

/// Parses `\s* "=" \s* ( "…" / '…' / bare )` and returns the value.
fn attribute_value(text: &[u8]) -> Option<String> {
    let text = trim_start(text).strip_prefix(b"=")?;
    let text = trim_start(text);
    let (quote, text) = match text.first() {
        Some(&q @ (b'"' | b'\'')) => (Some(q), text.get(1..)?),
        _ => (None, text),
    };
    let end = text
        .iter()
        .position(|&b| {
            quote.map_or_else(
                || b.is_ascii_whitespace() || matches!(b, b';' | b'"' | b'\'' | b'/' | b'>'),
                |q| b == q,
            )
        })
        .unwrap_or(text.len());
    label(text.get(..end)?)
}

fn label(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    (!text.is_empty() && text.len() <= 64).then(|| text.to_owned())
}

fn trim_start(text: &[u8]) -> &[u8] {
    let start = text
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(text.len());
    text.get(start..).unwrap_or_default()
}

/// First index of `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence() {
        assert_eq!(
            detect_charset(b"<meta charset=utf-8>\xe9", Some("windows-1252")).source,
            CharsetSource::Declared
        );
        assert_eq!(
            detect_charset(b"<meta charset=koi8-r>", Some("  ")).charset,
            Charset::Other("koi8-r".into())
        );
        assert_eq!(
            detect_charset("caf\u{e9}".as_bytes(), None).source,
            CharsetSource::Utf8Valid
        );
        assert_eq!(
            detect_charset(b"caf\xe9", None).charset,
            Charset::Windows1252
        );
        assert_eq!(detect_charset(b"", None).source, CharsetSource::Ascii);
        assert_eq!(
            detect_charset(b"\xff\xfeh\x00", None).charset,
            Charset::Utf16Le
        );
    }

    #[test]
    fn in_document_declarations() {
        let cases: [(&[u8], Charset); 5] = [
            (
                b"<?xml version=\"1.0\" encoding='ISO-8859-1'?><a/>",
                Charset::Iso8859_1,
            ),
            (b"@charset \"UTF-8\";\nbody{}", Charset::Utf8),
            (
                b"<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=windows-1252\">",
                Charset::Windows1252,
            ),
            (
                b"<meta name=x><meta charset = \"latin1\" >",
                Charset::Iso8859_1,
            ),
            (b"<meta charset=utf-8/>", Charset::Utf8),
        ];
        for (body, expected) in cases {
            let found = detect_charset(body, None);
            assert_eq!(found.charset, expected, "{}", String::from_utf8_lossy(body));
            assert_eq!(found.source, CharsetSource::Document);
        }
        assert_eq!(prescan(b"<meta name=charset>"), None);
        assert_eq!(prescan(b"<meta charset=>"), None);
    }

    #[test]
    fn decoding() {
        assert_eq!(Charset::Iso8859_1.decode(b"caf\xe9").unwrap(), "café");
        assert_eq!(
            Charset::Windows1252.decode(b"\x80\x81\x9f").unwrap(),
            "€\u{81}Ÿ"
        );
        assert_eq!(Charset::UsAscii.decode(b"a\xffb").unwrap(), "a\u{fffd}b");
        assert_eq!(
            Charset::Utf16Le.decode(b"h\x00i\x00!").unwrap(),
            "hi\u{fffd}"
        );
        assert_eq!(Charset::Utf16Be.decode(b"\xd8\x00").unwrap(), "\u{fffd}");
        assert_eq!(Charset::Utf8.decode(b"\xef\xbb\xbfok").unwrap(), "ok");
        assert!(matches!(
            Charset::Utf8.decode(b"ok").unwrap(),
            Cow::Borrowed(_)
        ));
        assert!(Charset::Other("koi8-r".into()).decode(b"x").is_none());
    }

    #[test]
    fn labels_round_trip_through_names() {
        for charset in [
            Charset::Utf8,
            Charset::Utf16Le,
            Charset::Utf16Be,
            Charset::UsAscii,
            Charset::Iso8859_1,
            Charset::Windows1252,
        ] {
            assert_eq!(Charset::from_label(charset.name()), charset);
            assert!(charset.is_decodable());
        }
    }
}

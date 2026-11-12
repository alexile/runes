//! Bounded multipart parsing and encoding ([RFC 2046 §5.1], [RFC 7578]).
//!
//! The parser borrows part bodies from the input and records the byte
//! range of every header block and body, so tools that rewrite one field
//! (insertion points, fuzzers) can splice the original bytes. Work and
//! allocation are bounded by [`MultipartOptions`]; no input panics.
//!
//! [RFC 2046 §5.1]: https://www.rfc-editor.org/rfc/rfc2046#section-5.1
//! [RFC 7578]: https://www.rfc-editor.org/rfc/rfc7578

use std::ops::Range;

use rune_http_model::{HeaderEntry, header_value};

use crate::charset::find;
use crate::params::{Param, is_token};
use crate::{ContentDisposition, MediaType, MimeError};

/// Longest boundary [`parse_multipart`] accepts. RFC 2046 caps boundaries
/// at 70 characters, but parsers in the wild accept longer ones, so the
/// parser is lenient (the encoder is not).
pub const MAX_PARSE_BOUNDARY: usize = 256;

/// Limits and leniency for [`parse_multipart`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultipartOptions {
    /// Most parts accepted. Default 1024.
    pub max_parts: usize,
    /// Largest header block per part, in bytes, including line breaks and
    /// the blank line. Default 16 KiB.
    pub max_header_bytes: usize,
    /// Most header fields per part. Default 64.
    pub max_headers: usize,
    /// Fail with [`MimeError::Unterminated`] when the closing delimiter is
    /// missing. When `false`, the last part runs to the end of the input
    /// and [`Multipart::closed`] is `false`. Default `true`.
    pub require_close: bool,
}

impl Default for MultipartOptions {
    fn default() -> Self {
        Self {
            max_parts: 1024,
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            require_close: true,
        }
    }
}

impl MultipartOptions {
    /// Sets [`max_parts`](Self::max_parts).
    #[must_use]
    pub const fn with_max_parts(mut self, max_parts: usize) -> Self {
        self.max_parts = max_parts;
        self
    }

    /// Sets [`max_header_bytes`](Self::max_header_bytes).
    #[must_use]
    pub const fn with_max_header_bytes(mut self, max_header_bytes: usize) -> Self {
        self.max_header_bytes = max_header_bytes;
        self
    }

    /// Sets [`max_headers`](Self::max_headers).
    #[must_use]
    pub const fn with_max_headers(mut self, max_headers: usize) -> Self {
        self.max_headers = max_headers;
        self
    }

    /// Sets [`require_close`](Self::require_close).
    #[must_use]
    pub const fn with_require_close(mut self, require_close: bool) -> Self {
        self.require_close = require_close;
        self
    }
}

/// One body part.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Part<'a> {
    /// Header fields in order. Folded lines are joined with one space,
    /// values are trimmed, and non-UTF-8 bytes are replaced with U+FFFD
    /// (the raw bytes stay available through
    /// [`headers_range`](Self::headers_range)).
    pub headers: Vec<HeaderEntry>,
    /// The part body, borrowed from the input.
    pub body: &'a [u8],
    /// Where the header block (including the blank line) sits in the
    /// input. Empty for parts built with [`Part::new`].
    pub headers_range: Range<usize>,
    /// Where [`body`](Self::body) sits in the input. For parts built with
    /// [`Part::new`], `0..body.len()`.
    pub body_range: Range<usize>,
}

impl<'a> Part<'a> {
    /// A part with the given headers and body, for [`encode_multipart`].
    #[must_use]
    pub const fn new(headers: Vec<HeaderEntry>, body: &'a [u8]) -> Self {
        Self {
            headers,
            body,
            headers_range: 0..0,
            body_range: 0..body.len(),
        }
    }

    /// A `multipart/form-data` text field: `Content-Disposition:
    /// form-data; name="…"`.
    ///
    /// # Errors
    ///
    /// Never in practice; kept fallible for symmetry with
    /// [`form_file`](Self::form_file).
    pub fn form_field(name: &str, value: &'a [u8]) -> Result<Self, MimeError> {
        let disposition = ContentDisposition::form_data(name)?;
        Ok(Self::new(
            vec![HeaderEntry::new(
                "Content-Disposition",
                disposition.to_string(),
            )],
            value,
        ))
    }

    /// A `multipart/form-data` file field with a file name and content
    /// type. Non-ASCII file names are also sent as `filename*`.
    ///
    /// # Errors
    ///
    /// Never in practice; parameter names are fixed tokens.
    pub fn form_file(
        name: &str,
        filename: &str,
        content_type: &MediaType,
        data: &'a [u8],
    ) -> Result<Self, MimeError> {
        let mut disposition = ContentDisposition::form_data(name)?;
        if filename.is_ascii() {
            disposition = disposition.with_param("filename", filename)?;
        } else {
            disposition = disposition.with_param("filename", ascii_fallback(filename))?;
            disposition
                .params
                .push(Param::extended("filename", filename)?);
        }
        Ok(Self::new(
            vec![
                HeaderEntry::new("Content-Disposition", disposition.to_string()),
                HeaderEntry::new("Content-Type", content_type.to_string()),
            ],
            data,
        ))
    }

    /// The first header value called `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// The parsed `Content-Type`, if the part has one. RFC 2046 makes a
    /// missing one `text/plain; charset=us-ascii`; RFC 7578 makes it
    /// `text/plain` for form fields.
    #[must_use]
    pub fn content_type(&self) -> Option<Result<MediaType, MimeError>> {
        self.header("content-type").map(MediaType::parse)
    }

    /// The parsed `Content-Disposition`, if the part has one.
    #[must_use]
    pub fn content_disposition(&self) -> Option<Result<ContentDisposition, MimeError>> {
        self.header("content-disposition")
            .map(ContentDisposition::parse)
    }

    /// The form field name (`Content-Disposition` `name`), if it parses.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.content_disposition()?.ok()?.name().map(str::to_owned)
    }

    /// The file name (`filename*` or `filename`), if it parses. Returned as
    /// sent: sanitise it before touching the file system.
    #[must_use]
    pub fn filename(&self) -> Option<String> {
        self.content_disposition()?
            .ok()?
            .filename()
            .map(str::to_owned)
    }
}

/// Replaces every non-ASCII character with `_`.
fn ascii_fallback(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect()
}

/// A parsed multipart body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Multipart<'a> {
    /// Bytes before the first delimiter (ignored by recipients).
    pub preamble: &'a [u8],
    /// The body parts, in order.
    pub parts: Vec<Part<'a>>,
    /// Bytes after the closing delimiter line (ignored by recipients).
    pub epilogue: &'a [u8],
    /// `true` if the closing `--boundary--` delimiter was seen.
    pub closed: bool,
}

impl<'a> Multipart<'a> {
    /// The first part whose form field name is `name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Part<'a>> {
        self.parts
            .iter()
            .find(|part| part.name().as_deref() == Some(name))
    }
}

/// Checks a boundary against RFC 2046 §5.1.1: 1 to 70 characters from
/// `bchars`, not ending in a space.
///
/// # Errors
///
/// [`MimeError::InvalidBoundary`].
pub fn validate_boundary(boundary: &str) -> Result<(), MimeError> {
    let bchar = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'\''
                    | b'('
                    | b')'
                    | b'+'
                    | b'_'
                    | b','
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b'='
                    | b'?'
                    | b' '
            )
    };
    let valid = (1..=70).contains(&boundary.len())
        && boundary.bytes().all(bchar)
        && !boundary.ends_with(' ');
    if valid {
        Ok(())
    } else {
        Err(MimeError::InvalidBoundary(boundary.to_owned()))
    }
}

/// Parses a multipart body given its `Content-Type`, which must be
/// `multipart/*` with a `boundary`.
///
/// # Errors
///
/// [`MimeError::NotMultipart`], [`MimeError::MissingBoundary`], or any
/// error of [`parse_multipart`].
pub fn parse_multipart_body<'a>(
    content_type: &MediaType,
    body: &'a [u8],
    options: &MultipartOptions,
) -> Result<Multipart<'a>, MimeError> {
    if !content_type.is_multipart() {
        return Err(MimeError::NotMultipart(content_type.essence()));
    }
    let boundary = content_type.boundary().ok_or(MimeError::MissingBoundary)?;
    parse_multipart(body, boundary, options)
}

/// Parses a multipart body with the given boundary.
///
/// Line breaks may be CRLF or bare LF. A delimiter is `--boundary` at the
/// start of a line, followed by optional spaces or tabs and a line break,
/// or by `--` for the closing one; any other line that merely starts with
/// `--boundary` is body content.
///
/// ```
/// use rune_mime::{MultipartOptions, parse_multipart};
///
/// let body = b"preamble\r\n--XyZ\r\n\
///     Content-Disposition: form-data; name=\"user\"\r\n\r\n\
///     alice\r\n--XyZ\r\n\
///     Content-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n\
///     Content-Type: text/plain\r\n\r\n\
///     hello\r\n--XyZ--\r\n";
/// let multipart = parse_multipart(body, "XyZ", &MultipartOptions::default()).unwrap();
/// assert_eq!(multipart.preamble, b"preamble");
/// assert_eq!(multipart.parts.len(), 2);
/// let doc = multipart.field("doc").unwrap();
/// assert_eq!(doc.filename().as_deref(), Some("a.txt"));
/// assert_eq!(doc.body, b"hello");
/// assert_eq!(&body[doc.body_range.clone()], b"hello");
/// ```
///
/// # Errors
///
/// [`MimeError::InvalidBoundary`] (empty, longer than
/// [`MAX_PARSE_BOUNDARY`], or containing a line break),
/// [`MimeError::NoOpeningDelimiter`], [`MimeError::Unterminated`],
/// [`MimeError::MalformedPartHeaders`], and the limit errors of
/// [`MultipartOptions`].
pub fn parse_multipart<'a>(
    body: &'a [u8],
    boundary: &str,
    options: &MultipartOptions,
) -> Result<Multipart<'a>, MimeError> {
    if boundary.is_empty() || boundary.len() > MAX_PARSE_BOUNDARY || boundary.contains(['\r', '\n'])
    {
        return Err(MimeError::InvalidBoundary(boundary.to_owned()));
    }
    let mut dash_boundary = Vec::with_capacity(boundary.len() + 2);
    dash_boundary.extend_from_slice(b"--");
    dash_boundary.extend_from_slice(boundary.as_bytes());

    let first = next_delimiter(body, 0, &dash_boundary).ok_or(MimeError::NoOpeningDelimiter)?;
    let mut multipart = Multipart {
        preamble: body.get(..first.line_start).unwrap_or_default(),
        parts: Vec::new(),
        epilogue: &[],
        closed: false,
    };
    if first.close {
        multipart.closed = true;
        multipart.epilogue = body.get(first.after..).unwrap_or_default();
        return Ok(multipart);
    }

    let mut cursor = first.after;
    loop {
        let next = next_delimiter(body, cursor, &dash_boundary);
        let content_end = match &next {
            Some(delimiter) => delimiter.line_start.max(cursor),
            None if options.require_close => return Err(MimeError::Unterminated),
            None if cursor >= body.len() => break,
            None => body.len(),
        };
        if multipart.parts.len() >= options.max_parts {
            return Err(MimeError::TooManyParts {
                limit: options.max_parts,
            });
        }
        let index = multipart.parts.len();
        multipart
            .parts
            .push(parse_part(body, cursor..content_end, index, options)?);
        match next {
            None => break,
            Some(delimiter) if delimiter.close => {
                multipart.closed = true;
                multipart.epilogue = body.get(delimiter.after..).unwrap_or_default();
                break;
            }
            Some(delimiter) => cursor = delimiter.after,
        }
    }
    Ok(multipart)
}

/// A delimiter line found in the input.
struct Delimiter {
    /// Start of the line break before `--boundary` (it belongs to the
    /// delimiter), or of `--boundary` itself at the start of the input.
    line_start: usize,
    /// First byte after the delimiter line, including its line break.
    after: usize,
    /// `true` for the closing `--boundary--`.
    close: bool,
}

fn next_delimiter(body: &[u8], from: usize, dash_boundary: &[u8]) -> Option<Delimiter> {
    let mut search = from;
    loop {
        let at = search + find(body.get(search..)?, dash_boundary)?;
        let at_line_start = at == 0 || body.get(at - 1) == Some(&b'\n');
        if at_line_start
            && let Some((after, close)) = delimiter_tail(body, at + dash_boundary.len())
        {
            let line_start = if at == 0 {
                0
            } else if at >= 2 && body.get(at - 2) == Some(&b'\r') {
                at - 2
            } else {
                at - 1
            };
            return Some(Delimiter {
                line_start,
                after,
                close,
            });
        }
        search = at + 1;
    }
}

/// Checks what follows `--boundary` at `at`. Returns the end of the
/// delimiter line and whether it closes the body, or `None` if this is not
/// a delimiter.
fn delimiter_tail(body: &[u8], at: usize) -> Option<(usize, bool)> {
    let rest = body.get(at..).unwrap_or_default();
    let (close, skip) = if rest.starts_with(b"--") {
        (true, 2)
    } else {
        (false, 0)
    };
    let mut pos = at + skip;
    while matches!(body.get(pos), Some(b' ' | b'\t')) {
        pos += 1;
    }
    match (body.get(pos), body.get(pos + 1)) {
        (Some(b'\r'), Some(b'\n')) => Some((pos + 2, close)),
        (Some(b'\n'), _) => Some((pos + 1, close)),
        (None, _) => Some((pos, close)),
        // Anything after a closing `--` on the same line is epilogue.
        _ if close => Some((at + skip, close)),
        _ => None,
    }
}

fn parse_part<'a>(
    body: &'a [u8],
    range: Range<usize>,
    index: usize,
    options: &MultipartOptions,
) -> Result<Part<'a>, MimeError> {
    let malformed = MimeError::MalformedPartHeaders { part: index };
    let content = body.get(range.clone()).unwrap_or_default();
    if content.is_empty() {
        return Ok(Part {
            headers: Vec::new(),
            body: content,
            headers_range: range.start..range.start,
            body_range: range,
        });
    }
    let too_large = MimeError::PartHeadersTooLarge {
        part: index,
        limit: options.max_header_bytes,
    };

    let mut headers: Vec<HeaderEntry> = Vec::new();
    let mut pos = 0;
    loop {
        // Look for the line end no further than the header limit allows.
        let window_end = content
            .len()
            .min(options.max_header_bytes.saturating_add(1));
        let window = content.get(pos..window_end).unwrap_or_default();
        let Some(newline) = window.iter().position(|&b| b == b'\n') else {
            return Err(if window_end < content.len() {
                too_large
            } else {
                malformed
            });
        };
        let next = pos + newline + 1;
        if next > options.max_header_bytes {
            return Err(too_large);
        }
        let line = window.get(..newline).unwrap_or_default();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        pos = next;
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            // obs-fold: continue the previous field.
            let last = headers.last_mut().ok_or_else(|| malformed.clone())?;
            let more = String::from_utf8_lossy(line);
            let more = more.trim_matches([' ', '\t']);
            if !more.is_empty() {
                if !last.value.is_empty() {
                    last.value.push(' ');
                }
                last.value.push_str(more);
            }
            continue;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| malformed.clone())?;
        let name = std::str::from_utf8(line.get(..colon).unwrap_or_default())
            .ok()
            .filter(|name| is_token(name))
            .ok_or_else(|| malformed.clone())?;
        if headers.len() >= options.max_headers {
            return Err(MimeError::TooManyHeaders {
                part: index,
                limit: options.max_headers,
            });
        }
        let value = String::from_utf8_lossy(line.get(colon + 1..).unwrap_or_default());
        headers.push(HeaderEntry::new(name, value.trim_matches([' ', '\t'])));
    }
    let body_start = range.start + pos;
    Ok(Part {
        headers,
        body: body.get(body_start..range.end).unwrap_or_default(),
        headers_range: range.start..body_start,
        body_range: body_start..range.end,
    })
}

/// Encodes parts as a multipart body with CRLF line breaks:
/// `--boundary CRLF headers CRLF CRLF body CRLF … --boundary-- CRLF`.
///
/// The output parses back with [`parse_multipart`] to the same headers and
/// bodies (header values are trimmed by the parser, so leading or trailing
/// whitespace in a value is not preserved).
///
/// ```
/// use rune_mime::{MediaType, MultipartOptions, Part, encode_multipart, parse_multipart};
///
/// let png = MediaType::new("image", "png").unwrap();
/// let parts = [
///     Part::form_field("title", b"Hi").unwrap(),
///     Part::form_file("pic", "a.png", &png, b"\x89PNG").unwrap(),
/// ];
/// let body = encode_multipart("b0undary", &parts).unwrap();
/// let back = parse_multipart(&body, "b0undary", &MultipartOptions::default()).unwrap();
/// assert_eq!(back.parts[1].filename().as_deref(), Some("a.png"));
/// assert_eq!(back.parts[1].body, b"\x89PNG");
/// ```
///
/// # Errors
///
/// [`MimeError::InvalidBoundary`] if the boundary breaks RFC 2046,
/// [`MimeError::InvalidValue`] for a header name that is not a token or a
/// value with a line break, and [`MimeError::BoundaryInBody`] if a body
/// contains a line starting with `--boundary`.
pub fn encode_multipart(boundary: &str, parts: &[Part<'_>]) -> Result<Vec<u8>, MimeError> {
    validate_boundary(boundary)?;
    let mut dash_boundary = b"--".to_vec();
    dash_boundary.extend_from_slice(boundary.as_bytes());
    let mut line_boundary = b"\n".to_vec();
    line_boundary.extend_from_slice(&dash_boundary);

    let size: usize = parts.iter().map(|part| part.body.len() + 128).sum();
    let mut out = Vec::with_capacity(size + boundary.len() + 8);
    for (index, part) in parts.iter().enumerate() {
        if part.body.starts_with(&dash_boundary) || find(part.body, &line_boundary).is_some() {
            return Err(MimeError::BoundaryInBody { part: index });
        }
        out.extend_from_slice(&dash_boundary);
        out.extend_from_slice(b"\r\n");
        for header in &part.headers {
            if !is_token(&header.name) {
                return Err(MimeError::InvalidValue {
                    what: "header name",
                    value: header.name.clone(),
                });
            }
            if header.value.contains(['\r', '\n']) {
                return Err(MimeError::InvalidValue {
                    what: "header value",
                    value: header.value.clone(),
                });
            }
            out.extend_from_slice(header.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(header.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(part.body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&dash_boundary);
    out.extend_from_slice(b"--\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> MultipartOptions {
        MultipartOptions::default()
    }

    #[test]
    fn rfc2046_example() {
        // RFC 2046 §5.1.1, with its preamble and epilogue.
        let body = b"This is the preamble.  It is to be ignored, though it\r\n\
is a handy place for composition agents to include an\r\n\
explanatory note to non-MIME conformant readers.\r\n\
\r\n\
--simple boundary\r\n\
\r\n\
This is implicitly typed plain US-ASCII text.\r\n\
It does NOT end with a linebreak.\r\n\
--simple boundary\r\n\
Content-type: text/plain; charset=us-ascii\r\n\
\r\n\
This is explicitly typed plain US-ASCII text.\r\n\
It DOES end with a linebreak.\r\n\
\r\n\
--simple boundary--\r\n\
\r\n\
This is the epilogue.  It is also to be ignored.\r\n";
        let mp = parse_multipart(body, "simple boundary", &opts()).unwrap();
        assert!(mp.closed);
        assert_eq!(mp.parts.len(), 2);
        assert_eq!(mp.parts[0].headers, []);
        assert_eq!(
            mp.parts[0].body,
            b"This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."
        );
        assert_eq!(
            mp.parts[1].content_type().unwrap().unwrap().essence(),
            "text/plain"
        );
        assert!(mp.parts[1].body.ends_with(b"linebreak.\r\n"));
        assert!(mp.preamble.ends_with(b"readers.\r\n"));
        assert_eq!(
            mp.epilogue,
            b"\r\nThis is the epilogue.  It is also to be ignored.\r\n"
        );
        for part in &mp.parts {
            assert_eq!(&body[part.body_range.clone()], part.body);
        }
    }

    #[test]
    fn rfc7578_example_with_lf_and_folding() {
        let body = b"--AaB03x\n\
content-disposition: form-data;\n\t name=\"field1\"\n\
content-type: text/plain;charset=UTF-8\n\
content-transfer-encoding: quoted-printable\n\
\n\
Joe owes =E2=82=AC100.\n\
--AaB03x--";
        let mp = parse_multipart(body, "AaB03x", &opts()).unwrap();
        let part = &mp.parts[0];
        assert_eq!(part.name().as_deref(), Some("field1"));
        assert_eq!(
            part.header("Content-Disposition"),
            Some("form-data; name=\"field1\"")
        );
        assert_eq!(part.body, b"Joe owes =E2=82=AC100.");
        assert_eq!(mp.epilogue, b"");
    }

    #[test]
    fn boundary_prefix_lines_are_content() {
        let body = b"--b\r\n\r\n--bx\r\n--b -\r\n--b--";
        let mp = parse_multipart(body, "b", &opts()).unwrap();
        assert_eq!(mp.parts[0].body, b"--bx\r\n--b -");
    }

    #[test]
    fn empty_and_headerless_parts() {
        let mp = parse_multipart(b"--b\r\n--b\r\n\r\n\r\n--b--", "b", &opts()).unwrap();
        assert_eq!(mp.parts.len(), 2);
        assert!(
            mp.parts
                .iter()
                .all(|p| p.body.is_empty() && p.headers.is_empty())
        );
        let mp = parse_multipart(b"--b--\r\nepi", "b", &opts()).unwrap();
        assert!(mp.parts.is_empty() && mp.closed);
        assert_eq!(mp.epilogue, b"epi");
    }

    #[test]
    fn errors() {
        let o = opts();
        assert_eq!(
            parse_multipart(b"no delimiter", "b", &o),
            Err(MimeError::NoOpeningDelimiter)
        );
        assert_eq!(
            parse_multipart(b"--b\r\n\r\nx", "b", &o),
            Err(MimeError::Unterminated)
        );
        assert_eq!(
            parse_multipart(b"--b\r\nno colon\r\n\r\n\r\n--b--", "b", &o),
            Err(MimeError::MalformedPartHeaders { part: 0 })
        );
        assert_eq!(
            parse_multipart(b"--b\r\n\tfold first\r\n\r\n\r\n--b--", "b", &o),
            Err(MimeError::MalformedPartHeaders { part: 0 })
        );
        assert_eq!(
            parse_multipart(b"--b\r\nA: 1\r\n--b--", "b", &o),
            Err(MimeError::MalformedPartHeaders { part: 0 })
        );
        assert!(matches!(
            parse_multipart(b"--b--", "", &o),
            Err(MimeError::InvalidBoundary(_))
        ));
    }

    #[test]
    fn limits() {
        let body = b"--b\r\nA: 1\r\nB: 2\r\n\r\nx\r\n--b\r\n\r\ny\r\n--b--";
        assert_eq!(
            parse_multipart(body, "b", &opts().with_max_parts(1)),
            Err(MimeError::TooManyParts { limit: 1 })
        );
        assert_eq!(
            parse_multipart(body, "b", &opts().with_max_headers(1)),
            Err(MimeError::TooManyHeaders { part: 0, limit: 1 })
        );
        assert_eq!(
            parse_multipart(body, "b", &opts().with_max_header_bytes(8)),
            Err(MimeError::PartHeadersTooLarge { part: 0, limit: 8 })
        );
        assert!(parse_multipart(body, "b", &opts().with_max_header_bytes(14)).is_ok());
        assert!(parse_multipart(body, "b", &opts().with_max_header_bytes(13)).is_err());
    }

    #[test]
    fn lenient_unterminated() {
        let lenient = opts().with_require_close(false);
        let mp = parse_multipart(b"--b\r\n\r\ntail", "b", &lenient).unwrap();
        assert!(!mp.closed);
        assert_eq!(mp.parts[0].body, b"tail");
        let mp = parse_multipart(b"--b\r\n", "b", &lenient).unwrap();
        assert_eq!(mp.parts, []);
    }

    #[test]
    fn encode_validates() {
        assert!(encode_multipart("", &[]).is_err());
        assert!(encode_multipart(&"x".repeat(71), &[]).is_err());
        assert!(encode_multipart("ends ", &[]).is_err());
        assert_eq!(encode_multipart("b", &[]).unwrap(), b"--b--\r\n");
        let bad = [Part::new(vec![], b"x\r\n--b\r\n")];
        assert_eq!(
            encode_multipart("b", &bad),
            Err(MimeError::BoundaryInBody { part: 0 })
        );
        let bad = [Part::new(vec![HeaderEntry::new("A", "1\r\nB: 2")], b"")];
        assert!(encode_multipart("b", &bad).is_err());
    }

    #[test]
    fn form_file_non_ascii_name() {
        let ct = MediaType::new("text", "plain").unwrap();
        let part = Part::form_file("f", "résumé.txt", &ct, b"").unwrap();
        assert_eq!(
            part.header("content-disposition"),
            Some("form-data; name=f; filename=r_sum_.txt; filename*=UTF-8''r%C3%A9sum%C3%A9.txt")
        );
        assert_eq!(part.filename().as_deref(), Some("résumé.txt"));
    }
}

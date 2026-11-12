//! The crate's error type.

/// Everything that can go wrong while parsing or encoding MIME values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MimeError {
    /// The header value is empty (or only whitespace).
    #[error("empty header value")]
    Empty,
    /// The header value does not follow the grammar.
    #[error("syntax error at byte {offset}: expected {expected}")]
    Syntax {
        /// Byte offset in the input where parsing stopped.
        offset: usize,
        /// What the parser expected there.
        expected: &'static str,
    },
    /// An RFC 8187 / RFC 2231 extended parameter value (`name*=…`) is
    /// malformed or uses a charset other than UTF-8 or ISO-8859-1.
    #[error("invalid extended parameter value for `{name}`")]
    InvalidExtValue {
        /// The parameter name, without the trailing `*`.
        name: String,
    },
    /// A name or value cannot be represented in a header (control
    /// characters, an empty or non-token name).
    #[error("invalid {what}: {value:?}")]
    InvalidValue {
        /// Which component was rejected.
        what: &'static str,
        /// The rejected text.
        value: String,
    },
    /// The media type is not `multipart/*`.
    #[error("not a multipart media type: {0}")]
    NotMultipart(String),
    /// A multipart media type without a `boundary` parameter.
    #[error("multipart media type has no boundary parameter")]
    MissingBoundary,
    /// The boundary breaks RFC 2046 §5.1.1 (1 to 70 `bchars`, not ending
    /// in a space).
    #[error("invalid multipart boundary: {0:?}")]
    InvalidBoundary(String),
    /// The body has no opening `--boundary` delimiter line.
    #[error("multipart body has no opening delimiter")]
    NoOpeningDelimiter,
    /// The body ends before the closing `--boundary--` delimiter.
    #[error("multipart body ends without a closing delimiter")]
    Unterminated,
    /// A part's header block is malformed: a line without a colon, a
    /// non-token header name, or no blank line before the next delimiter.
    #[error("part {part}: malformed header block")]
    MalformedPartHeaders {
        /// Zero-based index of the part.
        part: usize,
    },
    /// More parts than [`MultipartOptions::max_parts`](crate::MultipartOptions).
    #[error("more than {limit} parts")]
    TooManyParts {
        /// The configured limit.
        limit: usize,
    },
    /// A part's header block is larger than
    /// [`MultipartOptions::max_header_bytes`](crate::MultipartOptions).
    #[error("part {part}: header block larger than {limit} bytes")]
    PartHeadersTooLarge {
        /// Zero-based index of the part.
        part: usize,
        /// The configured limit.
        limit: usize,
    },
    /// A part has more header fields than
    /// [`MultipartOptions::max_headers`](crate::MultipartOptions).
    #[error("part {part}: more than {limit} header fields")]
    TooManyHeaders {
        /// Zero-based index of the part.
        part: usize,
        /// The configured limit.
        limit: usize,
    },
    /// While encoding: a part body contains the delimiter, so the encoded
    /// body would not parse back.
    #[error("part {part}: body contains the boundary delimiter")]
    BoundaryInBody {
        /// Zero-based index of the part.
        part: usize,
    },
}

use std::fmt;
use std::sync::Arc;

use http::HeaderValue;
use rand::RngCore;

use crate::Error;

/// Default upper bound on the length of a request id, in bytes.
pub const DEFAULT_MAX_ID_LEN: usize = 128;

/// A validated request (correlation) id.
///
/// A request id is 1 to `max` bytes of visible ASCII (`0x21..=0x7e`): no
/// spaces, control characters or non-ASCII text. That keeps it safe to echo
/// in a response header and to write to logs without escaping, so a client
/// cannot inject line breaks or terminal escapes through it.
///
/// Cloning is cheap (reference counted).
///
/// # Examples
///
/// ```
/// use rune_axum_requestid::RequestId;
///
/// let id = RequestId::new("req-42")?;
/// assert_eq!(id.as_str(), "req-42");
/// assert!(RequestId::new("has space").is_err());
///
/// let generated = RequestId::uuid_v4([0xab; 16]);
/// assert_eq!(generated.as_str(), "abababab-abab-4bab-abab-abababababab");
/// # Ok::<(), rune_axum_requestid::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RequestId {
    text: Arc<str>,
    header: HeaderValue,
}

impl RequestId {
    /// Validates `id` against [`DEFAULT_MAX_ID_LEN`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyId`], [`Error::IdTooLong`] or
    /// [`Error::InvalidIdByte`] when `id` is not an acceptable request id.
    pub fn new(id: impl AsRef<str>) -> Result<Self, Error> {
        Self::with_max_len(id.as_ref().as_bytes(), DEFAULT_MAX_ID_LEN)
    }

    /// Validates raw header bytes against an explicit length limit.
    ///
    /// Leading and trailing spaces and tabs (HTTP optional whitespace) are
    /// not part of the id and are rejected like any other invalid byte;
    /// HTTP parsers already strip them from header values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyId`], [`Error::IdTooLong`] or
    /// [`Error::InvalidIdByte`] when `bytes` is not an acceptable request id.
    pub fn with_max_len(bytes: &[u8], max: usize) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyId);
        }
        if bytes.len() > max {
            return Err(Error::IdTooLong {
                len: bytes.len(),
                max,
            });
        }
        if let Some(index) = bytes.iter().position(|b| !b.is_ascii_graphic()) {
            return Err(Error::InvalidIdByte { index });
        }
        // Visible ASCII is valid UTF-8 and a valid header value.
        let text = std::str::from_utf8(bytes).map_err(|e| Error::InvalidIdByte {
            index: e.valid_up_to(),
        })?;
        let header =
            HeaderValue::from_bytes(bytes).map_err(|_| Error::InvalidIdByte { index: 0 })?;
        Ok(Self {
            text: Arc::from(text),
            header,
        })
    }

    /// Formats 16 bytes as an RFC 9562 version 4 UUID
    /// (`xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx`, lowercase).
    ///
    /// The version and variant bits are overwritten, so 122 bits of `bytes`
    /// end up in the id. Pass random bytes; [`RequestId::random`] does that
    /// for you.
    #[must_use]
    pub fn uuid_v4(mut bytes: [u8; 16]) -> Self {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let mut out = String::with_capacity(36);
        for (i, b) in bytes.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            push_hex(&mut out, *b);
        }
        Self::from_trusted(out)
    }

    /// Generates a random version 4 UUID request id from the thread-local
    /// CSPRNG.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Self::uuid_v4(bytes)
    }

    /// Builds an id from text the crate produced itself (lowercase hex and
    /// dashes), which is always valid.
    fn from_trusted(text: String) -> Self {
        let header = HeaderValue::from_str(&text)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-request-id"));
        Self {
            text: Arc::from(text),
            header,
        }
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The id as a header value, ready to insert into a request or response.
    #[must_use]
    pub const fn header_value(&self) -> &HeaderValue {
        &self.header
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestId").field(&&*self.text).finish()
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl std::str::FromStr for RequestId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<RequestId> for HeaderValue {
    fn from(id: RequestId) -> Self {
        id.header
    }
}

pub fn push_hex(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX[usize::from(b >> 4)]));
    out.push(char::from(HEX[usize::from(b & 0x0f)]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_visible_ascii() {
        let id = RequestId::new("abc-123_~!").unwrap();
        assert_eq!(id.as_str(), "abc-123_~!");
        assert_eq!(id.header_value(), "abc-123_~!");
        assert_eq!(id.to_string(), "abc-123_~!");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(RequestId::new(""), Err(Error::EmptyId));
    }

    #[test]
    fn rejects_whitespace_and_control() {
        assert_eq!(
            RequestId::new("a b"),
            Err(Error::InvalidIdByte { index: 1 })
        );
        assert_eq!(
            RequestId::new("ab\r\nc"),
            Err(Error::InvalidIdByte { index: 2 })
        );
        assert_eq!(
            RequestId::new("\u{1b}[31m"),
            Err(Error::InvalidIdByte { index: 0 })
        );
        assert_eq!(RequestId::new("é"), Err(Error::InvalidIdByte { index: 0 }));
    }

    #[test]
    fn enforces_length_limit() {
        let ok = "a".repeat(DEFAULT_MAX_ID_LEN);
        assert!(RequestId::new(&ok).is_ok());
        let long = "a".repeat(DEFAULT_MAX_ID_LEN + 1);
        assert_eq!(
            RequestId::new(&long),
            Err(Error::IdTooLong {
                len: DEFAULT_MAX_ID_LEN + 1,
                max: DEFAULT_MAX_ID_LEN
            })
        );
        assert!(RequestId::with_max_len(b"abcd", 3).is_err());
        assert!(RequestId::with_max_len(b"abc", 3).is_ok());
    }

    #[test]
    fn uuid_v4_sets_version_and_variant() {
        let id = RequestId::uuid_v4([0; 16]);
        assert_eq!(id.as_str(), "00000000-0000-4000-8000-000000000000");
        let id = RequestId::uuid_v4([0xff; 16]);
        assert_eq!(id.as_str(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let id = RequestId::uuid_v4([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ]);
        assert_eq!(id.as_str(), "12345678-9abc-4ef0-9234-56789abcdef0");
    }

    #[test]
    fn random_ids_are_valid_and_distinct() {
        let a = RequestId::random();
        let b = RequestId::random();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 36);
        assert_eq!(RequestId::new(a.as_str()).unwrap(), a);
    }

    #[test]
    fn parses_from_str() {
        let id: RequestId = "x".parse().unwrap();
        assert_eq!(HeaderValue::from(id), "x");
    }
}

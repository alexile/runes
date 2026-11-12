//! Byte-exact bodies and the ways a textual body is turned into bytes.

use std::borrow::Cow;

use bytes::Bytes;

use crate::HttpModelError;

/// Decodes base64 body text: standard or URL-safe alphabet, padding
/// optional, surrounding whitespace ignored.
fn decode_base64(text: &str) -> Result<Bytes, HttpModelError> {
    rune_base64::decode(text.trim())
        .map(Bytes::from)
        .map_err(|error| HttpModelError::InvalidBase64(error.to_string()))
}

/// A byte-exact HTTP body. The bytes are never normalised.
///
/// Besides the bytes, a body records capture metadata: the content coding
/// the bytes are still in, and whether the capture was cut at a size cap.
///
/// With the `serde` feature a body serializes as an object whose `data` is
/// the UTF-8 text when the bytes are valid UTF-8 and standard base64
/// otherwise; `encoding` says which. Deserialization also accepts a bare JSON
/// string as a UTF-8 body.
///
/// ```
/// use rune_http_model::HttpBody;
///
/// let body = HttpBody::new(vec![b'h', 0xff]);
/// assert_eq!(body.as_utf8(), None);
/// assert_eq!(body.text_lossy(), "h\u{fffd}");
/// assert_eq!(HttpBody::from_base64(&body.to_base64())?, body);
/// # Ok::<(), rune_http_model::HttpModelError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpBody {
    bytes: Bytes,
    /// Content coding the bytes are still in, e.g. `gzip`. `None` means the bytes are decoded.
    pub content_encoding: Option<String>,
    /// Whether the capture was cut at a size cap.
    pub truncated: bool,
    /// Full on-wire length when known, e.g. when truncated.
    pub total_len: Option<u64>,
}

impl HttpBody {
    /// Creates a body from raw bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            ..Self::default()
        }
    }

    /// Creates an empty body.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a body from UTF-8 text.
    #[must_use]
    pub fn from_text(text: impl Into<String>) -> Self {
        Self::new(text.into())
    }

    /// Creates a body from base64 text.
    ///
    /// Accepts the standard and URL-safe alphabets ([RFC 4648]), with or
    /// without padding; surrounding whitespace is ignored.
    ///
    /// [RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
    ///
    /// # Errors
    /// Returns [`HttpModelError::InvalidBase64`] if `text` is not valid base64.
    pub fn from_base64(text: &str) -> Result<Self, HttpModelError> {
        decode_base64(text).map(Self::new)
    }

    /// The body bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The body bytes as a cheaply cloneable buffer.
    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consumes the body and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// Replaces the bytes, keeping the capture metadata.
    pub fn set_bytes(&mut self, bytes: impl Into<Bytes>) {
        self.bytes = bytes.into();
    }

    /// Number of captured bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether no bytes were captured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The body as text, or `None` when the bytes are not valid UTF-8.
    #[must_use]
    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// The body as text, replacing invalid UTF-8 sequences.
    #[must_use]
    pub fn text_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// The body bytes encoded as standard, padded base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        rune_base64::encode(&self.bytes)
    }

    /// Sets the content coding the bytes are still in.
    #[must_use]
    pub fn with_content_encoding(mut self, encoding: impl Into<String>) -> Self {
        self.content_encoding = Some(encoding.into());
        self
    }

    /// Marks the body as truncated and records the full on-wire length when known.
    #[must_use]
    pub const fn with_truncated(mut self, total_len: Option<u64>) -> Self {
        self.truncated = true;
        self.total_len = total_len;
        self
    }

    /// Records the full on-wire length.
    #[must_use]
    pub const fn with_total_len(mut self, total_len: u64) -> Self {
        self.total_len = Some(total_len);
        self
    }
}

impl From<Bytes> for HttpBody {
    fn from(bytes: Bytes) -> Self {
        Self::new(bytes)
    }
}

impl From<Vec<u8>> for HttpBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for HttpBody {
    fn from(bytes: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(bytes))
    }
}

impl From<String> for HttpBody {
    fn from(text: String) -> Self {
        Self::from_text(text)
    }
}

impl From<&str> for HttpBody {
    fn from(text: &str) -> Self {
        Self::from_text(text.to_owned())
    }
}

/// How a textual body given by a user or agent is encoded on the wire.
///
/// ```
/// use rune_http_model::BodyKind;
///
/// let body = BodyKind::Base64.encode("AP8=")?;
/// assert_eq!(body.as_bytes(), [0x00, 0xff]);
/// assert_eq!(BodyKind::Json.default_content_type(), Some("application/json"));
/// # Ok::<(), rune_http_model::HttpModelError>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum BodyKind {
    /// No body; any given text is ignored.
    Empty,
    /// Plain text, sent verbatim.
    #[default]
    Text,
    /// JSON text, sent verbatim (not re-serialised).
    Json,
    /// URL-encoded form text, sent verbatim.
    Form,
    /// Base64 text, decoded to raw bytes.
    Base64,
}

impl BodyKind {
    /// Content-Type to add when the caller set none.
    #[must_use]
    pub const fn default_content_type(self) -> Option<&'static str> {
        match self {
            Self::Json => Some("application/json"),
            Self::Form => Some("application/x-www-form-urlencoded"),
            Self::Empty | Self::Text | Self::Base64 => None,
        }
    }

    /// Encodes `text` into body bytes.
    ///
    /// Text, JSON and form text are used verbatim; `Empty` ignores the input;
    /// `Base64` is decoded as by [`HttpBody::from_base64`].
    ///
    /// # Errors
    /// Returns [`HttpModelError::InvalidBase64`] if a `Base64` body does not decode.
    pub fn encode(self, text: &str) -> Result<HttpBody, HttpModelError> {
        match self {
            Self::Empty => Ok(HttpBody::empty()),
            Self::Text | Self::Json | Self::Form => Ok(HttpBody::from_text(text)),
            Self::Base64 => HttpBody::from_base64(text),
        }
    }
}

#[cfg(feature = "serde")]
mod wire {
    //! The JSON shape of [`HttpBody`].

    use std::borrow::Cow;

    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{HttpBody, decode_base64};

    /// How the `data` field of a body is encoded in JSON.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    #[serde(rename_all = "snake_case")]
    enum DataEncoding {
        /// `data` is the body as UTF-8 text.
        #[default]
        Utf8,
        /// `data` is the body bytes as standard base64.
        Base64,
    }

    /// An HTTP body. `data` holds the exact bytes, as UTF-8 text or base64.
    #[derive(Serialize, Deserialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    pub(super) struct BodyWire<'a> {
        /// How `data` is encoded: `utf8` text or `base64` bytes.
        #[serde(default)]
        encoding: DataEncoding,
        /// The body content, encoded as `encoding` says.
        #[serde(default)]
        data: Cow<'a, str>,
        /// Content coding the bytes are still in, e.g. `gzip`. `null` means decoded.
        #[serde(default)]
        content_encoding: Option<String>,
        /// Whether the capture was cut at a size cap.
        #[serde(default)]
        truncated: bool,
        /// Full on-wire length when known.
        #[serde(default)]
        total_len: Option<u64>,
    }

    /// An HTTP body: either a plain UTF-8 string, or an object with explicit encoding.
    #[derive(Deserialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    #[serde(untagged)]
    pub(super) enum BodyInput<'a> {
        /// The body as plain UTF-8 text.
        Text(String),
        /// The body with explicit encoding and capture metadata.
        Wire(BodyWire<'a>),
    }

    impl Serialize for HttpBody {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let (encoding, data) = self.as_utf8().map_or_else(
                || (DataEncoding::Base64, Cow::Owned(self.to_base64())),
                |text| (DataEncoding::Utf8, Cow::Borrowed(text)),
            );
            BodyWire {
                encoding,
                data,
                content_encoding: self.content_encoding.clone(),
                truncated: self.truncated,
                total_len: self.total_len,
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for HttpBody {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            match BodyInput::deserialize(deserializer)? {
                BodyInput::Text(text) => Ok(Self::from_text(text)),
                BodyInput::Wire(wire) => {
                    let bytes = match wire.encoding {
                        DataEncoding::Utf8 => Bytes::from(wire.data.into_owned()),
                        DataEncoding::Base64 => {
                            decode_base64(&wire.data).map_err(serde::de::Error::custom)?
                        }
                    };
                    Ok(Self {
                        bytes,
                        content_encoding: wire.content_encoding,
                        truncated: wire.truncated,
                        total_len: wire.total_len,
                    })
                }
            }
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for HttpBody {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("HttpBody")
        }

        fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            BodyInput::json_schema(generator)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors() {
        let mut body = HttpBody::new(vec![b'h', 0xff]).with_content_encoding("br");
        assert_eq!(body.len(), 2);
        assert!(!body.is_empty());
        assert_eq!(body.as_utf8(), None);
        assert_eq!(body.text_lossy(), "h\u{fffd}");
        assert_eq!(body.to_base64(), "aP8=");
        body.set_bytes(&b"ok"[..]);
        assert_eq!(body.as_utf8(), Some("ok"));
        assert_eq!(body.content_encoding.as_deref(), Some("br"));
        assert_eq!(body.bytes().as_ref(), b"ok");
        assert_eq!(body.into_bytes().as_ref(), b"ok");
        assert!(HttpBody::empty().is_empty());
        assert_eq!(HttpBody::from(&b"x"[..]), HttpBody::from("x"));
        assert_eq!(HttpBody::from(vec![b'x']), HttpBody::from("x".to_owned()));
        assert_eq!(
            HttpBody::from(Bytes::from_static(b"x")),
            HttpBody::from_text("x")
        );
    }

    #[test]
    fn base64_known_answers() {
        // RFC 4648 §10 test vectors.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let body = HttpBody::from_text(plain);
            assert_eq!(body.to_base64(), encoded);
            assert_eq!(HttpBody::from_base64(encoded), Ok(body));
        }
        assert_eq!(
            HttpBody::from_base64("  Zm9v\n").map(|b| b.as_utf8().map(str::to_owned)),
            Ok(Some("foo".to_owned()))
        );
        let error = HttpBody::from_base64("!!").unwrap_err();
        assert!(matches!(error, HttpModelError::InvalidBase64(_)));
    }

    #[test]
    fn truncation_metadata() {
        let body = HttpBody::from_text("abc").with_truncated(Some(10));
        assert!(body.truncated);
        assert_eq!(body.total_len, Some(10));
        let body = HttpBody::from_text("abc").with_total_len(3);
        assert!(!body.truncated);
        assert_eq!(body.total_len, Some(3));
    }

    #[test]
    fn body_kind_encode() {
        assert!(BodyKind::Empty.encode("ignored").unwrap().is_empty());
        assert_eq!(BodyKind::Text.encode("a b").unwrap().as_bytes(), b"a b");
        assert_eq!(
            BodyKind::Json.encode("{ \"a\" : 1 }").unwrap().as_bytes(),
            b"{ \"a\" : 1 }"
        );
        assert_eq!(
            BodyKind::Form.encode("a=1&b=2").unwrap().as_bytes(),
            b"a=1&b=2"
        );
        assert_eq!(
            BodyKind::Base64.encode("AP8=").unwrap().as_bytes(),
            &[0x00, 0xff]
        );
        let error = BodyKind::Base64.encode("not base64!").unwrap_err();
        assert_eq!(error.code(), "invalid_base64");
        assert_eq!(
            BodyKind::Form.default_content_type(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(BodyKind::Text.default_content_type(), None);
        assert_eq!(BodyKind::default(), BodyKind::Text);
    }

    #[cfg(feature = "serde")]
    mod serde_shape {
        use super::*;

        fn round_trip(body: &HttpBody) -> (serde_json::Value, HttpBody) {
            let json = serde_json::to_value(body).unwrap();
            let back: HttpBody = serde_json::from_value(json.clone()).unwrap();
            (json, back)
        }

        #[test]
        fn utf8_body_round_trips_as_text() {
            let body = HttpBody::from_text("héllo wörld");
            let (json, back) = round_trip(&body);
            assert_eq!(json["encoding"], "utf8");
            assert_eq!(json["data"], "héllo wörld");
            assert_eq!(back, body);
        }

        #[test]
        fn non_utf8_body_round_trips_as_base64() {
            let raw: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x80, b'a', 0xc3];
            let body = HttpBody::new(raw.clone())
                .with_content_encoding("gzip")
                .with_truncated(Some(4096));
            let (json, back) = round_trip(&body);
            assert_eq!(json["encoding"], "base64");
            assert_eq!(json["data"], "//4AgGHD");
            assert_eq!(json["content_encoding"], "gzip");
            assert_eq!(json["truncated"], true);
            assert_eq!(json["total_len"], 4096);
            assert_eq!(back.as_bytes(), raw.as_slice());
            assert_eq!(back, body);
        }

        #[test]
        fn crlf_and_nul_bytes_survive() {
            let raw = b"line1\r\nline2\r\n\r\n\0tail\0".to_vec();
            let body = HttpBody::new(raw.clone());
            let text = serde_json::to_string(&body).unwrap();
            let back: HttpBody = serde_json::from_str(&text).unwrap();
            assert_eq!(back.as_bytes(), raw.as_slice());
        }

        #[test]
        fn bare_string_and_minimal_object() {
            let body: HttpBody = serde_json::from_str("\"a=1&b=2\"").unwrap();
            assert_eq!(body.as_bytes(), b"a=1&b=2");
            assert!(!body.truncated);
            assert_eq!(body.content_encoding, None);
            let body: HttpBody = serde_json::from_str(r#"{"data":"x"}"#).unwrap();
            assert_eq!(body, HttpBody::from_text("x"));
            let body: HttpBody = serde_json::from_str("{}").unwrap();
            assert_eq!(body, HttpBody::empty());
            let bad = serde_json::from_str::<HttpBody>(r#"{"encoding":"base64","data":"!!"}"#);
            assert!(bad.is_err());
            assert!(serde_json::from_str::<HttpBody>("42").is_err());
        }

        #[test]
        fn body_kind_names() {
            assert_eq!(serde_json::to_value(BodyKind::Base64).unwrap(), "base64");
            let kind: BodyKind = serde_json::from_str("\"form\"").unwrap();
            assert_eq!(kind, BodyKind::Form);
        }
    }
}

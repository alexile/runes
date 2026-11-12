//! The crate's error type.

/// Everything that can go wrong while parsing or building authentication
/// headers and messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The header value is empty (or only whitespace).
    #[error("empty header value")]
    Empty,
    /// The header value does not follow the RFC 9110 §11 grammar.
    #[error("syntax error at byte {offset}: expected {expected}")]
    Syntax {
        /// Byte offset in the input where parsing stopped.
        offset: usize,
        /// What the parser expected there.
        expected: &'static str,
    },
    /// The credentials or challenge use another scheme.
    #[error("expected the {expected} scheme, found {found:?}")]
    WrongScheme {
        /// The scheme the caller asked for.
        expected: &'static str,
        /// The scheme that was found.
        found: String,
    },
    /// A token68 is not valid Base64.
    #[error("invalid base64 in credentials")]
    Base64,
    /// Decoded credentials are not UTF-8.
    #[error("credentials are not valid UTF-8")]
    InvalidUtf8,
    /// A value cannot be sent: a Basic user-id with a colon, a control
    /// character, or a Bearer token outside the `b64token` alphabet.
    #[error("invalid {what}")]
    InvalidValue {
        /// Which value was rejected.
        what: &'static str,
    },
    /// A required parameter is missing from a Digest challenge or response.
    #[error("missing Digest parameter `{0}`")]
    MissingParam(&'static str),
    /// A Digest `algorithm` this crate does not implement.
    #[error("unsupported Digest algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// A Digest `qop` list that offers neither `auth` nor `auth-int`, or a
    /// response with an unknown `qop`.
    #[error("unsupported Digest qop {0:?}")]
    UnsupportedQop(String),
    /// A Digest parameter has an invalid value (a non-hex `nc`, …).
    #[error("invalid Digest parameter `{0}`")]
    InvalidParam(&'static str),
    /// The NTLM message is shorter than its fixed header or a field points
    /// outside the message.
    #[error("NTLM message truncated or field `{0}` out of bounds")]
    NtlmTruncated(&'static str),
    /// The NTLM message does not start with `NTLMSSP\0`.
    #[error("not an NTLMSSP message")]
    NtlmSignature,
    /// The NTLM message type is not the one expected (or not 1, 2 or 3).
    #[error("unexpected NTLM message type {0}")]
    NtlmMessageType(u32),
    /// An NTLM string field has an odd length in Unicode mode.
    #[error("NTLM field `{0}` is not valid UTF-16")]
    NtlmString(&'static str),
    /// An NTLM field is longer than 65535 bytes and cannot be encoded.
    #[error("NTLM field `{0}` is too long")]
    NtlmFieldTooLong(&'static str),
}

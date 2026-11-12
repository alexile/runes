//! Signing secrets that never show up in `Debug` output or error messages.

use std::fmt;

/// A webhook signing secret.
///
/// The bytes are used as the HMAC key. `Debug` prints `Secret(<redacted>)`, so
/// a verifier can be logged without leaking key material.
///
/// Most providers use the secret string as-is (`Secret::from("...")`).
/// Standard Webhooks / Svix secrets are base64 with an optional `whsec_`
/// prefix; parse those with [`Secret::from_whsec`].
///
/// # Examples
///
/// ```rust
/// use rune_axum_signature::Secret;
///
/// let raw = Secret::from("my-github-secret");
/// let svix = Secret::from_whsec("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
/// assert_eq!(format!("{raw:?}"), "Secret(<redacted>)");
/// assert_eq!(svix.len(), 24);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wraps raw key bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses a Standard Webhooks / Svix secret: base64, optionally prefixed
    /// with `whsec_`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSecret`] if the base64 is invalid or decodes to
    /// nothing. The error does not contain the input.
    pub fn from_whsec(encoded: &str) -> Result<Self, InvalidSecret> {
        let trimmed = encoded.trim();
        let b64 = trimmed.strip_prefix("whsec_").unwrap_or(trimmed);
        match rune_base64::decode(b64) {
            Ok(bytes) if !bytes.is_empty() => Ok(Self(bytes)),
            _ => Err(InvalidSecret),
        }
    }

    /// Number of key bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value.into_bytes())
    }
}

impl From<&[u8]> for Secret {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Secret {
    fn from(value: &[u8; N]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// A Standard Webhooks secret could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSecret;

impl fmt::Display for InvalidSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("webhook secret is not valid base64 (expected `whsec_<base64>`)")
    }
}

impl std::error::Error for InvalidSecret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whsec_prefix_is_optional() {
        let a = Secret::from_whsec("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        let b = Secret::from_whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        assert_eq!(a, b);
        assert!(a.is_ok());
    }

    #[test]
    fn bad_whsec_is_rejected_without_echoing_input() {
        let err = Secret::from_whsec("whsec_!!!not base64").unwrap_err();
        assert!(!err.to_string().contains("not base64!"));
        assert!(Secret::from_whsec("whsec_").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let s = Secret::from("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}

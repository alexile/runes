//! The generic "HMAC of the body, hex in a header" mode, plus shared MAC and
//! encoding helpers.

use crate::Secret;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

/// HMAC hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha1,
    Sha512,
}

/// HMAC over the concatenation of `parts`. `None` only if the key is
/// rejected, which HMAC never does in practice.
pub fn mac(algorithm: Algorithm, key: &[u8], parts: &[&[u8]]) -> Option<Vec<u8>> {
    fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], parts: &[&[u8]]) -> Option<Vec<u8>> {
        let mut mac = <M as Mac>::new_from_slice(key).ok()?;
        for part in parts {
            mac.update(part);
        }
        Some(mac.finalize().into_bytes().to_vec())
    }
    match algorithm {
        Algorithm::Sha256 => run::<Hmac<Sha256>>(key, parts),
        Algorithm::Sha1 => run::<Hmac<Sha1>>(key, parts),
        Algorithm::Sha512 => run::<Hmac<Sha512>>(key, parts),
    }
}

/// Constant-time check of every candidate against every expected MAC.
/// Walks all pairs, so the timing does not say which pair matched.
pub fn any_match(expected: &[Vec<u8>], candidates: &[Vec<u8>]) -> bool {
    let mut found = subtle::Choice::from(0);
    for e in expected {
        for c in candidates {
            found |= e.as_slice().ct_eq(c.as_slice());
        }
    }
    found.into()
}

pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((from_hex_nibble(pair[0])? << 4) | from_hex_nibble(pair[1])?))
        .collect()
}

const fn from_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Configuration for the generic HMAC mode: HMAC of the raw body, hex-encoded
/// in one header, with an optional prefix.
///
/// This is the 0.2 API and still works unchanged. For the providers that have
/// a preset (Standard Webhooks, Stripe, GitHub, Slack, Shopify), use
/// [`WebhookVerifier`](crate::WebhookVerifier) instead: the presets also check
/// timestamps and know the exact header formats.
///
/// `Debug` never prints the secret.
///
/// # Examples
///
/// ```rust
/// use rune_axum_signature::HmacConfig;
///
/// let config = HmacConfig::sha256(b"secret")
///     .header("x-signature")
///     .prefix("sha256=");
///
/// // HMAC-SHA256("secret", "hello world")
/// let sig = "sha256=734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a";
/// assert!(config.verify(b"hello world", sig));
/// assert!(!config.verify(b"hello world!", sig));
/// ```
#[derive(Clone)]
pub struct HmacConfig {
    pub(crate) secret: Secret,
    pub(crate) algorithm: Algorithm,
    pub(crate) header_name: String,
    pub(crate) prefix: String,
}

impl std::fmt::Debug for HmacConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacConfig")
            .field("secret", &self.secret)
            .field("algorithm", &self.algorithm)
            .field("header_name", &self.header_name)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl HmacConfig {
    fn with(secret: &[u8], algorithm: Algorithm, header: &str) -> Self {
        Self {
            secret: Secret::from(secret),
            algorithm,
            header_name: header.to_owned(),
            prefix: String::new(),
        }
    }

    /// HMAC-SHA256, default header `x-signature-256`.
    #[must_use]
    pub fn sha256(secret: &[u8]) -> Self {
        Self::with(secret, Algorithm::Sha256, "x-signature-256")
    }

    /// HMAC-SHA1, default header `x-signature`. Only for legacy senders.
    #[must_use]
    pub fn sha1(secret: &[u8]) -> Self {
        Self::with(secret, Algorithm::Sha1, "x-signature")
    }

    /// HMAC-SHA512, default header `x-signature-512`.
    #[must_use]
    pub fn sha512(secret: &[u8]) -> Self {
        Self::with(secret, Algorithm::Sha512, "x-signature-512")
    }

    /// Sets the header that carries the signature (case-insensitive).
    #[must_use]
    pub fn header(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into();
        self
    }

    /// Strips this prefix (e.g. `sha256=`) from the header value before
    /// hex-decoding. A value without the prefix is decoded as-is.
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Checks `raw_header_value` against the HMAC of `body`, in constant time.
    ///
    /// Returns `false` for malformed hex or a mismatch.
    #[must_use]
    pub fn verify(&self, body: &[u8], raw_header_value: &str) -> bool {
        self.verify_with(std::slice::from_ref(&self.secret), body, raw_header_value)
    }

    pub(crate) fn verify_with(&self, secrets: &[Secret], body: &[u8], raw: &str) -> bool {
        let hex = raw.trim();
        let hex = hex.strip_prefix(self.prefix.as_str()).unwrap_or(hex);
        let Some(candidate) = decode_hex(hex) else {
            return false;
        };
        let expected: Vec<Vec<u8>> = secrets
            .iter()
            .filter_map(|s| mac(self.algorithm, s.as_bytes(), &[body]))
            .collect();
        any_match(&expected, &[candidate])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_none());
    }

    #[test]
    fn decode_hex_rejects_invalid_chars() {
        assert!(decode_hex("zz").is_none());
    }

    #[test]
    fn decode_hex_handles_uppercase() {
        assert_eq!(decode_hex("DEADBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn verify_returns_false_on_invalid_hex() {
        assert!(!HmacConfig::sha256(b"secret").verify(b"body", "not-valid-hex!!!"));
    }

    // RFC 4231 test case 2 (key "Jefe").
    #[test]
    fn rfc4231_case_2() {
        let config = HmacConfig::sha256(b"Jefe");
        assert!(config.verify(
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        ));
    }

    #[test]
    fn debug_hides_secret() {
        let config = HmacConfig::sha256(b"topsecret");
        assert!(!format!("{config:?}").contains("topsecret"));
    }

    #[test]
    fn any_match_requires_equal_length() {
        assert!(!any_match(&[vec![1, 2, 3]], &[vec![1, 2]]));
        assert!(any_match(&[vec![9], vec![1, 2]], &[vec![0], vec![1, 2]]));
    }
}

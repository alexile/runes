//! Signed token generation and verification (sans-I/O).
//!
//! Token wire format (ASCII, cookie/header/form safe):
//!
//! ```text
//! <nonce hex>.<issued-at unix seconds, decimal>.<HMAC-SHA256 hex>
//! ```
//!
//! The MAC covers a domain-separation label, the length-prefixed session
//! binding and the `<nonce>.<issued-at>` payload, so a token minted for one
//! session (or by another key) never verifies for another.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const DOMAIN: &[u8] = b"rune-axum-csrf/v1";
const MAC_LEN: usize = 32;
/// Minimum key length accepted by [`CsrfKey::from_bytes`].
pub const MIN_KEY_LEN: usize = 32;
/// Minimum nonce length (128 bits, the OWASP floor for CSRF tokens).
pub const MIN_TOKEN_BYTES: usize = 16;
/// Maximum nonce length, so an over-configured token still fits in a cookie.
pub const MAX_TOKEN_BYTES: usize = 256;

/// Secret HMAC key that signs CSRF tokens.
///
/// Cloning is cheap (the bytes are shared). The [`Debug`] output never shows the
/// key material.
///
/// Every instance of a horizontally scaled service must use the **same** key,
/// loaded from your secret store with [`CsrfKey::from_bytes`]; otherwise a token
/// issued by one instance is rejected by the others. [`CsrfKey::generate`] (the
/// default) is fine for a single process, but tokens do not survive a restart.
///
/// # Examples
///
/// ```rust
/// use rune_axum_csrf::CsrfKey;
///
/// let key = CsrfKey::from_bytes(&[7u8; 32]).unwrap();
/// assert_eq!(format!("{key:?}"), "CsrfKey([redacted])");
/// assert!(CsrfKey::from_bytes(b"too short").is_err());
/// ```
#[derive(Clone)]
pub struct CsrfKey(Arc<[u8]>);

impl CsrfKey {
    /// Generates a fresh 256-bit key from the operating system's CSPRNG
    /// (via `rand`'s thread-local, OS-seeded `ChaCha` generator).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; MIN_KEY_LEN];
        rand::rng().fill_bytes(&mut bytes);
        Self(Arc::from(&bytes[..]))
    }

    /// Wraps existing key material. It must be at least 32 bytes of
    /// high-entropy secret data (not a password).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyTooShort> {
        if bytes.len() < MIN_KEY_LEN {
            return Err(KeyTooShort { len: bytes.len() });
        }
        Ok(Self(Arc::from(bytes)))
    }

    /// `None` only if HMAC rejects the key length, which it never does; callers
    /// treat that as a verification failure (fail closed).
    fn mac(&self, session: &[u8], payload: &[u8]) -> Option<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.0).ok()?;
        mac.update(DOMAIN);
        mac.update(&[0]);
        mac.update(&(session.len() as u64).to_be_bytes());
        mac.update(session);
        mac.update(payload);
        Some(mac)
    }
}

impl fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfKey([redacted])")
    }
}

/// Error returned by [`CsrfKey::from_bytes`] when the key is shorter than 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyTooShort {
    len: usize,
}

impl fmt::Display for KeyTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CSRF key is {} bytes, at least {MIN_KEY_LEN} are required",
            self.len
        )
    }
}

impl std::error::Error for KeyTooShort {}

/// Why a token failed verification (internal; mapped to `CsrfRejection`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    Malformed,
    BadSignature,
    Expired,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    const fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Mints a signed token with `nonce_bytes` of CSPRNG output, bound to `session`.
pub fn issue(key: &CsrfKey, session: &[u8], nonce_bytes: usize, now: u64) -> Option<String> {
    let mut nonce = vec![0u8; nonce_bytes.clamp(MIN_TOKEN_BYTES, MAX_TOKEN_BYTES)];
    rand::rng().fill_bytes(&mut nonce);
    let payload = format!("{}.{now}", hex(&nonce));
    let tag = key
        .mac(session, payload.as_bytes())?
        .finalize()
        .into_bytes();
    Some(format!("{payload}.{}", hex(&tag)))
}

/// Verifies `token`'s signature (constant time) and age.
pub fn verify(
    key: &CsrfKey,
    session: &[u8],
    token: &str,
    now: u64,
    ttl: Option<Duration>,
) -> Result<(), Invalid> {
    let (payload, tag_hex) = token.rsplit_once('.').ok_or(Invalid::Malformed)?;
    let (nonce_hex, issued) = payload.split_once('.').ok_or(Invalid::Malformed)?;
    let nonce_len = nonce_hex.len() / 2;
    if !nonce_hex.len().is_multiple_of(2)
        || !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&nonce_len)
        || unhex(nonce_hex).is_none()
        || issued.is_empty()
        || issued.len() > 20
        || !issued.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Invalid::Malformed);
    }
    let issued: u64 = issued.parse().map_err(|_| Invalid::Malformed)?;
    if tag_hex.len() != MAC_LEN * 2 {
        return Err(Invalid::Malformed);
    }
    let tag = unhex(tag_hex).ok_or(Invalid::Malformed)?;
    if tag.len() != MAC_LEN {
        return Err(Invalid::Malformed);
    }
    key.mac(session, payload.as_bytes())
        .ok_or(Invalid::BadSignature)?
        .verify_slice(&tag)
        .map_err(|_| Invalid::BadSignature)?;
    if let Some(ttl) = ttl
        && now.saturating_sub(issued) > ttl.as_secs()
    {
        return Err(Invalid::Expired);
    }
    Ok(())
}

/// Constant-time equality for submitted vs. cookie tokens. The length is not
/// secret (every valid token of a given config has the same length), so a
/// length mismatch may return early.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key() -> CsrfKey {
        CsrfKey::from_bytes(&[42u8; 32]).unwrap()
    }

    #[test]
    fn roundtrip() {
        let t = issue(&key(), b"sess", 32, 1_000).unwrap();
        assert_eq!(verify(&key(), b"sess", &t, 1_000, None), Ok(()));
        // 64 hex nonce + '.' + "1000" + '.' + 64 hex mac
        assert_eq!(t.len(), 64 + 1 + 4 + 1 + 64);
    }

    #[test]
    fn nonce_is_at_least_128_bits() {
        let t = issue(&key(), b"", 1, 0).unwrap();
        assert_eq!(t.split('.').next().unwrap().len(), MIN_TOKEN_BYTES * 2);
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(
            issue(&key(), b"", 16, 0).unwrap(),
            issue(&key(), b"", 16, 0).unwrap()
        );
    }

    #[test]
    fn other_session_rejected() {
        let t = issue(&key(), b"alice", 32, 0).unwrap();
        assert_eq!(
            verify(&key(), b"mallory", &t, 0, None),
            Err(Invalid::BadSignature)
        );
    }

    #[test]
    fn session_binding_is_length_prefixed() {
        // "ab" + payload "c..." must not collide with "a" + payload "bc...".
        let t = issue(&key(), b"ab", 16, 0).unwrap();
        assert!(verify(&key(), b"a", &t, 0, None).is_err());
    }

    #[test]
    fn other_key_rejected() {
        let t = issue(&key(), b"", 32, 0).unwrap();
        let other = CsrfKey::from_bytes(&[1u8; 32]).unwrap();
        assert_eq!(verify(&other, b"", &t, 0, None), Err(Invalid::BadSignature));
    }

    #[test]
    fn unsigned_legacy_token_rejected() {
        let legacy = "a".repeat(64);
        assert_eq!(
            verify(&key(), b"", &legacy, 0, None),
            Err(Invalid::Malformed)
        );
    }

    #[test]
    fn expiry() {
        let t = issue(&key(), b"", 16, 100).unwrap();
        let ttl = Some(Duration::from_secs(10));
        assert_eq!(verify(&key(), b"", &t, 110, ttl), Ok(()));
        assert_eq!(verify(&key(), b"", &t, 111, ttl), Err(Invalid::Expired));
    }

    #[test]
    fn timestamp_tamper_rejected() {
        let t = issue(&key(), b"", 16, 100).unwrap();
        let forged = t.replacen(".100.", ".999999.", 1);
        assert_eq!(
            verify(&key(), b"", &forged, 100, None),
            Err(Invalid::BadSignature)
        );
    }

    #[test]
    fn ct_eq_semantics() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "a"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn short_key_rejected() {
        let err = CsrfKey::from_bytes(&[0u8; 31]).unwrap_err();
        assert!(err.to_string().contains("31 bytes"));
    }

    #[test]
    fn key_debug_redacted() {
        let dbg = format!("{:?}", CsrfKey::from_bytes(&[0x41u8; 40]).unwrap());
        assert_eq!(dbg, "CsrfKey([redacted])");
    }

    proptest! {
        #[test]
        fn any_single_char_tamper_is_rejected(idx in 0usize..200, c in "[0-9a-f.]") {
            let t = issue(&key(), b"s", 16, 5).unwrap();
            let idx = idx % t.len();
            let mut bytes = t.into_bytes();
            let c = c.as_bytes()[0];
            prop_assume!(bytes[idx] != c);
            bytes[idx] = c;
            let forged = String::from_utf8(bytes).unwrap();
            prop_assert!(verify(&key(), b"s", &forged, 5, None).is_err());
        }

        #[test]
        fn garbage_never_verifies(s in ".{0,200}") {
            prop_assert!(verify(&key(), b"", &s, 0, None).is_err());
        }
    }
}

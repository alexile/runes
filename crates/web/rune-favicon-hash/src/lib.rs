//! Shodan-style favicon hashing.
//!
//! The favicon hash is a widely used web-service fingerprint (Shodan's
//! `http.favicon.hash`, FOFA's `icon_hash`, httpx's `-favicon`). It is the
//! signed 32-bit [MurmurHash3](https://github.com/aappleby/smhasher)
//! (`x86_32`, seed 0) of the icon's base64 encoding *as Python's
//! [`base64.encodebytes`](https://docs.python.org/3/library/base64.html#base64.encodebytes)
//! writes it*: standard alphabet with padding
//! ([RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648#section-4)), a
//! `\n` after every 76 characters and after the last line. Getting that
//! wrapping wrong is the usual reason two tools disagree, so this crate
//! pins it down once:
//!
//! - [`favicon_hash`] — the hash of raw icon bytes.
//! - [`favicon_hash_base64`] — the hash of an icon you hold as base64
//!   (a `data:` URI payload, a HAR body), re-encoded canonically first.
//! - [`mime_base64`] — the exact text that is hashed.
//! - [`shodan_query`] — the matching Shodan search filter.
//!
//! The murmur core is [`rune_murmur::murmurhash3_x86_32`] and the base64
//! encoder is [`rune_base64`].
//!
//! # Example
//!
//! ```
//! use rune_favicon_hash::{favicon_hash, favicon_hash_base64, mime_base64, shodan_query};
//!
//! assert_eq!(mime_base64(b"hello"), "aGVsbG8=\n");
//! assert_eq!(favicon_hash(b"hello"), 1_155_597_304);
//! assert_eq!(favicon_hash_base64("aGVs bG8=")?, 1_155_597_304);
//! assert_eq!(shodan_query(-757_223_386), "http.favicon.hash:-757223386");
//! # Ok::<(), rune_favicon_hash::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Characters per line in the MIME-style base64 that is hashed (RFC 2045
/// §6.8, as written by Python's `base64.encodebytes`).
pub const LINE_LEN: usize = 76;

/// Errors from [`favicon_hash_base64`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not valid standard base64.
    #[error("invalid base64: {0}")]
    Base64(#[from] rune_base64::Base64Error),
}

/// The base64 text that the favicon hash is computed over: standard
/// alphabet with padding, a `\n` after every [`LINE_LEN`] characters and
/// after the final line. Empty input gives an empty string.
///
/// ```
/// use rune_favicon_hash::mime_base64;
///
/// assert_eq!(mime_base64(b""), "");
/// assert_eq!(mime_base64(&[0xFF; 57]), format!("{}\n", "/".repeat(76)));
/// assert_eq!(mime_base64(&[0xFF; 58]).lines().count(), 2);
/// ```
#[must_use]
pub fn mime_base64(icon: &[u8]) -> String {
    let encoded = rune_base64::encode(icon);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / LINE_LEN + 1);
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        // Base64 output is ASCII, so any byte offset is a char boundary.
        let (line, tail) = rest.split_at(rest.len().min(LINE_LEN));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out
}

/// The favicon hash of raw icon bytes: the signed `MurmurHash3` `x86_32`
/// (seed 0) of the [`mime_base64`] text of `icon`, as Shodan and Python's
/// `mmh3.hash(codecs.encode(icon, "base64"))` compute it.
///
/// ```
/// use rune_favicon_hash::favicon_hash;
///
/// assert_eq!(favicon_hash(b""), 0);
/// assert_eq!(favicon_hash(b"hello"), 1_155_597_304);
/// ```
#[must_use]
pub fn favicon_hash(icon: &[u8]) -> i32 {
    let hash = rune_murmur::murmurhash3_x86_32(mime_base64(icon).as_bytes(), 0);
    i32::from_ne_bytes(hash.to_ne_bytes())
}

/// The favicon hash of an icon given as base64 (for example the payload of
/// a `data:image/x-icon;base64,…` URI or a HAR response body).
///
/// ASCII whitespace, including any existing line wrapping, is ignored; the
/// decoded bytes are re-encoded canonically before hashing, so the result
/// equals [`favicon_hash`] of the decoded icon whatever wrapping the input
/// used.
pub fn favicon_hash_base64(encoded: &str) -> Result<i32, Error> {
    let compact: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    Ok(favicon_hash(&rune_base64::decode(&compact)?))
}

/// The Shodan search filter for a favicon hash: `http.favicon.hash:<hash>`.
#[must_use]
pub fn shodan_query(hash: i32) -> String {
    format!("http.favicon.hash:{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers computed with Python's `mmh3.hash(codecs.encode(data,
    /// "base64"))` semantics.
    #[test]
    fn known_answers() {
        let ramp: Vec<u8> = (0..=255).collect();
        let mut ico = vec![0u8, 0, 1, 0];
        ico.extend((0..1000u32).map(|i| u8::try_from(i * 7 % 256).unwrap()));
        let cases: [(&[u8], i32); 6] = [
            (b"", 0),
            (b"hello", 1_155_597_304),
            (&ramp, -757_223_386),
            (&ico, 859_315_360),
            (&[b'a'; 57], 1_654_473_660),
            (&[b'a'; 58], 801_193_522),
        ];
        for (input, expected) in cases {
            assert_eq!(favicon_hash(input), expected, "{} bytes", input.len());
        }
    }

    #[test]
    fn wrapping_matches_python() {
        let ramp: Vec<u8> = (0..=255).collect();
        let text = mime_base64(&ramp);
        assert_eq!(text.matches('\n').count(), 5);
        assert!(text.lines().take(4).all(|line| line.len() == LINE_LEN));
        assert!(text.ends_with("+/w==\n"));
        assert!(text.starts_with("AAECAwQFBgcICQoLDA0O"));
    }

    #[test]
    fn base64_input() {
        let ramp: Vec<u8> = (0..=255).collect();
        assert_eq!(favicon_hash_base64(&mime_base64(&ramp)), Ok(-757_223_386));
        assert_eq!(
            favicon_hash_base64(&rune_base64::encode(&ramp)),
            Ok(-757_223_386)
        );
        assert!(matches!(favicon_hash_base64("@@@@"), Err(Error::Base64(_))));
    }

    #[test]
    fn query() {
        assert_eq!(shodan_query(116_323_821), "http.favicon.hash:116323821");
    }
}

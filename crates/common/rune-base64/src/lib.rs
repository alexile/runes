//! Base64 encoder and decoder — standard (RFC 4648) and URL-safe variants.
//!
//! Implements Base64 from scratch with no external crates. Covers the two
//! alphabets defined by RFC 4648: the standard alphabet using `+` and `/`,
//! and the URL-safe alphabet using `-` and `_`. Both alphabets are supported
//! for encoding with and without `=` padding, and decoding auto-detects which
//! alphabet was used.
//!
//! # Features
//!
//! - [`encode`] — standard Base64 with `=` padding.
//! - [`encode_url`] — URL-safe Base64 with `=` padding.
//! - [`encode_no_pad`] — standard Base64 without padding.
//! - [`encode_url_no_pad`] — URL-safe Base64 without padding.
//! - [`decode`] — decode standard or URL-safe Base64, with or without padding.
//! - [`Base64Error`] — error type for malformed input.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_base64::{encode, decode};
//!
//! let encoded = encode(b"hello");
//! assert_eq!(encoded, "aGVsbG8=");
//!
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded, b"hello");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-base64 encode myfile.bin
//! rune-base64 encode --url --no-pad myfile.bin
//! rune-base64 decode encoded.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Error returned when [`decode`] encounters invalid Base64 input.
#[derive(Debug, PartialEq, Eq)]
pub enum Base64Error {
    /// A character that does not belong to any Base64 alphabet was found.
    InvalidChar(char),
    /// The encoded string length (after stripping padding) does not correspond
    /// to a valid Base64 sequence. Valid lengths are congruent to 0, 2, or 3
    /// modulo 4 — a length congruent to 1 modulo 4 is always malformed.
    InvalidLength,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "invalid Base64 character: {c:?}"),
            Self::InvalidLength => f.write_str("invalid Base64 encoded length"),
        }
    }
}

impl core::error::Error for Base64Error {}

/// Encodes bytes as standard Base64 (RFC 4648) with `=` padding.
///
/// Uses the alphabet `A–Z a–z 0–9 + /`. The output length is always a
/// multiple of 4, padded with `=` characters as required.
///
/// # Examples
///
/// ```rust
/// use rune_base64::encode;
///
/// assert_eq!(encode(b""), "");
/// assert_eq!(encode(b"f"), "Zg==");
/// assert_eq!(encode(b"fo"), "Zm8=");
/// assert_eq!(encode(b"foo"), "Zm9v");
/// assert_eq!(encode(b"Man"), "TWFu");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    encode_with_alphabet(bytes, STANDARD_ALPHABET, true)
}

/// Encodes bytes as URL-safe Base64 (RFC 4648 §5) with `=` padding.
///
/// Identical to [`encode`] except `+` is replaced by `-` and `/` by `_`.
/// This form is safe to include in URLs and filenames without percent-encoding.
///
/// # Examples
///
/// ```rust
/// use rune_base64::encode_url;
///
/// assert_eq!(encode_url(b"\xfb\xff"), "-_8=");
/// assert_eq!(encode_url(b"\xfb\xff\xfe"), "-__-");
/// ```
#[must_use]
pub fn encode_url(bytes: &[u8]) -> String {
    encode_with_alphabet(bytes, URL_SAFE_ALPHABET, true)
}

/// Encodes bytes as standard Base64 without `=` padding.
///
/// Same alphabet as [`encode`] but omits trailing `=` characters. Useful
/// when the length is known from context, such as in JWT headers and payloads.
///
/// # Examples
///
/// ```rust
/// use rune_base64::encode_no_pad;
///
/// assert_eq!(encode_no_pad(b"f"), "Zg");
/// assert_eq!(encode_no_pad(b"fo"), "Zm8");
/// assert_eq!(encode_no_pad(b"foo"), "Zm9v");
/// ```
#[must_use]
pub fn encode_no_pad(bytes: &[u8]) -> String {
    encode_with_alphabet(bytes, STANDARD_ALPHABET, false)
}

/// Encodes bytes as URL-safe Base64 without `=` padding.
///
/// Combines the URL-safe alphabet of [`encode_url`] with the omitted padding
/// of [`encode_no_pad`]. This is the form used in JWT tokens.
///
/// # Examples
///
/// ```rust
/// use rune_base64::encode_url_no_pad;
///
/// assert_eq!(encode_url_no_pad(b"f"), "Zg");
/// assert_eq!(encode_url_no_pad(b"fo"), "Zm8");
/// ```
#[must_use]
pub fn encode_url_no_pad(bytes: &[u8]) -> String {
    encode_with_alphabet(bytes, URL_SAFE_ALPHABET, false)
}

/// Decodes a Base64-encoded string to bytes.
///
/// Accepts standard and URL-safe alphabets, detected automatically: if the
/// input contains `-` or `_`, the URL-safe alphabet is used; otherwise the
/// standard alphabet is used. Padding (`=`) is optional — both padded and
/// unpadded inputs are accepted.
///
/// # Errors
///
/// Returns [`Base64Error::InvalidChar`] if a character does not belong to the
/// detected alphabet. Returns [`Base64Error::InvalidLength`] if the number of
/// data characters is congruent to 1 modulo 4 (which can never represent a
/// whole number of bytes).
///
/// # Examples
///
/// ```rust
/// use rune_base64::decode;
///
/// assert_eq!(decode("Zm9v").unwrap(), b"foo");
/// assert_eq!(decode("Zm8=").unwrap(), b"fo");
/// assert_eq!(decode("Zg==").unwrap(), b"f");
/// assert_eq!(decode("").unwrap(), b"");
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub fn decode(encoded: &str) -> Result<Vec<u8>, Base64Error> {
    let is_url_safe = encoded.contains('-') || encoded.contains('_');
    let alphabet = if is_url_safe {
        URL_SAFE_ALPHABET
    } else {
        STANDARD_ALPHABET
    };

    let data: Vec<u8> = encoded
        .chars()
        .filter(|&ch| ch != '=')
        .map(|ch| char_to_value(ch, alphabet))
        .collect::<Result<Vec<u8>, Base64Error>>()?;

    if data.len() % 4 == 1 {
        return Err(Base64Error::InvalidLength);
    }

    let output_len = (data.len() * 6) / 8;
    let mut output = Vec::with_capacity(output_len);

    for chunk in data.chunks(4) {
        let combined = chunk
            .iter()
            .fold(0u32, |acc, &value| (acc << 6) | u32::from(value));

        match chunk.len() {
            4 => {
                output.push((combined >> 16) as u8);
                output.push((combined >> 8) as u8);
                output.push(combined as u8);
            }
            3 => {
                output.push((combined >> 10) as u8);
                output.push((combined >> 2) as u8);
            }
            2 => {
                output.push((combined >> 4) as u8);
            }
            _ => {}
        }
    }

    Ok(output)
}

fn encode_with_alphabet(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let combined = chunk
            .iter()
            .fold(0u32, |acc, &byte| (acc << 8) | u32::from(byte));

        match chunk.len() {
            3 => {
                output.push(alphabet[((combined >> 18) & 0x3f) as usize] as char);
                output.push(alphabet[((combined >> 12) & 0x3f) as usize] as char);
                output.push(alphabet[((combined >> 6) & 0x3f) as usize] as char);
                output.push(alphabet[(combined & 0x3f) as usize] as char);
            }
            2 => {
                output.push(alphabet[((combined >> 10) & 0x3f) as usize] as char);
                output.push(alphabet[((combined >> 4) & 0x3f) as usize] as char);
                output.push(alphabet[((combined << 2) & 0x3f) as usize] as char);
                if pad {
                    output.push('=');
                }
            }
            1 => {
                output.push(alphabet[((combined >> 2) & 0x3f) as usize] as char);
                output.push(alphabet[((combined << 4) & 0x3f) as usize] as char);
                if pad {
                    output.push('=');
                    output.push('=');
                }
            }
            _ => {}
        }
    }

    output
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn char_to_value(ch: char, alphabet: &[u8; 64]) -> Result<u8, Base64Error> {
    alphabet
        .iter()
        .position(|&byte| byte as char == ch)
        .map(|pos| pos as u8)
        .ok_or(Base64Error::InvalidChar(ch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_one_byte() {
        assert_eq!(encode(b"f"), "Zg==");
    }

    #[test]
    fn encode_two_bytes() {
        assert_eq!(encode(b"fo"), "Zm8=");
    }

    #[test]
    fn encode_three_bytes() {
        assert_eq!(encode(b"foo"), "Zm9v");
    }

    #[test]
    fn encode_six_bytes() {
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encode_man() {
        assert_eq!(encode(b"Man"), "TWFu");
    }

    #[test]
    fn encode_hello() {
        assert_eq!(encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn decode_three_bytes() {
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn decode_with_one_pad() {
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
    }

    #[test]
    fn decode_with_two_pads() {
        assert_eq!(decode("Zg==").unwrap(), b"f");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn decode_without_padding() {
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    #[test]
    fn roundtrip_various_lengths() {
        for length in 0usize..=20 {
            let input: Vec<u8> = (0..length).map(|i| i as u8).collect();
            assert_eq!(decode(&encode(&input)).unwrap(), input, "length {length}");
        }
    }

    #[test]
    fn encode_url_replaces_plus_and_slash() {
        let bytes = b"\xfb\xff\xfe";
        let standard = encode(bytes);
        let url_safe = encode_url(bytes);
        assert!(standard.contains('+') || standard.contains('/'));
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));
    }

    #[test]
    fn decode_url_safe() {
        let encoded = encode_url(b"hello world");
        assert_eq!(decode(&encoded).unwrap(), b"hello world");
    }

    #[test]
    fn encode_no_pad_omits_equals() {
        assert!(!encode_no_pad(b"f").contains('='));
        assert!(!encode_no_pad(b"fo").contains('='));
        assert_eq!(encode_no_pad(b"foo"), "Zm9v");
    }

    #[test]
    fn encode_url_no_pad_omits_equals() {
        assert!(!encode_url_no_pad(b"f").contains('='));
        assert_eq!(encode_url_no_pad(b"foo"), "Zm9v");
    }

    #[test]
    fn roundtrip_all_byte_values() {
        let all: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn decode_error_invalid_char() {
        assert!(matches!(
            decode("Zm9!").unwrap_err(),
            Base64Error::InvalidChar('!')
        ));
    }

    #[test]
    fn decode_error_invalid_length() {
        assert_eq!(decode("Zm9vZ").unwrap_err(), Base64Error::InvalidLength);
    }
}

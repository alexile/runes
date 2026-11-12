//! URL percent-encoding and decoding for byte slices and strings.
//!
//! Encodes bytes as `%XX` sequences using the unreserved character set from
//! RFC 3986 (A–Z, a–z, 0–9, `-`, `_`, `.`, `~`). All other bytes are encoded.
//! Decoding accepts both `%XX` (hex escape) and `+` (space, form-data style).
//!
//! # Features
//!
//! - [`encode`] — percent-encode a string (query-string safe).
//! - [`encode_bytes`] — percent-encode raw bytes.
//! - [`decode`] — decode a percent-encoded string; returns [`Err`] on malformed input.
//! - [`decode_bytes`] — decode to raw bytes (no UTF-8 requirement).
//! - [`decode_lossy`] — decode and replace invalid sequences with the literal `%XX` text.
//! - [`DecodeError`] — structured error type for malformed input.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_url_encode::{encode, decode};
//!
//! let encoded = encode("hello world/path?q=1");
//! assert_eq!(encoded, "hello%20world%2Fpath%3Fq%3D1");
//!
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded, "hello world/path?q=1");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-url-encode "hello world"      # encode
//! rune-url-encode -d "hello%20world" # decode
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use alloc::string::FromUtf8Error;
use core::fmt;

/// Error returned when [`decode`] encounters malformed percent-encoded input.
#[derive(Debug)]
pub enum DecodeError {
    /// A `%` at `pos` was not followed by two hex digits (end of input reached).
    TruncatedSequence {
        /// Byte offset of the `%`.
        pos: usize,
    },
    /// A `%` at `pos` was followed by a non-hex character `ch`.
    InvalidHexDigit {
        /// The offending character.
        ch: char,
        /// Byte offset of the `%`.
        pos: usize,
    },
    /// The decoded bytes are not valid UTF-8.
    InvalidUtf8(FromUtf8Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedSequence { pos } => {
                write!(f, "truncated percent-sequence at position {pos}")
            }
            Self::InvalidHexDigit { ch, pos } => {
                write!(f, "invalid hex digit {ch:?} at position {pos}")
            }
            Self::InvalidUtf8(err) => {
                write!(f, "decoded bytes are not valid UTF-8: {err}")
            }
        }
    }
}

impl core::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(err) => Some(err),
            _ => None,
        }
    }
}

impl From<FromUtf8Error> for DecodeError {
    fn from(err: FromUtf8Error) -> Self {
        Self::InvalidUtf8(err)
    }
}

/// Percent-encodes a string, escaping all characters outside the RFC 3986
/// unreserved set (`A–Z a–z 0–9 - _ . ~`).
///
/// # Examples
///
/// ```rust
/// use rune_url_encode::encode;
///
/// assert_eq!(encode("hello world"), "hello%20world");
/// assert_eq!(encode("a+b=c&d=e"), "a%2Bb%3Dc%26d%3De");
/// assert_eq!(encode("abc-_.~"), "abc-_.~");
/// ```
#[must_use]
pub fn encode(input: &str) -> String {
    encode_bytes(input.as_bytes())
}

/// Percent-encodes raw bytes, escaping all bytes outside the RFC 3986
/// unreserved set.
///
/// # Examples
///
/// ```rust
/// use rune_url_encode::encode_bytes;
///
/// assert_eq!(encode_bytes(b"\x00\xFF"), "%00%FF");
/// assert_eq!(encode_bytes(b"hello"), "hello");
/// ```
#[must_use]
pub fn encode_bytes(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for &byte in input {
        if is_unreserved(byte) {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 0x0F));
        }
    }
    output
}

/// Decodes a percent-encoded string.
///
/// Treats `+` as a space (application/x-www-form-urlencoded convention).
/// Returns [`Err`] with a [`DecodeError`] if a `%XX` sequence is malformed or
/// the decoded bytes are not valid UTF-8.
///
/// # Errors
///
/// - [`DecodeError::TruncatedSequence`] — `%` appears without two following characters.
/// - [`DecodeError::InvalidHexDigit`] — `%` is followed by a non-hex character.
/// - [`DecodeError::InvalidUtf8`] — the decoded byte sequence is not valid UTF-8.
///
/// # Examples
///
/// ```rust
/// use rune_url_encode::decode;
///
/// assert_eq!(decode("hello%20world").unwrap(), "hello world");
/// assert_eq!(decode("a%2Bb").unwrap(), "a+b");
/// assert_eq!(decode("hello+world").unwrap(), "hello world");
/// assert!(decode("bad%GG").is_err());
/// ```
pub fn decode(input: &str) -> Result<String, DecodeError> {
    Ok(String::from_utf8(decode_bytes(input.as_bytes())?)?)
}

/// Decodes percent-encoded bytes into raw bytes, without requiring UTF-8.
///
/// Same rules as [`decode`] (`%XX` escapes, `+` as a space, other bytes
/// copied through), but the result may be any byte sequence, so it is the
/// inverse of [`encode_bytes`] for binary data.
///
/// # Errors
///
/// - [`DecodeError::TruncatedSequence`] — `%` appears without two following characters.
/// - [`DecodeError::InvalidHexDigit`] — `%` is followed by a non-hex character.
///
/// # Examples
///
/// ```rust
/// use rune_url_encode::{decode_bytes, encode_bytes};
///
/// assert_eq!(decode_bytes(b"%00%FF+a").unwrap(), b"\x00\xFF a");
/// assert_eq!(decode_bytes(encode_bytes(b"\x80bin").as_bytes()).unwrap(), b"\x80bin");
/// assert!(decode_bytes(b"%G0").is_err());
/// ```
pub fn decode_bytes(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                output.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(DecodeError::TruncatedSequence { pos: i });
                }
                let high = from_hex(bytes[i + 1]).ok_or(DecodeError::InvalidHexDigit {
                    ch: bytes[i + 1] as char,
                    pos: i + 1,
                })?;
                let low = from_hex(bytes[i + 2]).ok_or(DecodeError::InvalidHexDigit {
                    ch: bytes[i + 2] as char,
                    pos: i + 2,
                })?;
                output.push((high << 4) | low);
                i += 3;
            }
            byte => {
                output.push(byte);
                i += 1;
            }
        }
    }
    Ok(output)
}

/// Decodes a percent-encoded string, keeping malformed `%XX` sequences as-is.
///
/// Unlike [`decode`], this never fails — invalid sequences are passed through
/// unchanged.
///
/// # Examples
///
/// ```rust
/// use rune_url_encode::decode_lossy;
///
/// assert_eq!(decode_lossy("hello%20world"), "hello world");
/// assert_eq!(decode_lossy("bad%GGvalue"), "bad%GGvalue");
/// ```
#[must_use]
pub fn decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                output.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                    let decoded_byte = (high << 4) | low;
                    output.push(decoded_byte as char);
                    i += 3;
                } else {
                    output.push('%');
                    i += 1;
                }
            }
            byte => {
                output.push(byte as char);
                i += 1;
            }
        }
    }
    output
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// Uppercase hex digit for the low four bits of `nibble`.
fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(nibble & 0x0F)])
}

const fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_unreserved_unchanged() {
        assert_eq!(encode("abcABC123-_.~"), "abcABC123-_.~");
    }

    #[test]
    fn encode_space() {
        assert_eq!(encode("hello world"), "hello%20world");
    }

    #[test]
    fn encode_special_chars() {
        assert_eq!(encode("a+b=c&d"), "a%2Bb%3Dc%26d");
    }

    #[test]
    fn encode_slash_and_query() {
        assert_eq!(encode("/path?q=1"), "%2Fpath%3Fq%3D1");
    }

    #[test]
    fn encode_bytes_high() {
        assert_eq!(encode_bytes(b"\x00\x7F\xFF"), "%00%7F%FF");
    }

    #[test]
    fn decode_basic() {
        assert_eq!(decode("hello%20world").unwrap(), "hello world");
    }

    #[test]
    fn decode_plus_as_space() {
        assert_eq!(decode("hello+world").unwrap(), "hello world");
    }

    #[test]
    fn decode_mixed_case_hex() {
        assert_eq!(decode("a%2bb").unwrap(), "a+b");
        assert_eq!(decode("a%2Bb").unwrap(), "a+b");
    }

    #[test]
    fn decode_error_bad_hex() {
        assert!(matches!(
            decode("bad%GG").unwrap_err(),
            DecodeError::InvalidHexDigit { ch: 'G', pos: 4 }
        ));
    }

    #[test]
    fn decode_error_truncated() {
        assert!(matches!(
            decode("bad%2").unwrap_err(),
            DecodeError::TruncatedSequence { pos: 3 }
        ));
    }

    #[test]
    fn decode_lossy_passthrough() {
        assert_eq!(decode_lossy("bad%GGvalue"), "bad%GGvalue");
    }

    #[test]
    fn roundtrip() {
        let original = "hello/world?q=rust & encoding!";
        assert_eq!(decode(&encode(original)).unwrap(), original);
    }
}

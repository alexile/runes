//! Hex encoding and decoding for byte slices and files.
//!
//! Converts between raw bytes and their hexadecimal string representation.
//! Decoding accepts mixed-case input and optional `0x` prefix.
//! The library has zero dependencies.
//!
//! # Features
//!
//! - [`encode`] — encode bytes to a lowercase hex string.
//! - [`encode_upper`] — encode bytes to an uppercase hex string.
//! - [`decode`] — decode a hex string to bytes; accepts mixed case and `0x` prefix.
//! - [`HexError`] — error type for malformed input.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_hex::{encode, decode};
//!
//! let hex = encode(b"hello");
//! assert_eq!(hex, "68656c6c6f");
//!
//! let bytes = decode(&hex).unwrap();
//! assert_eq!(bytes, b"hello");
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

/// Error returned when [`decode`] encounters invalid hex input.
#[derive(Debug, PartialEq, Eq)]
pub enum HexError {
    /// Input has an odd number of hex digits (each byte needs two).
    OddLength,
    /// A character in the input is not a valid hex digit.
    InvalidChar(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("odd number of hex digits"),
            Self::InvalidChar(c) => write!(f, "invalid hex character: {c:?}"),
        }
    }
}

impl core::error::Error for HexError {}

/// Encodes bytes as a lowercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_hex::encode;
///
/// assert_eq!(encode(b"\xde\xad\xbe\xef"), "deadbeef");
/// assert_eq!(encode(b""), "");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| nibble_to_hex(b >> 4, false).chain(nibble_to_hex(b & 0xf, false)))
        .collect()
}

/// Encodes bytes as an uppercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_hex::encode_upper;
///
/// assert_eq!(encode_upper(b"\xde\xad\xbe\xef"), "DEADBEEF");
/// ```
#[must_use]
pub fn encode_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| nibble_to_hex(b >> 4, true).chain(nibble_to_hex(b & 0xf, true)))
        .collect()
}

fn nibble_to_hex(nibble: u8, upper: bool) -> core::array::IntoIter<char, 1> {
    let ch = match nibble {
        0..=9 => b'0' + nibble,
        _ if upper => b'A' + nibble - 10,
        _ => b'a' + nibble - 10,
    };
    [ch as char].into_iter()
}

/// Decodes a hex string to bytes.
///
/// Accepts lowercase, uppercase, and mixed-case input. An optional `0x` or
/// `0X` prefix is stripped before decoding.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] if the number of hex digits is odd, or
/// [`HexError::InvalidChar`] if any character is not a valid hex digit.
///
/// # Examples
///
/// ```rust
/// use rune_hex::decode;
///
/// assert_eq!(decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
/// assert_eq!(decode("DEADBEEF").unwrap(), b"\xde\xad\xbe\xef");
/// assert_eq!(decode("0xDeAdBeEf").unwrap(), b"\xde\xad\xbe\xef");
/// assert_eq!(decode("").unwrap(), b"");
/// ```
pub fn decode(hex: &str) -> Result<Vec<u8>, HexError> {
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    if !hex.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }

    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = from_hex_char(pair[0] as char)?;
            let lo = from_hex_char(pair[1] as char)?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

const fn from_hex_char(c: char) -> Result<u8, HexError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(HexError::InvalidChar(c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode(b"\xff"), "ff");
        assert_eq!(encode(b"\x00"), "00");
    }

    #[test]
    fn encode_lowercase() {
        assert_eq!(encode(b"\xde\xad\xbe\xef"), "deadbeef");
    }

    #[test]
    fn encode_upper_uppercase() {
        assert_eq!(encode_upper(b"\xde\xad\xbe\xef"), "DEADBEEF");
    }

    #[test]
    fn encode_roundtrip() {
        let original = b"Hello, world!\x00\xff";
        assert_eq!(decode(&encode(original)).unwrap(), original);
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn decode_lowercase() {
        assert_eq!(decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn decode_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn decode_mixed_case() {
        assert_eq!(decode("DeAdBeEf").unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn decode_0x_prefix() {
        assert_eq!(decode("0xdeadbeef").unwrap(), b"\xde\xad\xbe\xef");
        assert_eq!(decode("0Xdeadbeef").unwrap(), b"\xde\xad\xbe\xef");
    }

    #[test]
    fn decode_odd_length_errors() {
        assert_eq!(decode("abc").unwrap_err(), HexError::OddLength);
    }

    #[test]
    fn decode_invalid_char_errors() {
        assert!(matches!(
            decode("zz").unwrap_err(),
            HexError::InvalidChar('z')
        ));
    }

    #[test]
    fn encode_all_bytes() {
        let all: Vec<u8> = (0u8..=255).collect();
        let hex = encode(&all);
        assert_eq!(hex.len(), 512);
        assert_eq!(decode(&hex).unwrap(), all);
    }
}

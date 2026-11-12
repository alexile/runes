//! Binary representation encoder and decoder for byte slices.
//!
//! Converts between raw bytes and their 8-bit binary string representation.
//! Useful in CTF challenges, protocol debugging, and educational tools where
//! bit-level inspection of data is needed. The library has zero dependencies.
//!
//! # Features
//!
//! - [`encode`] — encode bytes to a space-separated binary string.
//! - [`encode_compact`] — encode bytes to a continuous binary string with no spaces.
//! - [`decode`] — parse a binary string (with or without spaces) back to bytes.
//! - [`BinaryError`] — error type for malformed input.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_binary::{encode, decode};
//!
//! let bits = encode(b"AB");
//! assert_eq!(bits, "01000001 01000010");
//!
//! let bytes = decode(&bits).unwrap();
//! assert_eq!(bytes, b"AB");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-binary encode myfile.bin
//! rune-binary decode "01000001 01000010"
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

/// Error returned when [`decode`] encounters invalid binary input.
#[derive(Debug, PartialEq, Eq)]
pub enum BinaryError {
    /// A character other than `'0'` or `'1'` (or space) was found in the input.
    InvalidChar(char),
    /// The total number of bits is not a multiple of 8 — cannot form whole bytes.
    NotByteAligned,
}

impl fmt::Display for BinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "invalid binary character: {c:?}"),
            Self::NotByteAligned => f.write_str("bit count is not a multiple of 8"),
        }
    }
}

impl core::error::Error for BinaryError {}

/// Encodes bytes as a space-separated binary string.
///
/// Each byte becomes exactly 8 characters of `'0'` and `'1'`, and bytes are
/// separated by a single space. The space separator makes the output easy to
/// read and is accepted by [`decode`] without stripping manually.
///
/// # Examples
///
/// ```rust
/// use rune_binary::encode;
///
/// assert_eq!(encode(b"A"), "01000001");
/// assert_eq!(encode(b"AB"), "01000001 01000010");
/// assert_eq!(encode(b""), "");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| byte_to_bits(byte))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Encodes bytes as a continuous binary string with no spaces between bytes.
///
/// Produces a compact representation where all bits run together. Useful when
/// feeding output into another tool that expects a raw bit stream.
///
/// # Examples
///
/// ```rust
/// use rune_binary::encode_compact;
///
/// assert_eq!(encode_compact(b"AB"), "0100000101000010");
/// assert_eq!(encode_compact(b""), "");
/// ```
#[must_use]
pub fn encode_compact(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte_to_bits(byte)).collect()
}

/// Decodes a binary string back to bytes.
///
/// Accepts input with or without spaces between byte groups. All space
/// characters are stripped before parsing, so `"01000001 01000010"` and
/// `"0100000101000010"` decode identically.
///
/// # Errors
///
/// Returns [`BinaryError::InvalidChar`] if any character other than `'0'`,
/// `'1'`, or `' '` appears in the input. Returns
/// [`BinaryError::NotByteAligned`] if the total number of bits (after
/// stripping spaces) is not a multiple of 8.
///
/// # Examples
///
/// ```rust
/// use rune_binary::decode;
///
/// assert_eq!(decode("01000001").unwrap(), b"A");
/// assert_eq!(decode("01000001 01000010").unwrap(), b"AB");
/// assert_eq!(decode("").unwrap(), b"");
/// ```
pub fn decode(binary: &str) -> Result<Vec<u8>, BinaryError> {
    for ch in binary.chars() {
        if ch != '0' && ch != '1' && ch != ' ' {
            return Err(BinaryError::InvalidChar(ch));
        }
    }

    let bits: Vec<char> = binary.chars().filter(|&ch| ch != ' ').collect();

    if !bits.len().is_multiple_of(8) {
        return Err(BinaryError::NotByteAligned);
    }

    bits.chunks(8)
        .map(|chunk| {
            let byte = chunk
                .iter()
                .fold(0u8, |acc, &bit| (acc << 1) | u8::from(bit == '1'));
            Ok(byte)
        })
        .collect()
}

fn byte_to_bits(byte: u8) -> String {
    (0..8)
        .map(|i| if (byte >> (7 - i)) & 1 == 1 { '1' } else { '0' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode(b"A"), "01000001");
    }

    #[test]
    fn encode_two_bytes() {
        assert_eq!(encode(b"AB"), "01000001 01000010");
    }

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_compact_two_bytes() {
        assert_eq!(encode_compact(b"AB"), "0100000101000010");
    }

    #[test]
    fn encode_compact_empty() {
        assert_eq!(encode_compact(b""), "");
    }

    #[test]
    fn decode_single_byte() {
        assert_eq!(decode("01000001").unwrap(), b"A");
    }

    #[test]
    fn decode_with_spaces() {
        assert_eq!(decode("01000001 01000010").unwrap(), b"AB");
    }

    #[test]
    fn decode_compact() {
        assert_eq!(decode("0100000101000010").unwrap(), b"AB");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn roundtrip() {
        let original = b"Hello, world!\x00\xff";
        assert_eq!(decode(&encode(original)).unwrap(), original);
    }

    #[test]
    fn roundtrip_compact() {
        let original = b"Hello, world!\x00\xff";
        assert_eq!(decode(&encode_compact(original)).unwrap(), original);
    }

    #[test]
    fn decode_error_invalid_char() {
        assert!(matches!(
            decode("0100000x").unwrap_err(),
            BinaryError::InvalidChar('x')
        ));
    }

    #[test]
    fn decode_error_not_byte_aligned() {
        assert_eq!(decode("0100").unwrap_err(), BinaryError::NotByteAligned);
    }

    #[test]
    fn encode_all_bytes() {
        let all: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }
}

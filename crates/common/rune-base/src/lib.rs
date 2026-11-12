//! Encode and decode byte strings in any numeric base using a caller-supplied alphabet.
//!
//! Supports arbitrary bases from 2 to 256 by accepting a user-defined alphabet whose
//! length determines the base. Each input byte is encoded to a fixed number of output
//! characters: the smallest `k` such that `base^k ≥ 256`. This gives a clean,
//! lossless, fixed-width-per-byte encoding across the full byte range:
//!
//! | Base | Chars per byte |
//! |------|----------------|
//! |    2 | 8 (binary)     |
//! |    8 | 3 (octal)      |
//! |   10 | 3 (decimal)    |
//! |   16 | 2 (hex)        |
//! |  256 | 1              |
//!
//! No external crates required.
//!
//! # Features
//!
//! - [`encode`] — encode bytes to a string using a custom alphabet.
//! - [`decode`] — decode a string back to bytes using the same alphabet.
//! - [`BaseError`] — error type for invalid alphabets or malformed input.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_base::{encode, decode};
//!
//! // Base 16 (hex) with lowercase alphabet
//! let alphabet = b"0123456789abcdef";
//! let encoded = encode(b"hi", alphabet).unwrap();
//! assert_eq!(encoded, "6869");
//!
//! let decoded = decode(&encoded, alphabet).unwrap();
//! assert_eq!(decoded, b"hi");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-base encode --alphabet "0123456789abcdef" myfile.bin
//! rune-base encode --alphabet "01" - < myfile.bin
//! echo -n "6869" | rune-base decode --alphabet "0123456789abcdef" -
//! rune-base decode --alphabet "0123456789abcdef" encoded.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use core::fmt;

/// Error returned when an alphabet or encoded input is invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum BaseError {
    /// The alphabet has fewer than 2 symbols.
    AlphabetTooShort,
    /// The alphabet contains duplicate symbols.
    AlphabetHasDuplicates,
    /// The encoded input contains a character not present in the alphabet.
    InvalidChar(char),
    /// The encoded string length is not a multiple of the digits-per-byte count
    /// for this alphabet (i.e., it cannot represent a whole number of bytes).
    InvalidLength,
    /// A group of digits decoded to a value greater than 255 and cannot be
    /// represented as a single byte. Only possible for non-power-of-2 bases
    /// such as base 10, where three decimal digits span 0–999 but only 0–255
    /// are valid byte values.
    ValueOutOfRange,
}

impl fmt::Display for BaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlphabetTooShort => f.write_str("alphabet must contain at least 2 symbols"),
            Self::AlphabetHasDuplicates => f.write_str("alphabet contains duplicate symbols"),
            Self::InvalidChar(c) => write!(f, "character not in alphabet: {c:?}"),
            Self::InvalidLength => {
                f.write_str("encoded length is not a multiple of the digits-per-byte count")
            }
            Self::ValueOutOfRange => f.write_str("digit group decodes to a value greater than 255"),
        }
    }
}

impl core::error::Error for BaseError {}

/// Encodes `bytes` as a base-N string where N is the length of `alphabet`.
///
/// Each byte is converted independently to exactly `k` characters, where `k`
/// is the smallest integer such that `N^k ≥ 256`. This ensures a fixed,
/// lossless mapping with no ambiguity:
///
/// - Base 2 → 8 chars per byte (`"00000101"` for `0x05`)
/// - Base 16 → 2 chars per byte (`"ff"` for `0xFF`)
/// - Base 10 → 3 chars per byte (`"065"` for `'A'`)
///
/// # Errors
///
/// Returns [`BaseError::AlphabetTooShort`] if fewer than 2 symbols are given,
/// or [`BaseError::AlphabetHasDuplicates`] if any symbol appears more than once.
///
/// # Examples
///
/// ```rust
/// use rune_base::encode;
///
/// // Base 2 (binary) — 8 chars per byte
/// let bits = encode(b"\x05", b"01").unwrap();
/// assert_eq!(bits, "00000101");
///
/// // Base 16 (hex) — 2 chars per byte
/// let hex = encode(b"\xff", b"0123456789abcdef").unwrap();
/// assert_eq!(hex, "ff");
///
/// // Multi-byte input
/// let hex2 = encode(b"hi", b"0123456789abcdef").unwrap();
/// assert_eq!(hex2, "6869");
/// ```
pub fn encode(bytes: &[u8], alphabet: &[u8]) -> Result<String, BaseError> {
    validate_alphabet(alphabet)?;
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let base = alphabet.len();
    let k = digits_per_byte(base);
    let mut out = String::with_capacity(bytes.len() * k);
    let mut buf = vec![0usize; k];
    for &byte in bytes {
        let mut value = usize::from(byte);
        for slot in buf.iter_mut().rev() {
            *slot = value % base;
            value /= base;
        }
        for &index in &buf {
            out.push(alphabet[index] as char);
        }
    }
    Ok(out)
}

/// Decodes a base-N encoded string back to bytes using the given `alphabet`.
///
/// The input must have a length that is a multiple of the digits-per-byte
/// count for this base (see [`encode`] for the formula). Each group of `k`
/// characters is converted to one byte.
///
/// # Errors
///
/// Returns [`BaseError::AlphabetTooShort`] or [`BaseError::AlphabetHasDuplicates`]
/// for an invalid alphabet, [`BaseError::InvalidChar`] if any character in
/// `encoded` is not present in the alphabet, [`BaseError::InvalidLength`] if
/// the length is not a multiple of `k`, and [`BaseError::ValueOutOfRange`] if
/// a digit group decodes to a value greater than 255.
///
/// # Examples
///
/// ```rust
/// use rune_base::decode;
///
/// let decoded = decode("ff", b"0123456789abcdef").unwrap();
/// assert_eq!(decoded, b"\xff");
///
/// let decoded = decode("00000101", b"01").unwrap();
/// assert_eq!(decoded, b"\x05");
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub fn decode(encoded: &str, alphabet: &[u8]) -> Result<Vec<u8>, BaseError> {
    validate_alphabet(alphabet)?;
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let base = alphabet.len();
    let k = digits_per_byte(base);

    let chars: Vec<char> = encoded.chars().collect();
    if !chars.len().is_multiple_of(k) {
        return Err(BaseError::InvalidLength);
    }

    let mut table = [0xffffu16; 256];
    for (i, &byte) in alphabet.iter().enumerate() {
        table[usize::from(byte)] = i as u16;
    }

    let mut out = Vec::with_capacity(chars.len() / k);
    for group in chars.chunks(k) {
        let mut value: usize = 0;
        for &ch in group {
            let code = ch as u32;
            if code > 255 {
                return Err(BaseError::InvalidChar(ch));
            }
            let digit = table[code as usize];
            if digit == 0xffff {
                return Err(BaseError::InvalidChar(ch));
            }
            value = value * base + usize::from(digit);
        }
        if value > 255 {
            return Err(BaseError::ValueOutOfRange);
        }
        out.push(value as u8);
    }

    Ok(out)
}

/// Returns the number of alphabet characters needed to represent one byte for
/// a given base. This is the smallest `k` such that `base^k >= 256`.
const fn digits_per_byte(base: usize) -> usize {
    let mut k = 1usize;
    let mut power = base;
    while power < 256 {
        k += 1;
        power = power.saturating_mul(base);
    }
    k
}

fn validate_alphabet(alphabet: &[u8]) -> Result<(), BaseError> {
    if alphabet.len() < 2 {
        return Err(BaseError::AlphabetTooShort);
    }
    let mut seen = [false; 256];
    for &byte in alphabet {
        if seen[usize::from(byte)] {
            return Err(BaseError::AlphabetHasDuplicates);
        }
        seen[usize::from(byte)] = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_too_short() {
        assert_eq!(encode(b"x", b"0").unwrap_err(), BaseError::AlphabetTooShort);
    }

    #[test]
    fn alphabet_has_duplicates() {
        assert_eq!(
            encode(b"x", b"00").unwrap_err(),
            BaseError::AlphabetHasDuplicates
        );
    }

    #[test]
    fn encode_base2_single_byte() {
        assert_eq!(encode(b"\x05", b"01").unwrap(), "00000101");
    }

    #[test]
    fn encode_base2_all_zeros() {
        assert_eq!(encode(b"\x00", b"01").unwrap(), "00000000");
    }

    #[test]
    fn encode_base2_all_ones() {
        assert_eq!(encode(b"\xff", b"01").unwrap(), "11111111");
    }

    #[test]
    fn encode_base16_single_byte() {
        assert_eq!(encode(b"\xff", b"0123456789abcdef").unwrap(), "ff");
        assert_eq!(encode(b"\x00", b"0123456789abcdef").unwrap(), "00");
    }

    #[test]
    fn encode_base16_multi_byte() {
        assert_eq!(encode(b"hi", b"0123456789abcdef").unwrap(), "6869");
    }

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b"", b"01").unwrap(), "");
    }

    #[test]
    fn decode_base16() {
        assert_eq!(decode("ff", b"0123456789abcdef").unwrap(), b"\xff");
        assert_eq!(decode("00", b"0123456789abcdef").unwrap(), b"\x00");
    }

    #[test]
    fn decode_base16_multi_byte() {
        assert_eq!(decode("6869", b"0123456789abcdef").unwrap(), b"hi");
    }

    #[test]
    fn decode_base2() {
        assert_eq!(decode("00000101", b"01").unwrap(), b"\x05");
        assert_eq!(decode("11111111", b"01").unwrap(), b"\xff");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("", b"01").unwrap(), b"");
    }

    #[test]
    fn decode_invalid_char() {
        assert!(matches!(
            decode("zz", b"0123456789abcdef").unwrap_err(),
            BaseError::InvalidChar('z')
        ));
    }

    #[test]
    fn decode_invalid_length() {
        assert_eq!(
            decode("f", b"0123456789abcdef").unwrap_err(),
            BaseError::InvalidLength
        );
    }

    #[test]
    fn decode_value_out_of_range() {
        let decimal = b"0123456789";
        assert_eq!(
            decode("256", decimal).unwrap_err(),
            BaseError::ValueOutOfRange
        );
    }

    #[test]
    fn roundtrip_base16() {
        let data: Vec<u8> = (0u8..=255).collect();
        let alphabet = b"0123456789abcdef";
        assert_eq!(
            decode(&encode(&data, alphabet).unwrap(), alphabet).unwrap(),
            data
        );
    }

    #[test]
    fn roundtrip_base2() {
        let data = b"Hello!";
        let alphabet = b"01";
        assert_eq!(
            decode(&encode(data, alphabet).unwrap(), alphabet).unwrap(),
            data
        );
    }

    #[test]
    fn roundtrip_base10() {
        let data: Vec<u8> = (0u8..=255).collect();
        let alphabet = b"0123456789";
        assert_eq!(
            decode(&encode(&data, alphabet).unwrap(), alphabet).unwrap(),
            data
        );
    }

    #[test]
    fn digits_per_byte_powers_of_two() {
        assert_eq!(digits_per_byte(2), 8);
        assert_eq!(digits_per_byte(4), 4);
        assert_eq!(digits_per_byte(16), 2);
        assert_eq!(digits_per_byte(256), 1);
    }

    #[test]
    fn digits_per_byte_base10() {
        assert_eq!(digits_per_byte(10), 3);
    }
}

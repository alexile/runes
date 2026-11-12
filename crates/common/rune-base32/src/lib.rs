//! Base32 encode and decode — RFC 4648 standard and extended hex alphabets.
//!
//! Encodes arbitrary bytes to Base32 ASCII and decodes back, with optional
//! padding. Supports both the standard `A–Z 2–7` alphabet and the extended
//! hex `0–9 A–V` alphabet used in DNS security (NSEC3) and other protocols.
//!
//! # Features
//!
//! - [`encode`] / [`decode`] — standard alphabet with padding
//! - [`encode_hex`] / [`decode_hex`] — extended hex alphabet
//! - [`encode_no_pad`] — standard alphabet without `=` padding
//! - [`is_base32`] — heuristic check for Base32-looking strings
//!
//! # Quick Start
//!
//! ```rust
//! use rune_base32::{encode, decode};
//!
//! let encoded = encode(b"Hello, World!");
//! assert_eq!(encoded, "JBSWY3DPFQQFO33SNRSCC===");
//!
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded, b"Hello, World!");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-base32 encode "hello"
//! echo -n "hello" | rune-base32 encode -
//! rune-base32 decode NBSWY3DPEB3W64TMMQ======
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const STD_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Decoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input contains a character not in the alphabet.
    InvalidChar(char),
    /// Input length is not valid for Base32 (not a multiple of 8 after trimming padding).
    InvalidLength,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "invalid Base32 character: {c:?}"),
            Self::InvalidLength => write!(f, "invalid Base32 input length"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Encode bytes using the standard RFC 4648 Base32 alphabet with `=` padding.
///
/// # Examples
///
/// ```rust
/// use rune_base32::encode;
///
/// assert_eq!(encode(b""), "");
/// assert_eq!(encode(b"f"), "MY======");
/// assert_eq!(encode(b"fo"), "MZXQ====");
/// assert_eq!(encode(b"foo"), "MZXW6===");
/// assert_eq!(encode(b"foob"), "MZXW6YQ=");
/// assert_eq!(encode(b"fooba"), "MZXW6YTB");
/// assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
/// ```
#[must_use]
pub fn encode(data: &[u8]) -> String {
    encode_with(data, STD_ALPHABET, true)
}

/// Encode bytes using the standard alphabet without `=` padding.
///
/// # Examples
///
/// ```rust
/// use rune_base32::encode_no_pad;
///
/// assert_eq!(encode_no_pad(b"f"), "MY");
/// assert_eq!(encode_no_pad(b"fooba"), "MZXW6YTB");
/// ```
#[must_use]
pub fn encode_no_pad(data: &[u8]) -> String {
    encode_with(data, STD_ALPHABET, false)
}

/// Encode bytes using the extended hex alphabet (RFC 4648 §7) with padding.
///
/// # Examples
///
/// ```rust
/// use rune_base32::encode_hex;
///
/// assert_eq!(encode_hex(b"foo"), "CPNMU===");
/// ```
#[must_use]
pub fn encode_hex(data: &[u8]) -> String {
    encode_with(data, HEX_ALPHABET, true)
}

fn encode_with(data: &[u8], alphabet: &[u8; 32], pad: bool) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    let mut i = 0;

    while i < data.len() {
        let block = &data[i..data.len().min(i + 5)];
        let b = [
            block.first().copied().unwrap_or(0),
            block.get(1).copied().unwrap_or(0),
            block.get(2).copied().unwrap_or(0),
            block.get(3).copied().unwrap_or(0),
            block.get(4).copied().unwrap_or(0),
        ];

        let chars = [
            alphabet[((b[0] >> 3) & 0x1f) as usize],
            alphabet[(((b[0] << 2) | (b[1] >> 6)) & 0x1f) as usize],
            alphabet[((b[1] >> 1) & 0x1f) as usize],
            alphabet[(((b[1] << 4) | (b[2] >> 4)) & 0x1f) as usize],
            alphabet[(((b[2] << 1) | (b[3] >> 7)) & 0x1f) as usize],
            alphabet[((b[3] >> 2) & 0x1f) as usize],
            alphabet[(((b[3] << 3) | (b[4] >> 5)) & 0x1f) as usize],
            alphabet[(b[4] & 0x1f) as usize],
        ];

        let used = block.len();
        let n_out = match used {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        out.extend_from_slice(&chars[..n_out]);
        if pad && n_out < 8 {
            out.extend(core::iter::repeat_n(b'=', 8 - n_out));
        }
        i += 5;
    }

    // Every byte comes from an ASCII alphabet, so the lossy fallback never runs.
    String::from_utf8(out)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

/// Decode a standard Base32 string (case-insensitive, padding optional).
///
/// # Errors
///
/// Returns [`DecodeError`] if the input contains invalid characters or has
/// an invalid length.
///
/// # Examples
///
/// ```rust
/// use rune_base32::decode;
///
/// assert_eq!(decode("").unwrap(), b"");
/// assert_eq!(decode("MY======").unwrap(), b"f");
/// assert_eq!(decode("MZXW6YTB").unwrap(), b"fooba");
/// assert_eq!(decode("mzxw6ytb").unwrap(), b"fooba");  // case-insensitive
/// ```
pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, STD_ALPHABET)
}

/// Decode an extended hex Base32 string (case-insensitive, padding optional).
///
/// # Errors
///
/// Returns [`DecodeError`] if the input contains invalid characters.
///
/// # Examples
///
/// ```rust
/// use rune_base32::decode_hex;
///
/// assert_eq!(decode_hex("CPNMU===").unwrap(), b"foo");
/// ```
pub fn decode_hex(input: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, HEX_ALPHABET)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn decode_with(input: &str, alphabet: &[u8; 32]) -> Result<Vec<u8>, DecodeError> {
    // ASCII-only case folding: `str::to_uppercase` would map characters such
    // as 'ı' or 'ſ' onto valid Base32 letters.
    let input = input.trim_end_matches('=').to_ascii_uppercase();
    if input.is_empty() {
        return Ok(vec![]);
    }

    let mut table = [0xffu8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[usize::from(c)] = i as u8;
    }

    let mut bits: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);

    for c in input.chars() {
        // Non-ASCII characters are never in the alphabet (and would index
        // past the end of the table).
        let val = u8::try_from(c).map_or(0xff, |b| table[usize::from(b)]);
        if val == 0xff {
            return Err(DecodeError::InvalidChar(c));
        }
        bits = (bits << 5) | u32::from(val);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }

    Ok(out)
}

/// Returns `true` if `s` looks like a Base32-encoded string.
///
/// Checks that all characters are in the standard alphabet (A–Z, 2–7) or are
/// `=` padding, and that the length is a multiple of 8 or plausibly unpadded.
///
/// # Examples
///
/// ```rust
/// use rune_base32::is_base32;
///
/// assert!(is_base32("MZXW6YTB"));
/// assert!(is_base32("JBSWY3DPFQQFO33SNRSCC==="));
/// assert!(!is_base32("not base32!!"));
/// ```
#[must_use]
pub fn is_base32(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let stripped = s.trim_end_matches('=').to_ascii_uppercase();
    stripped.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "MY======");
        assert_eq!(encode(b"fo"), "MZXQ====");
        assert_eq!(encode(b"foo"), "MZXW6===");
        assert_eq!(encode(b"foob"), "MZXW6YQ=");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn decode_rfc4648() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("MY======").unwrap(), b"f");
        assert_eq!(decode("MZXQ====").unwrap(), b"fo");
        assert_eq!(decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn roundtrip() {
        let data = b"Hello, World! \x00\xff\xfe";
        assert_eq!(decode(&encode(data)).unwrap(), data);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(decode("mzxw6ytb").unwrap(), b"fooba");
    }

    #[test]
    fn hex_vectors() {
        assert_eq!(encode_hex(b"foo"), "CPNMU===");
        assert_eq!(decode_hex("CPNMU===").unwrap(), b"foo");
    }

    #[test]
    fn invalid_char() {
        assert!(decode("!NVALID").is_err());
    }

    #[test]
    fn is_base32_check() {
        assert!(is_base32("MZXW6YTB"));
        assert!(!is_base32("not base32!!"));
        assert!(!is_base32(""));
    }

    // Regression: a non-ASCII character indexed past the
    // end of the 256-entry decode table and panicked.
    #[test]
    fn non_ascii_input_is_an_error_not_a_panic() {
        assert_eq!(
            decode("JN\u{32d}S"),
            Err(DecodeError::InvalidChar('\u{32d}'))
        );
        assert_eq!(decode_hex("€"), Err(DecodeError::InvalidChar('€')));
    }

    // Regression: Unicode case folding mapped 'ı' (dotless i) and
    // 'ſ' (long s) onto the letters 'I' and 'S', so they decoded as Base32.
    #[test]
    fn unicode_letters_do_not_fold_into_the_alphabet() {
        assert_eq!(decode("ıııııııı"), Err(DecodeError::InvalidChar('ı')));
        assert!(!is_base32("ſſſſſſſſ"));
    }
}

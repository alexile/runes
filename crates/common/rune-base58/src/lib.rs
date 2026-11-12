//! Base58 encode and decode — Bitcoin and Flickr alphabets.
//!
//! Base58 is the encoding used by Bitcoin addresses, IPFS `CIDv0` hashes, and
//! various other protocols that need short, human-readable, URL-safe identifiers
//! without visually ambiguous characters (`0`, `O`, `I`, `l`).
//!
//! # Alphabets
//!
//! | Alphabet | Characters | Used by |
//! |---|---|---|
//! | Bitcoin (default) | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` | Bitcoin, IPFS, Monero |
//! | Flickr | `123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ` | Flickr short URLs |
//!
//! # Features
//!
//! - [`encode`] / [`decode`] — Bitcoin alphabet
//! - [`encode_flickr`] / [`decode_flickr`] — Flickr alphabet
//! - [`is_base58`] — heuristic check for Base58-looking strings
//!
//! # Quick Start
//!
//! ```rust
//! use rune_base58::{encode, decode};
//!
//! let encoded = encode(b"Hello World");
//! let decoded = decode(&encoded).unwrap();
//! assert_eq!(decoded, b"Hello World");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-base58 encode "hello"
//! rune-base58 decode "Cn8eVZg"
//! echo -n "hello" | rune-base58 encode -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const BITCOIN: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FLICKR: &[u8; 58] = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

/// Errors produced by decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A character not in the alphabet was encountered.
    InvalidChar(char),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "invalid Base58 character: {c:?}"),
        }
    }
}

/// Encode bytes using the Bitcoin Base58 alphabet.
///
/// # Examples
///
/// ```rust
/// use rune_base58::encode;
///
/// assert_eq!(encode(b""), "");
/// assert_eq!(encode(b"\x00"), "1");
/// assert_eq!(encode(b"Hello World"), "JxF12TrwUP45BMd");
/// ```
#[must_use]
pub fn encode(data: &[u8]) -> String {
    encode_with(data, BITCOIN)
}

/// Encode bytes using the Flickr Base58 alphabet.
///
/// # Examples
///
/// ```rust
/// use rune_base58::encode_flickr;
///
/// let s = encode_flickr(b"Hello World");
/// assert!(!s.is_empty());
/// ```
#[must_use]
pub fn encode_flickr(data: &[u8]) -> String {
    encode_with(data, FLICKR)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn encode_with(data: &[u8], alphabet: &[u8; 58]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();
    // Strip leading zeros before the division loop — they are added back as "1"s
    let mut n: Vec<u8> = data[leading_zeros..].to_vec();
    let mut result: Vec<u8> = Vec::new();

    while !n.is_empty() {
        let mut remainder = 0u32;
        let mut new_n: Vec<u8> = Vec::new();
        for &byte in &n {
            let cur = u32::from(byte) + remainder * 256;
            if !new_n.is_empty() || cur / 58 > 0 {
                new_n.push((cur / 58) as u8);
            }
            remainder = cur % 58;
        }
        result.push(alphabet[remainder as usize]);
        n = new_n;
    }

    for _ in 0..leading_zeros {
        result.push(alphabet[0]);
    }
    result.reverse();
    // Every byte comes from an ASCII alphabet, so the lossy fallback never runs.
    String::from_utf8(result)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

/// Decode a Bitcoin Base58 string.
///
/// # Errors
///
/// Returns [`DecodeError`] if the input contains characters not in the
/// Bitcoin Base58 alphabet.
///
/// # Examples
///
/// ```rust
/// use rune_base58::decode;
///
/// assert_eq!(decode("").unwrap(), b"");
/// assert_eq!(decode("1").unwrap(), b"\x00");
/// assert_eq!(decode("JxF12TrwUP45BMd").unwrap(), b"Hello World");
/// ```
pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, BITCOIN)
}

/// Decode a Flickr Base58 string.
///
/// # Errors
///
/// Returns [`DecodeError`] if the input contains invalid characters.
///
/// # Examples
///
/// ```rust
/// use rune_base58::{encode_flickr, decode_flickr};
///
/// let s = encode_flickr(b"hello");
/// assert_eq!(decode_flickr(&s).unwrap(), b"hello");
/// ```
pub fn decode_flickr(input: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, FLICKR)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn decode_with(input: &str, alphabet: &[u8; 58]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(vec![]);
    }

    let mut table = [0xffu8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[usize::from(c)] = i as u8;
    }

    let leading_ones = input
        .chars()
        .take_while(|&c| c == char::from(alphabet[0]))
        .count();

    // Validate all characters first
    for c in input.chars() {
        // Non-ASCII characters are never in the alphabet (and would index
        // past the end of the table).
        if !c.is_ascii() || table[c as usize] == 0xff {
            return Err(DecodeError::InvalidChar(c));
        }
    }

    // Process the non-leading-ones portion as a base-58 number
    let rest = &input[leading_ones..];
    let mut num: Vec<u8> = Vec::new();

    for c in rest.chars() {
        let val = u32::from(table[c as usize]);
        let mut carry = val;
        for byte in num.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Strip internal leading zeros from num (left over from arithmetic)
    let num_start = num.iter().take_while(|&&b| b == 0).count();
    let mut result = vec![0u8; leading_ones];
    result.extend_from_slice(&num[num_start..]);
    Ok(result)
}

/// Returns `true` if `s` looks like a Base58-encoded string (Bitcoin alphabet).
///
/// # Examples
///
/// ```rust
/// use rune_base58::is_base58;
///
/// assert!(is_base58("JxF12TrwUP45BMd"));
/// assert!(is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"));  // genesis block
/// assert!(!is_base58("Hello World!"));  // spaces and !
/// ```
#[must_use]
pub fn is_base58(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            matches!(c,
                '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_leading_zero() {
        assert_eq!(encode(b"\x00"), "1");
        assert_eq!(encode(b"\x00\x00"), "11");
    }

    #[test]
    fn encode_hello_world() {
        assert_eq!(encode(b"Hello World"), "JxF12TrwUP45BMd");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn decode_leading_zero() {
        assert_eq!(decode("1").unwrap(), b"\x00");
    }

    #[test]
    fn decode_hello_world() {
        assert_eq!(decode("JxF12TrwUP45BMd").unwrap(), b"Hello World");
    }

    #[test]
    fn roundtrip() {
        let data = b"The quick brown fox";
        assert_eq!(decode(&encode(data)).unwrap(), data);
    }

    #[test]
    fn roundtrip_binary() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn flickr_roundtrip() {
        let data = b"flickr short URL";
        assert_eq!(decode_flickr(&encode_flickr(data)).unwrap(), data);
    }

    #[test]
    fn invalid_char() {
        assert!(decode("0invalid").is_err());
        assert!(decode("Oinvalid").is_err());
    }

    #[test]
    fn is_base58_check() {
        assert!(is_base58("JxF12TrwUP45BMd"));
        assert!(!is_base58("Hello World!"));
        assert!(!is_base58(""));
    }

    // Regression: a non-ASCII character indexed past the
    // end of the 256-entry decode table and panicked.
    #[test]
    fn non_ascii_input_is_an_error_not_a_panic() {
        assert_eq!(
            decode("JxF1\u{36b}Urw"),
            Err(DecodeError::InvalidChar('\u{36b}'))
        );
        assert_eq!(decode_flickr("ñ"), Err(DecodeError::InvalidChar('ñ')));
    }
}

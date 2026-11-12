//! ROT13 cipher — rotate ASCII letters by 13 positions.
//!
//! ROT13 is a simple letter substitution cipher that replaces each ASCII letter
//! with the letter 13 positions after it in the alphabet, wrapping around at the
//! boundary. Because the alphabet has 26 letters, applying ROT13 twice returns
//! the original text — encoding and decoding are the same operation.
//!
//! Non-letter bytes (digits, punctuation, whitespace, binary data) pass through
//! unchanged. The library has zero dependencies.
//!
//! # Features
//!
//! - [`rot13`] — applies ROT13 to a string; non-letter characters are unchanged.
//! - [`rot13_bytes`] — applies ROT13 to a raw byte slice.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_rot13::rot13;
//!
//! let encoded = rot13("Hello, World!");
//! assert_eq!(encoded, "Uryyb, Jbeyq!");
//!
//! let decoded = rot13(&encoded);
//! assert_eq!(decoded, "Hello, World!");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-rot13 "Hello, World!"
//! echo "Hello, World!" | rune-rot13
//! rune-rot13 -f message.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Applies ROT13 to a UTF-8 string, rotating only ASCII letters.
///
/// Each ASCII letter is shifted 13 positions within its case range (`a-z` or
/// `A-Z`). All other bytes, including digits, punctuation, whitespace, and
/// non-ASCII bytes, are passed through unchanged. Applying this function twice
/// to the same input returns the original string.
///
/// # Examples
///
/// ```rust
/// use rune_rot13::rot13;
///
/// assert_eq!(rot13("Hello, World!"), "Uryyb, Jbeyq!");
/// assert_eq!(rot13("Uryyb, Jbeyq!"), "Hello, World!");
/// assert_eq!(rot13("123 !@#"), "123 !@#");
/// assert_eq!(rot13(""), "");
/// ```
#[must_use]
pub fn rot13(text: &str) -> String {
    // Only ASCII bytes are rewritten, so the result is always valid UTF-8 and
    // the lossy fallback never runs.
    String::from_utf8(rot13_bytes(text.as_bytes()))
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

/// Applies ROT13 to a raw byte slice, rotating only ASCII letters.
///
/// Suitable for binary data where only the letter bytes should be rotated.
/// Non-letter bytes are passed through unchanged. Applying this function twice
/// to the same input returns the original bytes.
///
/// # Examples
///
/// ```rust
/// use rune_rot13::rot13_bytes;
///
/// assert_eq!(rot13_bytes(b"Hello!"), b"Uryyb!");
/// assert_eq!(rot13_bytes(b"Uryyb!"), b"Hello!");
/// assert_eq!(rot13_bytes(b"\x00\xff"), b"\x00\xff");
/// assert_eq!(rot13_bytes(b""), b"");
/// ```
pub fn rot13_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().map(rotate_byte).collect()
}

const fn rotate_byte(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' => (byte - b'a' + 13) % 26 + b'a',
        b'A'..=b'Z' => (byte - b'A' + 13) % 26 + b'A',
        _ => byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_empty() {
        assert_eq!(rot13(""), "");
    }

    #[test]
    fn rot13_lowercase() {
        assert_eq!(
            rot13("abcdefghijklmnopqrstuvwxyz"),
            "nopqrstuvwxyzabcdefghijklm"
        );
    }

    #[test]
    fn rot13_uppercase() {
        assert_eq!(
            rot13("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "NOPQRSTUVWXYZABCDEFGHIJKLM"
        );
    }

    #[test]
    fn rot13_mixed_case() {
        assert_eq!(rot13("Hello, World!"), "Uryyb, Jbeyq!");
    }

    #[test]
    fn rot13_non_letters_unchanged() {
        assert_eq!(rot13("123 !@# \t\n"), "123 !@# \t\n");
    }

    #[test]
    fn rot13_idempotent() {
        let inputs = ["Hello, World!", "The quick brown fox", "abc XYZ 123 !"];
        for input in inputs {
            assert_eq!(rot13(&rot13(input)), input);
        }
    }

    #[test]
    fn rot13_bytes_empty() {
        assert_eq!(rot13_bytes(b""), b"");
    }

    #[test]
    fn rot13_bytes_non_ascii_unchanged() {
        assert_eq!(rot13_bytes(b"\x00\x80\xff"), b"\x00\x80\xff");
    }

    #[test]
    fn rot13_bytes_idempotent() {
        let original = b"Attack at dawn! \x00\xff";
        assert_eq!(rot13_bytes(&rot13_bytes(original)), original);
    }

    #[test]
    fn rot13_roundtrip() {
        let plaintext = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(rot13(&rot13(plaintext)), plaintext);
    }
}

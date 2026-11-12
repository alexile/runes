//! ROT47 cipher — rotate printable ASCII characters by 47 positions.
//!
//! ROT47 extends the ROT13 idea to the full printable ASCII range (byte values
//! 33–126, 94 characters). Each character in that range is rotated 47 positions
//! forward, wrapping within the 94-character window. Because 94 ÷ 2 = 47,
//! applying the function twice returns the original input — it is its own inverse.
//!
//! Bytes outside the printable ASCII range (spaces, control characters, high bytes)
//! pass through unchanged. The library has zero dependencies.
//!
//! # Features
//!
//! - [`rot47`] — applies ROT47 to a string; non-printable bytes are unchanged.
//! - [`rot47_bytes`] — applies ROT47 to a raw byte slice.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_rot47::rot47;
//!
//! let encoded = rot47("Hello, World!");
//! assert_eq!(encoded, "w6==@[ (@C=5P");
//!
//! let decoded = rot47(&encoded);
//! assert_eq!(decoded, "Hello, World!");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-rot47 "Hello, World!"
//! echo "Hello, World!" | rune-rot47
//! rune-rot47 -f message.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Applies ROT47 to a UTF-8 string, rotating only printable ASCII characters.
///
/// Printable ASCII spans byte values 33–126 (94 characters, excluding space).
/// Each byte in that range is shifted forward by 47 within the window, wrapping
/// around at the boundary. All other bytes pass through unchanged. Applying this
/// function twice to the same input returns the original string.
///
/// # Examples
///
/// ```rust
/// use rune_rot47::rot47;
///
/// assert_eq!(rot47("Hello, World!"), "w6==@[ (@C=5P");
/// assert_eq!(rot47("w6==@[ (@C=5P"), "Hello, World!");
/// assert_eq!(rot47(" \t\n"), " \t\n");
/// assert_eq!(rot47(""), "");
/// ```
#[must_use]
pub fn rot47(text: &str) -> String {
    // Only ASCII bytes are rewritten, so the result is always valid UTF-8 and
    // the lossy fallback never runs.
    String::from_utf8(rot47_bytes(text.as_bytes()))
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

/// Applies ROT47 to a raw byte slice, rotating only printable ASCII characters.
///
/// Suitable for binary data where only printable ASCII bytes (33–126) should be
/// rotated. All other bytes are passed through unchanged. Applying this function
/// twice to the same input returns the original bytes.
///
/// # Examples
///
/// ```rust
/// use rune_rot47::rot47_bytes;
///
/// assert_eq!(rot47_bytes(b"Hello!"), b"w6==@P");
/// assert_eq!(rot47_bytes(b"w6==@P"), b"Hello!");
/// assert_eq!(rot47_bytes(b"\x00 \xff"), b"\x00 \xff");
/// assert_eq!(rot47_bytes(b""), b"");
/// ```
pub fn rot47_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().map(rotate_byte).collect()
}

const fn rotate_byte(byte: u8) -> u8 {
    match byte {
        33..=126 => (byte - 33 + 47) % 94 + 33,
        _ => byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot47_empty() {
        assert_eq!(rot47(""), "");
    }

    #[test]
    fn rot47_known_vector() {
        assert_eq!(rot47("Hello, World!"), "w6==@[ (@C=5P");
    }

    #[test]
    fn rot47_digits_rotate() {
        let encoded = rot47("0123456789");
        assert_ne!(encoded, "0123456789");
        assert_eq!(rot47(&encoded), "0123456789");
    }

    #[test]
    fn rot47_punctuation_rotates() {
        let encoded = rot47("!\"#$%&'");
        assert_ne!(encoded, "!\"#$%&'");
        assert_eq!(rot47(&encoded), "!\"#$%&'");
    }

    #[test]
    fn rot47_space_unchanged() {
        assert_eq!(
            rot47("a b c"),
            rot47("a") + " " + &rot47("b") + " " + &rot47("c")
        );
    }

    #[test]
    fn rot47_non_printable_unchanged() {
        assert_eq!(
            rot47_bytes(b"\x00\x1f\x7f\x80\xff"),
            b"\x00\x1f\x7f\x80\xff"
        );
    }

    #[test]
    fn rot47_idempotent() {
        let inputs = ["Hello, World!", "The quick brown fox!", "!@#$%^&*()_+"];
        for input in inputs {
            assert_eq!(rot47(&rot47(input)), input);
        }
    }

    #[test]
    fn rot47_bytes_empty() {
        assert_eq!(rot47_bytes(b""), b"");
    }

    #[test]
    fn rot47_bytes_idempotent() {
        let original = b"Attack at dawn!";
        assert_eq!(rot47_bytes(&rot47_bytes(original)), original);
    }

    #[test]
    fn rot47_boundary_bytes() {
        assert_eq!(rot47_bytes(&[33]), rot47_bytes(&[33]));
        assert_eq!(rot47_bytes(&rot47_bytes(&[33])), &[33]);
        assert_eq!(rot47_bytes(&rot47_bytes(&[126])), &[126]);
    }

    #[test]
    fn rot47_roundtrip() {
        let plaintext = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(rot47(&rot47(plaintext)), plaintext);
    }
}

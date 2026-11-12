//! Atbash cipher — reverse-alphabet substitution for Latin letters.
//!
//! Atbash maps each letter to its mirror image in the alphabet: A↔Z, B↔Y, C↔X,
//! and so on. It originated as a Hebrew cipher and is commonly encountered in CTF
//! challenges, historical puzzles, and cryptography courses. This implementation
//! handles Latin (ASCII) letters only, preserving case. Non-letter bytes pass
//! through unchanged.
//!
//! Because the mapping is its own inverse (mirroring twice is a no-op), encoding
//! and decoding are the same operation. The library has zero dependencies.
//!
//! # Features
//!
//! - [`atbash`] — applies Atbash to a string; non-letter characters are unchanged.
//! - [`atbash_bytes`] — applies Atbash to a raw byte slice.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_atbash::atbash;
//!
//! let encoded = atbash("Hello, World!");
//! assert_eq!(encoded, "Svool, Dliow!");
//!
//! let decoded = atbash(&encoded);
//! assert_eq!(decoded, "Hello, World!");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-atbash "Hello, World!"
//! echo "Hello, World!" | rune-atbash
//! rune-atbash -f message.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Applies the Atbash cipher to a UTF-8 string, substituting only ASCII letters.
///
/// Each uppercase letter maps to its mirror: `A`→`Z`, `B`→`Y`, …, `Z`→`A`.
/// Lowercase letters mirror within their own range: `a`→`z`, `b`→`y`, …, `z`→`a`.
/// Case is preserved. All other bytes pass through unchanged. Applying this
/// function twice to the same input returns the original string.
///
/// # Examples
///
/// ```rust
/// use rune_atbash::atbash;
///
/// assert_eq!(atbash("Hello, World!"), "Svool, Dliow!");
/// assert_eq!(atbash("Svool, Dliow!"), "Hello, World!");
/// assert_eq!(atbash("abcxyz"), "zyxcba");
/// assert_eq!(atbash("ABCXYZ"), "ZYXCBA");
/// assert_eq!(atbash("123 !@#"), "123 !@#");
/// assert_eq!(atbash(""), "");
/// ```
#[must_use]
pub fn atbash(text: &str) -> String {
    // Only ASCII bytes are rewritten, so the result is always valid UTF-8 and
    // the lossy fallback never runs.
    String::from_utf8(atbash_bytes(text.as_bytes()))
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

/// Applies the Atbash cipher to a raw byte slice, substituting only ASCII letters.
///
/// Suitable for binary data where only the letter bytes should be substituted.
/// Non-letter bytes are passed through unchanged. Applying this function twice
/// to the same input returns the original bytes.
///
/// # Examples
///
/// ```rust
/// use rune_atbash::atbash_bytes;
///
/// assert_eq!(atbash_bytes(b"Hello!"), b"Svool!");
/// assert_eq!(atbash_bytes(b"Svool!"), b"Hello!");
/// assert_eq!(atbash_bytes(b"\x00\xff"), b"\x00\xff");
/// assert_eq!(atbash_bytes(b""), b"");
/// ```
pub fn atbash_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().map(mirror_byte).collect()
}

const fn mirror_byte(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' => b'a' + b'z' - byte,
        b'A'..=b'Z' => b'A' + b'Z' - byte,
        _ => byte,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atbash_empty() {
        assert_eq!(atbash(""), "");
    }

    #[test]
    fn atbash_lowercase_full_alphabet() {
        assert_eq!(
            atbash("abcdefghijklmnopqrstuvwxyz"),
            "zyxwvutsrqponmlkjihgfedcba"
        );
    }

    #[test]
    fn atbash_uppercase_full_alphabet() {
        assert_eq!(
            atbash("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        );
    }

    #[test]
    fn atbash_known_vector() {
        assert_eq!(atbash("Hello, World!"), "Svool, Dliow!");
    }

    #[test]
    fn atbash_case_preserved() {
        assert_eq!(atbash("aAbBzZ"), "zZyYaA");
    }

    #[test]
    fn atbash_non_letters_unchanged() {
        assert_eq!(atbash("123 !@# \t\n"), "123 !@# \t\n");
    }

    #[test]
    fn atbash_idempotent() {
        let inputs = ["Hello, World!", "The quick brown fox", "abc XYZ 123 !"];
        for input in inputs {
            assert_eq!(atbash(&atbash(input)), input);
        }
    }

    #[test]
    fn atbash_bytes_empty() {
        assert_eq!(atbash_bytes(b""), b"");
    }

    #[test]
    fn atbash_bytes_non_ascii_unchanged() {
        assert_eq!(atbash_bytes(b"\x00\x80\xff"), b"\x00\x80\xff");
    }

    #[test]
    fn atbash_bytes_idempotent() {
        let original = b"Attack at dawn! \x00\xff";
        assert_eq!(atbash_bytes(&atbash_bytes(original)), original);
    }

    #[test]
    fn atbash_roundtrip() {
        let plaintext = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(atbash(&atbash(plaintext)), plaintext);
    }

    #[test]
    fn atbash_boundary_letters() {
        assert_eq!(atbash("azAZ"), "zaZA");
    }
}

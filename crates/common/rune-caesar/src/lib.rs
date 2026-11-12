//! Caesar cipher — shift-based substitution cipher with brute-force decoder.
//!
//! Encrypts and decrypts ASCII text by rotating each letter a fixed number of
//! positions through the alphabet. Non-letter characters pass through unchanged.
//! Useful for CTF challenges, teaching classical cryptography, and quick obfuscation.
//!
//! # Features
//!
//! - [`encrypt`] — shift letters forward by a given amount.
//! - [`decrypt`] — shift letters backward by a given amount.
//! - [`brute_force`] — try all 25 non-trivial shifts and return every candidate plaintext.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_caesar::{encrypt, decrypt, brute_force};
//!
//! let ciphertext = encrypt("Hello, World!", 13);
//! assert_eq!(ciphertext, "Uryyb, Jbeyq!");
//!
//! let plaintext = decrypt(&ciphertext, 13);
//! assert_eq!(plaintext, "Hello, World!");
//!
//! let candidates = brute_force("Khoor");
//! assert!(candidates.iter().any(|(shift, text)| *shift == 3 && text == "Hello"));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-caesar encrypt "Hello, World!" --shift 13
//! rune-caesar decrypt "Uryyb, Jbeyq!" --shift 13
//! rune-caesar brute "Khoor"
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Encrypts `text` using a Caesar cipher with the given `shift`.
///
/// Each ASCII letter is rotated forward by `shift` positions within its case
/// (`A`–`Z` or `a`–`z`). Every other character, including non-ASCII text,
/// passes through unchanged. Shifts
/// outside 0–25 wrap via modulo 26, so `shift = 26` is the identity.
///
/// # Examples
///
/// ```rust
/// use rune_caesar::encrypt;
///
/// assert_eq!(encrypt("Hello", 3), "Khoor");
/// assert_eq!(encrypt("Hello, World!", 3), "Khoor, Zruog!");
/// assert_eq!(encrypt("Hello", 0), "Hello");
/// assert_eq!(encrypt("Hello", 26), "Hello");
/// assert_eq!(encrypt("xyz", 3), "abc");
/// assert_eq!(encrypt("XYZ", 3), "ABC");
/// ```
#[must_use]
pub fn encrypt(text: &str, shift: u8) -> String {
    let effective_shift = shift % 26;
    text.chars()
        .map(|ch| shift_char(ch, effective_shift))
        .collect()
}

/// Decrypts `text` encrypted with a Caesar cipher using the given `shift`.
///
/// Equivalent to encrypting with the complementary shift `(26 - shift % 26) % 26`,
/// which reverses the forward rotation applied during encryption.
///
/// # Examples
///
/// ```rust
/// use rune_caesar::decrypt;
///
/// assert_eq!(decrypt("Khoor", 3), "Hello");
/// assert_eq!(decrypt("Khoor, Zruog!", 3), "Hello, World!");
/// assert_eq!(decrypt("Hello", 0), "Hello");
/// assert_eq!(decrypt("Hello", 26), "Hello");
/// ```
#[must_use]
pub fn decrypt(text: &str, shift: u8) -> String {
    let reverse_shift = (26 - shift % 26) % 26;
    encrypt(text, reverse_shift)
}

/// Returns all 25 non-trivial Caesar decryptions of `ciphertext`.
///
/// Tries every shift from 1 to 25 inclusive and collects each candidate
/// plaintext alongside the shift that produced it. Shift 0 (the identity)
/// is excluded because it yields the ciphertext unchanged.
///
/// The caller can scan the results for recognisable words to identify the
/// correct shift — the standard approach when the key is unknown.
///
/// # Examples
///
/// ```rust
/// use rune_caesar::brute_force;
///
/// let candidates = brute_force("Khoor");
/// assert_eq!(candidates.len(), 25);
/// assert!(candidates.iter().any(|(shift, text)| *shift == 3 && text == "Hello"));
/// ```
#[must_use]
pub fn brute_force(ciphertext: &str) -> Vec<(u8, String)> {
    (1u8..=25)
        .map(|shift| (shift, decrypt(ciphertext, shift)))
        .collect()
}

/// Rotates `ch` by `shift` (already reduced modulo 26) if it is an ASCII
/// letter. Every other character, including non-ASCII ones, is returned as is.
const fn shift_char(ch: char, shift: u8) -> char {
    let base = if ch.is_ascii_uppercase() {
        b'A'
    } else if ch.is_ascii_lowercase() {
        b'a'
    } else {
        return ch;
    };
    // `ch` is ASCII here, so the cast is lossless.
    let byte = ch as u8;
    ((byte - base + shift) % 26 + base) as char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_hello_shift_3() {
        assert_eq!(encrypt("Hello", 3), "Khoor");
    }

    #[test]
    fn decrypt_khoor_shift_3() {
        assert_eq!(decrypt("Khoor", 3), "Hello");
    }

    #[test]
    fn encrypt_preserves_non_letters() {
        assert_eq!(encrypt("Hello, World!", 3), "Khoor, Zruog!");
    }

    #[test]
    fn encrypt_shift_zero_is_identity() {
        assert_eq!(encrypt("Hello, World!", 0), "Hello, World!");
    }

    #[test]
    fn encrypt_shift_26_is_identity() {
        assert_eq!(encrypt("Hello, World!", 26), "Hello, World!");
    }

    #[test]
    fn brute_force_returns_25_entries() {
        let candidates = brute_force("Khoor");
        assert_eq!(candidates.len(), 25);
    }

    #[test]
    fn brute_force_contains_correct_plaintext() {
        let candidates = brute_force("Khoor");
        assert!(
            candidates
                .iter()
                .any(|(shift, text)| *shift == 3 && text == "Hello")
        );
    }

    #[test]
    fn roundtrip_all_shifts() {
        let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
        for shift in 0u8..26 {
            assert_eq!(decrypt(&encrypt(original, shift), shift), original);
        }
    }

    #[test]
    fn encrypt_wraps_at_end_of_alphabet() {
        assert_eq!(encrypt("xyz", 3), "abc");
        assert_eq!(encrypt("XYZ", 3), "ABC");
    }

    #[test]
    fn encrypt_empty_string() {
        assert_eq!(encrypt("", 13), "");
    }

    #[test]
    fn decrypt_empty_string() {
        assert_eq!(decrypt("", 13), "");
    }
}

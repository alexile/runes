//! Known-answer vectors and properties: Atbash is an involution that mirrors
//! ASCII letters within their case and leaves every other byte alone.

use proptest::prelude::*;
use rune_atbash::{atbash, atbash_bytes};

/// Reference mapping written independently of the crate: letter index `i`
/// maps to `25 - i` within its case.
const fn reference(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() {
        b'a' + (25 - (byte - b'a'))
    } else if byte.is_ascii_uppercase() {
        b'A' + (25 - (byte - b'A'))
    } else {
        byte
    }
}

#[test]
fn kat_vectors() {
    let vectors = [
        ("", ""),
        ("WIZARD", "DRAZIW"),
        ("wizard", "draziw"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ZYXWVUTSRQPONMLKJIHGFEDCBA"),
        (
            "The quick brown fox jumps over the lazy dog.",
            "Gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt.",
        ),
        ("Hello, World! 123", "Svool, Dliow! 123"),
        ("héllo ✓", "séool ✓"),
    ];
    for (plain, cipher) in vectors {
        assert_eq!(atbash(plain), cipher, "atbash({plain:?})");
        assert_eq!(atbash(cipher), plain, "atbash({cipher:?})");
    }
}

#[test]
fn every_byte_matches_reference() {
    for byte in 0..=u8::MAX {
        assert_eq!(atbash_bytes(&[byte]), [reference(byte)], "byte {byte:#04x}");
    }
}

proptest! {
    #[test]
    fn string_is_involution(text in any::<String>()) {
        prop_assert_eq!(atbash(&atbash(&text)), text);
    }

    #[test]
    fn bytes_is_involution(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(atbash_bytes(&atbash_bytes(&bytes)), bytes);
    }

    #[test]
    fn bytes_match_reference(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let expected: Vec<u8> = bytes.iter().copied().map(reference).collect();
        prop_assert_eq!(atbash_bytes(&bytes), expected);
    }

    #[test]
    fn string_and_bytes_agree(text in any::<String>()) {
        let out = atbash(&text);
        prop_assert_eq!(out.len(), text.len());
        prop_assert_eq!(out.into_bytes(), atbash_bytes(text.as_bytes()));
    }

    #[test]
    fn only_letters_change_and_case_is_kept(text in any::<String>()) {
        for (before, after) in text.chars().zip(atbash(&text).chars()) {
            if before.is_ascii_alphabetic() {
                prop_assert!(after.is_ascii_alphabetic());
                prop_assert_eq!(before.is_ascii_uppercase(), after.is_ascii_uppercase());
            } else {
                prop_assert_eq!(before, after);
            }
        }
    }
}

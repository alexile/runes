//! Known-answer vectors and properties: ROT13 is an involution that rotates
//! ASCII letters by 13 within their case and leaves every other byte alone.

use proptest::prelude::*;
use rune_rot13::{rot13, rot13_bytes};

/// Reference mapping written independently of the crate.
fn reference(byte: u8) -> u8 {
    let rotate = |base: u8| base + (byte - base + 13) % 26;
    if byte.is_ascii_lowercase() {
        rotate(b'a')
    } else if byte.is_ascii_uppercase() {
        rotate(b'A')
    } else {
        byte
    }
}

#[test]
fn kat_vectors() {
    // Classic Usenet / Wikipedia examples.
    let vectors = [
        ("", ""),
        (
            "Why did the chicken cross the road?",
            "Jul qvq gur puvpxra pebff gur ebnq?",
        ),
        ("To get to the other side!", "Gb trg gb gur bgure fvqr!"),
        ("Hello, World!", "Uryyb, Jbeyq!"),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ),
        ("0123456789 !?", "0123456789 !?"),
        ("naïve café", "anïir pnsé"),
    ];
    for (plain, cipher) in vectors {
        assert_eq!(rot13(plain), cipher, "rot13({plain:?})");
        assert_eq!(rot13(cipher), plain, "rot13({cipher:?})");
    }
}

#[test]
fn every_byte_matches_reference() {
    for byte in 0..=u8::MAX {
        assert_eq!(rot13_bytes(&[byte]), [reference(byte)], "byte {byte:#04x}");
    }
}

proptest! {
    #[test]
    fn string_is_involution(text in any::<String>()) {
        prop_assert_eq!(rot13(&rot13(&text)), text);
    }

    #[test]
    fn bytes_is_involution(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(rot13_bytes(&rot13_bytes(&bytes)), bytes);
    }

    #[test]
    fn bytes_match_reference(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let expected: Vec<u8> = bytes.iter().copied().map(reference).collect();
        prop_assert_eq!(rot13_bytes(&bytes), expected);
    }

    #[test]
    fn string_and_bytes_agree(text in any::<String>()) {
        prop_assert_eq!(rot13(&text).into_bytes(), rot13_bytes(text.as_bytes()));
    }

    #[test]
    fn letters_always_change(text in "[A-Za-z]{1,64}") {
        // 13 is not a multiple of 26, so no letter is a fixed point.
        for (before, after) in text.bytes().zip(rot13(&text).bytes()) {
            prop_assert_ne!(before, after);
            prop_assert_eq!(before.is_ascii_uppercase(), after.is_ascii_uppercase());
        }
    }
}

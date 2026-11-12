//! Known-answer vectors and properties: decryption inverts encryption for
//! every shift, shifts compose modulo 26, only ASCII letters change, and
//! `brute_force` always contains the plaintext.

use proptest::prelude::*;
use rune_caesar::{brute_force, decrypt, encrypt};

#[test]
fn kat_vectors() {
    // Wikipedia's Caesar example uses a left shift of 3, i.e. a right shift of 23.
    let plain = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
    let cipher = "QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD";
    assert_eq!(encrypt(plain, 23), cipher);
    assert_eq!(decrypt(plain, 3), cipher);
    assert_eq!(decrypt(cipher, 23), plain);
    assert_eq!(encrypt(cipher, 3), plain);

    // Julius Caesar's own shift of 3.
    assert_eq!(encrypt("veni, vidi, vici", 3), "yhql, ylgl, ylfl");
    // ROT13 is Caesar with shift 13.
    assert_eq!(encrypt("Hello, World!", 13), "Uryyb, Jbeyq!");
    // Shifts reduce modulo 26.
    assert_eq!(encrypt("abc", 255), encrypt("abc", 255 % 26));
}

#[test]
fn non_ascii_text_is_preserved() {
    // Regression: encryption used to map every UTF-8 byte to a `char`
    // separately, turning `é` into `Ã©`.
    assert_eq!(encrypt("café", 3), "fdié");
    assert_eq!(decrypt("fdié", 3), "café");
    assert_eq!(encrypt("Grüße, 世界!", 1), "Hsüßf, 世界!");
    assert_eq!(encrypt("✓", 0), "✓");
}

proptest! {
    #[test]
    fn decrypt_inverts_encrypt(text in any::<String>(), shift in any::<u8>()) {
        prop_assert_eq!(&decrypt(&encrypt(&text, shift), shift), &text);
        prop_assert_eq!(&encrypt(&decrypt(&text, shift), shift), &text);
    }

    #[test]
    fn shifts_compose(text in any::<String>(), a in any::<u8>(), b in any::<u8>()) {
        let combined = (a % 26 + b % 26) % 26;
        prop_assert_eq!(encrypt(&encrypt(&text, a), b), encrypt(&text, combined));
    }

    #[test]
    fn shift_reduces_mod_26(text in any::<String>(), shift in any::<u8>()) {
        prop_assert_eq!(encrypt(&text, shift), encrypt(&text, shift % 26));
    }

    #[test]
    fn only_ascii_letters_change(text in any::<String>(), shift in any::<u8>()) {
        let out = encrypt(&text, shift);
        prop_assert_eq!(out.chars().count(), text.chars().count());
        prop_assert_eq!(out.len(), text.len());
        for (before, after) in text.chars().zip(out.chars()) {
            if before.is_ascii_alphabetic() {
                prop_assert_eq!(before.is_ascii_uppercase(), after.is_ascii_uppercase());
                let base = if before.is_ascii_uppercase() { b'A' } else { b'a' };
                let expected = (before as u8 - base + shift % 26) % 26 + base;
                prop_assert_eq!(after, char::from(expected));
            } else {
                prop_assert_eq!(before, after);
            }
        }
    }

    #[test]
    fn brute_force_contains_plaintext(text in "[A-Za-z ,.!]{0,64}", shift in 1u8..26) {
        let candidates = brute_force(&encrypt(&text, shift));
        prop_assert_eq!(candidates.len(), 25);
        let shifts: Vec<u8> = candidates.iter().map(|(s, _)| *s).collect();
        prop_assert_eq!(shifts, (1u8..=25).collect::<Vec<_>>());
        prop_assert!(candidates.iter().any(|(s, t)| *s == shift && *t == text));
    }
}

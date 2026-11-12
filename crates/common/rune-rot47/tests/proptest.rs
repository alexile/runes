//! Known-answer vectors and properties: ROT47 is an involution over the 94
//! printable ASCII characters `!`..=`~` and leaves every other byte alone.

use proptest::prelude::*;
use rune_rot47::{rot47, rot47_bytes};

/// Reference mapping written independently of the crate.
fn reference(byte: u8) -> u8 {
    if (b'!'..=b'~').contains(&byte) {
        b'!' + (byte - b'!' + 47) % 94
    } else {
        byte
    }
}

#[test]
fn kat_vectors() {
    // Wikipedia's ROT47 example plus edges of the printable window.
    let vectors = [
        ("", ""),
        (
            "The Quick Brown Fox Jumps Over The Lazy Dog.",
            "%96 \"F:4< qC@H? u@I yF>AD ~G6C %96 {2KJ s@8]",
        ),
        ("Hello, World!", "w6==@[ (@C=5P"),
        ("!~", "PO"),
        ("0123456789", "_`abcdefgh"),
        ("a b\tc\n", "2 3\t4\n"),
        ("über", "ü36C"),
    ];
    for (plain, cipher) in vectors {
        assert_eq!(rot47(plain), cipher, "rot47({plain:?})");
        assert_eq!(rot47(cipher), plain, "rot47({cipher:?})");
    }
}

#[test]
fn every_byte_matches_reference() {
    for byte in 0..=u8::MAX {
        assert_eq!(rot47_bytes(&[byte]), [reference(byte)], "byte {byte:#04x}");
    }
}

proptest! {
    #[test]
    fn string_is_involution(text in any::<String>()) {
        prop_assert_eq!(rot47(&rot47(&text)), text);
    }

    #[test]
    fn bytes_is_involution(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(rot47_bytes(&rot47_bytes(&bytes)), bytes);
    }

    #[test]
    fn bytes_match_reference(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let expected: Vec<u8> = bytes.iter().copied().map(reference).collect();
        prop_assert_eq!(rot47_bytes(&bytes), expected);
    }

    #[test]
    fn string_and_bytes_agree(text in any::<String>()) {
        prop_assert_eq!(rot47(&text).into_bytes(), rot47_bytes(text.as_bytes()));
    }

    #[test]
    fn printable_stays_printable_and_changes(text in "[!-~]{1,64}") {
        for (before, after) in text.bytes().zip(rot47(&text).bytes()) {
            prop_assert!((b'!'..=b'~').contains(&after));
            prop_assert_ne!(before, after);
        }
    }
}

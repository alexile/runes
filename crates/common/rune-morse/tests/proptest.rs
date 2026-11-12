//! Known-answer vectors (ITU-R M.1677-1) and properties: encoding then
//! decoding returns the upper-cased input, the encoder emits only Morse
//! symbols, and neither direction panics on arbitrary text.

use proptest::prelude::*;
use rune_morse::{MorseError, decode, encode};

/// The ITU-R M.1677-1 letter and figure table, transcribed independently of
/// the crate's own table.
const ITU: [(char, &str); 36] = [
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('0', "-----"),
];

#[test]
fn itu_table() {
    for (ch, code) in ITU {
        assert_eq!(encode(&ch.to_string()).unwrap(), code, "encode {ch:?}");
        assert_eq!(
            encode(&ch.to_ascii_lowercase().to_string()).unwrap(),
            code,
            "encode lowercase {ch:?}"
        );
        assert_eq!(decode(code).unwrap(), ch.to_string(), "decode {code:?}");
    }
}

#[test]
fn kat_vectors() {
    let vectors = [
        ("SOS", "... --- ..."),
        // "PARIS" is the standard word used to define words-per-minute.
        ("PARIS", ".--. .- .-. .. ..."),
        ("CQ DX", "-.-. --.- / -.. -..-"),
        ("73", "--... ...--"),
    ];
    for (text, morse) in vectors {
        assert_eq!(encode(text).unwrap(), morse, "encode {text:?}");
        assert_eq!(decode(morse).unwrap(), text, "decode {morse:?}");
    }
}

#[test]
fn empty_words_round_trip() {
    // Regression: `encode` accepts leading, trailing and repeated spaces, but
    // `decode` used to reject the empty words they produce.
    for text in [" ", "A ", " A", "A  B", "  "] {
        let morse = encode(text).unwrap();
        assert_eq!(
            decode(&morse).unwrap(),
            text,
            "round trip {text:?} via {morse:?}"
        );
    }
    assert_eq!(encode("A ").unwrap(), ".- / ");
    assert_eq!(decode(".- / ").unwrap(), "A ");
}

#[test]
fn errors() {
    assert_eq!(encode("HI!"), Err(MorseError::UnknownChar('!')));
    assert_eq!(encode("é"), Err(MorseError::UnknownChar('é')));
    assert_eq!(
        decode("...---..."),
        Err(MorseError::UnknownCode("...---...".to_owned()))
    );
    assert_eq!(
        decode(".-  -..."),
        Err(MorseError::UnknownCode(String::new()))
    );
}

proptest! {
    #[test]
    fn round_trip_uppercases(text in "[A-Za-z0-9 ]{0,64}") {
        let morse = encode(&text).unwrap();
        prop_assert_eq!(decode(&morse).unwrap(), text.to_ascii_uppercase());
    }

    #[test]
    fn decode_then_encode_is_identity(
        words in proptest::collection::vec(
            proptest::collection::vec(proptest::sample::select(&ITU[..]), 1..8),
            1..6,
        )
    ) {
        let morse = words
            .iter()
            .map(|word| word.iter().map(|(_, code)| *code).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(" / ");
        let text = decode(&morse).unwrap();
        prop_assert_eq!(encode(&text).unwrap(), morse);
    }

    #[test]
    fn encoder_emits_only_morse_symbols(text in "[A-Za-z0-9 ]{0,64}") {
        let morse = encode(&text).unwrap();
        prop_assert!(morse.chars().all(|c| matches!(c, '.' | '-' | ' ' | '/')));
    }

    #[test]
    fn encode_never_panics(text in any::<String>()) {
        if let Err(MorseError::UnknownChar(ch)) = encode(&text) {
            prop_assert!(!ch.is_ascii_alphanumeric() && ch != ' ');
            prop_assert!(text.contains(ch));
        }
    }

    #[test]
    fn decode_never_panics(text in any::<String>()) {
        let _ = decode(&text);
    }

    #[test]
    fn decode_never_panics_on_morse_alphabet(text in "[.\\-/ ]{0,64}") {
        if let Ok(decoded) = decode(&text) {
            prop_assert!(decoded.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' '));
        }
    }
}

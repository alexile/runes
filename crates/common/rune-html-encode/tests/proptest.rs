//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_html_encode::{decode, encode};

/// Text biased towards entity syntax, plus arbitrary Unicode.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..64).prop_map(String::from_iter),
        "([a-z<>\"'&;#xX0-9 ]|&(amp|lt|gt|quot|apos|nbsp|copy|hellip);|&#[0-9]{1,8};|&#[xX][0-9a-fA-F]{1,8};){0,32}",
    ]
}

proptest! {
    #[test]
    fn round_trips(input in text()) {
        prop_assert_eq!(decode(&encode(&input)), input);
    }

    /// Encoded output never contains a raw markup character, and every `&`
    /// starts one of the entities `encode` emits.
    #[test]
    fn encoded_output_is_inert(input in text()) {
        let encoded = encode(&input);
        prop_assert!(!encoded.contains(['<', '>', '"', '\'']));
        for (pos, _) in encoded.match_indices('&') {
            let tail = &encoded[pos..];
            prop_assert!(
                ["&amp;", "&lt;", "&gt;", "&quot;", "&#x27;"]
                    .iter()
                    .any(|entity| tail.starts_with(entity)),
                "stray `&` in {encoded:?}"
            );
        }
    }

    /// Text without `&` is unchanged by decoding.
    #[test]
    fn decode_is_identity_without_ampersand(input in "[^&]{0,64}") {
        prop_assert_eq!(decode(&input), input);
    }

    /// Decoding never panics, and every entity is at least as long as the
    /// character it stands for, so the output never grows.
    #[test]
    fn decode_never_panics_or_grows(input in text()) {
        let decoded = decode(&input);
        prop_assert!(decoded.len() <= input.len());
    }

    /// Numeric references decode to the scalar value they name.
    #[test]
    fn numeric_references_decode(ch in any::<char>()) {
        let code = u32::from(ch);
        prop_assert_eq!(decode(&format!("&#{code};")), ch.to_string());
        prop_assert_eq!(decode(&format!("&#x{code:X};")), ch.to_string());
        prop_assert_eq!(decode(&format!("&#X{code:x};")), ch.to_string());
    }
}

//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_base32::{decode, decode_hex, encode, encode_hex, encode_no_pad, is_base32};

/// Arbitrary Unicode text, plus text drawn mostly from the Base32 alphabets.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "[A-Za-z0-9=]{0,48}",
    ]
}

proptest! {
    #[test]
    fn standard_round_trips(data in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(decode(&encode(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(&encode_no_pad(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(&encode(&data).to_lowercase()), Ok(data));
    }

    #[test]
    fn extended_hex_round_trips(data in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(decode_hex(&encode_hex(&data)), Ok(data));
    }

    #[test]
    fn padded_output_is_whole_blocks(data in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(encode(&data).len() % 8, 0);
        prop_assert!(data.is_empty() || is_base32(&encode(&data)));
    }

    #[test]
    fn decoders_never_panic(input in text()) {
        let decoded = decode(&input);
        let _ = decode_hex(&input);
        if is_base32(&input) {
            prop_assert!(decoded.is_ok());
        }
    }
}

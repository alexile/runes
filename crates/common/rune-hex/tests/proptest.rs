//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_hex::{decode, encode, encode_upper};

proptest! {
    #[test]
    fn round_trips(data in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(decode(&encode(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(&encode_upper(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(&format!("0x{}", encode(&data))), Ok(data));
    }

    /// Valid hex decodes and re-encodes to its lower-case form.
    #[test]
    fn valid_text_re_encodes(text in "([0-9a-fA-F]{2}){0,32}") {
        let bytes = decode(&text).unwrap();
        prop_assert_eq!(encode(&bytes), text.to_lowercase());
    }

    #[test]
    fn decode_never_panics(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "(0x)?[0-9a-gA-G]{0,48}",
    ]) {
        let _ = decode(&text);
    }
}

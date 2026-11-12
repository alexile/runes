//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_base58::{decode, decode_flickr, encode, encode_flickr, is_base58};

proptest! {
    #[test]
    fn bitcoin_round_trips(data in prop::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(decode(&encode(&data)), Ok(data));
    }

    #[test]
    fn leading_zero_bytes_survive(zeros in 0usize..8, data in prop::collection::vec(any::<u8>(), 0..32)) {
        let mut bytes = vec![0u8; zeros];
        bytes.extend(data);
        prop_assert_eq!(decode(&encode(&bytes)), Ok(bytes));
    }

    #[test]
    fn flickr_round_trips(data in prop::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(decode_flickr(&encode_flickr(&data)), Ok(data));
    }

    /// Base58 has one encoding per byte string, so valid text re-encodes to
    /// itself.
    #[test]
    fn valid_text_is_canonical(text in "[1-9A-HJ-NP-Za-km-z]{0,48}") {
        prop_assert!(text.is_empty() || is_base58(&text));
        let bytes = decode(&text).unwrap();
        prop_assert_eq!(encode(&bytes), text);
    }

    #[test]
    fn decoders_never_panic(chars in prop::collection::vec(any::<char>(), 0..48)) {
        let text = String::from_iter(chars);
        let decoded = decode(&text);
        let _ = decode_flickr(&text);
        prop_assert_eq!(decoded.is_ok(), text.is_empty() || is_base58(&text));
    }
}

//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_base::{decode, encode};

/// 2 to 256 distinct symbols in random order.
fn alphabet() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::subsequence((0..=255u8).collect::<Vec<_>>(), 2..=256).prop_shuffle()
}

proptest! {
    #[test]
    fn any_alphabet_round_trips(
        alphabet in alphabet(),
        data in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let encoded = encode(&data, &alphabet).unwrap();
        prop_assert_eq!(decode(&encoded, &alphabet), Ok(data));
    }

    #[test]
    fn decode_never_panics(
        alphabet in prop::collection::vec(any::<u8>(), 0..40),
        chars in prop::collection::vec(any::<char>(), 0..32),
    ) {
        let _ = decode(&String::from_iter(chars), &alphabet);
    }
}

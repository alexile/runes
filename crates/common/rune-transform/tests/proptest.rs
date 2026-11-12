//! Round-trip and robustness properties for every built-in transform.

use proptest::prelude::*;
use rune_transform::{Transform, TransformRegistry};

fn check_round_trip(registry: &TransformRegistry, data: &[u8]) -> Result<(), TestCaseError> {
    for transform in registry.iter() {
        // Text-only transforms reject non-UTF-8 input; that is fine.
        let Ok(encoded) = transform.encode(data) else {
            continue;
        };
        if transform.is_reversible() {
            match transform.decode(&encoded) {
                Ok(decoded) => prop_assert_eq!(
                    decoded.as_slice(),
                    data,
                    "round trip failed for {}",
                    transform.id()
                ),
                Err(error) => prop_assert!(false, "decode failed for {}: {error}", transform.id()),
            }
        } else {
            prop_assert!(transform.decode(&encoded).is_err(), "{}", transform.id());
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn reversible_transforms_round_trip_bytes(data in prop::collection::vec(any::<u8>(), 0..64)) {
        check_round_trip(&TransformRegistry::builtin(), &data)?;
    }

    /// HTML entities and the UTF-16 escapes need text, so they also get a
    /// string strategy.
    #[test]
    fn reversible_transforms_round_trip_text(text in any::<String>()) {
        check_round_trip(&TransformRegistry::builtin(), text.as_bytes())?;
    }

    #[test]
    fn decoders_never_panic(data in prop::collection::vec(any::<u8>(), 0..64), text in any::<String>()) {
        let registry = TransformRegistry::builtin();
        for transform in registry.iter() {
            let _ = transform.decode(&data);
            let _ = transform.decode(text.as_bytes());
            let _ = transform.encode(text.as_bytes());
        }
        let _ = rune_transform::smart_decode(&text);
    }

    #[test]
    fn random_reversible_chains_round_trip(
        picks in prop::collection::vec(any::<prop::sample::Index>(), 0..5),
        data in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let registry = TransformRegistry::builtin();
        // Byte-safe reversible steps (no text-only transforms).
        let pool = [
            "base64", "base64url_nopad", "base32", "hex", "hex_space", "url", "double_url",
            "js_hex_escape", "octal_escape", "binary", "ascii_decimal", "gzip", "deflate",
            "rot13", "rot47", "reverse", "nibble_swap", "bitwise_not",
        ];
        let specs: Vec<&str> = picks.iter().map(|i| pool[i.index(pool.len())]).collect();
        let chain = registry.chain(&specs).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let encoded = chain.encode(&data).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(chain.decode(&encoded).ok(), Some(data));
    }
}

//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_base64::encode_url_no_pad as b64;
use rune_jwt::{claims, decode, decode_raw, header};
use serde_json::{Map, Value};

fn json_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        ".{0,12}".prop_map(Value::String),
    ]
}

fn json_value() -> impl Strategy<Value = Value> {
    json_leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(".{0,8}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

fn json_object() -> impl Strategy<Value = Value> {
    prop::collection::btree_map(".{0,8}", json_value(), 0..5)
        .prop_map(|m| Value::Object(m.into_iter().collect()))
}

proptest! {
    #[test]
    fn decode_round_trips(
        hdr in json_object(),
        payload in json_object(),
        signature in prop::collection::vec(any::<u8>(), 0..80),
    ) {
        let sig = b64(&signature);
        let token = format!(
            "{}.{}.{}",
            b64(hdr.to_string().as_bytes()),
            b64(payload.to_string().as_bytes()),
            sig,
        );
        let decoded = decode(&token).unwrap();
        prop_assert_eq!(&decoded.header, &hdr);
        prop_assert_eq!(&decoded.payload, &payload);
        prop_assert_eq!(&decoded.signature, &sig);
        prop_assert_eq!(header(&token).unwrap(), hdr);
        prop_assert_eq!(claims(&token).unwrap(), payload);
    }

    #[test]
    fn decode_raw_round_trips(
        h in prop::collection::vec(any::<u8>(), 0..64),
        p in prop::collection::vec(any::<u8>(), 0..64),
        s in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let raw = decode_raw(&format!("{}.{}.{}", b64(&h), b64(&p), b64(&s))).unwrap();
        prop_assert_eq!(raw.header, h);
        prop_assert_eq!(raw.payload, p);
        prop_assert_eq!(raw.signature, s);
    }

    #[test]
    fn never_panics_and_helpers_agree(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..64).prop_map(String::from_iter),
        "[A-Za-z0-9_=.+/-]{0,64}",
        "(eyJ[A-Za-z0-9_-]{0,20}\\.){0,4}[A-Za-z0-9_-]{0,20}",
    ]) {
        let full = decode(&text);
        let hdr = header(&text);
        let payload = claims(&text);
        let raw = decode_raw(&text);
        let _ = (
            rune_jwt::algorithm(&text),
            rune_jwt::subject(&text),
            rune_jwt::expiry(&text),
        );
        if let Ok(decoded) = full {
            prop_assert_eq!(hdr.ok(), Some(decoded.header));
            prop_assert_eq!(payload.ok(), Some(decoded.payload));
            prop_assert!(raw.is_ok());
        } else if hdr.is_ok() && payload.is_ok() {
            // Only the signature can be at fault.
            prop_assert!(raw.is_err());
        }
    }
}

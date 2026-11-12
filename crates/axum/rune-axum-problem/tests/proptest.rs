//! Properties: parsing never panics, and serialise -> parse is the identity.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use http::StatusCode;
use proptest::prelude::*;
use rune_axum_problem::Problem;

fn problem() -> impl Strategy<Value = Problem> {
    (
        proptest::option::of(".*"),
        proptest::option::of(".*"),
        proptest::option::of(100u16..600),
        proptest::option::of(".*"),
        proptest::option::of(".*"),
        prop::collection::btree_map("[a-z_]{1,8}", any::<i64>(), 0..4),
    )
        .prop_map(|(ty, title, status, detail, instance, ext)| {
            let mut p = Problem::default();
            if let Some(t) = ty {
                p = p.with_type(t);
            }
            if let Some(t) = title {
                p = p.with_title(t);
            }
            if let Some(s) = status.and_then(|s| StatusCode::from_u16(s).ok()) {
                p = p.with_status(s);
            }
            if let Some(d) = detail {
                p = p.with_detail(d);
            }
            if let Some(i) = instance {
                p = p.with_instance(i);
            }
            for (k, v) in ext {
                p = p.with_extension(k, v);
            }
            p
        })
}

proptest! {
    #[test]
    fn from_json_never_panics(input in ".*") {
        let _ = Problem::from_json(input.as_bytes());
    }

    #[test]
    fn from_json_never_panics_on_objects(
        members in prop::collection::btree_map(
            prop_oneof!["type", "title", "status", "detail", "instance", "[a-z]{1,4}"],
            prop_oneof![
                Just(serde_json::Value::Null),
                any::<bool>().prop_map(serde_json::Value::from),
                any::<i64>().prop_map(serde_json::Value::from),
                any::<f64>().prop_map(serde_json::Value::from),
                ".*".prop_map(serde_json::Value::from),
            ],
            0..8,
        )
    ) {
        let doc = serde_json::to_vec(&members).unwrap();
        let _ = Problem::from_json(&doc).unwrap();
    }

    #[test]
    fn round_trip(p in problem()) {
        prop_assert_eq!(Problem::from_json(&p.to_json()).unwrap(), p);
    }
}

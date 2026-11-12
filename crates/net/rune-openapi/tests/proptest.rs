//! Property tests: the importer never panics, and synthesized values
//! respect their schema bounds.

use proptest::prelude::*;
use rune_openapi::{ExampleStrategy, Options, Schema, SchemaType, Value, from_value, parse};
use serde_json::json;

/// Arbitrary JSON values, biased toward `OpenAPI` keywords.
fn json_value() -> impl Strategy<Value = Value> {
    let key = prop_oneof![
        Just("type".to_owned()),
        Just("$ref".to_owned()),
        Just("properties".to_owned()),
        Just("items".to_owned()),
        Just("allOf".to_owned()),
        Just("oneOf".to_owned()),
        Just("parameters".to_owned()),
        Just("in".to_owned()),
        Just("name".to_owned()),
        Just("schema".to_owned()),
        Just("content".to_owned()),
        Just("requestBody".to_owned()),
        Just("security".to_owned()),
        Just("get".to_owned()),
        Just("post".to_owned()),
        "[a-z/{}#~]{0,6}",
    ];
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        prop_oneof![
            Just("object".to_owned()),
            Just("array".to_owned()),
            Just("string".to_owned()),
            Just("integer".to_owned()),
            Just("query".to_owned()),
            Just("path".to_owned()),
            Just("body".to_owned()),
            Just("formData".to_owned()),
            Just("#/components/schemas/a".to_owned()),
            Just("#/paths".to_owned()),
            Just("#".to_owned()),
            "[ -~]{0,8}",
        ]
        .prop_map(Value::String),
    ];
    leaf.prop_recursive(5, 64, 6, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(key.clone(), inner, 0..5)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = parse(&bytes, &Options::default());
    }

    #[test]
    fn arbitrary_text_never_panics(text in "[ -~\n]{0,200}") {
        let _ = parse(text.as_bytes(), &Options::default());
    }

    #[test]
    fn arbitrary_documents_never_panic(
        paths in json_value(),
        components in json_value(),
        swagger in any::<bool>(),
    ) {
        let mut document = json!({
            "paths": {"/a/{id}": paths, "/b": {"get": paths, "post": components}},
            "components": {"schemas": {"a": components}, "parameters": components},
            "definitions": {"a": components},
        });
        if swagger {
            document["swagger"] = json!("2.0");
        } else {
            document["openapi"] = json!("3.1.0");
        }
        if let Ok(spec) = from_value(&document, &Options::default()) {
            for endpoint in &spec.endpoints {
                prop_assert!(!endpoint.request.url.contains('{'), "{}", endpoint.request.url);
                for strategy in [ExampleStrategy::PreferExamples, ExampleStrategy::TypeDefaults] {
                    let _ = endpoint.render(&Options::default().with_example_strategy(strategy));
                }
            }
        }
    }

    #[test]
    fn integers_respect_bounds(
        minimum in -1_000_i32..1_000,
        span in 0_i32..1_000,
        exclusive_minimum in any::<bool>(),
        exclusive_maximum in any::<bool>(),
    ) {
        let maximum = minimum + span;
        let mut schema = Schema::new(SchemaType::Integer);
        schema.minimum = Some(f64::from(minimum));
        schema.maximum = Some(f64::from(maximum));
        schema.exclusive_minimum = exclusive_minimum;
        schema.exclusive_maximum = exclusive_maximum;
        let lowest = i64::from(minimum) + i64::from(exclusive_minimum);
        let highest = i64::from(maximum) - i64::from(exclusive_maximum);
        prop_assume!(lowest <= highest);
        let value = schema.example_value(ExampleStrategy::TypeDefaults).as_i64().unwrap();
        prop_assert!((lowest..=highest).contains(&value), "{value} not in {lowest}..={highest}");
    }

    #[test]
    fn strings_respect_lengths(min in 0_u64..40, extra in 0_u64..40, format in "[a-z-]{0,10}") {
        let mut schema = Schema::new(SchemaType::String);
        schema.min_length = Some(min);
        schema.max_length = Some(min + extra);
        schema.format = Some(format);
        let value = schema.example_value(ExampleStrategy::TypeDefaults);
        let length = value.as_str().unwrap().chars().count() as u64;
        prop_assert!(length >= min && length <= min + extra);
    }
}

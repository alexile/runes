//! Property tests: extraction and validation never panic, and well-formed
//! JSON embedded in noise is always recovered.

use proptest::prelude::*;
use rune_chain_output_parser::{
    Extractor, JsonSchema, OutputParser, PartialJsonParser, StructuredOutputParser, extract_json,
    parse_partial,
};
use serde_json::{Value, json};

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        "[a-zA-Z0-9 {}\\[\\],:\"\\\\]{0,12}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,6}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn extract_never_panics(text in "\\PC{0,200}") {
        let _ = extract_json(&text);
    }

    #[test]
    fn extract_never_panics_on_json_ish(text in "[{}\\[\\]\",:\\\\a1 \n`]{0,120}") {
        let _ = extract_json(&text);
    }

    #[test]
    fn container_in_prose_is_recovered(
        v in arb_json().prop_filter("container", |v| v.is_object() || v.is_array()),
        prefix in "[a-zA-Z .!:]{0,30}",
        suffix in "[a-zA-Z .!]{0,30}",
    ) {
        let text = format!("{prefix}{v}{suffix}");
        prop_assert_eq!(extract_json(&text), Some(v));
    }

    #[test]
    fn fenced_value_is_recovered(v in arb_json()) {
        let text = format!("Here you go:\n```json\n{v:#}\n```\n");
        prop_assert_eq!(extract_json(&text), Some(v));
    }

    #[test]
    fn validation_never_panics(v in arb_json()) {
        let schema = JsonSchema::new(json!({
            "$defs": {"t": {"anyOf": [
                {"type": ["string", "integer", "null", "boolean"], "maxLength": 5},
                {"type": "array", "items": {"$ref": "#/$defs/t"}, "uniqueItems": true},
                {"type": "object", "additionalProperties": {"$ref": "#/$defs/t"},
                 "patternProperties": {"^a": {"not": {"type": "null"}}}}
            ]}},
            "$ref": "#/$defs/t"
        })).unwrap();
        let _ = schema.validate(&v);
    }

    #[test]
    fn permissive_schema_accepts_every_value(v in arb_json()) {
        let parser = StructuredOutputParser::<Value>::new(json!(true)).unwrap();
        prop_assert_eq!(parser.parse(&v.to_string()).unwrap(), v);
    }

    #[test]
    fn partial_never_panics(text in "\\PC{0,200}") {
        let _ = parse_partial(&text);
    }

    #[test]
    fn partial_never_panics_on_json_ish(text in "[{}\\[\\]\",:\\\\a1eE.+\\-tru \n`]{0,160}") {
        let _ = parse_partial(&text);
    }

    #[test]
    fn every_prefix_of_a_container_parses(
        v in arb_json().prop_filter("container", |v| v.is_object() || v.is_array()),
    ) {
        let text = v.to_string();
        for end in 1..text.len() {
            if text.is_char_boundary(end) {
                prop_assert!(parse_partial(&text[..end]).is_some(), "{}", &text[..end]);
            }
        }
        prop_assert_eq!(parse_partial(&text), Some(v));
    }

    #[test]
    fn chunked_stream_ends_with_the_value(
        v in arb_json().prop_filter("container", |v| v.is_object() || v.is_array()),
        cut in 1usize..7,
    ) {
        let text = v.to_string();
        let mut p = PartialJsonParser::<Value>::new();
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(cut) {
            let _ = p.push(&chunk.iter().collect::<String>());
        }
        let last = p.current().unwrap();
        prop_assert!(last.complete);
        prop_assert_eq!(last.json, v);
    }

    #[test]
    fn extractor_parse_never_panics(text in "\\PC{0,200}") {
        let ex = Extractor::<Vec<u8>>::new(json!({"type": "array"}))
            .unwrap()
            .with_validator(|v| if v.len() < 3 { Ok(()) } else { Err("too long".into()) });
        let _ = ex.parse(&text);
    }
}

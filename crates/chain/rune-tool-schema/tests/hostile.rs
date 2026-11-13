//! Property tests: the validator, the dialect rewriter and the text
//! hygiene helpers never panic on arbitrary input, and the strict-mode
//! rewrite keeps valid arguments valid.

use proptest::prelude::*;
use rune_tool_schema::{
    Dialect, ToolDescriptor, Validator, ViolationKind, drop_optional_nulls, find_hidden,
    is_hidden_char, strip_hidden, truncate_chars,
};
use serde_json::{Map, Value, json};

const KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "anyOf",
    "oneOf",
    "allOf",
    "$ref",
    "$defs",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "format",
    "description",
];

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        (-5i64..5).prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        prop::sample::select(vec![
            "string",
            "integer",
            "number",
            "object",
            "array",
            "null",
            "boolean",
            "#",
            "#/$defs/a",
            "^a+$",
            "(",
            "[a-z]{2,}",
        ])
        .prop_map(Value::from),
        "\\PC{0,6}".prop_map(Value::from),
    ]
}

fn key() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(KEYWORDS.to_vec()).prop_map(str::to_owned),
        "[a-z]{1,3}",
    ]
}

/// JSON that often looks like a schema.
fn json() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(6, 96, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map(key(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn validator_never_panics(schema in json(), value in json()) {
        if let Ok(validator) = Validator::new(&schema) {
            let _ = validator.validate(&value);
        }
    }

    #[test]
    fn dialects_never_panic(schema in json(), name in "[a-z_]{1,8}") {
        let mut object = match schema {
            Value::Object(map) => map,
            other => Map::from_iter([("items".to_owned(), other)]),
        };
        object.insert("type".into(), "object".into());
        let tool = ToolDescriptor::new(name, "d").with_input_schema(Value::Object(object));
        for dialect in Dialect::ALL {
            let _ = tool.lint(dialect);
            if let Ok(exported) = tool.export(dialect) {
                prop_assert!(exported.findings.iter().all(|f| !f.is_blocking()));
            }
        }
        let mut args = json!({"a": null});
        drop_optional_nulls(&tool.input_schema, &mut args);
        let _ = tool.clone().sanitized().check_hygiene(4096);
    }

    #[test]
    fn strip_hidden_leaves_nothing_hidden(text in "\\PC*|[\\u{0}-\\u{3000}\\u{e0000}-\\u{e0080}]*") {
        let clean = strip_hidden(&text);
        prop_assert_eq!(find_hidden(&clean), None);
        let again = strip_hidden(&clean).into_owned();
        prop_assert_eq!(again.as_str(), clean.as_ref());
        let visible: String = text
            .chars()
            .filter(|c| !is_hidden_char(*c) && !matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}'))
            .collect();
        let kept: String = clean.chars().filter(|c| *c != '\n').collect();
        prop_assert_eq!(kept, visible);
    }

    #[test]
    fn truncation_respects_the_cap(text in "\\PC{0,40}", max in 0usize..50) {
        let cut = truncate_chars(&text, max);
        prop_assert!(cut.chars().count() <= max);
        if text.chars().count() <= max {
            prop_assert_eq!(cut.as_ref(), text.as_str());
        }
    }

    /// Arguments valid for the original schema, with absent optional
    /// properties sent as `null` (what a strict-mode model does), pass the
    /// strict schema; dropping those nulls makes them pass the original.
    #[test]
    fn strict_rewrite_keeps_arguments_valid(
        props in prop::collection::btree_map(
            "[a-z]{1,6}",
            (prop::sample::select(vec!["string", "integer", "boolean", "enum", "array", "object"]),
             any::<bool>(), any::<bool>(), any::<u8>()),
            1..8,
        ),
    ) {
        let mut properties = Map::new();
        let mut required = Vec::new();
        let mut args = Map::new();
        for (name, (kind, is_required, present, seed)) in &props {
            let (schema, value) = match *kind {
                "string" => (json!({"type": "string", "minLength": 1}), json!(format!("s{seed}"))),
                "integer" => (json!({"type": "integer", "minimum": 0}), json!(seed)),
                "boolean" => (json!({"type": "boolean"}), json!(seed % 2 == 0)),
                "enum" => (json!({"type": "string", "enum": ["a", "b"]}), json!("a")),
                "array" => (json!({"type": "array", "items": {"type": "integer"}}), json!([seed])),
                _ => (
                    json!({"type": "object", "properties": {"x": {"type": "string"}}}),
                    json!({"x": "y"}),
                ),
            };
            properties.insert(name.clone(), schema);
            if *is_required {
                required.push(json!(name));
            }
            if *is_required || *present {
                args.insert(name.clone(), value);
            }
        }
        let schema = json!({"type": "object", "properties": properties, "required": required});
        let tool = ToolDescriptor::new("t", "d").with_input_schema(schema.clone());
        prop_assert!(tool.validate_arguments(&Value::Object(args.clone())).is_ok());

        let strict = tool.export(Dialect::OpenAiStrict).expect("plain schemas export");
        let strict_schema = &strict.definition["function"]["parameters"];
        let mut model_args = args;
        for name in props.keys() {
            model_args.entry(name.clone()).or_insert(Value::Null);
        }
        if let Some(Value::Object(x)) = model_args.values_mut().find(|v| v.get("x").is_some()) {
            x.entry("x").or_insert(Value::Null);
        }
        let mut model_args = Value::Object(model_args);
        let strict_validator = Validator::new(strict_schema).expect("strict schema compiles");
        prop_assert!(strict_validator.validate(&model_args).is_ok(), "{}", strict_schema);

        drop_optional_nulls(&schema, &mut model_args);
        prop_assert!(tool.validate_arguments(&model_args).is_ok(), "{}", model_args);
    }
}

#[test]
fn very_deep_values_are_refused_without_recursion() {
    let mut value = json!(1);
    for _ in 0..500 {
        value = json!([value]);
    }
    let validator = Validator::new(&json!({"type": "array"})).unwrap();
    let errors = validator.validate(&value).unwrap_err();
    assert_eq!(errors.as_slice()[0].kind, ViolationKind::TooDeep(32));
}

#[test]
fn hostile_patterns_are_bounded() {
    // Catastrophic for a backtracking engine; linear for this one.
    let validator = Validator::new(&json!({"type": "string", "pattern": "^(a+)+$"})).unwrap();
    let input = format!("{}!", "a".repeat(50_000));
    assert!(!validator.is_valid(&json!(input)));
}

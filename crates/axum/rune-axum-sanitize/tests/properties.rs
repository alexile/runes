//! Property tests: no panics, valid output, no markup, structure preserved.

use proptest::prelude::*;
use rune_axum_sanitize::{JsonError, Mode, Normalization, Sanitizer, strip_html};
use serde_json::Value;

fn has_markup(text: &str) -> bool {
    text.as_bytes().windows(2).any(|pair| {
        pair[0] == b'<' && (pair[1].is_ascii_alphabetic() || matches!(pair[1], b'/' | b'!' | b'?'))
    })
}

/// Strings biased towards markup fragments.
fn markupish() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        Just("<".to_owned()),
        Just(">".to_owned()),
        Just("</".to_owned()),
        Just("<!--".to_owned()),
        Just("-->".to_owned()),
        Just("<script>".to_owned()),
        Just("</script>".to_owned()),
        Just("<style>".to_owned()),
        Just("\"".to_owned()),
        Just("'".to_owned()),
        Just("=".to_owned()),
        Just(" ".to_owned()),
        Just("&lt;".to_owned()),
        Just("＜".to_owned()),
        Just("\u{202E}".to_owned()),
        "[a-z]{1,4}",
        any::<char>().prop_map(String::from),
    ];
    prop::collection::vec(piece, 0..24).prop_map(|pieces| pieces.concat())
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        markupish().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-z<>]{0,4}", inner, 0..6)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

/// Applies `sanitizer` to every string in `value`, as the JSON cleaner should.
/// Whether cleaning makes two keys of one object equal anywhere in `value`.
fn keys_collide(sanitizer: &Sanitizer, value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| keys_collide(sanitizer, item)),
        Value::Object(map) => {
            let mut seen = std::collections::HashSet::new();
            map.keys()
                .any(|key| !seen.insert(sanitizer.clean(key).into_owned()))
                || map.values().any(|item| keys_collide(sanitizer, item))
        }
        _ => false,
    }
}

fn clean_value(sanitizer: &Sanitizer, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(sanitizer.clean(text).into_owned()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| clean_value(sanitizer, item))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    (
                        sanitizer.clean(key).into_owned(),
                        clean_value(sanitizer, item),
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

proptest! {
    #[test]
    fn strip_output_has_no_markup(input in markupish()) {
        let out = strip_html(&input);
        prop_assert!(!has_markup(&out), "{input:?} -> {out:?}");
        prop_assert_eq!(strip_html(&out), out);
    }

    #[test]
    fn strip_handles_any_string(input in any::<String>()) {
        let out = strip_html(&input);
        prop_assert!(!has_markup(&out));
        if !input.contains('<') {
            prop_assert_eq!(out, input);
        }
    }

    #[test]
    fn full_pipeline_never_panics(input in any::<String>(), mode in 0..2u8, form in 0..3u8) {
        let sanitizer = Sanitizer::new()
            .mode(if mode == 0 { Mode::StripTags } else { Mode::Escape })
            .normalization(match form { 0 => None, 1 => Some(Normalization::Nfc), _ => Some(Normalization::Nfkc) })
            .strip_invisible(true);
        let out = sanitizer.clean(&input);
        prop_assert!(!out.contains('\0'));
        prop_assert!(!has_markup(&out));
    }

    #[test]
    fn escape_round_trips(input in any::<String>()) {
        let sanitizer = Sanitizer::new().mode(Mode::Escape).strip_control_chars(false);
        let out = sanitizer.clean(&input);
        prop_assert!(!out.contains(['<', '>', '"', '\'']));
        prop_assert_eq!(rune_html_encode::decode(&out), input);
    }

    #[test]
    fn json_structure_is_preserved(value in json_value(), pretty in any::<bool>()) {
        let sanitizer = Sanitizer::new();
        let text = if pretty { serde_json::to_string_pretty(&value) } else { serde_json::to_string(&value) }.unwrap();
        match sanitizer.clean_json(&text, 64) {
            Ok(cleaned) => {
                let parsed: Value = serde_json::from_str(&cleaned).unwrap();
                prop_assert_eq!(parsed, clean_value(&sanitizer, &value));
            }
            Err(JsonError::DuplicateKey { .. }) => prop_assert!(keys_collide(&sanitizer, &value)),
            Err(error) => prop_assert!(false, "{error}"),
        }
    }

    #[test]
    fn json_cleaner_never_panics(input in any::<String>()) {
        let sanitizer = Sanitizer::new();
        if let Ok(cleaned) = sanitizer.clean_json(&input, 16)
            && serde_json::from_str::<Value>(&input).is_ok()
        {
            prop_assert!(serde_json::from_str::<Value>(&cleaned).is_ok());
        }
    }

    #[test]
    fn json_agrees_with_serde_on_validity(input in "[\\[\\]{}\",:0-9a-z \\\\]{0,24}") {
        let ours = Sanitizer::new().clean_json(&input, 128).is_ok();
        let theirs = serde_json::from_str::<Value>(&input).is_ok();
        // Numbers are only shape-checked, so we may accept a few that serde
        // rejects, never the other way round.
        prop_assert!(ours || !theirs, "{input:?}");
    }

    #[test]
    fn urlencoded_values_are_clean(pairs in prop::collection::vec((markupish(), markupish()), 0..6)) {
        let query: String = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().map(|(key, value)| (key.as_str(), value.as_str())))
            .finish();
        let sanitizer = Sanitizer::new();
        let cleaned = sanitizer.clean_urlencoded(&query);
        let decoded: Vec<(String, String)> = form_urlencoded::parse(cleaned.as_bytes()).into_owned().collect();
        let expected: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(key, value)| (sanitizer.clean(&key).into_owned(), sanitizer.clean(&value).into_owned()))
            .collect();
        prop_assert_eq!(decoded, expected);
    }

    #[test]
    fn urlencoded_handles_any_input(input in any::<String>()) {
        let _ = Sanitizer::new().clean_urlencoded(&input);
    }
}

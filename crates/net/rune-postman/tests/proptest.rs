//! Property tests: reading never panics, folder trees survive import, and
//! variable resolution behaves.

use std::collections::BTreeMap;

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use rune_postman::{ReadOptions, parse_environment, read, resolve};
use serde_json::{Value, json};

/// Arbitrary JSON, biased towards the keys a collection uses.
fn json_value() -> impl Strategy<Value = Value> {
    let key = prop_oneof![
        Just("item".to_owned()),
        Just("request".to_owned()),
        Just("url".to_owned()),
        Just("raw".to_owned()),
        Just("header".to_owned()),
        Just("body".to_owned()),
        Just("mode".to_owned()),
        Just("auth".to_owned()),
        Just("type".to_owned()),
        Just("key".to_owned()),
        Just("value".to_owned()),
        Just("variable".to_owned()),
        Just("event".to_owned()),
        Just("disabled".to_owned()),
        "[a-z]{1,6}",
    ];
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        prop_oneof![
            ".{0,12}",
            "[{}a-z:/ ]{0,16}",
            Just("raw".to_owned()),
            Just("formdata".to_owned()),
            Just("bearer".to_owned()),
            Just("prerequest".to_owned()),
        ]
        .prop_map(Value::String),
    ];
    leaf.prop_recursive(5, 64, 6, move |inner| {
        prop_oneof![
            vec(inner.clone(), 0..6).prop_map(Value::Array),
            btree_map(key.clone(), inner, 0..6)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

/// A folder tree: `Some(children)` is a folder, `None` a request.
#[derive(Debug, Clone)]
enum Node {
    Folder(String, Vec<Self>),
    Request(String),
}

fn tree() -> impl Strategy<Value = Vec<Node>> {
    let leaf = "[A-Za-z0-9 ]{1,8}".prop_map(Node::Request);
    let node = leaf.prop_recursive(4, 40, 4, |inner| {
        ("[A-Za-z0-9 ]{1,8}", vec(inner, 0..4))
            .prop_map(|(name, children)| Node::Folder(name, children))
    });
    vec(node, 0..6)
}

fn to_json(nodes: &[Node], expected: &mut Vec<String>, prefix: &str) -> Value {
    Value::Array(
        nodes
            .iter()
            .map(|node| match node {
                Node::Folder(name, children) => {
                    let inner = to_json(children, expected, &format!("{prefix}{name}/"));
                    json!({"name": name, "item": inner})
                }
                Node::Request(name) => {
                    let path = format!("{prefix}{name}");
                    let url = format!("{{{{base}}}}/{}", expected.len());
                    expected.push(path);
                    json!({"name": name, "request": {"method": "POST", "url": url}})
                }
            })
            .collect(),
    )
}

proptest! {
    #[test]
    fn reading_bytes_never_panics(input in vec(any::<u8>(), 0..256)) {
        let _ = read(&input, &ReadOptions::default());
        let _ = parse_environment(&input);
    }

    #[test]
    fn reading_json_never_panics(value in json_value()) {
        let text = value.to_string();
        let _ = read(text.as_bytes(), &ReadOptions::default());
        let wrapped = json!({"item": [&value], "auth": &value, "variable": [&value]});
        let _ = read(wrapped.to_string().as_bytes(), &ReadOptions::default());
        let _ = parse_environment(text.as_bytes());
    }

    #[test]
    fn folder_trees_import_in_order(nodes in tree()) {
        let mut expected = Vec::new();
        let items = to_json(&nodes, &mut expected, "");
        let input = json!({"info": {"name": "t"}, "variable": [{"key": "base", "value": "https://h.test"}], "item": items});
        let collection = read(input.to_string().as_bytes(), &ReadOptions::default()).unwrap();
        prop_assert!(collection.warnings.is_empty(), "{:?}", collection.warnings);
        let paths: Vec<String> = collection.requests.iter().map(rune_postman::CollectionRequest::path).collect();
        prop_assert_eq!(&paths, &expected);
        for (index, request) in collection.requests.iter().enumerate() {
            prop_assert_eq!(&request.request.url, &format!("https://h.test/{index}"));
            prop_assert_eq!(&request.request.method, "POST");
        }
    }

    #[test]
    fn text_without_placeholders_is_unchanged(text in "[^{]{0,40}", limit in 0_usize..64) {
        let resolved = resolve(&text, &BTreeMap::new(), limit);
        prop_assert_eq!(resolved.text, text);
        prop_assert!(!resolved.truncated);
    }

    #[test]
    fn known_variables_resolve(
        prefix in "[^{}]{0,10}",
        suffix in "[^{}]{0,10}",
        name in "[A-Za-z_][A-Za-z0-9_.-]{0,10}",
        value in "[^{}]{0,20}",
    ) {
        let variables = BTreeMap::from([(name.clone(), value.clone())]);
        let resolved = resolve(&format!("{prefix}{{{{{name}}}}}{suffix}"), &variables, 1024);
        prop_assert_eq!(resolved.text, format!("{prefix}{value}{suffix}"));
        prop_assert!(resolved.unresolved.is_empty());
        let missing = resolve(&format!("{{{{{name}x}}}}"), &variables, 1024);
        prop_assert_eq!(missing.unresolved, [format!("{name}x")]);
    }

    #[test]
    fn resolution_is_bounded(
        variables in btree_map("[a-c]", "([a-c{}]|\\{\\{[a-c]\\}\\}){0,6}", 0..4),
        text in "([a-c{}]|\\{\\{[a-c]\\}\\}){0,8}",
        limit in 0_usize..256,
    ) {
        let resolved = resolve(&text, &variables, limit);
        prop_assert!(resolved.text.len() <= limit.max(text.len()));
    }
}

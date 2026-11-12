//! Property tests: key round trips, merge invariants, no panics.

use proptest::prelude::*;
use rune_config::{ConfigLoader, Source, Table, Value, ValueKind, format_key, parse_key};

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::Integer),
        any::<bool>().prop_map(Value::Boolean),
        "[ -~]{0,8}".prop_map(Value::String),
        prop::collection::vec(any::<i64>().prop_map(Value::Integer), 0..3).prop_map(Value::Array),
    ]
}

fn table() -> impl Strategy<Value = Table> {
    let value = leaf().prop_recursive(2, 16, 4, |inner| {
        prop::collection::btree_map("[a-c]{1,2}", inner, 0..4)
            .prop_map(|map| Value::Table(map.into_iter().collect()))
    });
    prop::collection::btree_map("[a-c]{1,2}", value, 0..5).prop_map(|map| map.into_iter().collect())
}

/// Every (dotted key, value) leaf of `table`.
fn leaves(table: &Table, prefix: &[String], out: &mut Vec<(Vec<String>, Value)>) {
    for (key, value) in table {
        let mut path = prefix.to_vec();
        path.push(key.clone());
        match value {
            Value::Table(sub) => leaves(sub, &path, out),
            other => out.push((path, other.clone())),
        }
    }
}

proptest! {
    #[test]
    fn keys_round_trip(segments in prop::collection::vec(any::<String>(), 1..4)) {
        prop_assert_eq!(parse_key(&format_key(&segments)).unwrap(), segments);
    }

    #[test]
    fn parse_key_never_panics(text in any::<String>()) {
        let _ = parse_key(&text);
    }

    #[test]
    fn value_kinds_never_panic(text in any::<String>()) {
        for kind in [ValueKind::Auto, ValueKind::String, ValueKind::Integer,
                     ValueKind::Float, ValueKind::Boolean, ValueKind::StringList] {
            let _ = kind.parse(&text);
        }
    }

    #[test]
    fn auto_round_trips_integers(n in any::<i64>()) {
        prop_assert_eq!(ValueKind::Auto.parse(&n.to_string()), Ok(Value::Integer(n)));
    }

    #[test]
    fn single_layer_is_identity(t in table()) {
        let source = Source::Inline("only".into());
        let loaded = ConfigLoader::new().with_table(source.clone(), t.clone()).load().unwrap();
        prop_assert_eq!(loaded.table(), &t);
        let mut found = Vec::new();
        leaves(&t, &[], &mut found);
        prop_assert_eq!(loaded.provenance().count(), found.len());
        for (path, _) in found {
            prop_assert_eq!(loaded.source_of(&format_key(&path)), Some(&source));
        }
    }

    #[test]
    fn top_layer_wins_every_leaf_it_sets(lower in table(), upper in table()) {
        let top = Source::Inline("top".into());
        let loaded = ConfigLoader::new()
            .with_table(Source::Default, lower)
            .with_table(top.clone(), upper.clone())
            .load()
            .unwrap();
        let mut found = Vec::new();
        leaves(&upper, &[], &mut found);
        for (path, value) in found {
            let key = format_key(&path);
            prop_assert_eq!(loaded.get(&key), Some(&value));
            prop_assert_eq!(loaded.source_of(&key), Some(&top));
        }
        // Every recorded leaf exists in the merged table.
        for (key, _) in loaded.provenance() {
            prop_assert!(loaded.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn merged_table_round_trips_through_toml(lower in table(), upper in table()) {
        let loaded = ConfigLoader::new()
            .with_table(Source::Default, lower)
            .with_table(Source::Inline("top".into()), upper)
            .load()
            .unwrap();
        let text = loaded.to_toml_string().unwrap();
        let reparsed: Table = text.parse().unwrap();
        prop_assert_eq!(&reparsed, loaded.table());
    }
}

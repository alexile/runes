//! Property tests: key round trips, merge invariants, no panics.

use proptest::prelude::*;
use std::collections::HashMap;

use rune_config::{
    ConfigLoader, Dotenv, DotenvOptions, EnvReader, Source, Table, Value, ValueKind, format_dotenv,
    format_key, parse_key,
};

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

    #[test]
    fn dotenv_parser_never_panics(text in any::<String>()) {
        let _ = Dotenv::parse(&text);
        let _ = DotenvOptions::new().expand(true).expansion_env([("A", "1")]).parse(&text);
    }

    #[test]
    fn dotenv_parser_never_panics_on_dotenv_like_text(
        text in r#"([A-Za-z_ =#'"\$\{\}:\-\n\t]|export ){0,60}"#
    ) {
        let _ = Dotenv::parse(&text);
        let _ = DotenvOptions::new().expand(true).parse(&text);
    }

    #[test]
    fn dotenv_writer_round_trips(
        pairs in prop::collection::vec(("[A-Za-z_][A-Za-z0-9_.]{0,8}", any::<String>()), 0..6)
    ) {
        let text = format_dotenv(pairs.iter().map(|(k, v)| (k, v))).unwrap();
        for options in [DotenvOptions::new(), DotenvOptions::new().expand(true)] {
            let env = options.parse(&text).unwrap();
            let got: Vec<(String, String)> =
                env.vars().map(|(k, v)| (k.to_owned(), v.to_owned())).collect();
            prop_assert_eq!(&got, &pairs);
            prop_assert_eq!(env.to_dotenv_string(), text.clone());
        }
    }

    #[test]
    fn unquoted_simple_values_survive(key in "[A-Z_][A-Z0-9_]{0,8}", value in "[A-Za-z0-9_./:@-]{0,20}") {
        let env = Dotenv::parse(&format!("{key}={value}")).unwrap();
        prop_assert_eq!(env.get(&key), Some(value.as_str()));
    }

    #[test]
    fn env_reader_never_panics(
        vars in prop::collection::vec(("APP_[A-Z_]{0,10}", any::<String>()), 0..6)
    ) {
        let _ = EnvReader::new().prefix("APP_").from_vars::<HashMap<String, Value>, _, _, _>(vars.clone());
        let _ = EnvReader::new().prefix("app_").case_insensitive(true)
            .from_vars::<HashMap<String, Vec<u8>>, _, _, _>(vars);
    }

    #[test]
    fn env_reader_round_trips_integers(n in any::<i64>(), m in any::<u16>()) {
        let vars = [("APP_N".to_owned(), n.to_string()), ("APP_M__X".to_owned(), m.to_string())];
        let got: HashMap<String, Value> = EnvReader::new().prefix("APP_").from_vars(vars).unwrap();
        let text = n.to_string();
        prop_assert_eq!(got["n"].as_str(), Some(text.as_str()));
        let typed: HashMap<String, i64> = EnvReader::new().prefix("APP_N").from_vars([("APP_N_V", n.to_string())]).unwrap();
        prop_assert_eq!(typed["_v"], n);
    }
}

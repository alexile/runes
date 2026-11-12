//! Property tests: canonicalization is idempotent and never panics, query
//! splitting round-trips, and dedup keys ignore parameter order.

use proptest::prelude::*;
use rune_url::{
    KeyOptions, Options, ParamFilter, Scope, Url, canonicalize, canonicalize_url, dedup_key,
    join_query, normalize_percent_encoding, split_query,
};

fn all_options() -> Vec<Options> {
    vec![
        Options::default(),
        Options::crawler(),
        Options::crawler()
            .with_sort_query(true)
            .with_remove_userinfo(true)
            .with_drop_params(Some(
                ParamFilter::tracking().union(&ParamFilter::session_ids()),
            )),
    ]
}

/// URL-ish text: a scheme, then characters that exercise escapes, dots,
/// separators and hosts.
fn url_like() -> impl Strategy<Value = String> {
    let scheme = prop::sample::select(vec![
        "http://", "https://", "HTTP://", "ws://", "foo://", "file:///", "mailto:", "data:",
    ]);
    let body = prop::collection::vec(
        prop::sample::select(vec![
            "a",
            "B",
            "%",
            "%2e",
            "%2E",
            "%7e",
            "%41",
            "%2f",
            "%zz",
            ".",
            "..",
            "/",
            "?",
            "#",
            "&",
            "=",
            ";",
            ":",
            "@",
            "[",
            "]",
            "::1",
            "ffff:",
            "0x7f",
            "1",
            "é",
            " ",
            "+",
            "~",
            "_",
            "utm_source",
            "jsessionid",
            "www.",
            "xn--",
            "\\",
        ]),
        0..24,
    )
    .prop_map(|parts| parts.concat());
    (scheme, body).prop_map(|(scheme, body)| format!("{scheme}{body}"))
}

proptest! {
    #[test]
    fn canonicalize_is_idempotent(input in url_like()) {
        for options in all_options() {
            if let Ok(once) = canonicalize(&input, &options) {
                let twice = canonicalize_url(&once, &options);
                prop_assert_eq!(once.as_str(), twice.as_str());
                let reparsed = Url::parse(once.as_str()).unwrap();
                let again = canonicalize_url(&reparsed, &options);
                prop_assert_eq!(again.as_str(), once.as_str());
            }
        }
    }

    #[test]
    fn never_panics_on_arbitrary_text(input in any::<String>()) {
        for options in all_options() {
            let _ = canonicalize(&input, &options);
        }
        let _ = dedup_key(&input, &KeyOptions::default());
        let rules = [input.as_str()];
        let _ = Scope::parse(rules, rules);
        let _ = normalize_percent_encoding(&input);
        let params = split_query(&input);
        for param in &params {
            let _ = (param.name(), param.value());
        }
    }

    #[test]
    fn dedup_key_is_stable(input in url_like()) {
        if let Ok(key) = dedup_key(&input, &KeyOptions::default()) {
            let canonical = canonicalize(&input, &Options::crawler()).unwrap();
            prop_assert_eq!(dedup_key(canonical.as_str(), &KeyOptions::default()).unwrap(), key);
        }
    }

    #[test]
    fn split_join_round_trips(query in "[a-z=&%+0-9;]{0,40}") {
        prop_assert_eq!(&split_query(&query).to_string(), &query);
        prop_assert_eq!(join_query(split_query(&query).iter()), query);
    }

    #[test]
    fn key_ignores_parameter_order(
        names in prop::collection::btree_set("[a-z]{1,6}", 1..6),
        seed in any::<u64>(),
    ) {
        let params: Vec<String> = names.iter().enumerate().map(|(i, n)| format!("{n}={i}")).collect();
        let mut shuffled = params.clone();
        // Deterministic rotation by the seed.
        let len = shuffled.len();
        shuffled.rotate_left(usize::try_from(seed % len as u64).unwrap());
        let a = format!("https://h/p?{}", params.join("&"));
        let b = format!("https://h/p?{}", shuffled.join("&"));
        let options = KeyOptions::default();
        prop_assert_eq!(dedup_key(&a, &options).unwrap(), dedup_key(&b, &options).unwrap());
    }

    #[test]
    fn percent_normalization_preserves_meaning(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
        // Encode every byte, normalize, and decode: the bytes come back.
        let encoded: String = bytes.iter().flat_map(|b| ['%', hex(b >> 4), hex(b & 0xF)]).collect();
        let normalized = normalize_percent_encoding(&encoded);
        prop_assert_eq!(rune_url_encode::decode_bytes(normalized.as_bytes()).ok(), Some(bytes));
        prop_assert_eq!(normalize_percent_encoding(&normalized), normalized);
    }
}

fn hex(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble)])
}

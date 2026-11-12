//! Properties of the generator over arbitrary seeds and payloads.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::collections::HashSet;

use proptest::prelude::*;
use rune_subdomain_permute::{Options, Pattern, Payloads, Permutator, Seed};

fn label() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,8}[a-z0-9]"
}

fn seed() -> impl Strategy<Value = Seed> {
    (
        prop::collection::vec(label(), 0..3),
        prop::sample::select(vec!["example.com", "example.co.uk", "test.org"]),
    )
        .prop_filter_map("valid seed", |(sub, root)| {
            let mut host = sub.join(".");
            if !host.is_empty() {
                host.push('.');
            }
            host.push_str(root);
            Seed::parse(&host).ok()
        })
}

fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn output_is_unique_valid_and_bounded(
        seeds in prop::collection::vec(seed(), 1..4),
        words in prop::collection::vec("[a-z0-9-]{0,12}", 0..6),
        limit in 0usize..200,
        enrich in any::<bool>(),
    ) {
        let mut payloads = Payloads::builtin();
        payloads.insert("word", &words).unwrap();
        let options = Options::default().with_limit(limit).with_enrich(enrich).with_number_delta(2);
        let permutator = Permutator::new(rune_subdomain_permute::DEFAULT_PATTERNS, payloads, options).unwrap();
        let out: Vec<String> = permutator.permute(&seeds).collect();
        prop_assert!(out.len() <= limit);
        let unique: HashSet<&String> = out.iter().collect();
        prop_assert_eq!(unique.len(), out.len());
        let seed_names: HashSet<&str> = seeds.iter().map(Seed::name).collect();
        for candidate in &out {
            prop_assert!(valid_host(candidate), "{}", candidate);
            prop_assert!(!seed_names.contains(candidate.as_str()));
        }
        // Deterministic.
        let again: Vec<String> = permutator.permute(&seeds).collect();
        prop_assert_eq!(out, again);
    }

    #[test]
    fn pattern_parser_never_panics(text in "\\PC{0,40}") {
        let _ = Pattern::parse(&text);
    }

    #[test]
    fn seed_parser_never_panics(text in "\\PC{0,40}") {
        let _ = Seed::parse(&text);
    }
}

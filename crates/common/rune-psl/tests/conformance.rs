//! The Public Suffix List's own test suite, `tests/tests.txt` (pinned with
//! the list in `data/sources.toml`, CC0), against the embedded list.
//!
//! Each line is `<input> <expected registrable domain>`, `null` standing
//! for no value. `checkPublicSuffix` in the upstream harness lowercases the
//! input and expects `null` for a name that is itself a public suffix or is
//! invalid (a leading dot).

#![cfg(feature = "embedded")]

use rune_psl::{List, registrable_domain};

const SUITE: &str = include_str!("tests.txt");

/// `(input, expected)` pairs, or the malformed line.
fn cases() -> Vec<Result<(&'static str, Option<&'static str>), &'static str>> {
    SUITE
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(
            |line| match line.split_whitespace().collect::<Vec<_>>()[..] {
                [input, expected] => Ok((input, (expected != "null").then_some(expected))),
                _ => Err(line),
            },
        )
        .collect()
}

#[test]
fn official_test_suite_passes() {
    let cases: Vec<_> = cases().into_iter().map(Result::unwrap).collect();
    assert!(cases.len() > 70, "only {} cases", cases.len());
    let mut failures = Vec::new();
    for (input, expected) in cases {
        // `null` input stands for a missing argument; there is no such call.
        if input == "null" {
            continue;
        }
        let actual = registrable_domain(input);
        if actual.as_deref() != expected {
            failures.push(format!("{input}: expected {expected:?}, got {actual:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn embedded_list_is_sorted_and_complete() {
    let list = List::embedded();
    assert!(list.len() > 9_000, "{}", list.len());
    let rules: Vec<_> = list.rules().collect();
    assert!(
        rules
            .windows(2)
            .all(|pair| (pair[0].name(), pair[0].section()) <= (pair[1].name(), pair[1].section())),
        "embedded rules are not sorted"
    );
    assert!(rune_psl::EMBEDDED_VERSION.contains("publicsuffix/list@"));
}

#[cfg(feature = "runtime")]
#[test]
fn rendered_rules_reparse_to_the_same_list() {
    use std::fmt::Write as _;

    let list = List::embedded();
    let mut text = String::from("// ===BEGIN ICANN DOMAINS===\n");
    for rule in list
        .rules()
        .filter(|rule| rule.section() == rune_psl::Section::Icann)
    {
        writeln!(text, "{rule}").unwrap();
    }
    text.push_str("// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n");
    for rule in list
        .rules()
        .filter(|rule| rule.section() == rune_psl::Section::Private)
    {
        writeln!(text, "{rule}").unwrap();
    }
    let parsed = List::parse(&text).unwrap();
    assert!(parsed.rules().eq(list.rules()));
}

#[test]
fn well_known_suffixes() {
    let list = List::embedded();
    for (host, suffix, registrable) in [
        ("www.example.co.uk", "co.uk", Some("example.co.uk")),
        ("a.b.c.github.io", "github.io", Some("c.github.io")),
        ("s3.amazonaws.com", "s3.amazonaws.com", None),
        ("www.gov.uk", "gov.uk", Some("www.gov.uk")),
        ("example.local", "local", Some("example.local")),
        ("xn--fiqs8s", "xn--fiqs8s", None),
    ] {
        let domain = list.lookup(host).unwrap();
        assert_eq!(domain.public_suffix(), suffix, "{host}");
        assert_eq!(domain.registrable_domain(), registrable, "{host}");
    }
    assert!(list.lookup("blogspot.com").unwrap().is_private());
    assert!(list.lookup("co.uk").unwrap().is_icann());
}

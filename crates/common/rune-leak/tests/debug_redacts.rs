//! `Debug` output of a match or a leak never carries the full secret, so a
//! stray `{:?}` in a log line does not re-leak what the scanner found.

use rune_leak::{Ruleset, scan_text};

const KEY: &str = "AKIAIOSFODNN7EXAMPLE";

#[test]
fn secret_match_debug_is_redacted() {
    let rules = Ruleset::builtin();
    let text = format!("aws_key = \"{KEY}\"");
    let mut seen = 0;
    rules.for_each_match(&text, |m| {
        seen += 1;
        assert_eq!(m.value, KEY);
        let debug = format!("{m:?}");
        assert!(!debug.contains(KEY), "{debug}");
    });
    assert!(seen > 0);
}

#[test]
fn leak_debug_is_redacted() {
    let leaks = scan_text(&format!("aws_key = \"{KEY}\""));
    assert!(!leaks.is_empty());
    for leak in leaks {
        let debug = format!("{leak:?} {leak:#?}");
        assert!(!debug.contains(KEY), "{debug}");
    }
}

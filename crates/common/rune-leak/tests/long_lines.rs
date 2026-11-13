//! Scanning time stays linear in the length of a line: minified bundles and
//! hostile files put megabytes on one line.

use std::time::{Duration, Instant};

use rune_leak::Ruleset;

fn scan_time(text: &str) -> (usize, Duration) {
    let rules = Ruleset::builtin();
    let started = Instant::now();
    let mut count = 0;
    rules.for_each_match(text, |_| count += 1);
    (count, started.elapsed())
}

/// Debug builds are slow, so the bound is loose; the quadratic versions
/// took 25 s to well over a minute on these inputs.
const BOUND: Duration = Duration::from_secs(10);

#[test]
fn many_entropy_tokens_on_one_line() {
    let line = "Xk9mQ2vL7pR4tW8zB3nH ".repeat(50_000);
    let (count, took) = scan_time(&line);
    assert!(count > 0);
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn many_base64_markers_on_one_line() {
    let line = ";base64,".repeat(150_000);
    let (_, took) = scan_time(&line);
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn many_rule_matches_on_one_line() {
    let line = "AKIAIOSFODNN7EXAMPLE ".repeat(50_000);
    let (count, took) = scan_time(&line);
    assert_eq!(count, 50_000);
    assert!(took < BOUND, "{took:?}");
}

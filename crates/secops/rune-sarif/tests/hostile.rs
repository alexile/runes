//! Logs built to make reading slow.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rune_sarif::{Imported, Log, read};

/// One result whose rule has `n` distinct tags (and the result the same
/// ones again), in a run without taxonomies.
fn many_tags(prefix: &str, n: usize) -> String {
    let mut tags = String::new();
    for i in 0..n {
        if i > 0 {
            tags.push(',');
        }
        write!(tags, "\"{prefix}{i}\"").unwrap_or(());
    }
    format!(
        r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"x","rules":[{{"id":"r","properties":{{"tags":[{tags}]}}}}]}}}},"results":[{{"ruleIndex":0,"message":{{"text":"m"}},"properties":{{"tags":[{tags}]}}}}]}}]}}"#
    )
}

#[test]
fn many_tags_are_read_in_linear_time() {
    let log = Log::from_json(&many_tags("t", 50_000)).expect("valid log");
    let start = Instant::now();
    let findings = read::<Imported>(&log);
    let elapsed = start.elapsed();
    assert_eq!(findings[0].ext.tags.len(), 50_000);
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[test]
fn many_cwe_tags_are_read_in_linear_time() {
    let log = Log::from_json(&many_tags("CWE-", 50_000)).expect("valid log");
    let start = Instant::now();
    let findings = read::<()>(&log);
    let elapsed = start.elapsed();
    assert_eq!(findings[0].taxonomy.len(), 50_000);
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

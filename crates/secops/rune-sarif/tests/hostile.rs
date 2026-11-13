//! Logs built to make reading slow.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rune_sarif::{Error, Imported, Log, ReadOptions, json_len, read, read_with};

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
    let findings = read::<Imported>(&log).expect("within budget");
    let elapsed = start.elapsed();
    assert_eq!(findings[0].ext.tags.len(), 50_000);
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[test]
fn many_cwe_tags_are_read_in_linear_time() {
    let log = Log::from_json(&many_tags("CWE-", 50_000)).expect("valid log");
    let start = Instant::now();
    let findings = read::<()>(&log).expect("within budget");
    let elapsed = start.elapsed();
    assert_eq!(findings[0].taxonomy.len(), 50_000);
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

/// `results` tiny results that all point at one rule whose short
/// description and help URI are `rule_text` bytes each.
fn one_big_rule(rule_text: usize, results: usize) -> String {
    let big = "x".repeat(rule_text);
    let results = vec![r#"{"ruleIndex":0,"message":{}}"#; results].join(",");
    format!(
        r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"x","rules":[{{"id":"r","shortDescription":{{"text":"{big}"}},"helpUri":"{big}"}}]}}}},"results":[{results}]}}]}}"#
    )
}

#[test]
fn a_shared_rule_cannot_blow_up_the_findings() {
    // About 2 MB of log; without a budget this read builds about 600 MB.
    let json = one_big_rule(1 << 20, 300);
    let log = Log::from_json(&json).expect("valid log");
    let options = ReadOptions::default().with_max_text_bytes(8 * json.len());
    assert!(matches!(
        read_with::<Imported>(&log, &options),
        Err(Error::TooLarge { limit }) if limit == 8 * json.len()
    ));
    assert!(matches!(
        read_with::<()>(&log, &options),
        Err(Error::TooLarge { .. })
    ));
    // The default budget (256 MiB) catches it too.
    assert!(matches!(read::<()>(&log), Err(Error::TooLarge { .. })));
}

#[test]
fn findings_within_the_budget_stay_a_small_multiple_of_the_log() {
    let json = one_big_rule(1 << 10, 3);
    let log = Log::from_json(&json).expect("valid log");
    let options = ReadOptions::default().with_max_text_bytes(8 * json.len());
    let findings = read_with::<Imported>(&log, &options).expect("within budget");
    assert_eq!(findings.len(), 3);
    let size: usize = findings.iter().map(json_len).sum();
    assert!(size <= 8 * json.len(), "{size} > 8 × {}", json.len());
}

#[test]
fn an_unlimited_budget_reads_everything() {
    let json = one_big_rule(1 << 10, 100);
    let log = Log::from_json(&json).expect("valid log");
    let options = ReadOptions::default().with_max_text_bytes(usize::MAX);
    assert_eq!(read_with::<()>(&log, &options).expect("no cap").len(), 100);
}

//! Hostile header values must be analysed in time linear in their size.

use std::time::{Duration, Instant};

use rune_permissions_policy::{Options, run, run_feature_policy};

fn assert_fast(header: &str, legacy: bool) {
    let started = Instant::now();
    let report = if legacy {
        run_feature_policy(header, &Options::default())
    } else {
        run(header, &Options::default())
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "{} bytes took {elapsed:?}",
        header.len()
    );
    drop(report);
}

const N: usize = 50_000;

#[test]
fn many_distinct_features() {
    let header: Vec<String> = (0..N).map(|i| format!("f{i}=*")).collect();
    assert_fast(&header.join(", "), false);
    let legacy: Vec<String> = (0..N).map(|i| format!("f{i} *")).collect();
    assert_fast(&legacy.join("; "), true);
}

#[test]
fn many_duplicate_features() {
    assert_fast(&vec!["camera=*"; N].join(", "), false);
}

#[test]
fn long_allowlist() {
    let members: Vec<String> = (0..N)
        .map(|i| format!("\"https://a{i}.example\""))
        .collect();
    assert_fast(&format!("camera=({})", members.join(" ")), false);
}

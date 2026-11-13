//! Hostile header values must be analysed in time linear in their size.

use std::time::{Duration, Instant};

use rune_csp::{Options, run};

fn assert_fast(header: &str) {
    let started = Instant::now();
    let report = run(header, &Options::default());
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "{} bytes took {elapsed:?}",
        header.len()
    );
    drop(report);
}

#[test]
fn many_distinct_directives() {
    let header: Vec<String> = (0..100_000).map(|i| format!("d{i} 'self'")).collect();
    assert_fast(&header.join("; "));
}

#[test]
fn many_sources_and_duplicates() {
    let sources: Vec<String> = (0..100_000)
        .map(|i| format!("https://h{i}.example"))
        .collect();
    assert_fast(&format!("script-src {}", sources.join(" ")));
    assert_fast(&"img-src *;".repeat(100_000));
}

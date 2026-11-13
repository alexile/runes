//! Input built to make correlation slow.

use std::time::{Duration, Instant};

use rune_aspm_correlate::{Batch, Options, correlate};
use rune_finding::{Confidence, Finding, Location, Severity};

/// Each merge used to sort every source the issue had collected.
#[test]
fn many_duplicates_with_different_titles() {
    let mut batch = Batch::new();
    let findings = (0..20_000).map(|i| {
        Finding::<()>::new(
            "rule",
            format!("title {i}"),
            Severity::High,
            Confidence::Firm,
            Location::file("src/a.py").with_lines(1, 1),
        )
    });
    batch.add_findings("tool", findings);
    let start = Instant::now();
    let report = correlate(batch.into_findings(), &Options::default());
    let elapsed = start.elapsed();
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].finding.ext.sources.len(), 20_000);
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

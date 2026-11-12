//! The acceptance scenario: SARIF from a SAST tool and a DAST run (native
//! findings) correlate; overlapping issues merge with provenance kept.

#![allow(clippy::unwrap_used, reason = "fixture helpers outside #[test] fns")]

use rune_aspm_correlate::{Batch, Correlator, Corroboration, Kind, Options, Route};
use rune_finding::{Finding, Severity};
use rune_finding_dedupe::{Scan, Tracker};

const SAST: &str = include_str!("fixtures/sast_tool.sarif");
const SEMGREP: &str = include_str!("fixtures/semgrep.sarif");
const DAST: &str = include_str!("fixtures/dast_scanner.json");
const ROUTES: &str = include_str!("fixtures/routes.json");

fn options() -> Options {
    let routes: Vec<Route> = serde_json::from_str(ROUTES).unwrap();
    Options::default().with_routes(routes)
}

fn batch() -> Batch {
    let mut batch = Batch::new();
    assert_eq!(batch.add_sarif_json(SAST).unwrap(), 4);
    let dast: Vec<Finding> = serde_json::from_str(DAST).unwrap();
    assert_eq!(batch.add_findings("dast-scanner", dast), 3);
    batch
}

#[test]
fn sast_and_dast_correlate_with_provenance() {
    let report = batch().correlate(&options());
    assert_eq!(report.inputs, 7);
    assert_eq!(report.suppressed, 1, "the accepted test-data secret");

    let summary: Vec<_> = report
        .issues
        .iter()
        .map(|issue| {
            (
                issue.finding.check_id.as_str(),
                issue.finding.severity,
                issue.corroboration,
                issue.finding.ext.sources.len(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                "sqli.boolean",
                Severity::Critical,
                Corroboration::Confirmed,
                2
            ),
            // Same severity: the confirmed issue ranks first.
            ("xss.reflected", Severity::High, Corroboration::Confirmed, 2),
            (
                "generic.secret.hardcoded",
                Severity::High,
                Corroboration::Single,
                1
            ),
            (
                "headers.hsts_missing",
                Severity::Low,
                Corroboration::Single,
                1
            ),
        ]
    );

    // SQL injection: the SAST tool's sink in db.py, reached from the users
    // handler, and the exploited URL, each report intact.
    let sqli = &report.issues[0];
    let sources: Vec<_> = sqli
        .finding
        .ext
        .sources
        .iter()
        .map(|s| (s.kind, s.tool.as_str(), s.check_id.as_str()))
        .collect();
    assert_eq!(
        sources,
        [
            (Kind::Sast, "sast-tool", "python.sqli.format"),
            (Kind::Dast, "dast-scanner", "sqli.boolean")
        ]
    );
    let sast = &sqli.finding.ext.sources[0];
    assert_eq!(sast.flow.len(), 2, "taint flow kept");
    assert_eq!(
        sast.partial_fingerprints
            .get("primaryLocationLineHash")
            .map(String::as_str),
        Some("5d2f8a1c0e7b4a93:1")
    );
    assert_eq!(
        sqli.links
            .iter()
            .map(|l| (l.route.as_str(), l.cwe))
            .collect::<Vec<_>>(),
        [("users.show", 89)]
    );
    assert_eq!(sqli.finding.evidence.len(), 1, "DAST evidence kept");

    // XSS: CWE-79 (SAST) and CWE-80 (DAST) are one class.
    let xss = &report.issues[1];
    assert_eq!(xss.links.iter().map(|l| l.cwe).collect::<Vec<_>>(), [79]);
    assert_eq!(report.confirmed().count(), 2);
}

#[test]
fn without_routes_nothing_is_confirmed() {
    let report = batch().correlate(&Options::default());
    assert_eq!(report.issues.len(), 6);
    assert_eq!(report.confirmed().count(), 0);
}

#[test]
fn third_party_sarif_joins_the_view() {
    let mut batch = batch();
    let added = batch.add_sarif_json(SEMGREP).unwrap();
    assert!(added > 0);
    let report = batch.correlate(&options());
    assert_eq!(report.confirmed().count(), 2);
    assert!(
        report
            .issues
            .iter()
            .flat_map(|issue| &issue.finding.ext.sources)
            .any(|source| source.tool == "Semgrep OSS" || source.tool.starts_with("Semgrep"))
    );
    // Every input that was not suppressed is in exactly one issue.
    let sources: usize = report
        .issues
        .iter()
        .map(|i| i.finding.ext.sources.len())
        .sum();
    let counted: usize = report.issues.iter().map(|i| i.count).sum();
    assert_eq!(counted, report.inputs - report.suppressed);
    assert!(sources <= counted);
}

#[test]
fn tracker_keeps_identity_across_runs() {
    let options = options();
    let correlator = Correlator::new(&options);
    let mut tracker: Tracker<rune_aspm_correlate::Provenance> = Tracker::default();

    let first = batch().correlate(&options).into_findings();
    let report = tracker.observe(&Scan::new("aspm", 1), first, &correlator);
    assert_eq!(report.new.len(), 4);

    // Next run: only the DAST tool runs and still sees the SQL injection.
    let dast: Vec<Finding> = serde_json::from_str(DAST).unwrap();
    let mut next = Batch::new();
    next.add_findings("dast-scanner", dast.into_iter().take(1));
    let report = tracker.observe(
        &Scan::new("aspm", 2).partial(),
        next.correlate(&options).into_findings(),
        &correlator,
    );
    assert_eq!(report.new.len(), 0);
    assert_eq!(report.recurring.len(), 1);
}

#[test]
fn report_writes_sarif_with_sources() {
    let report = batch().correlate(&options());
    let log = report.to_sarif(&rune_sarif::Options::default().with_tool_name("aspm"));
    let json = log.to_json().unwrap();
    let back = rune_sarif::Log::from_json(&json).unwrap();
    assert_eq!(back.runs[0].results.len(), 4);
    let sources = back.runs[0].results[0]
        .properties
        .get(rune_aspm_correlate::sarif::SOURCES_PROPERTY)
        .and_then(|v| v.as_array())
        .map(Vec::len);
    assert_eq!(sources, Some(2));
    assert!(
        back.runs[0].results[0]
            .partial_fingerprints
            .contains_key("primaryLocationLineHash")
    );
}

//! Golden tests: real SARIF from four outside tools reads into findings.
//!
//! The fixtures are the tools' unmodified output for one small, deliberately
//! vulnerable Python project (a Flask app with SQL and command injection and
//! debug mode on, fake credentials, an old `requirements.txt` and a
//! `Dockerfile`), generated on 2026-11-11:
//!
//! - `codeql.sarif`: `CodeQL` 2.23.3, `python-code-scanning.qls`,
//!   `--format=sarif-latest --sarif-category=python`;
//! - `semgrep.sarif`: Semgrep OSS 1.140.0, a local taint rule plus four
//!   registry rules, `--sarif --dataflow-traces`;
//! - `trivy.sarif`: Trivy 0.67.2, `fs --scanners vuln,misconfig,secret
//!   --format sarif`;
//! - `gitleaks.sarif`: Gitleaks 8.28.0, `dir --report-format sarif`.
//!
//! The credentials in them are fake.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a bad fixture should fail loudly"
)]

mod common;

use common::Validator;
use rune_finding::{Confidence, Cvss, Finding, Location, Severity, Taxonomy, TaxonomyRef};
use rune_sarif::{Imported, Log, Options, github, read, write};

const CODEQL: &str = include_str!("fixtures/codeql.sarif");
const SEMGREP: &str = include_str!("fixtures/semgrep.sarif");
const TRIVY: &str = include_str!("fixtures/trivy.sarif");
const GITLEAKS: &str = include_str!("fixtures/gitleaks.sarif");

fn findings(json: &str) -> Vec<Finding<Imported>> {
    read(&Log::from_json(json).unwrap())
}

fn by_id<'a>(findings: &'a [Finding<Imported>], id: &str) -> &'a Finding<Imported> {
    findings
        .iter()
        .find(|finding| finding.check_id == id)
        .unwrap()
}

/// A region as `CodeQL` writes it: a start line, no end line, optional columns.
fn file(path: &str, line: u32, columns: Option<(u32, u32)>) -> Location {
    Location::File {
        path: path.to_owned(),
        start_line: Some(line),
        end_line: None,
        start_column: columns.map(|(start, _)| start),
        end_column: columns.map(|(_, end)| end),
        start_byte: None,
        end_byte: None,
        snippet: None,
    }
}

#[test]
fn every_fixture_conforms_to_the_schema() {
    let validator = Validator::new();
    for fixture in [CODEQL, SEMGREP, TRIVY, GITLEAKS] {
        let value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        assert_eq!(validator.validate(&value), Ok(()));
    }
}

#[test]
fn codeql() {
    let findings = findings(CODEQL);
    let ids: Vec<_> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "py/flask-debug",
            "py/sql-injection",
            "py/command-line-injection"
        ]
    );

    let sqli = by_id(&findings, "py/sql-injection");
    assert_eq!(
        sqli.title,
        "This SQL query depends on a [user-provided value](1)."
    );
    // security-severity 8.8 on the rule; precision "high".
    assert_eq!(sqli.severity, Severity::High);
    assert_eq!(sqli.confidence, Confidence::Firm);
    assert_eq!(sqli.location, file("src/app.py", 15, Some((20, 25))));
    // Tag `external/cwe/cwe-089`.
    assert_eq!(sqli.taxonomy, [TaxonomyRef::cwe(89)]);
    assert_eq!(sqli.tool, "CodeQL");
    assert_eq!(sqli.tool_version.as_deref(), Some("2.23.3"));
    assert_eq!(sqli.category.as_deref(), Some("python/"));
    assert!(
        sqli.partial_fingerprints
            .contains_key("primaryLocationLineHash")
    );
    // The taint path: request import to the execute call.
    let flow = &sqli.code_flows[0];
    assert_eq!(flow.len(), 8);
    assert_eq!(flow[0].location, file("src/app.py", 4, Some((26, 33))));
    assert_eq!(
        flow[0].message.as_deref(),
        Some("ControlFlowNode for ImportMember")
    );
    assert_eq!(flow[7].location, sqli.location);
    assert_eq!(
        sqli.related_locations[0].message.as_deref(),
        Some("user-provided value")
    );

    // security-severity 9.8.
    let command = by_id(&findings, "py/command-line-injection");
    assert_eq!(command.severity, Severity::Critical);
    assert_eq!(
        command.taxonomy,
        [TaxonomyRef::cwe(78), TaxonomyRef::cwe(88)]
    );

    let debug = by_id(&findings, "py/flask-debug");
    assert_eq!(debug.location, file("src/app.py", 26, Some((5, 24))));
    assert_eq!(debug.code_flows.len(), 0);
}

#[test]
fn semgrep() {
    let findings = findings(SEMGREP);
    assert_eq!(findings.len(), 5);
    let sqli = by_id(&findings, "python.flask.sqli.string-concat");
    // Level from the rule's defaultConfiguration; confidence from its tag.
    assert_eq!(sqli.severity, Severity::High);
    assert_eq!(sqli.confidence, Confidence::Certain);
    assert_eq!(
        sqli.location,
        Location::file("src/app.py")
            .with_lines(15, 15)
            .with_columns(5, 26)
            .with_snippet("    cursor.execute(query)")
    );
    assert_eq!(
        sqli.taxonomy,
        [
            TaxonomyRef::cwe(89).with_name(
                "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
            ),
            TaxonomyRef::owasp("A03:2021").with_name("Injection"),
        ]
    );
    assert_eq!(sqli.tool, "Semgrep OSS");

    let tainted = by_id(
        &findings,
        "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
    );
    assert_eq!(tainted.confidence, Confidence::Firm);
    let frameworks: Vec<_> = tainted
        .taxonomy
        .iter()
        .map(|t| t.framework.clone())
        .collect();
    assert_eq!(
        frameworks,
        [
            Taxonomy::Cwe,
            Taxonomy::Custom("owasp".to_owned()),
            Taxonomy::OwaspTop10_2021,
            Taxonomy::OwaspTop10_2025,
        ]
    );
    assert_eq!(
        tainted.help_uri.as_deref(),
        Some(
            "https://semgrep.dev/r/python.flask.security.injection.tainted-sql-string.tainted-sql-string"
        )
    );

    let debug = by_id(
        &findings,
        "python.flask.security.audit.debug-enabled.debug-enabled",
    );
    assert_eq!(debug.severity, Severity::Medium);
}

#[test]
fn trivy() {
    let findings = findings(TRIVY);
    assert_eq!(findings.len(), 12);
    let flask = by_id(&findings, "CVE-2018-1000656");
    assert_eq!(flask.severity, Severity::High);
    assert_eq!(flask.confidence, Confidence::Certain);
    assert_eq!(
        flask.location,
        Location::file("requirements.txt")
            .with_lines(1, 1)
            .with_columns(1, 1)
    );
    assert_eq!(
        flask.cvss,
        Some(Cvss::new(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            7.5
        ))
    );
    assert!(
        flask
            .title
            .starts_with("Package: flask\nInstalled Version: 0.12\n")
    );
    assert_eq!(
        flask.help_uri.as_deref(),
        Some("https://avd.aquasec.com/nvd/cve-2018-1000656")
    );
    assert_eq!(flask.tags, ["vulnerability", "security", "HIGH"]);

    let severities: Vec<_> = findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.severity))
        .collect();
    assert!(severities.contains(&("CVE-2026-27205", Severity::Low)));
    assert!(severities.contains(&("DS002", Severity::High)));
    assert!(severities.contains(&("jwt-token", Severity::Medium)));
    let secret = by_id(&findings, "jwt-token");
    assert!(matches!(&secret.location, Location::File { path, .. } if path == "src/settings.py"));
}

#[test]
fn gitleaks() {
    let findings = findings(GITLEAKS);
    let ids: Vec<_> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(ids, ["jwt", "generic-api-key"]);
    let key = by_id(&findings, "generic-api-key");
    // No level anywhere: SARIF's default, warning.
    assert_eq!(key.severity, Severity::Medium);
    assert_eq!(key.confidence, Confidence::Firm);
    assert_eq!(
        key.location,
        Location::file("src/settings.py")
            .with_lines(2, 2)
            .with_columns(2, 44)
            .with_snippet("a8Fk2Lq9Xz7Vb3Nm5Rt1Yw6Pc4Hd0Js")
    );
    assert_eq!(
        key.title,
        "generic-api-key has detected secret for file src/settings.py."
    );
    assert_eq!(key.tool, "gitleaks");
    assert!(key.partial_fingerprints.contains_key("commitSha"));
}

/// Imported findings write back out as valid SARIF that GitHub accepts,
/// and read back to the same findings.
#[test]
fn imported_findings_rewrite_and_read_back() {
    let validator = Validator::new();
    for fixture in [CODEQL, SEMGREP, TRIVY, GITLEAKS] {
        let imported = findings(fixture);
        let tool = imported[0].tool.clone();
        let log = write(&imported, &Options::default().with_tool_name(tool));
        let value: serde_json::Value = serde_json::from_str(&log.to_json().unwrap()).unwrap();
        assert_eq!(validator.validate(&value), Ok(()));
        assert!(github::accepts(&log), "{:#?}", github::check(&log));

        let again: Vec<Finding<Imported>> = read(&log);
        let core = |findings: &[Finding<Imported>]| -> Vec<Finding> {
            findings.iter().map(|f| f.clone().into_parts().0).collect()
        };
        assert_eq!(core(&again), core(&imported));
        for (again, imported) in again.iter().zip(&imported) {
            assert_eq!(again.code_flows, imported.code_flows);
            assert_eq!(again.related_locations, imported.related_locations);
            assert_eq!(again.properties, imported.properties);
        }
    }
}

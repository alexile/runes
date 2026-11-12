//! Written logs conform to the official SARIF 2.1.0 JSON schema, and GitHub
//! code scanning accepts them.

mod common;

use common::Validator;
use rune_finding::{
    Confidence, Cvss, Evidence, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use rune_sarif::model::{CodeFlow, ThreadFlowLocation};
use rune_sarif::{Imported, Log, Options, ToSarif, github, location, read, write};
use serde_json::Value;

/// A SAST tool's extension, as far as SARIF goes: a taint path.
#[derive(Debug, Clone, Default, PartialEq)]
struct SastExt {
    dataflow: Vec<Location>,
}

impl ToSarif for SastExt {
    fn write_result(finding: &Finding<Self>, result: &mut rune_sarif::model::Result) {
        if !finding.dataflow.is_empty() {
            let steps = finding
                .dataflow
                .iter()
                .map(|step| ThreadFlowLocation::new(location::to_sarif(step)));
            result.code_flows.push(CodeFlow::single(steps));
        }
    }
}

fn sast_findings() -> Vec<Finding<SastExt>> {
    let mut sqli = Finding::<SastExt>::new(
        "python.sqli.string-concat",
        "User input reaches a SQL query built by string concatenation",
        Severity::High,
        Confidence::Firm,
        Location::file("src/app.py")
            .with_lines(15, 15)
            .with_columns(5, 26)
            .with_bytes(310, 331)
            .with_snippet("    cursor.execute(query)"),
    )
    .push_taxonomy(TaxonomyRef::cwe(89).with_name("SQL Injection"))
    .push_taxonomy(TaxonomyRef::owasp("A03:2021").with_name("Injection"))
    .push_evidence(Evidence::new("sink", "cursor.execute(query)"))
    .with_remediation(
        Remediation::new("Use parameterised queries")
            .push_reference("https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
    );
    sqli.dataflow = vec![
        Location::file("src/app.py")
            .with_lines(11, 11)
            .with_columns(11, 33),
        Location::file("src/app.py")
            .with_lines(14, 14)
            .with_columns(13, 59),
        Location::file("src/app.py")
            .with_lines(15, 15)
            .with_columns(20, 25),
    ];
    let debug = Finding::<SastExt>::new(
        "python.flask.debug",
        "Flask debug mode enabled",
        Severity::Medium,
        Confidence::Certain,
        Location::file("src/app.py").with_lines(26, 26),
    )
    .push_taxonomy(TaxonomyRef::cwe(489));
    let secret = Finding::<SastExt>::new(
        "secret.generic-api-key",
        "Hard-coded API key",
        Severity::Critical,
        Confidence::Tentative,
        Location::file("config/ünïcode dir/settings.py").with_lines(2, 2),
    )
    .push_taxonomy(TaxonomyRef::cwe(798))
    .push_taxonomy(TaxonomyRef::new(
        Taxonomy::Custom("acme-secrets".to_owned()),
        "AK-1",
    ));
    vec![sqli, debug, secret]
}

fn dast_findings() -> Vec<Finding> {
    vec![
        Finding::<()>::new(
            "xss.reflected",
            "Reflected XSS",
            Severity::High,
            Confidence::Firm,
            Location::url("https://shop.example.test/search?q=x").with_parameter("q"),
        )
        .push_taxonomy(TaxonomyRef::cwe(79))
        .push_taxonomy(TaxonomyRef::new(Taxonomy::Wstg, "WSTG-INPV-01"))
        .with_cvss(Cvss::new(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            6.1,
        ))
        .push_remediation_ref("https://cheatsheetseries.owasp.org/"),
        Finding::<()>::new(
            "tls.weak_protocol",
            "TLS 1.0 accepted",
            Severity::Low,
            Confidence::Certain,
            Location::network("2001:db8::1", 443),
        ),
        Finding::<()>::new(
            "k8s.ingress.no_tls",
            "Ingress without TLS",
            Severity::Informational,
            Confidence::Firm,
            Location::cluster_object("prod", "Ingress", "web"),
        ),
        Finding::<()>::new(
            "binary.rwx_segment",
            "Writable and executable segment",
            Severity::Medium,
            Confidence::Certain,
            Location::artifact("bin/app", Some(0x1000)),
        ),
        // Locations that need the round-trip hint.
        Finding::<()>::new(
            "odd",
            "Odd locations",
            Severity::Low,
            Confidence::Tentative,
            Location::url("https://x.test/page#frag"),
        ),
        Finding::<()>::new(
            "odd",
            "Odd locations",
            Severity::Low,
            Confidence::Tentative,
            Location::artifact("bin/app", None),
        ),
    ]
}

fn to_value(log: &Log) -> Value {
    serde_json::from_str(&log.to_json().unwrap_or_default()).unwrap_or(Value::Null)
}

#[test]
fn written_logs_conform_to_the_schema() {
    let validator = Validator::new();
    let logs = [
        write(
            &sast_findings(),
            &Options::default().with_tool_name("sast-tool"),
        ),
        write(
            &dast_findings(),
            &Options::default().with_tool_name("payload-fuzzer"),
        ),
        write(
            &dast_findings(),
            &Options::default()
                .with_tool_name("payload-fuzzer")
                .with_tool_version("0.1.0")
                .with_tool_organization("example")
                .with_tool_information_uri("https://example.test/")
                .with_category("dast/")
                .with_details(false),
        ),
        write::<()>(&[], &Options::default()),
    ];
    for log in &logs {
        if let Err(errors) = validator.validate(&to_value(log)) {
            panic!("{errors}\n{}", log.to_json_pretty().unwrap_or_default());
        }
    }
}

#[test]
fn dast_scanner_snapshot_conforms_to_the_schema() {
    let snapshot: Value = serde_json::from_str(include_str!("fixtures/dast_scanner_sarif.json"))
        .unwrap_or(Value::Null);
    assert_eq!(Validator::new().validate(&snapshot), Ok(()));
}

#[test]
fn the_validator_rejects_invalid_logs() {
    let validator = Validator::new();
    let mut log = to_value(&write(&sast_findings(), &Options::default()));
    assert_eq!(validator.validate(&log), Ok(()));
    log["runs"][0]["results"][0]["level"] = Value::from("fatal");
    assert!(validator.validate(&log).is_err());
    let mut log = to_value(&write(&sast_findings(), &Options::default()));
    log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] =
        Value::from(0);
    assert!(validator.validate(&log).is_err());
    let mut log = to_value(&write(&sast_findings(), &Options::default()));
    log["$schema"] = Value::from("not a uri");
    assert!(validator.validate(&log).is_err());
}

#[test]
fn github_accepts_code_findings() {
    let log = write(
        &sast_findings(),
        &Options::default().with_category("sast/python/"),
    );
    assert_eq!(github::check(&log), []);
    let rule = &log.runs[0].tool.driver.rules[0];
    assert_eq!(rule.properties.tags, ["security", "external/cwe/cwe-89"]);
    assert_eq!(rule.properties.security_severity.as_deref(), Some("8.0"));
    let flow = &log.runs[0].results[0].code_flows[0].thread_flows[0];
    assert_eq!(flow.locations.len(), 3);
}

#[test]
fn github_accepts_dast_findings_with_degraded_display() {
    let log = write(&dast_findings(), &Options::default());
    let problems = github::check(&log);
    assert!(github::accepts(&log), "{problems:#?}");
    assert!(
        problems
            .iter()
            .all(|problem| problem.impact == github::Impact::Degraded)
    );
}

#[test]
fn written_logs_read_back() {
    let findings = sast_findings();
    let log = write(&findings, &Options::default());
    let json = log.to_json().unwrap_or_default();
    let read_back: Vec<Finding<Imported>> = read(&Log::from_json(&json).unwrap_or_default());
    assert_eq!(read_back.len(), findings.len());
    for (back, original) in read_back.into_iter().zip(findings) {
        let (core, imported) = back.into_parts();
        assert_eq!(core, original.clone().into_parts().0);
        let flow: Vec<_> = imported
            .code_flows
            .iter()
            .flatten()
            .map(|step| step.location.clone())
            .collect();
        assert_eq!(flow, original.dataflow);
    }
}

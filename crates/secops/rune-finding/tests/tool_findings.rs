//! Two tools' findings expressed as `rune_finding::Finding<X>` without
//! losing data.
//!
//! The fixtures are real tool output:
//!
//! - `fixtures/dast_scanner_findings.json`: a DAST scanner's serialized
//!   findings, each next to the `fingerprint()` the scanner computed for it.
//!   The first is a rich finding, the second a golden-fingerprint finding;
//!   the rest cover every other location kind.
//! - `fixtures/sast_tool_findings.json`: a SAST tool's serialized findings,
//!   one using every member.
//!
//! The DAST scanner's findings deserialize directly as `Finding<NetsecExt>`
//! (same JSON shape). The SAST tool's findings have their own shape, so they
//! go through a conversion to `Finding<SastExt>` and back.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns: a bad fixture should fail loudly"
)]

use std::collections::BTreeMap;

use rune_finding::ext::{HasExchanges, HasLegacyCwe, HasProof, HasSeenTimes};
use rune_finding::{
    Confidence, Cvss, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// -------------------------------------------------------------- DAST scanner

/// What the DAST scanner keeps beyond the shared model. HTTP exchanges stay
/// opaque here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct NetsecExt {
    /// Legacy CWE string, kept for compatibility next to `taxonomy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exchanges: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_seen_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seen_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Proof {
    summary: String,
    #[serde(default)]
    steps: Vec<String>,
    #[serde(default)]
    exchanges: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_at_unix_ms: Option<u64>,
}

// How a tool keeps its builder methods once `Finding` is the rune type: the
// `ext` capability traits make `with_cwe` and friends inherent methods of
// `Finding<NetsecExt>`, so call sites need no extra import.
impl HasLegacyCwe for NetsecExt {
    fn legacy_cwe_mut(&mut self) -> &mut Option<String> {
        &mut self.cwe
    }
}

impl HasExchanges for NetsecExt {
    type Exchange = Value;

    fn exchanges_mut(&mut self) -> &mut Vec<Value> {
        &mut self.exchanges
    }
}

impl HasProof for NetsecExt {
    type Proof = Proof;

    fn proof_mut(&mut self) -> &mut Option<Proof> {
        &mut self.proof
    }
}

impl HasSeenTimes for NetsecExt {
    fn first_seen_unix_ms_mut(&mut self) -> &mut Option<u64> {
        &mut self.first_seen_unix_ms
    }

    fn last_seen_unix_ms_mut(&mut self) -> &mut Option<u64> {
        &mut self.last_seen_unix_ms
    }
}

#[derive(Deserialize)]
struct DastFixture {
    fingerprint: String,
    finding: Value,
}

fn dast_fixtures() -> Vec<DastFixture> {
    serde_json::from_str(include_str!("fixtures/dast_scanner_findings.json")).unwrap()
}

#[test]
fn dast_findings_round_trip_losslessly() {
    let fixtures = dast_fixtures();
    assert_eq!(fixtures.len(), 7);
    for fixture in fixtures {
        let finding: Finding<NetsecExt> = serde_json::from_value(fixture.finding.clone()).unwrap();
        assert_eq!(serde_json::to_value(&finding).unwrap(), fixture.finding);
    }
}

#[test]
fn dast_fingerprints_are_unchanged() {
    for fixture in dast_fixtures() {
        let finding: Finding<NetsecExt> = serde_json::from_value(fixture.finding).unwrap();
        assert_eq!(
            finding.fingerprint(),
            fixture.fingerprint,
            "{}",
            finding.check_id
        );
    }
}

/// The rich fixture finding, built with the rune type's builders.
#[test]
fn dast_rich_finding_builds_the_same_json() {
    let fixtures = dast_fixtures();
    let expected = &fixtures[0].finding;
    let exchange = |index: usize| expected["exchanges"][index].clone();

    let finding = Finding::<NetsecExt>::new(
        "xss.reflected",
        "Reflected XSS",
        Severity::High,
        Confidence::Firm,
        Location::Url {
            url: "https://shop.example.test/search?q=x".to_owned(),
            parameter: Some("q".to_owned()),
        },
    )
    .with_cwe("CWE-79")
    .push_taxonomy(TaxonomyRef::new(Taxonomy::OwaspTop10_2025, "A05:2025").with_name("Injection"))
    .push_taxonomy(TaxonomyRef::new(Taxonomy::Wstg, "WSTG-INPV-01"))
    .push_exchange(exchange(0))
    .push_exchange(exchange(1))
    .with_proof(Proof {
        summary: "Payload reflected unencoded".to_owned(),
        steps: vec!["Send q=<script>alert(1)</script>".to_owned()],
        exchanges: vec![expected["proof"]["exchanges"][0].clone()],
        verified_at_unix_ms: Some(1_700_000_000_000),
    })
    .push_remediation_ref("https://cheatsheetseries.owasp.org/")
    .with_cvss(Cvss::new(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        6.1,
    ))
    .with_first_seen_unix_ms(1_700_000_000_000)
    .with_last_seen_unix_ms(1_700_000_100_000);

    assert_eq!(&serde_json::to_value(&finding).unwrap(), expected);
    assert_eq!(finding.fingerprint(), fixtures[0].fingerprint);
    // Extension fields read like core ones.
    assert_eq!(finding.cwe.as_deref(), Some("CWE-79"));
    assert_eq!(finding.exchanges.len(), 2);
    assert_eq!(
        finding.proof.as_ref().map(|proof| proof.steps.len()),
        Some(1)
    );
}

/// The scanner's stored CVSS score is the one its vector computes, and computing
/// it reproduces the stored object exactly (`cvss` feature).
#[cfg(feature = "cvss")]
#[test]
fn dast_cvss_matches_its_vector() {
    let cvss: Cvss = serde_json::from_value(
        serde_json::json!({"base_score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
    )
    .unwrap();
    assert!(cvss.verify().is_ok());
    assert_eq!(Cvss::parse(&cvss.vector).unwrap(), cvss);
}

/// A finding in the older v1 JSON shape.
#[test]
fn v1_json_still_deserializes() {
    let json = r#"{
        "check_id": "tls.weak_protocol",
        "title": "TLS 1.0 accepted",
        "severity": "high",
        "confidence": "certain",
        "cwe": "CWE-327",
        "location": {"location_kind": "network", "host": "example.test", "port": 443},
        "evidence": []
    }"#;
    let finding: Finding<NetsecExt> = serde_json::from_str(json).unwrap();
    assert_eq!(finding.cwe.as_deref(), Some("CWE-327"));
    assert_eq!(finding.exchanges, Vec::<Value>::new());
    assert_eq!(finding.taxonomy, Vec::<TaxonomyRef>::new());
    assert!(finding.proof.is_none());
    assert!(finding.cvss.is_none());
    assert_eq!(finding.location, Location::network("example.test", 443));
}

// ----------------------------------------------------------------- SAST tool

/// The SAST tool's own finding JSON, mirrored field for field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastFinding {
    rule_id: String,
    message: String,
    location: SastLocation,
    severity: String,
    confidence: String,
    cwe: Option<String>,
    owasp: Option<String>,
    code_snippet: Option<String>,
    fix: Option<String>,
    dataflow_path: Option<SastDataflowPath>,
    ai_metadata: Option<AiMetadata>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastLocation {
    file: String,
    span: SastSpan,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastSpan {
    start: SastPosition,
    end: SastPosition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastPosition {
    line: usize,
    column: usize,
    offset: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastDataflowPath {
    source: SastLocation,
    sink: SastLocation,
    steps: Vec<SastDataflowStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SastDataflowStep {
    location: SastLocation,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AiMetadata {
    exploitability: Option<f32>,
    criticality: Option<f32>,
    likely_false_positive: bool,
    explanation: Option<String>,
    remediation: Option<String>,
    ai_confidence: f32,
}

/// What the SAST tool keeps beyond the shared model. Dataflow locations use
/// the shared [`Location`], ready for SARIF `codeFlows`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct SastExt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dataflow_path: Option<DataflowPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ai_metadata: Option<AiMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DataflowPath {
    source: Location,
    sink: Location,
    steps: Vec<DataflowStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DataflowStep {
    location: Location,
    description: String,
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

fn location_to_rune(location: SastLocation) -> Location {
    let SastSpan { start, end } = location.span;
    Location::file(location.file)
        .with_lines(to_u32(start.line), to_u32(end.line))
        .with_columns(to_u32(start.column), to_u32(end.column))
        .with_bytes(to_u64(start.offset), to_u64(end.offset))
}

fn location_from_rune(location: &Location) -> SastLocation {
    let Location::File {
        path,
        start_line: Some(start_line),
        end_line: Some(end_line),
        start_column: Some(start_column),
        end_column: Some(end_column),
        start_byte: Some(start_byte),
        end_byte: Some(end_byte),
        ..
    } = location
    else {
        panic!("not a SAST tool location: {location:?}");
    };
    let position = |line: &u32, column: &u32, offset: &u64| SastPosition {
        line: usize::try_from(*line).unwrap(),
        column: usize::try_from(*column).unwrap(),
        offset: usize::try_from(*offset).unwrap(),
    };
    SastLocation {
        file: path.clone(),
        span: SastSpan {
            start: position(start_line, start_column, start_byte),
            end: position(end_line, end_column, end_byte),
        },
    }
}

fn is_owasp(framework: &Taxonomy) -> bool {
    match framework {
        Taxonomy::OwaspTop10_2021 | Taxonomy::OwaspTop10_2025 | Taxonomy::OwaspApi2023 => true,
        Taxonomy::Custom(name) => name.as_bytes().eq_ignore_ascii_case(b"owasp"),
        _ => false,
    }
}

fn sast_to_rune(sast: SastFinding) -> Finding<SastExt> {
    let mut location = location_to_rune(sast.location);
    if let Some(snippet) = sast.code_snippet {
        location = location.with_snippet(snippet);
    }
    let mut finding: Finding<SastExt> = Finding::new(
        sast.rule_id,
        sast.message,
        sast.severity.parse().unwrap(),
        sast.confidence.parse().unwrap(),
        location,
    );
    if let Some(cwe) = sast.cwe {
        finding = finding.push_taxonomy(TaxonomyRef::new(Taxonomy::Cwe, cwe));
    }
    if let Some(owasp) = sast.owasp {
        finding = finding.push_taxonomy(TaxonomyRef::owasp(owasp));
    }
    if let Some(fix) = sast.fix {
        finding = finding.with_remediation(Remediation::new(fix));
    }
    finding.with_ext(SastExt {
        dataflow_path: sast.dataflow_path.map(|path| DataflowPath {
            source: location_to_rune(path.source),
            sink: location_to_rune(path.sink),
            steps: path
                .steps
                .into_iter()
                .map(|step| DataflowStep {
                    location: location_to_rune(step.location),
                    description: step.description,
                })
                .collect(),
        }),
        ai_metadata: sast.ai_metadata,
        metadata: sast.metadata,
    })
}

fn rune_to_sast(finding: &Finding<SastExt>) -> SastFinding {
    let snippet = match &finding.location {
        Location::File { snippet, .. } => snippet.clone(),
        _ => None,
    };
    SastFinding {
        rule_id: finding.check_id.clone(),
        message: finding.title.clone(),
        location: location_from_rune(&finding.location),
        severity: match finding.severity {
            Severity::Informational => "info".to_owned(),
            other => other.as_str().to_owned(),
        },
        confidence: match finding.confidence {
            Confidence::Tentative => "low",
            Confidence::Firm => "medium",
            Confidence::Certain => "high",
        }
        .to_owned(),
        cwe: finding
            .taxonomy_in(&Taxonomy::Cwe)
            .next()
            .map(|entry| entry.id.clone()),
        owasp: finding
            .taxonomy
            .iter()
            .find(|entry| is_owasp(&entry.framework))
            .map(|entry| entry.id.clone()),
        code_snippet: snippet,
        fix: finding
            .remediation
            .as_ref()
            .map(|remediation| remediation.summary.clone()),
        dataflow_path: finding.dataflow_path.as_ref().map(|path| SastDataflowPath {
            source: location_from_rune(&path.source),
            sink: location_from_rune(&path.sink),
            steps: path
                .steps
                .iter()
                .map(|step| SastDataflowStep {
                    location: location_from_rune(&step.location),
                    description: step.description.clone(),
                })
                .collect(),
        }),
        ai_metadata: finding.ai_metadata.clone(),
        metadata: finding.metadata.clone(),
    }
}

fn sast_fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/sast_tool_findings.json")).unwrap()
}

#[test]
fn sast_findings_map_losslessly() {
    let fixtures = sast_fixtures();
    assert_eq!(fixtures.len(), 3);
    for original in fixtures {
        let sast: SastFinding = serde_json::from_value(original.clone()).unwrap();
        let finding = sast_to_rune(sast);
        // Through the shared JSON shape and back.
        let shared = serde_json::to_string(&finding).unwrap();
        let reread: Finding<SastExt> = serde_json::from_str(&shared).unwrap();
        assert_eq!(reread, finding);
        let back = serde_json::to_value(rune_to_sast(&reread)).unwrap();
        assert_eq!(back, original);
    }
}

#[test]
fn sast_rich_finding_uses_shared_members() {
    let sast: SastFinding = serde_json::from_value(sast_fixtures()[0].clone()).unwrap();
    let finding = sast_to_rune(sast);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Certain);
    assert_eq!(
        finding.taxonomy,
        [
            TaxonomyRef::cwe(89),
            TaxonomyRef::new(Taxonomy::OwaspTop10_2021, "A03:2021"),
        ]
    );
    assert!(matches!(
        &finding.location,
        Location::File {
            start_line: Some(42),
            start_column: Some(5),
            start_byte: Some(1200),
            snippet: Some(_),
            ..
        }
    ));
    assert_eq!(
        finding.dataflow_path.as_ref().map(|path| path.steps.len()),
        Some(1)
    );
    let json = serde_json::to_value(&finding).unwrap();
    assert_eq!(json["location"]["location_kind"], "file");
    assert_eq!(json["metadata"]["engine"], "taint");
}

//! A DAST scanner's SARIF output, reproduced through rune-sarif.
//!
//! `fixtures/dast_scanner_sarif.json` is the scanner's own snapshot, copied
//! unchanged. The finding below is the snapshot's finding, written against
//! `rune_finding`. `NetsecExt` stands in for the scanner's extension: its
//! `ToSarif` hook adds what only the scanner knows about (the legacy CWE tag
//! and the HTTP exchanges).

#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a bad fixture should fail loudly"
)]

use std::collections::BTreeMap;

use rune_finding::{
    Confidence, Cvss, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use rune_sarif::model::{
    ArtifactContent, ArtifactLocation, Attachment, Message, ReportingDescriptor, WebRequest,
    WebResponse,
};
use rune_sarif::{Options, ToSarif, write};

/// An HTTP exchange, reduced to what the scanner's SARIF writer reads.
#[derive(Debug, Clone)]
enum Exchange {
    Inline {
        id: u64,
        method: &'static str,
        url: String,
        request_headers: Vec<(&'static str, &'static str)>,
        status: u16,
        reason: &'static str,
        response_headers: Vec<(&'static str, &'static str)>,
        response_body: &'static str,
    },
    Stored {
        id: u64,
        store: Option<&'static str>,
    },
}

#[derive(Debug, Clone, Default)]
struct NetsecExt {
    cwe: Option<String>,
    exchanges: Vec<Exchange>,
    proof_exchanges: Vec<Exchange>,
}

/// SARIF headers are an object; the scanner joins repeated names with `, `.
fn header_map(headers: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        map.entry((*name).to_owned())
            .and_modify(|joined| {
                joined.push_str(", ");
                joined.push_str(value);
            })
            .or_insert_with(|| (*value).to_owned());
    }
    map
}

impl ToSarif for NetsecExt {
    fn write_rule(finding: &Finding<Self>, rule: &mut ReportingDescriptor) {
        rule.properties.tags = finding.cwe.iter().cloned().collect();
    }

    fn write_result(finding: &Finding<Self>, result: &mut rune_sarif::model::Result) {
        let all: Vec<&Exchange> = finding
            .exchanges
            .iter()
            .chain(&finding.proof_exchanges)
            .collect();
        let primary = all
            .iter()
            .position(|exchange| matches!(exchange, Exchange::Inline { .. }));
        if let Some(Exchange::Inline {
            method,
            url,
            request_headers,
            status,
            reason,
            response_headers,
            response_body,
            ..
        }) = primary.map(|index| all[index])
        {
            let mut request = WebRequest::default();
            request.protocol = Some("HTTP".to_owned());
            request.version = Some("1.1".to_owned());
            request.target = Some(url.clone());
            request.method = Some((*method).to_owned());
            request.headers = header_map(request_headers);
            result.web_request = Some(request);
            let mut response = WebResponse::default();
            response.protocol = Some("HTTP".to_owned());
            response.version = Some("1.1".to_owned());
            response.status_code = Some(*status);
            response.reason_phrase = Some((*reason).to_owned());
            response.headers = header_map(response_headers);
            response.body = Some(ArtifactContent::text(*response_body));
            result.web_response = Some(response);
        }
        for (index, exchange) in all.iter().enumerate() {
            if Some(index) == primary {
                continue;
            }
            let (description, uri) = match exchange {
                Exchange::Inline {
                    id,
                    method,
                    url,
                    status,
                    ..
                } => (
                    format!("HTTP exchange {id}: {method} {url} -> {status}"),
                    format!("netsec-exchange:inline/{id}"),
                ),
                Exchange::Stored { id, store } => {
                    let store = store.unwrap_or("local");
                    (
                        format!("Stored HTTP exchange {id} in {store}"),
                        format!("netsec-exchange:{store}/{id}"),
                    )
                }
            };
            let mut attachment = Attachment::default();
            attachment.description = Some(Message::text(description));
            attachment.artifact_location = ArtifactLocation::uri(uri);
            result.attachments.push(attachment);
        }
    }
}

/// `with_cwe`: the legacy field plus a CWE taxonomy entry.
fn with_cwe(mut finding: Finding<NetsecExt>, cwe: &str) -> Finding<NetsecExt> {
    if !finding
        .taxonomy_in(&Taxonomy::Cwe)
        .any(|entry| entry.id == cwe)
    {
        finding.taxonomy.push(TaxonomyRef::new(Taxonomy::Cwe, cwe));
    }
    finding.cwe = Some(cwe.to_owned());
    finding
}

fn inline(id: u64, url: &str) -> Exchange {
    Exchange::Inline {
        id,
        method: "GET",
        url: url.to_owned(),
        request_headers: vec![("Accept", "text/html")],
        status: 200,
        reason: "OK",
        response_headers: vec![
            ("Content-Type", "text/html"),
            ("Set-Cookie", "a=1"),
            ("Set-Cookie", "b=2"),
        ],
        response_body: "<script>alert(1)</script>",
    }
}

fn snapshot_finding() -> Finding<NetsecExt> {
    let mut finding = with_cwe(
        Finding::<NetsecExt>::new(
            "xss.reflected",
            "Reflected XSS",
            Severity::High,
            Confidence::Firm,
            Location::url("https://shop.example.test/search?q=x").with_parameter("q"),
        ),
        "CWE-79",
    )
    .push_taxonomy(TaxonomyRef::new(Taxonomy::OwaspTop10_2025, "A05:2025").with_name("Injection"))
    .push_taxonomy(TaxonomyRef::new(Taxonomy::Wstg, "WSTG-INPV-01"))
    .push_remediation_ref("https://cheatsheetseries.owasp.org/")
    .with_cvss(Cvss::new(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        6.1,
    ));
    finding.exchanges = vec![
        inline(1, "https://shop.example.test/search?q=%3Cscript%3E"),
        Exchange::Stored {
            id: 9,
            store: Some("proxy-history"),
        },
    ];
    finding.proof_exchanges = vec![inline(2, "https://shop.example.test/search?q=2")];
    finding
}

/// The scanner's `build_log`, on top of rune-sarif.
fn build_log(
    tool: &str,
    version: Option<&str>,
    findings: &[Finding<NetsecExt>],
) -> rune_sarif::Log {
    let mut options = Options::default().with_tool_name(tool).with_details(false);
    if let Some(version) = version {
        options = options.with_tool_version(version);
    }
    write(findings, &options)
}

#[test]
fn sarif_v2_snapshot_is_identical() {
    let log = build_log("payload-fuzzer", Some("0.1.0"), &[snapshot_finding()]);
    let mut actual = log.to_json_pretty().unwrap();
    actual.push('\n');
    assert_eq!(actual, include_str!("fixtures/dast_scanner_sarif.json"));
}

/// A TLS finding, against the scanner's own expected JSON.
#[test]
fn tls_unit_snapshot_is_identical() {
    let finding = with_cwe(
        Finding::<NetsecExt>::new(
            "tls.weak_protocol",
            "TLS 1.0 accepted",
            Severity::High,
            Confidence::Certain,
            Location::network("example.test", 443),
        ),
        "CWE-327",
    )
    .with_remediation(
        Remediation::new("Disable TLS 1.0")
            .with_references(vec!["https://example.test/ref".to_owned()]),
    );
    let fingerprint = finding.fingerprint();
    let log = build_log("tls-auditor", None, &[finding]);
    let expected = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "tls-auditor",
                "rules": [{
                    "id": "tls.weak_protocol",
                    "name": "TLS 1.0 accepted",
                    "shortDescription": {"text": "TLS 1.0 accepted"},
                    "helpUri": "https://example.test/ref",
                    "properties": {"security-severity": "8.0", "tags": ["CWE-327"]}
                }]
            }},
            "results": [{
                "ruleId": "tls.weak_protocol",
                "level": "error",
                "message": {"text": "TLS 1.0 accepted"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "tcp://example.test:443"}
                }}],
                "properties": {"security-severity": "8.0", "confidence": "certain"},
                "partialFingerprints": {"netsecFingerprint/v1": fingerprint},
                "taxa": [{
                    "id": "CWE-327",
                    "index": 0,
                    "toolComponent": {"name": "CWE", "index": 0}
                }]
            }],
            "taxonomies": [{
                "name": "CWE",
                "organization": "MITRE",
                "informationUri": "https://cwe.mitre.org/",
                "taxa": [{"id": "CWE-327"}]
            }]
        }]
    });
    assert_eq!(serde_json::to_value(&log).unwrap(), expected);
}

/// The fingerprint in the scanner's snapshot is the one rune-finding computes.
#[test]
fn snapshot_fingerprint_matches() {
    let log: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/dast_scanner_sarif.json")).unwrap();
    assert_eq!(
        log["runs"][0]["results"][0]["partialFingerprints"]["netsecFingerprint/v1"],
        snapshot_finding().fingerprint()
    );
}

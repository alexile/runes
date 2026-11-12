//! Property tests: write then read gives the findings back, for any
//! finding; the reader never panics; and reading is stable under a rewrite.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a serialization failure should fail loudly"
)]

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rune_finding::{
    Confidence, Cvss, Evidence, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use rune_sarif::model::{CodeFlow, ThreadFlowLocation};
use rune_sarif::{
    FromSarif, Imported, Log, Options, ResultContext, ToSarif, github, location, read, write,
};

/// Arbitrary text, plus strings shaped like the URIs the location mapping
/// distinguishes, so ambiguous cases come up often.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "\\PC{0,16}",
        "(https?|wss?|tcp|k8s|file|C|rune-finding):(//)?[a-z0-9.:/#%?@\\[\\] ]{0,16}",
        "[a-z]{1,4}(/[a-z0-9%#?:]{0,4}){0,3}",
    ]
}

fn severity() -> impl Strategy<Value = Severity> {
    proptest::sample::select(Severity::ALL.to_vec())
}

fn confidence() -> impl Strategy<Value = Confidence> {
    proptest::sample::select(Confidence::ALL.to_vec())
}

fn taxonomy() -> impl Strategy<Value = Taxonomy> {
    prop_oneof![
        proptest::sample::select(Taxonomy::KNOWN.to_vec()),
        // The reader takes a component named like a known taxonomy for that
        // taxonomy, so custom names must not be display names.
        text().prop_map(|name| Taxonomy::parse(&name)).prop_filter(
            "custom name is a display name",
            |taxonomy| {
                !Taxonomy::KNOWN
                    .iter()
                    .any(|known| known.display_name() == taxonomy.as_str())
            }
        ),
    ]
}

fn taxonomy_ref() -> impl Strategy<Value = TaxonomyRef> {
    (taxonomy(), text(), option::of(text())).prop_map(|(framework, id, name)| {
        let entry = TaxonomyRef::new(framework, id);
        match name {
            Some(name) => entry.with_name(name),
            None => entry,
        }
    })
}

fn small() -> impl Strategy<Value = u32> {
    prop_oneof![0..5_u32, any::<u32>()]
}

fn location() -> impl Strategy<Value = Location> {
    prop_oneof![
        (text(), any::<u16>()).prop_map(|(host, port)| Location::Network { host, port }),
        (text(), option::of(text())).prop_map(|(url, parameter)| Location::Url { url, parameter }),
        (
            text(),
            (
                option::of(small()),
                option::of(small()),
                option::of(small()),
                option::of(small()),
            ),
            option::of(any::<u64>()),
            option::of(any::<u64>()),
            option::of(text()),
        )
            .prop_map(
                |(
                    path,
                    (start_line, end_line, start_column, end_column),
                    start_byte,
                    end_byte,
                    snippet,
                )| {
                    Location::File {
                        path,
                        start_line,
                        end_line,
                        start_column,
                        end_column,
                        start_byte,
                        end_byte,
                        snippet,
                    }
                }
            ),
        (text(), text(), text()).prop_map(|(namespace, kind, name)| Location::ClusterObject {
            namespace,
            kind,
            name
        }),
        (text(), option::of(any::<u64>()))
            .prop_map(|(path, offset)| Location::Artifact { path, offset }),
    ]
}

fn cvss() -> impl Strategy<Value = Cvss> {
    // JSON has no NaN or infinity; every finite score survives.
    (
        text(),
        prop_oneof![
            0.0..=10.0_f64,
            any::<f64>().prop_filter("finite", |s| s.is_finite())
        ],
    )
        .prop_map(|(vector, score)| Cvss::new(vector, score))
}

fn finding() -> impl Strategy<Value = Finding> {
    (
        (text(), text(), severity(), confidence(), location()),
        vec((text(), text()), 0..3),
        option::of((text(), vec(text(), 0..3))),
        vec(taxonomy_ref(), 0..4),
        vec(text(), 0..3),
        option::of(cvss()),
    )
        .prop_map(
            |(
                (check_id, title, severity, confidence, location),
                evidence,
                remediation,
                taxonomy,
                refs,
                cvss,
            )| {
                let mut finding =
                    Finding::<()>::new(check_id, title, severity, confidence, location)
                        .with_evidence(
                            evidence
                                .into_iter()
                                .map(|(label, snippet)| Evidence::new(label, snippet))
                                .collect(),
                        )
                        .with_taxonomy(taxonomy)
                        .with_remediation_refs(refs);
                finding.remediation = remediation.map(|(summary, references)| {
                    Remediation::new(summary).with_references(references)
                });
                finding.cvss = cvss;
                finding
            },
        )
}

/// An extension that travels as a SARIF code flow, as a SAST tool's taint
/// paths do.
#[derive(Debug, Clone, Default, PartialEq)]
struct Flow {
    steps: Vec<Location>,
}

impl ToSarif for Flow {
    fn write_result(finding: &Finding<Self>, result: &mut rune_sarif::model::Result) {
        if !finding.steps.is_empty() {
            result.code_flows.push(CodeFlow::single(
                finding
                    .steps
                    .iter()
                    .map(|step| ThreadFlowLocation::new(location::to_sarif(step))),
            ));
        }
    }
}

impl FromSarif for Flow {
    fn from_sarif(context: &ResultContext<'_>) -> Self {
        let steps = context
            .result()
            .code_flows
            .first()
            .and_then(|flow| flow.thread_flows.first())
            .map(|thread| {
                thread
                    .locations
                    .iter()
                    .filter_map(|step| location::from_sarif(step.location.as_ref()?))
                    .collect()
            })
            .unwrap_or_default();
        Self { steps }
    }
}

/// Serialize and parse again, as a consumer of the file would.
fn through_json(log: &Log) -> Log {
    Log::from_json(&log.to_json().unwrap()).unwrap()
}

proptest! {
    #[test]
    fn write_then_read_round_trips(findings in vec(finding(), 0..6)) {
        let log = through_json(&write(&findings, &Options::default()));
        prop_assert_eq!(read::<()>(&log), findings);
    }

    #[test]
    fn extensions_round_trip_through_hooks(
        findings in vec((finding(), vec(location(), 0..4)), 0..4),
    ) {
        let findings: Vec<Finding<Flow>> = findings
            .into_iter()
            .map(|(finding, steps)| finding.with_ext(Flow { steps }))
            .collect();
        let log = through_json(&write(&findings, &Options::default()));
        prop_assert_eq!(read::<Flow>(&log), findings);
    }

    #[test]
    fn without_details_the_core_identity_survives(findings in vec(finding(), 0..6)) {
        let log = through_json(&write(&findings, &Options::default().with_details(false)));
        let back = read::<()>(&log);
        prop_assert_eq!(back.len(), findings.len());
        for (back, original) in back.iter().zip(&findings) {
            prop_assert_eq!(&back.check_id, &original.check_id);
            prop_assert_eq!(&back.title, &original.title);
            prop_assert_eq!(back.severity, original.severity);
            prop_assert_eq!(back.confidence, original.confidence);
            prop_assert_eq!(&back.taxonomy, &original.taxonomy);
        }
    }

    /// GitHub needs a rule id; everything else the writer produces passes.
    #[test]
    fn github_never_rejects_written_logs(
        findings in vec(finding().prop_filter("blank check id", |f| !f.check_id.trim().is_empty()), 0..6),
    ) {
        let log = write(&findings, &Options::default());
        prop_assert!(github::accepts(&log), "{:#?}", github::check(&log));
    }

    #[test]
    fn parsing_never_panics(text in "\\PC{0,64}") {
        if let Ok(log) = Log::from_json(&text) {
            let _ = read::<Imported>(&log);
            let _ = github::check(&log);
        }
    }

    /// Reading arbitrary (but well-formed) SARIF, writing the findings and
    /// reading again gives the same findings.
    #[test]
    fn reading_is_stable_under_rewrite(
        rule_id in option::of(text()),
        message in option::of(text()),
        level in option::of(proptest::sample::select(vec!["none", "note", "warning", "error"])),
        uri in option::of(text()),
        line in option::of(small()),
        security_severity in option::of(prop_oneof![text(), "[0-9]{1,2}\\.[0-9]"]),
        tags in vec(prop_oneof![text(), "CWE-[0-9]{1,4}(: [a-z ]{0,8})?", "OWASP-A0[0-9]:20[0-9]{2}( - [a-z]{0,6})?", "external/cwe/cwe-0[0-9]{2}"], 0..4),
    ) {
        let mut result = serde_json::json!({ "message": {} });
        if let Some(rule_id) = rule_id { result["ruleId"] = rule_id.into(); }
        if let Some(message) = message { result["message"]["text"] = message.into(); }
        if let Some(level) = level { result["level"] = level.into(); }
        if let Some(uri) = uri {
            let mut physical = serde_json::json!({ "artifactLocation": { "uri": uri } });
            if let Some(line) = line { physical["region"] = serde_json::json!({ "startLine": line }); }
            result["locations"] = serde_json::json!([{ "physicalLocation": physical }]);
        }
        let mut properties = serde_json::json!({ "tags": tags });
        if let Some(score) = security_severity { properties["security-severity"] = score.into(); }
        result["properties"] = properties;
        let log = serde_json::json!({
            "version": "2.1.0",
            "runs": [{ "tool": { "driver": { "name": "t" } }, "results": [result] }],
        });
        let log = Log::from_json(&log.to_string()).unwrap();
        let first = read::<()>(&log);
        let again = read::<()>(&through_json(&write(&first, &Options::default())));
        prop_assert_eq!(again, first);
    }
}

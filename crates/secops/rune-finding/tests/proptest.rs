//! Property tests: serde round trips for every type, a decoder that never
//! panics, and fingerprint invariants.

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rune_finding::{
    Confidence, Cvss, Evidence, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use serde::{Deserialize, Serialize};

fn text() -> impl Strategy<Value = String> {
    "\\PC{0,16}"
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
        // `parse` keeps custom names canonical (never a known name).
        text().prop_map(|name| Taxonomy::parse(&name)),
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

fn location() -> impl Strategy<Value = Location> {
    prop_oneof![
        (text(), any::<u16>()).prop_map(|(host, port)| Location::Network { host, port }),
        (text(), option::of(text())).prop_map(|(url, parameter)| Location::Url { url, parameter }),
        (
            text(),
            option::of(any::<u32>()),
            option::of(any::<u32>()),
            option::of(any::<u32>()),
            option::of(any::<u32>()),
            option::of(any::<u64>()),
            option::of(any::<u64>()),
            option::of(text()),
        )
            .prop_map(
                |(
                    path,
                    start_line,
                    end_line,
                    start_column,
                    end_column,
                    start_byte,
                    end_byte,
                    snippet,
                )| Location::File {
                    path,
                    start_line,
                    end_line,
                    start_column,
                    end_column,
                    start_byte,
                    end_byte,
                    snippet,
                }
            ),
        (text(), text(), text()).prop_map(|(namespace, kind, name)| Location::ClusterObject {
            namespace,
            kind,
            name
        }),
        (text(), option::of(any::<u64>()))
            .prop_map(|(path, offset)| Location::artifact(path, offset)),
    ]
}

fn cvss() -> impl Strategy<Value = Cvss> {
    // Real scores have one decimal; JSON round-trips those exactly.
    (text(), 0_u8..=100).prop_map(|(vector, tenths)| Cvss::new(vector, f64::from(tenths) / 10.0))
}

fn finding() -> impl Strategy<Value = Finding> {
    (
        (text(), text(), severity(), confidence(), location()),
        vec(
            (text(), text()).prop_map(|(l, s)| Evidence::new(l, s)),
            0..3,
        ),
        option::of(
            (text(), vec(text(), 0..3))
                .prop_map(|(summary, refs)| Remediation::new(summary).with_references(refs)),
        ),
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
                        .with_evidence(evidence)
                        .with_taxonomy(taxonomy)
                        .with_remediation_refs(refs);
                finding.remediation = remediation;
                finding.cvss = cvss;
                finding
            },
        )
}

/// An extension with the usual member shapes, flattened into the finding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_seen_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trail: Option<Vec<Location>>,
}

fn ext() -> impl Strategy<Value = Ext> {
    (
        vec(text(), 0..3),
        option::of(any::<u64>()),
        option::of(vec(location(), 0..3)),
    )
        .prop_map(|(steps, first_seen_unix_ms, trail)| Ext {
            steps,
            first_seen_unix_ms,
            trail,
        })
}

proptest! {
    #[test]
    fn finding_round_trips(finding in finding()) {
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&back, &finding);
        prop_assert_eq!(back.fingerprint(), finding.fingerprint());
    }

    #[test]
    fn extended_finding_round_trips(finding in finding(), ext in ext()) {
        let finding = finding.with_ext(ext);
        let json = serde_json::to_value(&finding).unwrap();
        let back: Finding<Ext> = serde_json::from_value(json.clone()).unwrap();
        prop_assert_eq!(&back, &finding);
        // The extension's members are flattened, and a plain reader of the
        // same JSON sees the same core finding.
        let core: Finding = serde_json::from_value(json).unwrap();
        prop_assert_eq!(core, finding.into_parts().0);
    }

    #[test]
    fn parts_round_trip(location in location(), severity in severity(), taxonomy in taxonomy_ref()) {
        let json = serde_json::to_string(&location).unwrap();
        prop_assert_eq!(serde_json::from_str::<Location>(&json).unwrap(), location);
        let json = serde_json::to_string(&severity).unwrap();
        prop_assert_eq!(serde_json::from_str::<Severity>(&json).unwrap(), severity);
        prop_assert_eq!(severity.as_str().parse::<Severity>().unwrap(), severity);
        let json = serde_json::to_string(&taxonomy).unwrap();
        prop_assert_eq!(serde_json::from_str::<TaxonomyRef>(&json).unwrap(), taxonomy);
    }

    #[test]
    fn decoding_arbitrary_text_never_panics(text in "\\PC{0,256}") {
        let _ = serde_json::from_str::<Finding>(&text);
        let _ = serde_json::from_str::<Finding<Ext>>(&text);
        let _ = serde_json::from_str::<Location>(&text);
        let _ = text.parse::<Severity>();
        let _ = text.parse::<Confidence>();
        let _ = TaxonomyRef::owasp(text.clone()).framework;
        let _ = TaxonomyRef::new(Taxonomy::Cwe, text).cwe_number();
    }

    #[test]
    fn fingerprint_never_panics_and_is_hex(check_id in text(), url in "\\PC{0,64}") {
        let finding: Finding =
            Finding::new(check_id, "t", Severity::Low, Confidence::Firm, Location::url(url));
        let fingerprint = finding.fingerprint();
        prop_assert_eq!(fingerprint.len(), 64);
        prop_assert!(fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn fingerprint_ignores_query_order_values_and_ids(
        keys in vec("[a-z]{1,6}", 1..5),
        values in vec("[a-z0-9]{0,6}", 5),
        ids in (any::<u32>(), any::<u32>()),
    ) {
        let query = |order: &[String], values: &[String]| {
            order
                .iter()
                .zip(values.iter().cycle())
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("&")
        };
        let mut reversed = keys.clone();
        reversed.reverse();
        let mut shifted = values.clone();
        shifted.rotate_left(1);
        let at = |url: String| -> Finding {
            Finding::new("idor", "t", Severity::High, Confidence::Firm, Location::url(url))
        };
        let one = at(format!("https://a.test/u/{}/x?{}", ids.0, query(&keys, &values)));
        let two = at(format!("HTTPS://A.TEST:443/u/{}/x/?{}#f", ids.1, query(&reversed, &shifted)));
        prop_assert_eq!(one.fingerprint(), two.fingerprint());
    }
}

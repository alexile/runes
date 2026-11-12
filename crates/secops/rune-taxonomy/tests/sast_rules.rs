//! Every CWE and OWASP tag on a SAST tool's bundled rules resolves strictly
//! against the embedded datasets.
//!
//! The tags are a snapshot of the tool's rule files in
//! `fixtures/sast-tool-rules.tsv`.

use rune_finding::{Taxonomy, TaxonomyRef};
use rune_taxonomy::{Entry, Error, resolve, resolve_id};

const RULES: &str = include_str!("fixtures/sast-tool-rules.tsv");

/// `(file, rule id, cwe, owasp)`, with `-` for an absent field.
fn rules() -> Vec<[&'static str; 4]> {
    RULES
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "malformed fixture line {line:?}");
            [fields[0], fields[1], fields[2], fields[3]]
        })
        .collect()
}

#[test]
fn every_sast_tool_tag_resolves() {
    let rules = rules();
    assert!(rules.len() > 100, "fixture looks truncated");
    let mut failures = Vec::new();
    for [file, rule, cwe, owasp] in rules {
        if cwe != "-" {
            match resolve_id(&Taxonomy::Cwe, cwe) {
                Ok(Entry::Cwe(entry)) => assert_eq!(entry.id.to_string(), cwe),
                Ok(other) => failures.push(format!("{file} {rule}: {cwe} resolved to {other:?}")),
                Err(err) => failures.push(format!("{file} {rule}: {err}")),
            }
        }
        if owasp != "-" {
            // The tool's `owasp` field does not say which list it means;
            // `TaxonomyRef::owasp` picks it from the year.
            if let Err(err) = resolve(&TaxonomyRef::owasp(owasp)) {
                failures.push(format!("{file} {rule}: {err}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "unresolved tags:\n{}",
        failures.join("\n")
    );
}

#[test]
fn sast_tool_style_mistakes_are_rejected() {
    // A SAST tool may write `Some("")` for a rule without a CWE or OWASP tag.
    assert!(matches!(
        resolve_id(&Taxonomy::Cwe, ""),
        Err(Error::Empty { .. })
    ));
    assert!(matches!(
        resolve(&TaxonomyRef::owasp("")),
        Err(Error::Empty { .. })
    ));
    for typo in ["CWE-79 ", " CWE-79", "cwe-79", "CWE79", "CWE-079"] {
        assert!(
            matches!(
                resolve_id(&Taxonomy::Cwe, typo),
                Err(Error::Malformed { .. })
            ),
            "{typo:?}"
        );
    }
    for typo in ["A3:2021", "A03:2021 ", "A03", "A03:2017"] {
        assert!(resolve(&TaxonomyRef::owasp(typo)).is_err(), "{typo:?}");
    }
}

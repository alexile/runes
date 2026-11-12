//! Properties of deduplication and tracking over small, collision-prone
//! finding sets.

use std::collections::BTreeSet;

use proptest::prelude::*;
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
use rune_finding_dedupe::{Options, Scan, Strategy as By, Tracker, dedupe};

fn severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Informational),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn finding() -> impl Strategy<Value = Finding> {
    (
        0..3_u8,
        0..3_u8,
        1..4_u32,
        proptest::option::of(1..4_u32),
        severity(),
    )
        .prop_map(|(check, file, line, cwe, severity)| {
            let finding = Finding::<()>::new(
                format!("check{check}"),
                "t",
                severity,
                Confidence::Firm,
                Location::file(format!("f{file}")).with_lines(line, line),
            );
            match cwe {
                Some(cwe) => finding.push_taxonomy(TaxonomyRef::cwe(cwe)),
                None => finding,
            }
        })
}

fn strategy() -> impl Strategy<Value = By> {
    prop_oneof![Just(By::Fingerprint), Just(By::FingerprintOrCwe)]
}

/// The partition of fingerprints into groups.
fn partition(groups: &[rune_finding_dedupe::Group]) -> BTreeSet<BTreeSet<String>> {
    groups.iter().map(|g| g.fingerprints.clone()).collect()
}

proptest! {
    #[test]
    fn every_finding_lands_in_exactly_one_group(
        findings in prop::collection::vec(finding(), 0..24),
        strategy in strategy(),
    ) {
        let groups = dedupe(findings.clone(), &strategy, &Options::default());
        prop_assert_eq!(groups.iter().map(|g| g.count).sum::<usize>(), findings.len());

        // Groups share no key, and same fingerprint means same group.
        let mut keys = BTreeSet::new();
        for group in &groups {
            for key in &group.keys {
                prop_assert!(keys.insert(key.clone()), "key {key} in two groups");
            }
        }
        for finding in &findings {
            let fp = finding.fingerprint();
            prop_assert_eq!(groups.iter().filter(|g| g.fingerprints.contains(&fp)).count(), 1);
        }
        // The merged finding is one of its members' fingerprints, at the
        // highest severity among them.
        for group in &groups {
            prop_assert!(group.fingerprints.contains(&group.finding.fingerprint()));
            let max = findings
                .iter()
                .filter(|f| group.fingerprints.contains(&f.fingerprint()))
                .map(|f| f.severity)
                .max();
            prop_assert_eq!(Some(group.finding.severity), max);
        }
    }

    #[test]
    fn grouping_ignores_input_order(
        (findings, shuffled) in prop::collection::vec(finding(), 0..24)
            .prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle())),
        strategy in strategy(),
    ) {
        let a = dedupe(findings, &strategy, &Options::default());
        let b = dedupe(shuffled, &strategy, &Options::default());
        prop_assert_eq!(partition(&a), partition(&b));
    }

    #[test]
    fn fingerprint_dedupe_is_idempotent(findings in prop::collection::vec(finding(), 0..24)) {
        let once = dedupe(findings, &By::Fingerprint, &Options::default());
        let twice = dedupe(
            once.iter().map(|g| g.finding.clone()),
            &By::Fingerprint,
            &Options::default(),
        );
        prop_assert_eq!(partition(&once), partition(&twice));
    }

    #[test]
    fn rescanning_the_same_findings_changes_nothing(
        findings in prop::collection::vec(finding(), 0..24),
        strategy in strategy(),
    ) {
        let mut tracker = Tracker::default();
        let first = tracker.observe(&Scan::new("t", 1), findings.clone(), &strategy);
        let groups = dedupe(findings.clone(), &strategy, &Options::default());
        prop_assert_eq!(first.new.len(), groups.len());
        prop_assert!(first.merged.is_empty());

        let second = tracker.observe(&Scan::new("t", 2), findings, &strategy);
        prop_assert!(second.new.is_empty());
        prop_assert!(second.fixed.is_empty());
        prop_assert!(second.merged.is_empty());
        prop_assert_eq!(second.recurring, first.new);
        prop_assert_eq!(tracker.open_issues().count(), groups.len());
    }

    #[test]
    fn identities_survive_any_scan_sequence(
        scans in prop::collection::vec(prop::collection::vec(finding(), 0..8), 1..6),
        strategy in strategy(),
    ) {
        let mut tracker = Tracker::default();
        let mut ever = BTreeSet::new();
        for (at, findings) in (1_u64..).zip(scans) {
            let report = tracker.observe(&Scan::new("t", at), findings.clone(), &strategy);
            ever.extend(report.new.iter().cloned());
            // Every finding of the scan now maps to an open issue whose id
            // was handed out as new at some point.
            for finding in &findings {
                let issue = tracker.issue_for(finding, &strategy);
                prop_assert!(issue.is_some());
                if let Some(issue) = issue {
                    prop_assert!(ever.contains(&issue.id));
                    prop_assert_eq!(issue.last_seen_unix_ms, at);
                }
            }
        }
        // Every id ever issued still resolves to a live issue.
        for id in &ever {
            prop_assert!(tracker.issue(id).is_some());
        }
    }
}

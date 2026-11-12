//! Integrity and known-answer tests for the generated datasets.

use std::collections::BTreeSet;

use rune_finding::Taxonomy;
use rune_taxonomy::{
    AsvsId, AsvsKind, AsvsVersion, AttackId, CWE_TOP25_YEAR, CapecAbstraction, CapecId, CapecKind,
    CweAbstraction, CweId, CweKind, Entry, Error, OwaspId, OwaspList, asvs, asvs_for_cwe,
    asvs_items, attack_for_capec, attack_for_cwe, capec, capec_for_cwe, capecs, cwe, cwe_top25,
    cwes, owasp, owasp_for_cwe, owasp_list, resolve_id, revoked_technique, sources, tactic,
    tactics, technique, techniques,
};

fn strictly_sorted<T: Ord + std::fmt::Debug>(ids: impl Iterator<Item = T>) {
    let ids: Vec<T> = ids.collect();
    for pair in ids.windows(2) {
        assert!(
            pair[0] < pair[1],
            "not sorted: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

fn clean(text: &str) -> bool {
    !text.is_empty() && text.trim() == text && !text.contains("  ") && !text.contains('\n')
}

#[test]
fn tables_are_sorted_for_binary_search() {
    strictly_sorted(cwes().iter().map(|e| e.id));
    strictly_sorted(capecs().iter().map(|e| e.id));
    strictly_sorted(techniques().iter().map(|e| e.id));
    for version in AsvsVersion::ALL {
        strictly_sorted(asvs_items(version).iter().map(|e| e.id));
    }
    for list in OwaspList::ALL {
        let ranks: Vec<u8> = owasp_list(list).iter().map(|c| c.id.rank()).collect();
        assert_eq!(ranks, (1..=10).collect::<Vec<_>>(), "{list:?}");
        assert!(owasp_list(list).iter().all(|c| c.id.list() == list));
    }
}

#[test]
fn every_reference_resolves() {
    for entry in cwes() {
        assert!(clean(entry.name), "{}: {:?}", entry.id, entry.name);
        assert_eq!(cwe(entry.id), Some(entry));
        assert!(
            entry.parents().count() == entry.parents.len(),
            "{}",
            entry.id
        );
        assert!(entry.capecs().count() == entry.capec.len(), "{}", entry.id);
        assert!(
            entry.owasp_categories().count() == entry.owasp.len(),
            "{}",
            entry.id
        );
        assert_eq!(
            entry.abstraction.is_some(),
            entry.kind == CweKind::Weakness,
            "{}",
            entry.id
        );
        for capec_id in entry.capec {
            let pattern = capec(*capec_id).unwrap();
            assert!(
                pattern.cwes.contains(&entry.id),
                "{} <-> {capec_id}",
                entry.id
            );
        }
        for owasp_id in entry.owasp {
            assert!(owasp(*owasp_id).unwrap().cwes.contains(&entry.id));
        }
    }
    for entry in capecs() {
        assert!(clean(entry.name), "{}: {:?}", entry.id, entry.name);
        assert_eq!(entry.parents().count(), entry.parents.len(), "{}", entry.id);
        assert_eq!(entry.weaknesses().count(), entry.cwes.len(), "{}", entry.id);
        assert_eq!(
            entry.techniques().count(),
            entry.attack.len(),
            "{}",
            entry.id
        );
        for cwe_id in entry.cwes {
            assert!(cwe(*cwe_id).unwrap().capec.contains(&entry.id));
        }
        for attack_id in entry.attack {
            assert!(technique(*attack_id).unwrap().capec.contains(&entry.id));
        }
    }
    let tactic_ids: BTreeSet<&str> = tactics().iter().map(|t| t.id).collect();
    for entry in techniques() {
        assert!(clean(entry.name), "{}: {:?}", entry.id, entry.name);
        assert!(
            !entry.tactics.is_empty() || entry.deprecated,
            "{} has no tactic",
            entry.id
        );
        assert!(entry.tactics.iter().all(|t| tactic_ids.contains(t.id)));
        assert_eq!(entry.capecs().count(), entry.capec.len());
        if entry.id.is_subtechnique() {
            assert!(entry.parent().is_some(), "{} has no parent", entry.id);
        }
    }
    for list in OwaspList::ALL {
        for category in owasp_list(list) {
            assert!(clean(category.name));
            assert_eq!(category.weaknesses().count(), category.cwes.len());
        }
    }
    for version in AsvsVersion::ALL {
        for item in asvs_items(version) {
            assert_eq!(item.version, version);
            assert_eq!(
                item.name.is_some(),
                item.id.kind() != AsvsKind::Requirement,
                "{}",
                item.id
            );
            assert!(item.name.is_none_or(clean));
            assert!(
                item.chapter().is_some()
                    && (item.id.kind() == AsvsKind::Chapter || item.section().is_some())
            );
            assert!(item.cwes.iter().all(|id| cwe(*id).is_some()));
            assert!(item.level.is_none_or(|level| (1..=3).contains(&level)));
        }
    }
}

#[test]
fn dataset_shape() {
    assert_eq!(cwe_top25().count(), 25);
    assert_eq!(CWE_TOP25_YEAR, 2025);
    assert!(cwes().len() > 1300, "{}", cwes().len());
    assert!(capecs().len() > 600, "{}", capecs().len());
    assert!(techniques().len() > 600, "{}", techniques().len());
    assert_eq!(tactics().len(), 15);
    let chapters = |version| {
        asvs_items(version)
            .iter()
            .filter(|item| item.id.kind() == AsvsKind::Chapter)
            .count()
    };
    assert_eq!(chapters(AsvsVersion::V4), 14);
    assert_eq!(chapters(AsvsVersion::V5), 17);
    let requirements = |version| {
        asvs_items(version)
            .iter()
            .filter(|item| item.id.kind() == AsvsKind::Requirement)
            .count()
    };
    assert_eq!(requirements(AsvsVersion::V4), 286);
    assert_eq!(requirements(AsvsVersion::V5), 345);
}

#[test]
fn known_answers() {
    let xss = cwe(79).unwrap();
    assert_eq!(xss.kind, CweKind::Weakness);
    assert_eq!(xss.abstraction, Some(CweAbstraction::Base));
    assert_eq!(xss.parents, [CweId::new(74)]);
    assert!(
        xss.description
            .starts_with("The product does not neutralize")
    );
    let xss_owasp: Vec<String> = owasp_for_cwe(79).map(|c| c.id.to_string()).collect();
    assert_eq!(xss_owasp, ["A03:2021", "A05:2025"]);
    assert!(capec_for_cwe(79).any(|p| p.id == CapecId::new(63)));
    assert_eq!(cwe(1000).unwrap().kind, CweKind::View);
    let a01 = cwe(1345).unwrap();
    assert_eq!(a01.kind, CweKind::Category);
    assert!(a01.name.contains("A01:2021"));
    assert_eq!(cwe(707).unwrap().abstraction, Some(CweAbstraction::Pillar));
    assert_eq!(cwe(707).unwrap().parents, []);
    assert!(
        cwe(707)
            .unwrap()
            .children()
            .any(|child| child.id == CweId::new(74))
    );

    let api: Vec<String> = owasp_for_cwe(918).map(|c| c.id.to_string()).collect();
    assert_eq!(api, ["A10:2021", "A01:2025", "API7:2023"]);
    assert_eq!(
        owasp(OwaspId::new(OwaspList::Top10_2025, 3).unwrap())
            .unwrap()
            .name,
        "Software Supply Chain Failures"
    );
    assert_eq!(
        owasp(OwaspId::new(OwaspList::Api2023, 1).unwrap())
            .unwrap()
            .name,
        "Broken Object Level Authorization"
    );

    let sqli = capec(66).unwrap();
    assert_eq!(sqli.kind, CapecKind::AttackPattern);
    assert_eq!(sqli.abstraction, Some(CapecAbstraction::Standard));
    assert!(sqli.parents().any(|p| p.id == CapecId::new(248)));
    assert!(attack_for_capec(17).any(|t| t.id == AttackId::subtechnique(1574, 10)));

    let exploit = technique(AttackId::technique(1190)).unwrap();
    assert_eq!(exploit.tactics, [tactic("initial-access").unwrap()]);
    assert_eq!(tactic("TA0001").unwrap().name, "Initial Access");
    assert_eq!(exploit.url(), "https://attack.mitre.org/techniques/T1190/");
    let js = technique(AttackId::subtechnique(1059, 7)).unwrap();
    assert_eq!(js.name, "JavaScript");
    assert_eq!(
        js.parent().unwrap().name,
        "Command and Scripting Interpreter"
    );
    assert_eq!(js.url(), "https://attack.mitre.org/techniques/T1059/007/");
    assert_eq!(
        revoked_technique(AttackId::technique(1086)),
        Some(AttackId::subtechnique(1059, 1))
    );
    assert!(
        attack_for_cwe(89)
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    );

    let chapter = asvs(AsvsVersion::V5, AsvsId::chapter(1)).unwrap();
    assert_eq!(chapter.name, Some("Encoding and Sanitization"));
    assert!(asvs_for_cwe(89).any(|item| item.id == AsvsId::requirement(5, 3, 4)));
}

#[test]
fn resolution_errors() {
    assert!(matches!(
        resolve_id(&Taxonomy::Attack, "T1086"),
        Err(Error::Revoked { replaced_by, .. }) if replaced_by == "T1059.001"
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::Attack, "T9999"),
        Err(Error::Unknown { .. })
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::Capec, "CAPEC-66"),
        Ok(Entry::Capec(_))
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::Asvs4, "V5.3.4"),
        Ok(Entry::Asvs(_))
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::Asvs5, "V5.3.40"),
        Err(Error::Unknown { .. })
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::OwaspApi2023, "API1:2023"),
        Ok(Entry::Owasp(_))
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::PciDss4, "6.2.4"),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        resolve_id(&Taxonomy::Custom("acme".into()), "R-1"),
        Err(Error::Unsupported(_))
    ));
    let entry = resolve_id(&Taxonomy::OwaspTop10_2025, "A05:2025").unwrap();
    assert_eq!(entry.taxonomy(), Taxonomy::OwaspTop10_2025);
    let reference = entry.to_taxonomy_ref();
    assert_eq!(
        (reference.id.as_str(), reference.name.as_deref()),
        ("A05:2025", Some("Injection"))
    );
    let requirement = resolve_id(&Taxonomy::Asvs4, "V5.3.4").unwrap();
    assert_eq!(requirement.name(), None);
    assert_eq!(requirement.to_taxonomy_ref().name, None);
}

#[test]
fn sources_match_the_pinned_manifest() {
    let manifest = include_str!("../data/sources.toml");
    assert_eq!(sources().len(), 7);
    for source in sources() {
        assert!(
            manifest.contains(&format!(
                "[{}]\nversion = \"{}\"",
                source.dataset, source.version
            )),
            "{}",
            source.dataset
        );
        for file in source.files {
            assert!(
                manifest.contains(&format!(
                    "{{ url = \"{}\", sha256 = \"{}\" }}",
                    file.url, file.sha256
                )),
                "{} is not pinned as generated",
                file.url
            );
        }
    }
}

#[cfg(feature = "serde")]
#[test]
fn records_serialize() {
    let json = serde_json::to_value(technique(AttackId::technique(1190)).unwrap()).unwrap();
    assert_eq!(json["id"], "T1190");
    assert_eq!(json["tactics"][0]["id"], "TA0001");
    let json = serde_json::to_value(cwe(79).unwrap()).unwrap();
    assert_eq!(json["kind"], "weakness");
    assert_eq!(json["owasp"][0], "A03:2021");
    assert_eq!(json["status"], "stable");
}

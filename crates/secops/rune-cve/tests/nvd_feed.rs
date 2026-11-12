//! Parses a small NVD CVE API 2.0 page and matches products against it.

use rune_cve::{Attribute, Cpe, CveIndex, Error, MetricType, NvdFeed, Part};

const PAGE: &[u8] = include_bytes!("fixtures/nvd_page.json");

#[allow(clippy::unwrap_used, reason = "test helper: the fixture is valid")]
fn index() -> CveIndex {
    CveIndex::new(NvdFeed::from_json(PAGE).unwrap().into_cves())
}

fn ids(index: &CveIndex, target: &Cpe) -> Vec<String> {
    index
        .lookup(target)
        .iter()
        .map(|c| c.id.to_string())
        .collect()
}

#[test]
fn parses_the_page() {
    let feed = NvdFeed::from_json(PAGE).unwrap();
    assert_eq!(feed.total_results, 5);
    assert_eq!(feed.format.as_deref(), Some("NVD_CVE"));
    let cves = feed.into_cves();
    assert_eq!(cves.len(), 5);

    let log4shell = &cves[0];
    assert_eq!(log4shell.id.to_string(), "CVE-2021-44228");
    assert!(
        log4shell
            .description("EN")
            .unwrap()
            .starts_with("Apache Log4j2")
    );
    assert!(log4shell.description("es").is_some());
    assert!(log4shell.is_known_exploited());
    assert_eq!(log4shell.cwes(), [400, 502, 917]);
    assert_eq!(log4shell.metrics.all().count(), 2);
    assert_eq!(log4shell.configurations[0].criteria().count(), 5);
    assert_eq!(
        log4shell.references[0].tags,
        ["Release Notes", "Vendor Advisory"]
    );
}

#[test]
fn log4j_ranges() {
    let index = index();
    let log4j = |v: &str| Cpe::new(Part::Application, "apache", "log4j").with_version(v);
    for affected in ["2.0.1", "2.3.0", "2.4", "2.11.2", "2.12.1", "2.14.1"] {
        assert_eq!(
            ids(&index, &log4j(affected)),
            ["CVE-2021-44228"],
            "{affected}"
        );
    }
    for fixed in ["1.2.17", "2.3.1", "2.12.2", "2.12.4", "2.15.0", "2.17.1"] {
        assert_eq!(ids(&index, &log4j(fixed)), Vec::<String>::new(), "{fixed}");
    }
    // Literal criteria: 2.0 with update NA, 2.0 with update beta9.
    let ga = log4j("2.0").with(Attribute::Update, rune_cve::Component::Na);
    assert_eq!(ids(&index, &ga), ["CVE-2021-44228"]);
    let beta9: Cpe = "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"
        .parse()
        .unwrap();
    assert_eq!(ids(&index, &beta9), ["CVE-2021-44228"]);
    // A version-less target never meets a ranged criterion.
    let unknown = Cpe::new(Part::Application, "apache", "log4j");
    assert_eq!(ids(&index, &unknown), Vec::<String>::new());
}

#[test]
fn openssl_letter_releases() {
    let index = index();
    let ossl = |v: &str| Cpe::new(Part::Application, "openssl", "openssl").with_version(v);
    for v in ["1.0.1", "1.0.1a", "1.0.1f"] {
        assert_eq!(ids(&index, &ossl(v)), ["CVE-2014-0160"], "{v}");
    }
    for v in ["1.0.0t", "1.0.1g", "1.0.2", "3.0.0"] {
        assert_eq!(ids(&index, &ossl(v)), Vec::<String>::new(), "{v}");
    }
}

#[test]
fn and_configurations_need_the_platform() {
    let index = index();
    let agent: Cpe = "cpe:2.3:a:example:agent:2.5".parse().unwrap();
    let windows: Cpe = "cpe:2.3:o:microsoft:windows:-".parse().unwrap();
    let linux: Cpe = "cpe:2.3:o:linux:linux_kernel:6.1".parse().unwrap();

    // Product-only lookup ignores the platform; the rejected duplicate is
    // left out.
    assert_eq!(ids(&index, &agent), ["CVE-2099-0001"]);

    let cve = index.get(&"CVE-2099-0001".parse().unwrap()).unwrap();
    assert!(cve.applies_to(&[agent.clone(), windows.clone()]));
    assert!(!cve.applies_to(&[agent.clone(), linux.clone()]));
    assert!(!cve.applies_to(std::slice::from_ref(&windows)));

    let found: Vec<_> = index
        .lookup_platform(&[agent.clone(), windows])
        .iter()
        .map(|c| c.id.to_string())
        .collect();
    assert_eq!(found, ["CVE-2099-0001"]);
    assert_eq!(index.lookup_platform(&[agent, linux]).len(), 0);
}

#[test]
fn wildcard_criteria() {
    let index = index();
    let any_product: Cpe = "cpe:2.3:a:example:widget:1.4".parse().unwrap();
    assert_eq!(ids(&index, &any_product), ["CVE-2099-0003"]);
    let newer: Cpe = "cpe:2.3:a:example:widget:2.0".parse().unwrap();
    assert_eq!(ids(&index, &newer), Vec::<String>::new());
}

#[test]
fn metrics_and_findings() {
    let index = index();
    let get = |id: &str| index.get(&id.parse().unwrap()).unwrap();

    // NVD's v3.1 is preferred over the CNA's v4.0.
    let agent = get("CVE-2099-0001");
    let preferred = agent.metrics.preferred().unwrap();
    assert_eq!(preferred.kind, MetricType::Primary);
    assert_eq!(preferred.cvss_data.version, "3.1");
    assert_eq!(preferred.vector().unwrap().base_score().to_string(), "7.8");
    let v4 = &agent.metrics.cvss_v40[0];
    assert_eq!(v4.vector().unwrap().score().to_string(), "8.5");
    assert_eq!(agent.cwes(), Vec::<u32>::new());

    let log4shell = get("CVE-2021-44228");
    assert!(matches!(
        log4shell.metrics.cvss_v2[0].vector(),
        Err(Error::UnsupportedCvssVersion(_))
    ));
    let finding = log4shell.to_finding(rune_finding::Location::file("pom.xml"));
    assert_eq!(finding.severity, rune_finding::Severity::Critical);
    assert_eq!(
        finding.title,
        "CVE-2021-44228: Apache Log4j2 Remote Code Execution Vulnerability"
    );
    assert_eq!(finding.taxonomy.len(), 3);
    assert_eq!(finding.cvss.as_ref().unwrap().base_score, 10.0);
    assert_eq!(finding.remediation_refs.len(), 1);

    // Unscored records default to Medium.
    let pending = get("CVE-2099-0003");
    assert_eq!(pending.severity(), None);
    let finding = pending.to_finding(rune_finding::Location::file("x"));
    assert_eq!(finding.severity, rune_finding::Severity::Medium);
    assert!(finding.cvss.is_none());
}

#[test]
fn serializes_back_to_the_same_records() {
    let feed = NvdFeed::from_json(PAGE).unwrap();
    let json = serde_json::to_vec(&feed).unwrap();
    assert_eq!(NvdFeed::from_json(&json).unwrap(), feed);
}

#[test]
fn rejects_invalid_records() {
    assert!(NvdFeed::from_json(b"{").is_err());
    assert!(NvdFeed::from_json(br#"{"vulnerabilities": [{"cve": {"id": "nope"}}]}"#).is_err());
    let bad_cpe = br#"{"vulnerabilities": [{"cve": {"id": "CVE-2020-0001", "configurations": [
        {"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:q:x"}]}]}]}}]}"#;
    assert!(NvdFeed::from_json(bad_cpe).is_err());
    // Empty object: an empty page.
    assert_eq!(NvdFeed::from_json(b"{}").unwrap().vulnerabilities.len(), 0);
}

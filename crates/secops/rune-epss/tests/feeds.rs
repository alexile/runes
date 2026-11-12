//! Parses small EPSS and KEV snapshots and joins them by CVE id.

use rune_cve::CveId;
use rune_epss::{Date, EpssSnapshot, KevCatalog, RiskIndex};

const EPSS: &[u8] = include_bytes!("fixtures/epss_scores.csv");
const KEV: &[u8] = include_bytes!("fixtures/kev.json");

#[allow(clippy::unwrap_used, reason = "test helper: ids are literals")]
fn id(s: &str) -> CveId {
    s.parse().unwrap()
}

#[allow(clippy::unwrap_used, reason = "test helper: the fixtures are valid")]
fn index() -> RiskIndex {
    RiskIndex::new(
        EpssSnapshot::from_csv(EPSS).unwrap(),
        KevCatalog::from_json(KEV).unwrap(),
    )
}

#[test]
fn parses_the_fixtures() {
    let index = index();
    assert_eq!(index.epss.len(), 6);
    assert_eq!(index.epss.model_version.as_deref(), Some("v2025.03.14"));
    assert_eq!(index.epss.score_date, Date::new(2025, 11, 11));
    assert_eq!(index.kev.len(), 3);
    assert_eq!(index.kev.catalog_version, "2025.11.10");
    let webp = index.kev.get(&id("CVE-2023-4863")).unwrap();
    assert_eq!(webp.product, "Chromium WebP");
    assert_eq!(webp.cwe_numbers(), [787]);
    assert!(!webp.is_ransomware_known());
    assert!(webp.notes.starts_with("https://nvd.nist.gov/"));
    let recent: Vec<_> = index
        .kev
        .added_since(Date::new(2022, 1, 1).unwrap())
        .map(|e| e.cve_id.to_string())
        .collect();
    assert_eq!(recent, ["CVE-2014-0160", "CVE-2023-4863"]);
}

#[test]
fn lookups_return_epss_and_kev() {
    let index = index();
    let log4shell = index.lookup(&id("CVE-2021-44228"));
    assert!(log4shell.is_known_exploited());
    assert_eq!(log4shell.probability(), Some(0.94358));
    assert_eq!(log4shell.epss.unwrap().percentile, 0.99957);

    let xz = index.lookup(&id("CVE-2024-3094"));
    assert!(!xz.is_known_exploited());
    assert_eq!(xz.probability(), Some(0.84321));

    let unknown = index.lookup(&id("CVE-2099-0001"));
    assert_eq!((unknown.epss, unknown.kev), (None, None));
}

#[test]
fn ranks_for_prioritization() {
    let index = index();
    let order: Vec<String> = index
        .rank(
            [
                "CVE-2025-0001",
                "CVE-2099-0001",
                "CVE-2024-3094",
                "CVE-2023-4863",
                "CVE-2014-0160",
                "CVE-2021-44228",
            ]
            .map(id),
        )
        .iter()
        .map(|r| r.cve.to_string())
        .collect();
    assert_eq!(
        order,
        [
            // KEV, ransomware
            "CVE-2021-44228",
            // KEV, by EPSS
            "CVE-2014-0160",
            "CVE-2023-4863",
            // by EPSS
            "CVE-2024-3094",
            "CVE-2025-0001",
            // unscored
            "CVE-2099-0001",
        ]
    );
}

#[test]
fn offline_snapshot_round_trips() {
    let index = index();
    let epss = EpssSnapshot::from_csv(index.epss.to_csv().as_bytes()).unwrap();
    let kev = KevCatalog::from_json(index.kev.to_json().as_bytes()).unwrap();
    assert_eq!(RiskIndex::new(epss, kev), index);
}

#[test]
fn joins_nvd_records() {
    let feed = rune_cve::NvdFeed::from_json(
        br#"{"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}, {"cve": {"id": "CVE-2024-3094"}}]}"#,
    )
    .unwrap();
    let index = index();
    let kev: Vec<bool> = feed
        .into_cves()
        .iter()
        .map(|c| index.for_cve(c).is_known_exploited())
        .collect();
    assert_eq!(kev, [true, false]);
}

#[test]
fn gzip_feed() {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(EPSS).unwrap();
    let gz = enc.finish().unwrap();
    #[cfg(feature = "gzip")]
    assert_eq!(
        EpssSnapshot::from_csv_gz(&gz, 1 << 20).unwrap(),
        EpssSnapshot::from_csv(EPSS).unwrap()
    );
    // Without the feature, the compressed bytes are not CSV.
    #[cfg(not(feature = "gzip"))]
    assert!(EpssSnapshot::from_csv(&gz).is_err());
}

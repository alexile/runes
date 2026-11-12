# rune-epss

> EPSS exploit-probability scores and the CISA KEV catalog, parsed from their feeds and joined by CVE id

[![crates.io](https://img.shields.io/crates/v/rune-epss)](https://crates.io/crates/rune-epss)
[![docs.rs](https://img.shields.io/docsrs/rune-epss)](https://docs.rs/rune-epss)
[![license](https://img.shields.io/crates/l/rune-epss)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Which of your CVEs are being exploited, or likely to be? Two public feeds
answer that:

- **EPSS** ([FIRST](https://www.first.org/epss/)): a daily probability,
  per CVE, of exploitation in the next 30 days, with its percentile.
  `EpssSnapshot` parses the daily CSV (`epss_scores-current.csv.gz`, plain
  or gzip-compressed with the `gzip` feature) and EPSS API responses.
- **KEV** ([CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)):
  CVEs known to be exploited in the wild, with remediation due dates and
  known ransomware use. `KevCatalog` parses
  `known_exploited_vulnerabilities.json`.

`RiskIndex` joins both by CVE id: `lookup` returns the EPSS score and the
KEV entry of a CVE, and `rank` orders a list of CVEs by urgency (KEV with
known ransomware use, other KEV, then by EPSS probability, unscored last).
CVE ids are [`rune-cve`](../rune-cve) `CveId`s, so results join directly
with NVD records.

**Offline snapshots**: `EpssSnapshot::to_csv` and `KevCatalog::to_json`
write the feeds back in their original formats, so a snapshot saved once
reloads later with the same parsers and no network.

The core is sans-I/O. With the `fetch` feature, `fetch::fetch_kev`,
`fetch::fetch_epss_csv` and `fetch::fetch_epss_api` download the feeds
over an HTTP client the caller supplies (any `Fn(&str, &[(&str, &str)])
-> Result<Vec<u8>, _>`); the crate pulls in no HTTP stack.

## Installation

```toml
[dependencies]
rune-epss = { version = "0.1", features = ["gzip"] }
```

## Usage

```rust
use rune_epss::{EpssSnapshot, KevCatalog, RiskIndex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let epss = EpssSnapshot::from_csv_gz(&std::fs::read("epss_scores-current.csv.gz")?, 256 << 20)?;
    let kev = KevCatalog::from_json(&std::fs::read("known_exploited_vulnerabilities.json")?)?;
    let index = RiskIndex::new(epss, kev);

    let findings = ["CVE-2024-3094", "CVE-2021-44228", "CVE-2023-4863"];
    for risk in index.rank(findings.map(|id| id.parse().unwrap())) {
        println!(
            "{} kev={} epss={:?}",
            risk.cve,
            risk.is_known_exploited(),
            risk.probability(),
        );
    }

    // Save an offline snapshot.
    std::fs::write("epss.csv", index.epss.to_csv())?;
    std::fs::write("kev.json", index.kev.to_json())?;
    Ok(())
}
```

Refreshing with your own HTTP client (feature `fetch`):

```rust
use rune_epss::fetch::{EPSS_CURRENT_CSV_GZ, KEV_JSON, TransportError, fetch_epss_csv, fetch_kev};
use rune_epss::RiskIndex;

fn refresh(
    get: impl Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, TransportError>,
) -> Result<RiskIndex, rune_epss::Error> {
    // `get` wraps ureq, reqwest::blocking, ...: it errors on non-2xx.
    Ok(RiskIndex::new(
        fetch_epss_csv(&get, EPSS_CURRENT_CSV_GZ)?,
        fetch_kev(&get, KEV_JSON)?,
    ))
}
```

## License

MIT

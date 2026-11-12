# rune-cve

> CVE and NVD 2.0 record model with CPE 2.3 parsing and version-range matching

[![crates.io](https://img.shields.io/crates/v/rune-cve)](https://crates.io/crates/rune-cve)
[![docs.rs](https://img.shields.io/docsrs/rune-cve)](https://docs.rs/rune-cve)
[![license](https://img.shields.io/crates/l/rune-cve)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Maps a detected product and version to the CVEs that affect it, using the
data the [NVD](https://nvd.nist.gov/) publishes.

- **`CveId`**: validated `CVE-YYYY-NNNN` ids, ordered numerically.
- **`Cpe`**: CPE names from the CPE 2.3 formatted string
  (`cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`) or the CPE 2.2 URI that
  scanners such as nmap print (`cpe:/a:apache:log4j:2.14.1`), with
  [NISTIR 7696](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf)
  name matching, ANY/NA and `*`/`?` wildcards.
- **`compare_versions`** and **`VersionRange`**: tolerant version ordering
  for NVD's `versionStart…`/`versionEnd…` bounds: `1.10 > 1.9`,
  `2.0 == 2.0.0`, `2.0-rc1 < 2.0`, `1.0.1g > 1.0.1`.
- **`Cve`** and **`NvdFeed`**: the
  [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
  record model, parsed from API pages and the `nvdcve-2.0-*.json` feeds:
  descriptions, CVSS v2/v3.0/v3.1/v4.0 metrics, CWEs, references, CISA KEV
  fields and configuration trees of CPE match criteria. Records serialize
  back to the same JSON shape.
- **Matching**: `Cve::affects(&cpe)` for one product; `Cve::applies_to(&[cpe])`
  evaluates `AND`/`OR` configurations ("log4j on any OS", "agent < 3.0
  running on Windows") against a whole platform. `CveIndex` indexes
  records by id and product.
- **Shared model**: CVSS vectors parse and score with
  [`rune-cvss`](../rune-cvss); `Cve::to_finding` builds a
  [`rune-finding`](../rune-finding) `Finding` with severity, CVSS and CWE
  taxonomy.

The core is sans-I/O. With the `fetch` feature, `fetch::NvdQuery` builds
NVD API requests and `fetch::fetch_all` pages through a result over an
HTTP client the caller supplies (any `Fn(&str, &[(&str, &str)]) ->
Result<Vec<u8>, _>`); the crate pulls in no HTTP stack.

## Installation

```toml
[dependencies]
rune-cve = "0.1"
```

The `rune-cve` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-cve --features cli
```

## Usage

### Library

```rust
use rune_cve::{Cpe, CveIndex, NvdFeed, Part};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read("nvdcve-2.0-2021.json")?;
    let index = CveIndex::new(NvdFeed::from_json(&json)?.into_cves());

    let log4j = Cpe::new(Part::Application, "apache", "log4j").with_version("2.14.1");
    for cve in index.lookup(&log4j) {
        println!("{} {:?} KEV={}", cve.id, cve.severity(), cve.is_known_exploited());
    }
    Ok(())
}
```

Fetching from the NVD API with your own HTTP client (feature `fetch`):

```rust
use rune_cve::fetch::{NvdQuery, TransportError, fetch_all};

fn changed_this_month(
    get: impl Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, TransportError>,
) -> Result<Vec<rune_cve::Cve>, rune_cve::Error> {
    // `get` wraps your HTTP client (ureq, reqwest::blocking, ...): it sends
    // the headers, errors on non-2xx and paces requests for NVD's limits.
    let query = NvdQuery::default()
        .with_last_modified("2026-11-01T00:00:00.000", "2026-11-12T00:00:00.000");
    fetch_all(&get, &query, Some("my-api-key"))
}
```

### CLI

```bash
rune-cve cpe:2.3:a:apache:log4j:2.14.1 nvdcve-2.0-2021.json
# CVE-2021-44228	10.0 KEV
# CVE-2021-45046	9.0 KEV
```

## Version comparison

Versions split into runs of digits and letters; other characters only
separate. Numbers compare numerically, the shorter version is padded with
zeros, pre-release words (`dev`, `snapshot`, `nightly`, `alpha`, `beta`,
`milestone`, `ea`, `pre`, `preview`, `cr`, `rc`) sort before zero, and other
words sort between zero and one, so OpenSSL letter releases and `p1`
patch levels come after their base version. The order is a total
preorder, which the property tests check.

## License

MIT

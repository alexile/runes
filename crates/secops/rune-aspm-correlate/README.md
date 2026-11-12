# rune-aspm-correlate

> ASPM correlation: ingest external SARIF and DAST findings, correlate SAST and DAST into one risk view with provenance

[![crates.io](https://img.shields.io/crates/v/rune-aspm-correlate)](https://crates.io/crates/rune-aspm-correlate)
[![docs.rs](https://img.shields.io/docsrs/rune-aspm-correlate)](https://docs.rs/rune-aspm-correlate)
[![license](https://img.shields.io/crates/l/rune-aspm-correlate)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

SAST tools report files and lines; DAST tools report URLs and parameters.
This crate puts both into one risk view, where an issue that a SAST tool
finds in the code and a DAST scanner exploits on the running site appears once,
marked **confirmed**, with every original report kept.

- **`Batch`** ingests SARIF 2.1.0 logs through
  [`rune-sarif`](../rune-sarif) (CodeQL, Semgrep, Trivy,
  Gitleaks, ZAP, …) and native [`rune-finding`](../rune-finding) findings
  (from a DAST scanner). Each finding gets a `Provenance` extension with one `Source`:
  tool, `Kind` (SAST, DAST, SCA, secrets, IaC), check id, title, severity,
  location, CWEs, fingerprint, SARIF `partialFingerprints`, and the
  code-flow and related locations of a SAST result.
- **`correlate`** merges duplicates with
  [`rune-finding-dedupe`](../rune-finding-dedupe): same fingerprint, same
  SARIF partial fingerprint from the same tool and check, or the same CWE
  at the same location. Then SAST and DAST issues meet on **`Route`s**: a
  DAST URL that matches a route pattern (`/users/{id}`) and a SAST result
  in the route's handler file (or whose taint flow passes through it),
  with the same CWE class, are one issue. CWE classes such as XSS
  (79/80/83/87) or SQL injection (89/564) are configurable.
- **`Report`** lists `RiskIssue`s by severity, then `Corroboration`
  (`Confirmed` > `MultiTool` > `Single`), then confidence. Suppressed SARIF
  results are dropped and counted unless `Options::keep_suppressed`.
- **`Correlator`** implements `rune_finding_dedupe::Correlate`, so the
  report's findings feed a `Tracker` for stable issue identity across runs.

Two SAST results on one route never merge just because they share it, nor
do two DAST results: only a SAST–DAST pair that agrees on route and CWE
class links issues.

The crate is sans-I/O: no files, no network, no clock.

## Installation

```toml
[dependencies]
rune-aspm-correlate = "0.1"
```

The `serde` feature serializes provenance, routes, options and reports, and
adds `Report::to_sarif`. The command-line tool is behind the opt-in `cli`
feature:

```bash
cargo install rune-aspm-correlate --features cli
```

## Usage

### Library

```rust
use rune_aspm_correlate::{Batch, Corroboration, Options, Route};
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};

let mut batch = Batch::new();
batch.add_sarif_json(&std::fs::read_to_string("sast-tool.sarif")?)?;
batch.add_findings("dast-scanner", [Finding::<()>::new(
    "sqli.boolean", "Boolean-based SQL injection", Severity::Critical, Confidence::Certain,
    Location::url("https://shop.test/users/7").with_parameter("id"),
)
.push_taxonomy(TaxonomyRef::cwe(89))]);

let options = Options::default()
    .with_route(Route::new("/users/{id}", "src/users.py")?.with_lines(1, 60));
let report = batch.correlate(&options);

for issue in report.confirmed() {
    println!("{} {:?}", issue.finding.title, issue.tools());
}
```

### Command line

```bash
rune-aspm-correlate \
  --sarif sast-tool.sarif --sarif semgrep.sarif \
  --findings dast-scanner=dast-findings.json \
  --routes routes.json \
  > risk.json

# Or as SARIF, each result listing its original reports in `aspmSources`.
rune-aspm-correlate --sarif sast-tool.sarif --findings dast-scanner=dast.json \
  --route '/users/{id}=src/users.py' --output-sarif
```

`routes.json` is an array of
`{"pattern": "/users/{id}", "file": "src/users.py", "name"?: "...", "host"?: "...", "lines"?: [1, 60]}`.
`--findings` files are JSON arrays of `rune-finding` findings.

## Correlation keys

- `fp:<fingerprint>`: the fingerprint of every source in the issue.
- `sarif:<hex>` (v1): lowercase hex SHA-256 of
  `"rune-aspm-correlate/sarif-partial/v1" US tool US check_id US name US value`
  for each SARIF partial fingerprint other than rune-sarif's own copy of
  the fingerprint.
- `cwe:<hex>`: rune-finding-dedupe's CWE-at-location key.
- `route:<route name>#CWE-<class>`: on issues holding both a SAST and a
  DAST source of that link.

## License

MIT

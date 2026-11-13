# rune-finding-dedupe

> Cross-scan finding deduplication and correlation: merge findings by fingerprint and track stable issue identity over time

[![crates.io](https://img.shields.io/crates/v/rune-finding-dedupe)](https://crates.io/crates/rune-finding-dedupe)
[![docs.rs](https://img.shields.io/docsrs/rune-finding-dedupe)](https://docs.rs/rune-finding-dedupe)
[![license](https://img.shields.io/crates/l/rune-finding-dedupe)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Scanners report the same issue many times: twice in one run, again in every
nightly scan, and once more from each tool that covers it. This crate turns
[`rune-finding`](../rune-finding) findings into issues with one identity for
life.

- **`dedupe`** merges the duplicates in a batch into `Group`s. Findings are
  the same issue when they share a `Key`: always the same
  `Finding::fingerprint` (check id plus normalized location), plus any keys
  a `Correlate` implementation adds. Sharing is transitive.
- **`Strategy`**: `Fingerprint` (the default), or `FingerprintOrCwe`, which
  also matches the same CWE at the same location, so CodeQL's and
  Semgrep's SQL injection rules on one line become one issue.
- **`merge`**: the higher severity and confidence win; evidence,
  taxonomy references and remediation links are unioned, each up to a
  bound in `Options` (32, 64 and 32 by default; since 0.1.1 the last two
  are bounded too, which only matters when merging hundreds of
  duplicates with different classifications); the higher CVSS
  score is kept; extensions merge through `Correlate::merge_ext`.
- **`Tracker`** follows issues across `Scan`s. Each issue keeps the
  `IssueId` it was first seen under; each scan returns a `ScanReport` of
  new, recurring, reopened, fixed and merged issues. An issue is fixed only
  when every tool that reported it has run a complete scan without it, and
  partial scans never fix anything. When a finding links two known issues,
  the younger id becomes an alias of the older (`Tracker::resolve`).

The crate is sans-I/O: no clock, no files, no global state. With the
`serde` feature the tracker, reports and groups serialize, so identity
survives restarts; restoring checks that the state is consistent.

## Installation

```toml
[dependencies]
rune-finding-dedupe = { version = "0.1", features = ["serde"] }
```

## Usage

```rust
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
use rune_finding_dedupe::{Options, Scan, Strategy, Tracker};

let sqli = |rule: &str, line: u32| -> Finding {
    Finding::<()>::new(rule, "SQL injection", Severity::High, Confidence::Firm,
        Location::file("app.py").with_lines(line, line))
    .push_taxonomy(TaxonomyRef::cwe(89))
};
let strategy = Strategy::FingerprintOrCwe;
let mut tracker = Tracker::new(Options::default());

let monday = tracker.observe(&Scan::new("codeql", 1), [sqli("py/sql-injection", 42)], &strategy);
let tuesday = tracker.observe(&Scan::new("semgrep", 2), [sqli("python.sqli", 42)], &strategy);
assert_eq!(tuesday.recurring, monday.new); // same issue, other tool

// Gone from both tools' complete scans: fixed.
tracker.observe(&Scan::new("codeql", 3), [], &strategy);
let thursday = tracker.observe(&Scan::new("semgrep", 4), [], &strategy);
assert_eq!(thursday.fixed, monday.new);
```

Custom keys, such as a SARIF `partialFingerprints` entry or a CVE in a
package, come from implementing `Correlate` for your own type and
delegating to a `Strategy` for the rest.

## Key algorithms

- `fp:<fingerprint>`: `Finding::fingerprint`, as `rune-finding` defines it.
- `cwe:<hex>` (`FingerprintOrCwe`, v1): lowercase hex SHA-256 of
  `"rune-finding-dedupe/cwe/v1" US "CWE-<n>" US <location digest>`, where
  `US` is `0x1F` and the location digest is the fingerprint of the
  location with an empty check id. One key per distinct CWE number.

Both are versioned and pinned by golden tests, so stored identities stay
valid.

## License

MIT

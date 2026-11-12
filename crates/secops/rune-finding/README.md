# rune-finding

> Shared security finding model: Finding, Severity, Confidence, Location, Evidence and taxonomy references, with a stable fingerprint

[![crates.io](https://img.shields.io/crates/v/rune-finding)](https://crates.io/crates/rune-finding)
[![docs.rs](https://img.shields.io/docsrs/rune-finding)](https://docs.rs/rune-finding)
[![license](https://img.shields.io/crates/l/rune-finding)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One finding model for every security tool: DAST and network scanners,
SAST, secret scanners and binary analysis all report the same `Finding`,
so reports, SARIF output and cross-tool correlation share a single shape.

- **`Severity`** (informational → critical, ordered) with SARIF `level`
  and GitHub `security-severity` mappings, and **`Confidence`**
  (tentative, firm, certain).
- **`Location`**: a URL and parameter, a network endpoint, a file region
  (lines, columns, byte offsets, snippet), a Kubernetes object, or a binary
  artifact at an offset.
- **`TaxonomyRef`**: CWE, CAPEC, ATT&CK, OWASP Top 10 / API Top 10, ASVS,
  PCI DSS, WSTG or a custom taxonomy, in place of loose `cwe`/`owasp`
  strings.
- **`Evidence`**, **`Remediation`** and **`Cvss`**. With the `cvss` feature,
  `Cvss::parse` computes the base score from a CVSS v3.0, v3.1 or v4.0
  vector with [`rune-cvss`](../rune-cvss), and `Cvss::verify` checks a
  supplied score against its vector.
- **`Finding<X>`**: a typed extension slot `X` for product-specific data
  (HTTP exchanges, dataflow paths, AI triage) instead of a string map.
  Extensions that implement the `ext` capability traits (`HasLegacyCwe`,
  `HasExchanges`, `HasProof`, `HasSeenTimes`) give `Finding<X>` builders
  such as `with_cwe` and `push_exchange` as inherent methods.
- **`Finding::fingerprint`**: a versioned SHA-256 of the check id and the
  normalized location, stable across scans, for deduplication.

## Installation

```toml
[dependencies]
rune-finding = { version = "0.1", features = ["serde"] }
```

| Feature | Enables |
| --- | --- |
| `serde` | `Serialize`/`Deserialize` for every type, with a stable JSON shape |
| `schemars` | `JsonSchema` for every type (implies `serde`) |
| `cvss` | Compute and verify `Cvss` scores from the vector with `rune-cvss` |

No feature is on by default.

## Usage

```rust
use rune_finding::{Confidence, Evidence, Finding, Location, Severity, TaxonomyRef};

let finding = Finding::<()>::new(
    "xss.reflected",
    "Reflected XSS",
    Severity::High,
    Confidence::Firm,
    Location::url("https://shop.example.test/search?q=x").with_parameter("q"),
)
.push_taxonomy(TaxonomyRef::cwe(79))
.push_taxonomy(TaxonomyRef::owasp("A03:2021"))
.push_evidence(Evidence::new("reflection", "<script>alert(1)</script>"));

assert_eq!(finding.severity.sarif_level(), "error");
assert_eq!(finding.fingerprint().len(), 64);
```

### Extension slot

Product data goes in `X`. `Finding<X>` dereferences to `X`, and with the
`serde` feature the extension's members are flattened into the finding's
JSON object:

```rust
use rune_finding::{Confidence, Finding, Location, Severity};

#[derive(Debug, Default, Clone, PartialEq)]
struct SastExt {
    dataflow: Vec<Location>,
}

type SastFinding = Finding<SastExt>;

let mut finding = SastFinding::new(
    "python.sqli",
    "SQL injection",
    Severity::High,
    Confidence::Certain,
    Location::file("app.py").with_lines(42, 42),
);
finding.dataflow.push(Location::file("app.py").with_lines(40, 40));
assert_eq!(finding.ext.dataflow.len(), 1);
```

### JSON shape

```json
{
  "check_id": "xss.reflected",
  "title": "Reflected XSS",
  "severity": "high",
  "confidence": "firm",
  "location": {"location_kind": "url", "url": "https://shop.example.test/search?q=x", "parameter": "q"},
  "evidence": [{"label": "reflection", "snippet": "<script>alert(1)</script>"}],
  "taxonomy": [{"framework": "cwe", "id": "CWE-79"}, {"framework": "owasp_top10_2021", "id": "A03:2021"}]
}
```

`remediation`, `taxonomy`, `remediation_refs` and `cvss` are left out when
empty. Each
type's rustdoc documents its part of the shape.

### Fingerprint

`fingerprint()` hashes only the check id and the normalized location
(lowercased host, default port dropped, numeric and UUID path segments
collapsed, query reduced to sorted parameter names, and so on). Title,
severity, evidence and the extension do not count. The algorithm is
versioned (`v1`) and never changes within a version.

## License

MIT

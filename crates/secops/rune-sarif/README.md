# rune-sarif

> SARIF 2.1.0 for security findings: typed log model, writer from rune-finding, reader for CodeQL, Semgrep, Trivy and Gitleaks output, GitHub upload checks

[![crates.io](https://img.shields.io/crates/v/rune-sarif)](https://crates.io/crates/rune-sarif)
[![docs.rs](https://img.shields.io/docsrs/rune-sarif)](https://docs.rs/rune-sarif)
[![license](https://img.shields.io/crates/l/rune-sarif)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One SARIF implementation for security tools. Findings in the
shared [`rune-finding`](../rune-finding) model go out as
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
that GitHub code scanning accepts, and SARIF from any tool comes back in
as findings.

- **`model`**: typed, serde-ready SARIF objects (`Log`, `Run`, `Tool`,
  `ToolComponent`, `ReportingDescriptor`, `Result`, `Location`,
  `PhysicalLocation`, `LogicalLocation`, `CodeFlow`, `ThreadFlow`, `Fix`,
  `WebRequest`, ...). Unknown members are ignored when reading.
- **`write`**: findings to a log. Severity becomes `level` and GitHub's
  `security-severity`, taxonomy references become `taxa` in
  `run.taxonomies` plus `external/cwe/cwe-<n>` tags, the fingerprint goes
  in `partialFingerprints`, and locations become `physicalLocation`s.
- **`read`**: a log to findings, as far as the log allows. Tested on real
  CodeQL, Semgrep, Trivy and Gitleaks output: rules in tool extensions,
  `security-severity` or levels, precision and confidence tags, CWE and
  OWASP tags, Trivy's CVSS properties, code flows. Findings copy text
  from the rule and run many results share, so `read` caps their total
  size (256 MiB by default, `read_with` + `ReadOptions` to change it) and
  a small log cannot build gigabytes of findings.
- **Round trips**: what SARIF has no slot for (evidence, CVSS,
  remediation, ambiguous locations) is kept in property bags, so
  `read(write(findings)) == findings`.
- **Extensions**: `ToSarif` lets a product add to the output (a DAST
  scanner's HTTP exchanges as `webRequest`/`webResponse`, a SAST tool's
  taint paths as `codeFlows`); `FromSarif` fills a product extension when reading.
  `Imported` keeps the tool, fingerprints, code flows and unknown
  properties of third-party results.
- **`github::check`**: the problems GitHub code scanning would have with a
  log (required members, upload limits, `security-severity` format), and
  whether it rejects the upload or only drops part of it.

Written logs are validated in the tests against the official OASIS SARIF
2.1.0 JSON schema.

## Installation

```toml
[dependencies]
rune-sarif = "0.1"
rune-finding = { version = "0.1", features = ["serde"] }
```

With the optional `taxonomy` feature, `Options::with_taxonomy_names(true)`
fills each `taxa` entry's `name` and `shortDescription` from
[rune-taxonomy](https://docs.rs/rune-taxonomy) (CWE, CAPEC, ATT&CK, OWASP,
ASVS).

## Usage

```rust
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
use rune_sarif::{Imported, Log, Options, github, read, write};

fn main() -> Result<(), rune_sarif::Error> {
    let finding = Finding::<()>::new(
        "python.sqli",
        "SQL built from user input",
        Severity::High,
        Confidence::Firm,
        Location::file("src/app.py").with_lines(15, 15),
    )
    .push_taxonomy(TaxonomyRef::cwe(89));

    // Findings to SARIF, ready for GitHub code scanning.
    let options = Options::default()
        .with_tool_name("sast-tool")
        .with_tool_version("0.4.0")
        .with_category("sast/python/");
    let log = write(std::slice::from_ref(&finding), &options);
    assert!(github::accepts(&log));
    let json = log.to_json_pretty()?;

    // SARIF from any tool to findings.
    let imported: Vec<Finding<Imported>> = read(&Log::from_json(&json)?)?;
    assert_eq!(imported[0].tool, "sast-tool");
    assert_eq!(imported[0].clone().into_parts().0, finding);
    Ok(())
}
```

Add product data to the output with a `ToSarif` hook on the extension:

```rust
use rune_finding::{Finding, Location};
use rune_sarif::model::{CodeFlow, ThreadFlowLocation};
use rune_sarif::{ToSarif, location};

#[derive(Default)]
struct SastExt {
    dataflow: Vec<Location>,
}

impl ToSarif for SastExt {
    fn write_result(finding: &Finding<Self>, result: &mut rune_sarif::model::Result) {
        let steps = finding.dataflow.iter().map(location::to_sarif);
        result.code_flows.push(CodeFlow::single(steps.map(ThreadFlowLocation::new)));
    }
}
```

`Options::with_details(false)` writes a leaner shape, without the property
bags that only round trips need.

## License

MIT

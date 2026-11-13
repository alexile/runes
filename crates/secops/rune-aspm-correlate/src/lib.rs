//! Application security posture management (ASPM) correlation: ingest
//! SARIF from SAST and third-party tools alongside DAST findings, and
//! correlate them into one risk view where every issue appears once and
//! keeps the provenance of every report behind it.
//!
//! - [`Batch`] collects findings: SARIF 2.1.0 logs through `rune-sarif`
//!   (`CodeQL`, Semgrep, Trivy, Gitleaks, …) and native
//!   [`rune_finding::Finding`]s (a DAST scanner's findings). Each becomes a
//!   finding whose extension is a [`Provenance`] with one [`Source`]: tool, [`Kind`]
//!   (SAST, DAST, …), check id, location, CWEs, fingerprint, SARIF
//!   partial fingerprints and code-flow locations.
//! - [`correlate`] merges duplicates with `rune-finding-dedupe`, keyed by
//!   the [`Correlator`] (fingerprint, SARIF partial fingerprints, CWE at
//!   location), then joins SAST and DAST issues that meet on a [`Route`]:
//!   the DAST URL matches the route's pattern, the SAST result (or a step
//!   of its taint flow) is in the route's handler file, and both carry the
//!   same CWE class. The [`Report`] lists the [`RiskIssue`]s by severity
//!   and [`Corroboration`]: an issue both a SAST and a DAST tool report is
//!   [confirmed](Corroboration::Confirmed).
//! - [`Correlator`] implements rune-finding-dedupe's `Correlate`, so the
//!   report's findings feed its `Tracker` for stable issue identity across
//!   runs.
//!
//! The crate is sans-I/O: it works on strings, logs and findings.
//!
//! # Features
//!
//! - `serde`: serialize provenance, routes, options and reports, and write
//!   the risk view as SARIF ([`Report::to_sarif`]).
//! - `cli`: the `rune-aspm-correlate` command-line tool.
//!
//! # Example
//!
//! A SAST tool finds SQL injection reached from the users handler; a
//! DAST run exploits it on `/users/{id}`. One confirmed issue comes out.
//!
//! ```
//! use rune_aspm_correlate::{Batch, Corroboration, Kind, Options, Route, correlate};
//! use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
//!
//! // The SAST tool's SARIF output (rune-sarif writes the same shape).
//! let sast = Finding::<()>::new("python.sqli.format", "SQL built with string formatting",
//!     Severity::High, Confidence::Firm, Location::file("src/db.py").with_lines(42, 42))
//!     .push_taxonomy(TaxonomyRef::cwe(89));
//! let mut sarif = rune_sarif::write(&[sast],
//!     &rune_sarif::Options::default().with_tool_name("sast-tool"));
//! // Its taint flow starts in the users handler.
//! sarif.runs[0].results[0].code_flows.push(rune_sarif::model::CodeFlow::single([
//!     rune_sarif::model::ThreadFlowLocation::new(rune_sarif::location::to_sarif(
//!         &Location::file("src/users.py").with_lines(12, 12))),
//! ]));
//!
//! // The DAST scanner's finding.
//! let dast = Finding::<()>::new("sqli.boolean", "Boolean-based SQL injection",
//!     Severity::Critical, Confidence::Certain,
//!     Location::url("https://shop.test/users/7?expand=1").with_parameter("id"))
//!     .push_taxonomy(TaxonomyRef::cwe(89));
//!
//! let mut batch = Batch::new();
//! batch.add_sarif(&sarif)?;
//! batch.add_findings("dast-scanner", [dast]);
//! let options = Options::default()
//!     .with_route(Route::new("/users/{id}", "src/users.py")?.with_lines(1, 60));
//! let report = correlate(batch.into_findings(), &options);
//!
//! assert_eq!(report.issues.len(), 1);
//! let issue = &report.issues[0];
//! assert_eq!(issue.corroboration, Corroboration::Confirmed);
//! assert_eq!(issue.finding.severity, Severity::Critical, "the worse report wins");
//! let tools: Vec<_> = issue.finding.ext.sources.iter().map(|s| (s.kind, s.tool.as_str())).collect();
//! assert_eq!(tools, [(Kind::Sast, "sast-tool"), (Kind::Dast, "dast-scanner")]);
//! # Ok::<(), rune_aspm_correlate::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod correlator;
mod error;
mod ingest;
mod options;
mod provenance;
mod report;
mod route;
#[cfg(feature = "serde")]
pub mod sarif;

pub use correlator::{Correlator, Link};
pub use error::Error;
pub use ingest::Batch;
pub use options::{COMMON_CWE_CLASSES, Options};
pub use provenance::{Kind, Provenance, Source};
pub use report::{Corroboration, Report, RiskIssue, correlate};
pub use route::Route;
pub use rune_finding_dedupe;
pub use rune_sarif;

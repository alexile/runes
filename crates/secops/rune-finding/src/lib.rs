//! Shared security finding model: [`Finding`], [`Severity`], [`Confidence`],
//! [`Location`], [`Evidence`], [`Remediation`], [`Cvss`] and taxonomy
//! references ([`TaxonomyRef`]), with a stable [fingerprint](Finding::fingerprint).
//!
//! Security tools (DAST and network scanners, SAST tools, `rune-leak`)
//! report findings in this one shape, so reports, SARIF output
//! (`rune-sarif`) and cross-tool correlation work on a single model.
//! Product-specific data rides in the typed extension slot of
//! [`Finding<X>`](Finding) rather than in a string map.
//!
//! The crate is plain data plus pure functions: no I/O, no global state.
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for every type, with a stable JSON
//!   shape documented on each type.
//! - `schemars`: `JsonSchema` for every type (implies `serde`).
//! - `cvss`: compute [`Cvss`] base scores from CVSS v3.0, v3.1 and v4.0
//!   vectors with `rune-cvss` ([`Cvss::parse`], [`Cvss::verify`]), and
//!   convert `rune_cvss::Severity` into [`Severity`].
//!
//! # Example
//!
//! ```
//! use rune_finding::{
//!     Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef,
//! };
//!
//! // Product-specific data goes in the extension slot.
//! #[derive(Debug, Default, Clone, PartialEq)]
//! struct SastExt {
//!     dataflow: Vec<Location>,
//! }
//!
//! let finding = Finding::<SastExt>::new(
//!     "python.sqli.format",
//!     "SQL built with string formatting",
//!     Severity::High,
//!     Confidence::Firm,
//!     Location::file("src/app.py").with_lines(42, 42).with_columns(5, 61),
//! )
//! .push_taxonomy(TaxonomyRef::cwe(89))
//! .push_taxonomy(TaxonomyRef::owasp("A03:2021"))
//! .push_evidence(Evidence::new("sink", "cursor.execute(f\"…{uid}\")"))
//! .with_remediation(Remediation::new("Use parameterised queries"));
//!
//! // Extension fields read like the finding's own.
//! assert!(finding.dataflow.is_empty());
//! assert_eq!(finding.severity.sarif_level(), "error");
//!
//! // The fingerprint only depends on the check id and the location, so the
//! // same issue matches across scans even when its wording changes.
//! let mut rescanned = finding.clone();
//! rescanned.title = "SQL injection".into();
//! assert_eq!(rescanned.fingerprint(), finding.fingerprint());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod ext;
mod finding;
mod fingerprint;
mod location;
mod severity;
mod taxonomy;

pub use error::Error;
pub use finding::{Cvss, Evidence, Finding, Remediation};
pub use location::Location;
pub use severity::{Confidence, Severity};
pub use taxonomy::{Taxonomy, TaxonomyRef};

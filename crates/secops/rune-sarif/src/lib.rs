//! [SARIF 2.1.0] for security findings: a typed log [`model`], a writer
//! from [`rune_finding::Finding`]s ([`write()`]), a reader back to findings
//! ([`read`]) that also understands `CodeQL`, Semgrep, Trivy and Gitleaks
//! output, and a check for GitHub code scanning's upload rules
//! ([`github::check`]).
//!
//! - **Writing** maps each finding to a SARIF result and each check id to
//!   a rule: severity to `level` and GitHub's `security-severity`,
//!   taxonomy references to `taxa` in `run.taxonomies` (plus
//!   `external/cwe/cwe-<n>` tags), the fingerprint to
//!   `partialFingerprints`, and the location to a `physicalLocation`
//!   ([`location`]). What SARIF has no slot for goes in property bags, so
//!   a written log reads back to the same findings.
//! - **Reading** maps any SARIF 2.1.0 result to a finding as far as the
//!   log allows. The extension type decides what else to keep:
//!   [`Imported`] keeps the tool, fingerprints, code flows and unknown
//!   properties; `()` keeps nothing.
//! - **Extensions** add to the output through [`ToSarif`] (a DAST scanner
//!   writes its HTTP exchanges as `webRequest`/`webResponse`, a SAST tool
//!   its taint paths as `codeFlows`) and fill themselves through
//!   [`FromSarif`].
//!
//! The crate is sans-I/O: it works on strings and values.
//!
//! # Features
//!
//! - `taxonomy`: [`Options::with_taxonomy_names`], which names and
//!   describes `taxa` from the [`rune_taxonomy`](https://docs.rs/rune-taxonomy)
//!   datasets (CWE, CAPEC, ATT&CK, OWASP, ASVS). Off by default, and the
//!   option is off by default too, so enabling the feature alone does not
//!   change the output.
//!
//! [SARIF 2.1.0]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
//!
//! # Example
//!
//! ```
//! use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
//! use rune_sarif::{Imported, Log, Options, github, read, write};
//!
//! let finding = Finding::<()>::new(
//!     "python.sqli",
//!     "SQL built from user input",
//!     Severity::High,
//!     Confidence::Firm,
//!     Location::file("src/app.py").with_lines(15, 15).with_columns(5, 26),
//! )
//! .push_taxonomy(TaxonomyRef::cwe(89));
//!
//! // Findings to SARIF JSON.
//! let options = Options::default().with_tool_name("sast-tool").with_tool_version("0.4.0");
//! let log = write(std::slice::from_ref(&finding), &options);
//! assert!(github::check(&log).is_empty());
//! let json = log.to_json_pretty()?;
//!
//! // SARIF JSON (from this crate or any other tool) to findings.
//! let log = Log::from_json(&json)?;
//! let back: Vec<Finding<Imported>> = read(&log);
//! assert_eq!(back[0].tool, "sast-tool");
//! let (core, _imported) = back[0].clone().into_parts();
//! assert_eq!(core, finding);
//! # Ok::<(), rune_sarif::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod github;
pub mod location;
pub mod model;
mod read;
mod write;

pub use model::Log;
pub use read::{FromSarif, Imported, ResultContext, Step, read};
pub use rune_finding;
pub use write::{Options, ToSarif, level, write};

/// Property bag keys and fingerprint names the writer uses and the reader
/// understands.
pub mod keys {
    /// `partialFingerprints` key of [`Finding::fingerprint`](rune_finding::Finding::fingerprint).
    pub const FINGERPRINT: &str = "netsecFingerprint/v1";
    /// Result property: the finding's confidence, e.g. `"firm"`.
    pub const CONFIDENCE: &str = "confidence";
    /// Result property: the evidence list (rune-finding JSON shape).
    pub const EVIDENCE: &str = "evidence";
    /// Result property: the CVSS vector and score (rune-finding JSON shape).
    pub const CVSS: &str = "cvss";
    /// Result property: the remediation (rune-finding JSON shape).
    pub const REMEDIATION: &str = "remediation";
    /// Result property: the remediation reference URLs.
    pub const REMEDIATION_REFS: &str = "remediationRefs";
    /// Location property: the original location, when the URI is ambiguous.
    pub const LOCATION: &str = crate::location::LOCATION_PROPERTY;
}

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not JSON, or not shaped like a SARIF log.
    #[error("invalid SARIF: {0}")]
    Json(#[from] serde_json::Error),
    /// The log is not SARIF 2.1.0.
    #[error("unsupported SARIF version `{0}`; expected 2.1.0")]
    UnsupportedVersion(String),
}

impl Log {
    /// Parse a SARIF 2.1.0 log from JSON text.
    ///
    /// Members the [`model`] does not cover are ignored. Nesting deeper
    /// than 128 levels is rejected, so hostile input cannot exhaust the
    /// stack.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        Self::checked(serde_json::from_str(json)?)
    }

    /// Parse a SARIF 2.1.0 log from JSON bytes.
    pub fn from_slice(json: &[u8]) -> Result<Self, Error> {
        Self::checked(serde_json::from_slice(json)?)
    }

    /// Compact JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }

    /// Pretty-printed JSON, two-space indented.
    pub fn to_json_pretty(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn checked(log: Self) -> Result<Self, Error> {
        if log.version == model::VERSION {
            Ok(log)
        } else {
            Err(Error::UnsupportedVersion(log.version))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        let log = Log::from_json(r#"{"version":"2.1.0","runs":[]}"#).unwrap();
        assert_eq!(log.runs.len(), 0);
        assert_eq!(
            Log::from_slice(br#"{"version":"2.1.0","runs":[],"x":1}"#).unwrap(),
            log
        );
        assert!(matches!(
            Log::from_json(r#"{"version":"2.0.0","runs":[]}"#),
            Err(Error::UnsupportedVersion(version)) if version == "2.0.0"
        ));
        assert!(matches!(Log::from_json("{}"), Err(Error::Json(_))));
        assert!(matches!(Log::from_json("[[[[["), Err(Error::Json(_))));
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(Log::from_json(&deep).is_err());
    }

    #[test]
    fn json_output() {
        let log = Log::new();
        assert_eq!(Log::from_json(&log.to_json().unwrap()).unwrap(), log);
        assert!(
            log.to_json_pretty()
                .unwrap()
                .contains("\n  \"version\": \"2.1.0\"")
        );
    }
}

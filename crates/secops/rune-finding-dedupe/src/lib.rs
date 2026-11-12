//! Cross-scan deduplication and correlation of security findings
//! ([`rune_finding::Finding`]), with a stable issue identity over time.
//!
//! Scanners report the same issue many times: twice in one run, again in
//! every nightly scan, and once more from each tool that covers it. This
//! crate turns those reports into issues:
//!
//! - [`dedupe`] merges the duplicates in one batch into [`Group`]s. Two
//!   findings are the same issue when they share a [`Key`]: always the same
//!   [`Finding::fingerprint`](rune_finding::Finding::fingerprint) (check id
//!   and normalized location), plus any keys a [`Correlate`]
//!   implementation adds. [`Strategy::FingerprintOrCwe`] adds "same CWE at
//!   the same location", which correlates tools with different rule ids.
//! - [`merge`] folds a duplicate into the kept finding: highest severity
//!   and confidence win, and evidence, taxonomy and references are unioned.
//! - [`Tracker`] follows issues across [`Scan`]s. Each issue keeps one
//!   [`IssueId`] (the fingerprint it was first seen under) for life; every
//!   scan's [`ScanReport`] lists what is new, recurring, reopened and
//!   fixed. An issue is fixed only when every tool that reported it has run
//!   a complete scan without it.
//!
//! The crate is sans-I/O: no clock, no files, no global state. With the
//! `serde` feature the tracker serializes, so identity survives restarts.
//!
//! # Example
//!
//! ```
//! use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
//! use rune_finding_dedupe::{Options, Scan, Strategy, Tracker};
//!
//! let sqli = |rule: &str, line: u32| -> Finding {
//!     Finding::<()>::new(rule, "SQL injection", Severity::High, Confidence::Firm,
//!         Location::file("app.py").with_lines(line, line))
//!     .push_taxonomy(TaxonomyRef::cwe(89))
//! };
//! let strategy = Strategy::FingerprintOrCwe;
//! let mut tracker = Tracker::new(Options::default());
//!
//! // CodeQL and Semgrep both flag line 42; Semgrep also flags line 7.
//! let monday = tracker.observe(&Scan::new("codeql", 1), [sqli("py/sql-injection", 42)], &strategy);
//! let tuesday = tracker.observe(
//!     &Scan::new("semgrep", 2),
//!     [sqli("python.sqli", 42), sqli("python.sqli", 7)],
//!     &strategy,
//! );
//! assert_eq!(monday.new.len(), 1);
//! assert_eq!(tuesday.recurring, monday.new, "same issue, other tool");
//! assert_eq!(tuesday.new.len(), 1, "line 7 is a distinct issue");
//!
//! // CodeQL no longer sees line 42, but Semgrep still does: still open.
//! let wednesday = tracker.observe(&Scan::new("codeql", 3), [], &strategy);
//! assert!(wednesday.fixed.is_empty());
//! assert_eq!(tracker.open_issues().count(), 2);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod dedupe;
mod error;
mod key;
mod merge;
mod tracker;

pub use dedupe::{Group, dedupe, keys_of};
pub use error::Error;
pub use key::{Correlate, Key, Strategy};
pub use merge::{Options, merge};
pub use tracker::{Issue, IssueId, Scan, ScanReport, Status, Tracker};

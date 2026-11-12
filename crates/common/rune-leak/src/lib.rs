//! Scan source trees and git history for hardcoded secrets, API keys, and
//! credentials.
//!
//! `rune-leak` has two layers over one set of detection helpers:
//!
//! - **The ruleset API**. Rules are data ([`SecretRule`]: id, name, pattern, entropy
//!   threshold, keywords, severity, CWE); [`default_rules`] ships 15 of them
//!   and users add their own, in code or from TOML ([`rules_from_toml`],
//!   `toml` feature). A compiled [`Ruleset`] scans text into
//!   [`SecretMatch`]es that become [`rune_finding::Finding`]s with a
//!   [`Location::File`](rune_finding::Location::File) and a CWE-798
//!   [`TaxonomyRef`](rune_finding::TaxonomyRef). [`run`] scans a working tree
//!   (and optionally git history) into a [`ScanReport`];
//!   [`scan_git_history`] and the sans-I/O [`HistoryScanner`] cover history
//!   alone.
//! - **The simple API**: [`scan_text`], [`scan_file`], [`scan_dir`] and
//!   [`LeakScanner`] classify `rune-regex-sec` categories by entropy into a
//!   [`Leak`] with a crate-local [`Severity`]. [`Leak::to_finding`] bridges to
//!   the finding model.
//!
//! Secrets never reach findings: evidence carries the rule id, a 4-character
//! prefix and the length. Inline base64 images (`data:` URIs), UUIDs and
//! subresource-integrity digests are not reported.
//!
//! # Ruleset API
//!
//! ```rust
//! use rune_finding::Severity;
//! use rune_leak::{Ruleset, SecretRule};
//!
//! let mut rules = Ruleset::builtin();
//! rules.extend([SecretRule::new("acme_token", "ACME API token", r"acme_[0-9a-f]{32}", Severity::High)
//!     .with_keywords(["acme_"])])?;
//!
//! let src = "jwt = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl\"\n\
//!            acme = acme_0123456789abcdef0123456789abcdef\n\
//!            id = 550e8400-e29b-41d4-a716-446655440000\n";
//! let ids: Vec<_> = rules.scan_str(src).iter().map(|m| m.rule.id.as_str()).collect();
//! assert_eq!(ids, ["jwt", "acme_token"]);
//!
//! let findings = rules.findings(src, "src/config.rs");
//! assert_eq!(findings[1].check_id, "secret.acme_token");
//! assert_eq!(findings[1].taxonomy[0].cwe_number(), Some(798));
//! # Ok::<(), rune_leak::Error>(())
//! ```
//!
//! # Simple API
//!
//! ```rust
//! use rune_leak::{scan_text, Severity};
//!
//! let code = r#"
//!     const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abc";
//!     const key = "AKIAIOSFODNN7EXAMPLE";
//! "#;
//!
//! let leaks = scan_text(code);
//! assert!(leaks.iter().any(|l| matches!(l.severity, Severity::Critical)));
//! ```
//!
//! # Git history
//!
//! With [`ScanOptions::scan_git_history`], [`run`] also walks up to
//! [`ScanOptions::max_commits`] commits back from `HEAD`, through the local
//! `git` executable's plumbing commands (no network, no hooks, no discovery
//! above the given path). Each secret is reported once, attributed to the
//! oldest commit in the window that contains it.
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for [`SecretRule`] and
//!   [`ScanReport`].
//! - `toml`: [`rules_from_toml`] (implies `serde`).
//! - `cli`: the `rune-leak` binary.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod detect;
mod error;
mod history;
mod rule;
mod ruleset;
mod scan;
mod simple;

pub use error::Error;
pub use history::{HistoryScanner, scan_git_history};
pub use rule::{CWE_HARDCODED_CREDENTIALS, HIGH_ENTROPY_RULE_ID, SecretRule, default_rules};
pub use ruleset::{DEFAULT_ENTROPY_THRESHOLD, Ruleset, SecretMatch};
pub use scan::{DEFAULT_EXCLUDED_DIRS, ScanOptions, ScanReport, run};
pub use simple::{Leak, LeakScanner, Severity, scan_dir, scan_file, scan_text};

/// Parses user rules from TOML.
///
/// The file is an array of `[[rules]]` tables with the [`SecretRule`] fields. `keywords`, `entropy_threshold`, `severity`
/// (default `"medium"`) and `cwe` (default 798) are optional; unknown keys
/// are rejected.
///
/// ```toml
/// [[rules]]
/// id = "acme_token"
/// name = "ACME API token"
/// pattern = 'acme_([0-9a-f]{32})'
/// keywords = ["acme_"]
/// entropy_threshold = 3.0
/// severity = "high"
/// ```
///
/// The rules are not compiled here; pass them to [`Ruleset::new`] or
/// [`Ruleset::extend`], or set them on [`ScanOptions::rules`].
///
/// # Errors
///
/// [`Error::Toml`] when the text is not valid TOML or does not have this
/// shape.
///
/// # Examples
///
/// ```rust
/// let rules = rune_leak::rules_from_toml(r#"
///     [[rules]]
///     id = "acme_token"
///     name = "ACME API token"
///     pattern = 'acme_[0-9a-f]{32}'
///     severity = "high"
/// "#)?;
/// let ruleset = rune_leak::Ruleset::new(rules)?;
/// assert_eq!(ruleset.scan_str("t = acme_0123456789abcdef0123456789abcdef").len(), 1);
/// # Ok::<(), rune_leak::Error>(())
/// ```
#[cfg(feature = "toml")]
pub fn rules_from_toml(text: &str) -> Result<Vec<SecretRule>, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RuleFile {
        #[serde(default)]
        rules: Vec<SecretRule>,
    }
    toml::from_str::<RuleFile>(text)
        .map(|file| file.rules)
        .map_err(|err| Error::Toml(Box::new(err)))
}

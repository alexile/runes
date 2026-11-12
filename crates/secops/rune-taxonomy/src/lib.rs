//! Security taxonomy reference data: MITRE [CWE], [CAPEC] and [ATT&CK]
//! Enterprise, the OWASP [Top 10] (2021 and 2025), the OWASP [API Security
//! Top 10] 2023 and OWASP [ASVS] 4.0.3 and 5.0.0, embedded as static tables,
//! with typed ids and the mappings between them.
//!
//! - **Typed ids**, parsed strictly: [`CweId`] (`CWE-79`), [`CapecId`]
//!   (`CAPEC-66`), [`AttackId`] (`T1059.007`), [`OwaspId`] (`A03:2021`,
//!   `A05:2025`, `API1:2023`) and [`AsvsId`] (`V5.3.4`). Parsing never trims
//!   or case-folds, so a tag like `"CWE-79 "` or `""` is an error, not a
//!   silent miss.
//! - **Lookups**: [`cwe`], [`capec`], [`technique`], [`owasp`], [`asvs`],
//!   each returning a `&'static` record with names and relations.
//! - **Mappings**: [`owasp_for_cwe`], [`capec_for_cwe`], [`attack_for_cwe`],
//!   [`attack_for_capec`] and [`asvs_for_cwe`]. CWE↔CAPEC and CAPEC↔ATT&CK
//!   links are the union of what both catalogues record.
//! - **`rune-finding` integration**: [`resolve`] checks a
//!   [`TaxonomyRef`](rune_finding::TaxonomyRef) and [`named`] fills in its
//!   name; every record converts with `to_taxonomy_ref`.
//!
//! The data is generated from upstream files pinned
//! by URL and SHA-256 in `data/sources.toml`; [`sources`] reports the
//! versions. No I/O happens at run time.
//!
//! # Example
//!
//! ```
//! use rune_finding::{Taxonomy, TaxonomyRef};
//! use rune_taxonomy::{CweId, Error};
//!
//! // Typed, strictly parsed ids.
//! let id: CweId = "CWE-89".parse()?;
//! let sqli = id.resolve()?;
//! assert!(sqli.name.contains("SQL"));
//!
//! // Mappings across taxonomies.
//! let owasp: Vec<String> = rune_taxonomy::owasp_for_cwe(89).map(|c| c.id.to_string()).collect();
//! assert_eq!(owasp, ["A03:2021", "A05:2025"]);
//! assert!(rune_taxonomy::capec_for_cwe(89).any(|pattern| pattern.name == "SQL Injection"));
//!
//! // Validating free-text tags from a rule file.
//! assert!(rune_taxonomy::resolve_id(&Taxonomy::OwaspTop10_2021, "A03:2021").is_ok());
//! assert!(matches!(
//!     rune_taxonomy::resolve_id(&Taxonomy::Cwe, "CWE-79 "),
//!     Err(Error::Malformed { .. }),
//! ));
//!
//! // Filling in names on rune-finding references.
//! let named = rune_taxonomy::named(&TaxonomyRef::owasp("A01:2025"))?;
//! assert_eq!(named.name.as_deref(), Some("Broken Access Control"));
//! # Ok::<(), Error>(())
//! ```
//!
//! # Features
//!
//! - `serde`: `Serialize` for every record and `Serialize`/`Deserialize` for
//!   the ids (as their canonical strings) and enums.
//! - `cli`: the `rune-taxonomy` binary, which resolves ids given on the
//!   command line.
//!
//! # Data and licences
//!
//! The generated tables take about 1 MiB of source and add a similar amount
//! to a binary that uses them; the crate README lists the size per dataset.
//! CWE, CAPEC and ATT&CK are © The MITRE Corporation and reproduced under
//! MITRE's terms of use. From OWASP material only identifiers, titles,
//! levels and CWE mappings are embedded, with attribution; no prose. See the
//! `NOTICE` file.
//!
//! [CWE]: https://cwe.mitre.org/
//! [CAPEC]: https://capec.mitre.org/
//! [ATT&CK]: https://attack.mitre.org/
//! [Top 10]: https://owasp.org/Top10/
//! [API Security Top 10]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
//! [ASVS]: https://owasp.org/www-project-application-security-verification-standard/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod asvs;
mod attack;
mod capec;
mod cwe;
mod data;
mod error;
mod id;
mod owasp;
mod resolve;

pub use asvs::{AsvsItem, asvs, asvs_for_cwe, asvs_items};
pub use attack::{Tactic, Technique, revoked_technique, tactic, tactics, technique, techniques};
pub use capec::{Capec, CapecAbstraction, CapecKind, Rating, attack_for_capec, capec, capecs};
pub use cwe::{
    CWE_TOP25_YEAR, Cwe, CweAbstraction, CweKind, attack_for_cwe, capec_for_cwe, cwe, cwe_top25,
    cwes, owasp_for_cwe,
};
pub use error::{Error, IdKind};
pub use id::{AsvsId, AsvsKind, AsvsVersion, AttackId, CapecId, CweId, OwaspId, OwaspList};
pub use owasp::{OwaspCategory, owasp, owasp_list};
pub use resolve::{Entry, named, resolve, resolve_id};

/// The maturity of a CWE or CAPEC entry, as MITRE rates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Status {
    /// Stable.
    Stable,
    /// Usable (CAPEC).
    Usable,
    /// Draft.
    Draft,
    /// Incomplete (CWE).
    Incomplete,
    /// Deprecated: kept so old references resolve, but not to be used.
    Deprecated,
    /// Obsolete: superseded, not to be used.
    Obsolete,
}

impl Status {
    /// Whether the entry is deprecated or obsolete.
    #[must_use]
    pub const fn is_deprecated(self) -> bool {
        matches!(self, Self::Deprecated | Self::Obsolete)
    }
}

/// One upstream dataset the embedded data was generated from.
///
/// ```
/// let cwe = rune_taxonomy::source("cwe").unwrap();
/// assert!(cwe.files[0].url.starts_with("https://cwe.mitre.org/"));
/// assert_eq!(cwe.files[0].sha256.len(), 64);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Source {
    /// The dataset key in `data/sources.toml`, e.g. `cwe` or `asvs_4`.
    pub dataset: &'static str,
    /// The upstream version, e.g. `5.0` for CWE or `20.1` for ATT&CK.
    pub version: &'static str,
    /// The files it was generated from.
    pub files: &'static [SourceFile],
}

/// One pinned upstream file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SourceFile {
    /// Where it was downloaded from.
    pub url: &'static str,
    /// Its SHA-256, in lower-case hex.
    pub sha256: &'static str,
}

/// Every upstream dataset, with its version and pinned files.
#[must_use]
pub fn sources() -> &'static [Source] {
    data::sources::SOURCES
}

/// The upstream dataset with this key: `cwe`, `capec`, `attack`,
/// `owasp_top10_2025`, `owasp_api_2023`, `asvs_4` or `asvs_5`. The OWASP Top
/// 10 2021 mapping comes from `cwe`.
#[must_use]
pub fn source(dataset: &str) -> Option<&'static Source> {
    sources().iter().find(|source| source.dataset == dataset)
}

//! CVE records as the [NVD](https://nvd.nist.gov/) publishes them, CPE
//! names, and the matching that maps a detected product and version to
//! the CVEs that affect it.
//!
//! - [`CveId`]: a validated `CVE-YYYY-NNNN` id, ordered numerically.
//! - [`Cpe`]: a CPE name, parsed from the CPE 2.3 formatted string or the
//!   CPE 2.2 URI, with NISTIR 7696 name matching ([`Cpe::matches`]),
//!   including `*` and `?` wildcards.
//! - [`compare_versions`] and [`VersionRange`]: tolerant version ordering
//!   (`1.10 > 1.9`, `2.0-rc1 < 2.0`, `1.1.1k > 1.1.1`) for the
//!   `versionStart…`/`versionEnd…` bounds of NVD criteria.
//! - [`Cve`] and [`NvdFeed`]: the NVD CVE API 2.0 record model, parsed
//!   from API pages and the NVD 2.0 JSON data feeds, with CVSS metrics,
//!   CWEs, references, KEV fields and [`Configuration`] trees of
//!   [`CpeMatch`] criteria. [`Cve::affects`] checks one product;
//!   [`Cve::applies_to`] evaluates `AND`/`OR` configurations against a
//!   whole platform.
//! - [`CveIndex`]: records indexed by id and by vendor and product.
//! - Bridges to the shared security model: CVSS vectors parse with
//!   `rune-cvss` ([`CvssMetric::vector`]), and [`Cve::to_finding`] builds a
//!   `rune_finding::Finding` with severity, CVSS and CWE taxonomy.
//!
//! The core is sans-I/O: it parses bytes the caller read. With the `fetch`
//! feature, [`fetch`] builds NVD API queries and pages through them with a
//! caller-supplied HTTP [`Transport`](fetch::Transport).
//!
//! Specifications: [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities),
//! [NISTIR 7695](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)
//! (CPE 2.3 Naming), [NISTIR 7696](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf)
//! (CPE 2.3 Name Matching).
//!
//! # Features
//!
//! - `fetch`: [`fetch::NvdQuery`] and [`fetch::fetch_all`] over a
//!   caller-supplied transport. No HTTP client is pulled in.
//! - `cli`: the `rune-cve` binary, which matches a CPE against NVD JSON
//!   files.
//!
//! # Example
//!
//! ```
//! use rune_cve::{Cpe, CveIndex, NvdFeed};
//!
//! let feed = NvdFeed::from_json(br#"{"totalResults": 1, "vulnerabilities": [{"cve": {
//!   "id": "CVE-2021-44228",
//!   "vulnStatus": "Analyzed",
//!   "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}],
//!   "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
//!     "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
//!                  "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
//!   "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
//!     "description": [{"lang": "en", "value": "CWE-502"}]}],
//!   "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [{
//!     "vulnerable": true, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
//!     "versionStartIncluding": "2.13.0", "versionEndExcluding": "2.15.0"}]}]}]
//! }}]}"#)?;
//! let index = CveIndex::new(feed.into_cves());
//!
//! // A scanner saw log4j 2.14.1 (CPE 2.2 URI, as nmap reports it).
//! let seen: Cpe = "cpe:/a:apache:log4j:2.14.1".parse()?;
//! let hits = index.lookup(&seen);
//! assert_eq!(hits.len(), 1);
//! let cve = hits[0];
//! assert_eq!(cve.id.to_string(), "CVE-2021-44228");
//! assert_eq!(cve.cwes(), [502]);
//! assert_eq!(cve.severity(), Some(rune_finding::Severity::Critical));
//! assert_eq!(cve.metrics.preferred().unwrap().vector()?.base_score().to_string(), "10.0");
//!
//! // The fixed version is not affected.
//! assert!(index.lookup(&"cpe:/a:apache:log4j:2.15.0".parse()?).is_empty());
//!
//! // Report it in the shared finding model.
//! let finding = cve.to_finding(rune_finding::Location::artifact("lib/log4j-core-2.14.1.jar", None));
//! assert_eq!(finding.check_id, "CVE-2021-44228");
//! assert_eq!(finding.taxonomy[0].cwe_number(), Some(502));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cpe;
mod error;
#[cfg(feature = "fetch")]
pub mod fetch;
mod id;
mod index;
mod nvd;
mod version;

pub use cpe::{Attribute, Component, Cpe, MAX_CPE_LEN, Part, Value};
pub use error::Error;
pub use id::CveId;
pub use index::CveIndex;
pub use nvd::{
    Configuration, CpeMatch, Cve, CveTag, CvssData, CvssMetric, LangString, MetricType, Metrics,
    Node, NvdFeed, Operator, Reference, Vulnerability, Weakness,
};
pub use version::{Bound, VersionRange, compare_versions};

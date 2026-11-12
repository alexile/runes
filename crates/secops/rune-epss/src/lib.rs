//! Exploit intelligence for CVEs: FIRST's [EPSS](https://www.first.org/epss/)
//! probability scores and CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
//! (KEV) catalog, parsed from their feeds and joined by CVE id.
//!
//! - [`EpssSnapshot`]: the daily EPSS CSV (plain or, with the `gzip`
//!   feature, gzip-compressed as FIRST serves it) and EPSS API responses.
//!   [`EpssSnapshot::to_csv`] writes the same CSV back, for offline use.
//! - [`KevCatalog`]: the KEV JSON catalog, with due dates and ransomware
//!   use. [`KevCatalog::to_json`] writes it back in CISA's shape.
//! - [`RiskIndex`]: both, looked up together ([`RiskIndex::lookup`]) and
//!   ranked by urgency ([`RiskIndex::rank`]): KEV with known ransomware
//!   use, other KEV, then by EPSS probability.
//! - [`Date`]: the `YYYY-MM-DD` dates both feeds use.
//!
//! CVE ids are [`rune_cve::CveId`]s, so results join directly with NVD
//! records from `rune-cve`.
//!
//! The core is sans-I/O: it parses bytes the caller read. With the `fetch`
//! feature, [`fetch`] downloads the feeds through the caller's HTTP client
//! (a [`Transport`](rune_cve::fetch::Transport)).
//!
//! # Features
//!
//! - `gzip`: [`EpssSnapshot::from_csv_gz`] for the compressed daily feed
//!   (pure-Rust `flate2`).
//! - `fetch`: [`fetch::fetch_kev`], [`fetch::fetch_epss_csv`] and
//!   [`fetch::fetch_epss_api`] over a caller-supplied transport. Implies
//!   `gzip`.
//!
//! # Example
//!
//! ```
//! use rune_epss::{EpssSnapshot, KevCatalog, RiskIndex};
//!
//! let epss = EpssSnapshot::from_csv(b"#model_version:v2025.03.14,score_date:2025-11-11T00:00:00+0000\n\
//!     cve,epss,percentile\n\
//!     CVE-2021-44228,0.94358,0.99957\n\
//!     CVE-2024-0001,0.00043,0.11000\n")?;
//! let kev = KevCatalog::from_json(br#"{"catalogVersion": "2025.11.10", "count": 1,
//!   "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache",
//!     "product": "Log4j2", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
//!     "knownRansomwareCampaignUse": "Known"}]}"#)?;
//! let index = RiskIndex::new(epss, kev);
//!
//! let risk = index.lookup(&"CVE-2021-44228".parse()?);
//! assert!(risk.is_known_exploited());
//! assert!(risk.kev.unwrap().is_ransomware_known());
//! assert_eq!(risk.epss.unwrap().percentile, 0.99957);
//!
//! // Most urgent first; unscored CVEs last.
//! let ranked = index.rank(["CVE-2024-0001", "CVE-2099-9999", "CVE-2021-44228"]
//!     .map(|id| id.parse().unwrap()));
//! let order: Vec<String> = ranked.iter().map(|r| r.cve.to_string()).collect();
//! assert_eq!(order, ["CVE-2021-44228", "CVE-2024-0001", "CVE-2099-9999"]);
//!
//! // Offline snapshot: write both feeds and read them back.
//! let again = RiskIndex::new(
//!     EpssSnapshot::from_csv(index.epss.to_csv().as_bytes())?,
//!     KevCatalog::from_json(index.kev.to_json().as_bytes())?,
//! );
//! assert_eq!(again, index);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod date;
mod epss;
mod error;
#[cfg(feature = "fetch")]
pub mod fetch;
mod kev;
mod risk;

pub use date::Date;
pub use epss::{EpssScore, EpssSnapshot};
pub use error::Error;
pub use kev::{KevCatalog, KevEntry};
pub use risk::{Risk, RiskIndex};

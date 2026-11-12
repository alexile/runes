//! [`RiskIndex`]: EPSS and KEV joined by CVE id.

use core::cmp::Ordering;

use rune_cve::CveId;

use crate::{EpssScore, EpssSnapshot, KevCatalog, KevEntry};

/// What the exploit-intelligence feeds say about one CVE.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Risk<'a> {
    /// The CVE.
    pub cve: CveId,
    /// Its EPSS score, if scored.
    pub epss: Option<EpssScore>,
    /// Its KEV entry, if it is known to be exploited.
    pub kev: Option<&'a KevEntry>,
}

impl Risk<'_> {
    /// Whether the CVE is in the KEV catalog.
    #[must_use]
    pub const fn is_known_exploited(&self) -> bool {
        self.kev.is_some()
    }

    /// The EPSS probability, or `None` when unscored.
    #[must_use]
    pub fn probability(&self) -> Option<f64> {
        self.epss.map(|s| s.epss)
    }

    /// Orders by urgency, most urgent first: KEV entries known in
    /// ransomware campaigns, other KEV entries, then by EPSS probability
    /// (descending), unscored CVEs last; ties by CVE id.
    ///
    /// Use it with `sort_by`: `risks.sort_by(Risk::urgency)`.
    #[must_use]
    pub fn urgency(&self, other: &Self) -> Ordering {
        let tier = |r: &Self| match r.kev {
            Some(k) if k.is_ransomware_known() => 0,
            Some(_) => 1,
            None => 2,
        };
        tier(self)
            .cmp(&tier(other))
            .then_with(|| {
                // Descending; `None` after every score.
                let p = |r: &Self| r.probability().unwrap_or(-1.0);
                p(other).total_cmp(&p(self))
            })
            .then_with(|| self.cve.cmp(&other.cve))
    }
}

/// EPSS scores and the KEV catalog, looked up together by CVE id.
///
/// Load it from feeds fetched earlier, or from an offline snapshot written
/// with [`EpssSnapshot::to_csv`] and [`KevCatalog::to_json`].
///
/// # Examples
///
/// ```
/// use rune_epss::{EpssSnapshot, KevCatalog, RiskIndex};
///
/// let epss = EpssSnapshot::from_csv(b"cve,epss,percentile\n\
///     CVE-2021-44228,0.94358,0.99957\nCVE-2022-27225,0.00042,0.05436\n")?;
/// let kev = KevCatalog::from_json(br#"{"vulnerabilities": [
///     {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}"#)?;
/// let index = RiskIndex::new(epss, kev);
///
/// let log4shell = index.lookup(&"CVE-2021-44228".parse()?);
/// assert!(log4shell.is_known_exploited());
/// assert_eq!(log4shell.probability(), Some(0.94358));
///
/// let ranked = index.rank(["CVE-2022-27225".parse()?, "CVE-2021-44228".parse()?]);
/// assert_eq!(ranked[0].cve.to_string(), "CVE-2021-44228");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct RiskIndex {
    /// The EPSS scores.
    pub epss: EpssSnapshot,
    /// The KEV catalog.
    pub kev: KevCatalog,
}

impl RiskIndex {
    /// Joins `epss` and `kev`.
    #[must_use]
    pub const fn new(epss: EpssSnapshot, kev: KevCatalog) -> Self {
        Self { epss, kev }
    }

    /// What the feeds say about `cve`.
    #[must_use]
    pub fn lookup(&self, cve: &CveId) -> Risk<'_> {
        Risk {
            cve: *cve,
            epss: self.epss.get(cve),
            kev: self.kev.get(cve),
        }
    }

    /// [`lookup`](Self::lookup) for every CVE, most urgent first (see
    /// [`Risk::urgency`]), without duplicates.
    #[must_use]
    pub fn rank(&self, cves: impl IntoIterator<Item = CveId>) -> Vec<Risk<'_>> {
        let mut out: Vec<Risk<'_>> = cves.into_iter().map(|c| self.lookup(&c)).collect();
        out.sort_by(Risk::urgency);
        out.dedup_by_key(|r| r.cve);
        out
    }

    /// What the feeds say about an NVD record. The record's own CISA fields
    /// (`cisaExploitAdd`) are not consulted; load the catalog for KEV data.
    #[must_use]
    pub fn for_cve<'a>(&'a self, cve: &rune_cve::Cve) -> Risk<'a> {
        self.lookup(&cve.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Date;

    #[test]
    fn ranks_kev_then_epss() {
        let id = |s: &str| s.parse::<CveId>().unwrap();
        let epss = EpssSnapshot::from_csv(
            b"cve,epss,percentile\n\
              CVE-2020-0001,0.9,0.99\n\
              CVE-2020-0002,0.1,0.8\n\
              CVE-2020-0003,0.5,0.9\n\
              CVE-2020-0004,0.01,0.2\n",
        )
        .unwrap();
        let added = Date::new(2024, 1, 1).unwrap();
        let mut ransom = KevEntry::new(id("CVE-2020-0004"), added);
        ransom.known_ransomware_campaign_use = "Known".into();
        let kev = KevCatalog::from_entries(vec![KevEntry::new(id("CVE-2020-0002"), added), ransom]);
        let index = RiskIndex::new(epss, kev);
        let ranked: Vec<String> = index
            .rank(
                ["0005", "0001", "0002", "0003", "0004", "0001"]
                    .map(|n| id(&format!("CVE-2020-{n}"))),
            )
            .iter()
            .map(|r| r.cve.to_string())
            .collect();
        assert_eq!(
            ranked,
            [
                "CVE-2020-0004",
                "CVE-2020-0002",
                "CVE-2020-0001",
                "CVE-2020-0003",
                "CVE-2020-0005"
            ]
        );
        let unknown = index.lookup(&id("CVE-2020-0005"));
        assert!(!unknown.is_known_exploited());
        assert_eq!(unknown.probability(), None);
        let rec = rune_cve::Cve::new(id("CVE-2020-0002"));
        assert!(index.for_cve(&rec).is_known_exploited());
    }
}

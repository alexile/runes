//! [`CveIndex`]: CVE records indexed by id and by product.

use std::collections::{BTreeMap, HashMap};

use crate::{Cpe, Cve, CveId};

/// CVE records indexed by id and by the vendor and product of their
/// criteria, to find the CVEs affecting a product quickly.
///
/// # Examples
///
/// ```
/// use rune_cve::{Cpe, CveIndex, NvdFeed, Part};
///
/// let feed = NvdFeed::from_json(br#"{"vulnerabilities": [{"cve": {
///   "id": "CVE-2021-44228",
///   "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
///     "vulnerable": true,
///     "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
///     "versionStartIncluding": "2.0.1", "versionEndExcluding": "2.12.2"}]}]}]
/// }}]}"#)?;
/// let index = CveIndex::new(feed.into_cves());
///
/// let log4j = |v: &str| Cpe::new(Part::Application, "apache", "log4j").with_version(v);
/// let hits = index.lookup(&log4j("2.11.0"));
/// assert_eq!(hits[0].id.to_string(), "CVE-2021-44228");
/// assert!(index.lookup(&log4j("2.12.2")).is_empty());
/// # Ok::<(), rune_cve::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct CveIndex {
    /// Sorted by id.
    cves: Vec<Cve>,
    by_id: HashMap<CveId, usize>,
    by_product: HashMap<(String, String), Vec<usize>>,
    /// Records with a criterion whose vendor or product is not a literal.
    wildcard: Vec<usize>,
}

impl CveIndex {
    /// Indexes `cves`. When an id appears more than once, the last record
    /// wins (feeds applied oldest first leave the newest data).
    #[must_use]
    pub fn new(cves: impl IntoIterator<Item = Cve>) -> Self {
        let unique: BTreeMap<CveId, Cve> = cves.into_iter().map(|c| (c.id, c)).collect();
        let cves: Vec<Cve> = unique.into_values().collect();
        let mut by_id = HashMap::with_capacity(cves.len());
        let mut by_product: HashMap<(String, String), Vec<usize>> = HashMap::new();
        let mut wildcard = Vec::new();
        for (i, cve) in cves.iter().enumerate() {
            by_id.insert(cve.id, i);
            let mut wild = false;
            for m in cve
                .configurations
                .iter()
                .flat_map(crate::Configuration::criteria)
            {
                match (m.criteria.vendor(), m.criteria.product()) {
                    (Some(v), Some(p)) => {
                        let list = by_product.entry((v.to_owned(), p.to_owned())).or_default();
                        if list.last() != Some(&i) {
                            list.push(i);
                        }
                    }
                    _ => wild = true,
                }
            }
            if wild {
                wildcard.push(i);
            }
        }
        Self {
            cves,
            by_id,
            by_product,
            wildcard,
        }
    }

    /// Number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.cves.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cves.is_empty()
    }

    /// The record for `id`.
    #[must_use]
    pub fn get(&self, id: &CveId) -> Option<&Cve> {
        self.by_id.get(id).map(|&i| &self.cves[i])
    }

    /// Every record, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Cve> {
        self.cves.iter()
    }

    /// The records that [affect](Cve::affects) `target`, in id order.
    /// Rejected records are left out.
    #[must_use]
    pub fn lookup(&self, target: &Cpe) -> Vec<&Cve> {
        let mut candidates: Vec<usize> = match (target.vendor(), target.product()) {
            (Some(v), Some(p)) => self
                .by_product
                .get(&(v.to_owned(), p.to_owned()))
                .into_iter()
                .flatten()
                .chain(&self.wildcard)
                .copied()
                .collect(),
            _ => (0..self.cves.len()).collect(),
        };
        candidates.sort_unstable();
        candidates.dedup();
        candidates
            .into_iter()
            .map(|i| &self.cves[i])
            .filter(|c| !c.is_rejected() && c.affects(target))
            .collect()
    }

    /// The records whose configurations [apply](Cve::applies_to) to a
    /// system made of `platform`, in id order. Rejected records are left
    /// out.
    #[must_use]
    pub fn lookup_platform(&self, platform: &[Cpe]) -> Vec<&Cve> {
        let mut candidates: Vec<usize> = Vec::new();
        for target in platform {
            match (target.vendor(), target.product()) {
                (Some(v), Some(p)) => candidates.extend(
                    self.by_product
                        .get(&(v.to_owned(), p.to_owned()))
                        .into_iter()
                        .flatten(),
                ),
                _ => candidates.extend(0..self.cves.len()),
            }
        }
        candidates.extend(&self.wildcard);
        candidates.sort_unstable();
        candidates.dedup();
        candidates
            .into_iter()
            .map(|i| &self.cves[i])
            .filter(|c| !c.is_rejected() && c.applies_to(platform))
            .collect()
    }
}

impl FromIterator<Cve> for CveIndex {
    fn from_iter<T: IntoIterator<Item = Cve>>(iter: T) -> Self {
        Self::new(iter)
    }
}

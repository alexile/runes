//! The CISA [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
//! catalog.

use std::collections::HashMap;

use rune_cve::CveId;
use serde::{Deserialize, Serialize};

use crate::{Date, Error};

/// The KEV catalog, as CISA publishes it in
/// `known_exploited_vulnerabilities.json`.
///
/// Field names follow CISA's
/// [JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json),
/// so [`to_json`](Self::to_json) writes a file that reads back with
/// [`from_json`](Self::from_json): an offline snapshot of the catalog.
///
/// # Examples
///
/// ```
/// use rune_epss::KevCatalog;
///
/// let kev = KevCatalog::from_json(br#"{
///   "title": "CISA Catalog of Known Exploited Vulnerabilities",
///   "catalogVersion": "2025.11.10", "dateReleased": "2025-11-10T17:00:00.000Z", "count": 1,
///   "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache",
///     "product": "Log4j2", "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
///     "dateAdded": "2021-12-10", "shortDescription": "JNDI lookups.", "requiredAction": "Apply updates.",
///     "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-20"]}]
/// }"#)?;
/// let entry = kev.get(&"CVE-2021-44228".parse()?).unwrap();
/// assert!(entry.is_ransomware_known());
/// assert_eq!(entry.due_date.unwrap().to_string(), "2021-12-24");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", from = "Wire")]
#[non_exhaustive]
pub struct KevCatalog {
    /// The catalog title.
    #[serde(default)]
    pub title: String,
    /// The catalog version, e.g. `2025.11.10`.
    #[serde(default)]
    pub catalog_version: String,
    /// When this version was released (ISO 8601 timestamp).
    #[serde(default)]
    pub date_released: String,
    /// Number of entries, as the file states it.
    #[serde(default)]
    pub count: u64,
    /// The entries, in the file's order. After changing them, call
    /// [`reindex`](Self::reindex) so [`get`](Self::get) sees the change.
    #[serde(default)]
    pub vulnerabilities: Vec<KevEntry>,
    #[serde(skip)]
    by_id: HashMap<CveId, usize>,
}

/// [`KevCatalog`] as it is read, before it is indexed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    #[serde(default)]
    title: String,
    #[serde(default)]
    catalog_version: String,
    #[serde(default)]
    date_released: String,
    #[serde(default)]
    count: u64,
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

impl From<Wire> for KevCatalog {
    fn from(wire: Wire) -> Self {
        let mut catalog = Self {
            title: wire.title,
            catalog_version: wire.catalog_version,
            date_released: wire.date_released,
            count: wire.count,
            vulnerabilities: wire.vulnerabilities,
            by_id: HashMap::new(),
        };
        catalog.reindex();
        catalog
    }
}

/// One KEV entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KevEntry {
    /// The CVE.
    #[serde(rename = "cveID")]
    pub cve_id: CveId,
    /// The vendor or project, e.g. `Apache`.
    #[serde(default)]
    pub vendor_project: String,
    /// The product, e.g. `Log4j2`.
    #[serde(default)]
    pub product: String,
    /// CISA's name for the vulnerability.
    #[serde(default)]
    pub vulnerability_name: String,
    /// When the CVE was added to the catalog.
    pub date_added: Date,
    /// A short description.
    #[serde(default)]
    pub short_description: String,
    /// What to do about it.
    #[serde(default)]
    pub required_action: String,
    /// The remediation deadline for US federal agencies (BOD 22-01).
    #[serde(default)]
    pub due_date: Option<Date>,
    /// `Known` when the CVE is known to be used in ransomware campaigns,
    /// `Unknown` otherwise.
    #[serde(default)]
    pub known_ransomware_campaign_use: String,
    /// Notes and reference URLs, `;`-separated.
    #[serde(default)]
    pub notes: String,
    /// CWE ids, e.g. `CWE-20`.
    #[serde(default)]
    pub cwes: Vec<String>,
}

impl KevEntry {
    /// An entry for `cve_id` added on `date_added`; every other field is
    /// empty.
    #[must_use]
    pub const fn new(cve_id: CveId, date_added: Date) -> Self {
        Self {
            cve_id,
            vendor_project: String::new(),
            product: String::new(),
            vulnerability_name: String::new(),
            date_added,
            short_description: String::new(),
            required_action: String::new(),
            due_date: None,
            known_ransomware_campaign_use: String::new(),
            notes: String::new(),
            cwes: Vec::new(),
        }
    }

    /// Whether the CVE is known to be used in ransomware campaigns.
    #[must_use]
    pub fn is_ransomware_known(&self) -> bool {
        self.known_ransomware_campaign_use
            .trim()
            .eq_ignore_ascii_case("Known")
    }

    /// Whether the due date is before `today`.
    #[must_use]
    pub fn is_overdue(&self, today: Date) -> bool {
        self.due_date.is_some_and(|due| due < today)
    }

    /// The CWE numbers.
    #[must_use]
    pub fn cwe_numbers(&self) -> Vec<u32> {
        self.cwes
            .iter()
            .filter_map(|c| c.trim().strip_prefix("CWE-")?.parse().ok())
            .collect()
    }
}

impl KevCatalog {
    /// Parses the catalog JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the JSON does not fit the schema (including an
    /// invalid CVE id or date).
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(json)?)
    }

    /// A catalog of `entries`.
    #[must_use]
    pub fn from_entries(entries: Vec<KevEntry>) -> Self {
        let mut catalog = Self {
            count: entries.len() as u64,
            vulnerabilities: entries,
            ..Self::default()
        };
        catalog.reindex();
        catalog
    }

    /// Writes the catalog as JSON in CISA's shape.
    #[must_use]
    pub fn to_json(&self) -> String {
        // Plain data with string keys: serialization cannot fail.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Rebuild the lookup index from [`vulnerabilities`](Self::vulnerabilities),
    /// after changing that list directly. Until then, [`get`](Self::get)
    /// may miss entries; it never returns the wrong one.
    ///
    /// # Examples
    ///
    /// ```
    /// use rune_epss::{Date, KevCatalog, KevEntry};
    ///
    /// let id = "CVE-2021-44228".parse()?;
    /// let mut kev = KevCatalog::default();
    /// kev.vulnerabilities.push(KevEntry::new(id, Date::new(2021, 12, 10).unwrap()));
    /// kev.reindex();
    /// assert!(kev.contains(&id));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn reindex(&mut self) {
        self.by_id = self
            .vulnerabilities
            .iter()
            .enumerate()
            .map(|(i, e)| (e.cve_id, i))
            .collect();
    }

    /// The entry for `cve`. When the file lists a CVE twice, the last
    /// entry wins.
    #[must_use]
    pub fn get(&self, cve: &CveId) -> Option<&KevEntry> {
        self.by_id
            .get(cve)
            .and_then(|&i| self.vulnerabilities.get(i))
            .filter(|entry| entry.cve_id == *cve)
    }

    /// Whether `cve` is in the catalog.
    #[must_use]
    pub fn contains(&self, cve: &CveId) -> bool {
        self.get(cve).is_some()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.vulnerabilities.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.vulnerabilities.is_empty()
    }

    /// Entries added on or after `since`, e.g. for an emerging-threat
    /// feed.
    pub fn added_since(&self, since: Date) -> impl Iterator<Item = &KevEntry> {
        self.vulnerabilities
            .iter()
            .filter(move |e| e.date_added >= since)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_and_index() {
        let d = |s: &str| s.parse::<Date>().unwrap();
        let id = |s: &str| s.parse::<CveId>().unwrap();
        let mut a = KevEntry::new(id("CVE-2021-44228"), d("2021-12-10"));
        a.due_date = Some(d("2021-12-24"));
        a.known_ransomware_campaign_use = "Known".into();
        a.cwes = vec!["CWE-20".into(), "CWE-917".into(), "NVD-CWE-Other".into()];
        let b = KevEntry::new(id("CVE-2014-0160"), d("2022-05-04"));
        let kev = KevCatalog::from_entries(vec![a, b]);
        assert_eq!(kev.len(), 2);
        assert_eq!(kev.count, 2);
        let e = kev.get(&id("CVE-2021-44228")).unwrap();
        assert!(e.is_ransomware_known());
        assert!(e.is_overdue(d("2021-12-25")));
        assert!(!e.is_overdue(d("2021-12-24")));
        assert_eq!(e.cwe_numbers(), [20, 917]);
        assert!(
            !kev.get(&id("CVE-2014-0160"))
                .unwrap()
                .is_overdue(d("2030-01-01"))
        );
        assert!(!kev.contains(&id("CVE-2020-0001")));
        assert_eq!(kev.added_since(d("2022-01-01")).count(), 1);

        let again = KevCatalog::from_json(kev.to_json().as_bytes()).unwrap();
        assert_eq!(again, kev);
    }

    // The lookup index sits next to a public entry list: plain serde left
    // it empty, and shrinking the list made `get` index out of bounds.
    #[test]
    fn lookups_survive_serde_and_edits() {
        let id: CveId = "CVE-2021-44228".parse().unwrap();
        let added = Date::new(2021, 12, 10).unwrap();
        let catalog = KevCatalog::from_entries(vec![KevEntry::new(id, added)]);
        let json = serde_json::to_vec(&catalog).unwrap();
        let read: KevCatalog = serde_json::from_slice(&json).unwrap();
        assert!(read.contains(&id));
        assert_eq!(read, catalog);

        let mut edited = catalog;
        edited.vulnerabilities.clear();
        assert_eq!(edited.get(&id), None);
        assert!(!edited.contains(&id));
    }
}

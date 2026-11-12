//! MITRE CWE: weaknesses, categories and views.

use rune_finding::{Taxonomy, TaxonomyRef};

use crate::data;
use crate::{Capec, CapecId, CweId, Error, IdKind, OwaspCategory, OwaspId, Status, Technique};

/// The year of the CWE Top 25 list that [`Cwe::top25`] marks.
pub const CWE_TOP25_YEAR: u16 = data::cwe::TOP25_YEAR;

/// What kind of CWE entry an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CweKind {
    /// A weakness, the kind of entry a finding should map to.
    Weakness,
    /// A category (a "grouping" since CWE 5), such as the OWASP Top 10 2021
    /// categories (CWE-1345 to CWE-1355).
    Category,
    /// A view, such as CWE-1000 "Research Concepts".
    View,
}

/// How abstract a CWE weakness is, from most to least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CweAbstraction {
    /// The most abstract weaknesses, e.g. CWE-707.
    Pillar,
    /// Abstract, independent of language or technology.
    Class,
    /// Specific enough to infer a detection or mitigation method.
    Base,
    /// Tied to a language or technology.
    Variant,
    /// A combination of weaknesses that together make a vulnerability.
    Compound,
}

/// A CWE entry.
///
/// ```
/// let xss = rune_taxonomy::cwe(79).unwrap();
/// assert_eq!(xss.id.to_string(), "CWE-79");
/// assert!(xss.parents().any(|parent| parent.id.get() == 74));
/// assert!(xss.top25);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Cwe {
    /// The id, `CWE-79`.
    pub id: CweId,
    /// Weakness, category or view.
    pub kind: CweKind,
    /// The entry's name.
    pub name: &'static str,
    /// The weakness abstraction; `None` for categories and views.
    pub abstraction: Option<CweAbstraction>,
    /// Maturity of the entry.
    pub status: Status,
    /// The weakness `Description`, the category `Summary` or the view
    /// `Objective`, as one paragraph.
    pub description: &'static str,
    /// `ChildOf` parents in the Research Concepts view (CWE-1000). Empty for
    /// pillars, categories and views.
    pub parents: &'static [CweId],
    /// Related CAPEC attack patterns, as either catalogue records them.
    pub capec: &'static [CapecId],
    /// OWASP Top 10 categories this entry is mapped to, in every list.
    pub owasp: &'static [OwaspId],
    /// Whether the entry is in the CWE Top 25 of [`CWE_TOP25_YEAR`].
    pub top25: bool,
}

impl Cwe {
    /// Parent entries (see [`parents`](Self::parents)).
    pub fn parents(&self) -> impl Iterator<Item = &'static Self> + use<> {
        self.parents.iter().filter_map(|id| cwe(*id))
    }

    /// Entries that name this one as a parent.
    pub fn children(&self) -> impl Iterator<Item = &'static Self> + use<> {
        let id = self.id;
        cwes()
            .iter()
            .filter(move |entry| entry.parents.contains(&id))
    }

    /// Related CAPEC attack patterns.
    pub fn capecs(&self) -> impl Iterator<Item = &'static Capec> + use<> {
        self.capec.iter().filter_map(|id| crate::capec(*id))
    }

    /// OWASP Top 10 categories this entry is mapped to.
    pub fn owasp_categories(&self) -> impl Iterator<Item = &'static OwaspCategory> + use<> {
        self.owasp.iter().filter_map(|id| crate::owasp(*id))
    }

    /// Whether MITRE deprecated or obsoleted the entry.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        self.status.is_deprecated()
    }

    /// The entry's page on cwe.mitre.org.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "https://cwe.mitre.org/data/definitions/{}.html",
            self.id.get()
        )
    }

    /// A `rune-finding` reference to this entry, with its name.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        TaxonomyRef::new(Taxonomy::Cwe, self.id.to_string()).with_name(self.name)
    }
}

impl CweId {
    /// The entry with this id.
    pub fn resolve(self) -> Result<&'static Cwe, Error> {
        cwe(self).ok_or_else(|| Error::unknown(IdKind::Cwe, self))
    }
}

/// The CWE entry with this id: weakness, category or view.
///
/// ```
/// let sqli = rune_taxonomy::cwe(89).unwrap();
/// assert!(sqli.name.contains("SQL"));
/// assert!(rune_taxonomy::cwe(0).is_none());
/// ```
pub fn cwe(id: impl Into<CweId>) -> Option<&'static Cwe> {
    let id = id.into();
    let table = cwes();
    table
        .binary_search_by_key(&id, |entry| entry.id)
        .ok()
        .and_then(|index| table.get(index))
}

/// Every CWE entry, sorted by id.
#[must_use]
pub fn cwes() -> &'static [Cwe] {
    data::cwe::CWES
}

/// The weaknesses in the CWE Top 25 of [`CWE_TOP25_YEAR`], by id.
pub fn cwe_top25() -> impl Iterator<Item = &'static Cwe> {
    cwes().iter().filter(|entry| entry.top25)
}

/// The OWASP Top 10 categories (2021, 2025 and API 2023) a CWE is mapped to.
///
/// Only direct mappings count: a child of a mapped weakness is not reported
/// unless the list names it too.
///
/// ```
/// let ids: Vec<String> = rune_taxonomy::owasp_for_cwe(89)
///     .map(|category| category.id.to_string())
///     .collect();
/// assert_eq!(ids, ["A03:2021", "A05:2025"]);
/// ```
pub fn owasp_for_cwe(id: impl Into<CweId>) -> impl Iterator<Item = &'static OwaspCategory> {
    cwe(id).into_iter().flat_map(Cwe::owasp_categories)
}

/// The CAPEC attack patterns related to a CWE.
///
/// ```
/// assert!(rune_taxonomy::capec_for_cwe(89).any(|p| p.id.get() == 66));
/// ```
pub fn capec_for_cwe(id: impl Into<CweId>) -> impl Iterator<Item = &'static Capec> {
    cwe(id).into_iter().flat_map(Cwe::capecs)
}

/// The ATT&CK techniques related to a CWE through its CAPEC attack patterns,
/// sorted by id and without duplicates.
#[must_use]
pub fn attack_for_cwe(id: impl Into<CweId>) -> Vec<&'static Technique> {
    let mut techniques: Vec<&'static Technique> =
        capec_for_cwe(id).flat_map(Capec::techniques).collect();
    techniques.sort_by_key(|technique| technique.id);
    techniques.dedup_by_key(|technique| technique.id);
    techniques
}

//! MITRE CAPEC: attack patterns, categories and views.

use rune_finding::{Taxonomy, TaxonomyRef};

use crate::data;
use crate::{AttackId, CapecId, Cwe, CweId, Error, IdKind, Status, Technique};

/// What kind of CAPEC entry an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CapecKind {
    /// An attack pattern.
    AttackPattern,
    /// A category of attack patterns.
    Category,
    /// A view of the catalogue.
    View,
}

/// How abstract a CAPEC attack pattern is, from most to least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CapecAbstraction {
    /// A very abstract pattern, e.g. CAPEC-248 "Command Injection".
    Meta,
    /// A specific methodology, e.g. CAPEC-66 "SQL Injection".
    Standard,
    /// A low-level, specific pattern.
    Detailed,
}

/// A five-step rating, as CAPEC uses for severity and likelihood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Rating {
    /// Very low.
    VeryLow,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Very high.
    VeryHigh,
}

/// A CAPEC entry.
///
/// ```
/// let sqli = rune_taxonomy::capec(66).unwrap();
/// assert_eq!(sqli.name, "SQL Injection");
/// assert!(sqli.cwes.iter().any(|id| id.get() == 89));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Capec {
    /// The id, `CAPEC-66`.
    pub id: CapecId,
    /// Attack pattern, category or view.
    pub kind: CapecKind,
    /// The entry's name.
    pub name: &'static str,
    /// The pattern abstraction; `None` for categories and views.
    pub abstraction: Option<CapecAbstraction>,
    /// Maturity of the entry.
    pub status: Status,
    /// Typical severity of a successful attack, when CAPEC rates it.
    pub severity: Option<Rating>,
    /// Likelihood of the attack, when CAPEC rates it.
    pub likelihood: Option<Rating>,
    /// `ChildOf` parent patterns.
    pub parents: &'static [CapecId],
    /// Related CWE weaknesses, as either catalogue records them.
    pub cwes: &'static [CweId],
    /// Related ATT&CK Enterprise techniques, as either catalogue records
    /// them, with revoked techniques replaced by their successors.
    pub attack: &'static [AttackId],
}

impl Capec {
    /// Parent patterns.
    pub fn parents(&self) -> impl Iterator<Item = &'static Self> + use<> {
        self.parents.iter().filter_map(|id| capec(*id))
    }

    /// Related CWE entries.
    pub fn weaknesses(&self) -> impl Iterator<Item = &'static Cwe> + use<> {
        self.cwes.iter().filter_map(|id| crate::cwe(*id))
    }

    /// Related ATT&CK techniques.
    pub fn techniques(&self) -> impl Iterator<Item = &'static Technique> + use<> {
        self.attack.iter().filter_map(|id| crate::technique(*id))
    }

    /// Whether MITRE deprecated or obsoleted the entry.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        self.status.is_deprecated()
    }

    /// The entry's page on capec.mitre.org.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "https://capec.mitre.org/data/definitions/{}.html",
            self.id.get()
        )
    }

    /// A `rune-finding` reference to this entry, with its name.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        TaxonomyRef::new(Taxonomy::Capec, self.id.to_string()).with_name(self.name)
    }
}

impl CapecId {
    /// The entry with this id.
    pub fn resolve(self) -> Result<&'static Capec, Error> {
        capec(self).ok_or_else(|| Error::unknown(IdKind::Capec, self))
    }
}

/// The CAPEC entry with this id.
pub fn capec(id: impl Into<CapecId>) -> Option<&'static Capec> {
    let id = id.into();
    let table = capecs();
    table
        .binary_search_by_key(&id, |entry| entry.id)
        .ok()
        .and_then(|index| table.get(index))
}

/// Every CAPEC entry, sorted by id.
#[must_use]
pub fn capecs() -> &'static [Capec] {
    data::capec::CAPECS
}

/// The ATT&CK techniques related to a CAPEC attack pattern.
///
/// ```
/// // CAPEC-17 "Using Malicious Files" maps to T1574.010 "Services File
/// // Permissions Weakness".
/// assert!(rune_taxonomy::attack_for_capec(17).any(|t| t.id.to_string() == "T1574.010"));
/// ```
pub fn attack_for_capec(id: impl Into<CapecId>) -> impl Iterator<Item = &'static Technique> {
    capec(id).into_iter().flat_map(Capec::techniques)
}

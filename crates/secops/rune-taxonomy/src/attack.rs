//! MITRE ATT&CK Enterprise: tactics and techniques.

use rune_finding::{Taxonomy, TaxonomyRef};

use crate::data;
use crate::{AttackId, Capec, CapecId, Error, IdKind};

/// An ATT&CK Enterprise tactic, the adversary's goal for a technique.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Tactic {
    /// The id, `TA0001`.
    pub id: &'static str,
    /// The STIX kill chain phase name, `initial-access`.
    pub shortname: &'static str,
    /// The display name, `Initial Access`.
    pub name: &'static str,
}

/// An ATT&CK Enterprise technique or sub-technique.
///
/// ```
/// use rune_taxonomy::AttackId;
///
/// let technique = rune_taxonomy::technique(AttackId::technique(1190)).unwrap();
/// assert_eq!(technique.name, "Exploit Public-Facing Application");
/// assert_eq!(technique.tactics[0].name, "Initial Access");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Technique {
    /// The id, `T1190` or `T1059.007`.
    pub id: AttackId,
    /// The technique's name. A sub-technique's name omits its parent's.
    pub name: &'static str,
    /// The tactics the technique serves, in matrix order.
    pub tactics: &'static [&'static Tactic],
    /// Whether MITRE deprecated the technique (it stays resolvable).
    pub deprecated: bool,
    /// Related CAPEC attack patterns, as either catalogue records them.
    pub capec: &'static [CapecId],
}

impl Technique {
    /// The parent technique of a sub-technique.
    #[must_use]
    pub fn parent(&self) -> Option<&'static Self> {
        self.id.parent().and_then(technique)
    }

    /// Related CAPEC attack patterns.
    pub fn capecs(&self) -> impl Iterator<Item = &'static Capec> + use<> {
        self.capec.iter().filter_map(|id| crate::capec(*id))
    }

    /// The technique's page on attack.mitre.org.
    #[must_use]
    pub fn url(&self) -> String {
        // Sub-techniques live under their parent: `T1059/007/`.
        let path = self.id.to_string().replace('.', "/");
        format!("https://attack.mitre.org/techniques/{path}/")
    }

    /// A `rune-finding` reference to this technique, with its name.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        TaxonomyRef::new(Taxonomy::Attack, self.id.to_string()).with_name(self.name)
    }
}

impl AttackId {
    /// The technique with this id. A revoked technique is an
    /// [`Error::Revoked`] that names its replacement.
    pub fn resolve(self) -> Result<&'static Technique, Error> {
        if let Some(technique) = technique(self) {
            return Ok(technique);
        }
        Err(revoked_technique(self).map_or_else(
            || Error::unknown(IdKind::Attack, self),
            |replacement| Error::Revoked {
                id: self.to_string(),
                replaced_by: replacement.to_string(),
            },
        ))
    }
}

/// The technique or sub-technique with this id. Revoked techniques are not
/// found; see [`revoked_technique`].
#[must_use]
pub fn technique(id: AttackId) -> Option<&'static Technique> {
    let table = techniques();
    table
        .binary_search_by_key(&id, |entry| entry.id)
        .ok()
        .and_then(|index| table.get(index))
}

/// Every Enterprise technique and sub-technique, sorted by id, including
/// deprecated ones but not revoked ones.
#[must_use]
pub fn techniques() -> &'static [Technique] {
    data::attack::TECHNIQUES
}

/// The technique that replaced a revoked one.
///
/// ```
/// use rune_taxonomy::AttackId;
///
/// // T1086 "PowerShell" became sub-technique T1059.001.
/// assert_eq!(
///     rune_taxonomy::revoked_technique(AttackId::technique(1086)),
///     Some(AttackId::subtechnique(1059, 1)),
/// );
/// ```
#[must_use]
pub fn revoked_technique(id: AttackId) -> Option<AttackId> {
    let table = data::attack::REVOKED;
    table
        .binary_search_by_key(&id, |(old, _)| *old)
        .ok()
        .and_then(|index| table.get(index))
        .map(|(_, new)| *new)
}

/// The Enterprise tactics, in matrix order.
#[must_use]
pub fn tactics() -> &'static [&'static Tactic] {
    data::attack::TACTICS
}

/// The tactic with this id (`TA0001`) or shortname (`initial-access`).
#[must_use]
pub fn tactic(id_or_shortname: &str) -> Option<&'static Tactic> {
    tactics()
        .iter()
        .copied()
        .find(|tactic| tactic.id == id_or_shortname || tactic.shortname == id_or_shortname)
}

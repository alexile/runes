//! Resolving `rune-finding` taxonomy references against the datasets.

use rune_finding::{Taxonomy, TaxonomyRef};

use crate::{
    AsvsId, AsvsItem, AsvsVersion, AttackId, Capec, CapecId, Cwe, CweId, Error, IdKind,
    OwaspCategory, OwaspId, OwaspList, Technique,
};

/// A dataset entry a taxonomy reference resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Entry {
    /// A CWE weakness, category or view.
    Cwe(&'static Cwe),
    /// A CAPEC attack pattern, category or view.
    Capec(&'static Capec),
    /// An ATT&CK technique or sub-technique.
    Technique(&'static Technique),
    /// An OWASP Top 10 category.
    Owasp(&'static OwaspCategory),
    /// An ASVS chapter, section or requirement.
    Asvs(&'static AsvsItem),
}

impl Entry {
    /// The entry's id in canonical notation, e.g. `CWE-79` or `A03:2021`.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Cwe(entry) => entry.id.to_string(),
            Self::Capec(entry) => entry.id.to_string(),
            Self::Technique(entry) => entry.id.to_string(),
            Self::Owasp(entry) => entry.id.to_string(),
            Self::Asvs(entry) => entry.id.to_string(),
        }
    }

    /// The entry's name. ASVS requirements have none.
    #[must_use]
    pub const fn name(&self) -> Option<&'static str> {
        match self {
            Self::Cwe(entry) => Some(entry.name),
            Self::Capec(entry) => Some(entry.name),
            Self::Technique(entry) => Some(entry.name),
            Self::Owasp(entry) => Some(entry.name),
            Self::Asvs(entry) => entry.name,
        }
    }

    /// The `rune-finding` taxonomy the entry belongs to.
    #[must_use]
    pub const fn taxonomy(&self) -> Taxonomy {
        match self {
            Self::Cwe(_) => Taxonomy::Cwe,
            Self::Capec(_) => Taxonomy::Capec,
            Self::Technique(_) => Taxonomy::Attack,
            Self::Owasp(entry) => entry.id.list().taxonomy(),
            Self::Asvs(entry) => entry.version.taxonomy(),
        }
    }

    /// A `rune-finding` reference to the entry, with its canonical id and
    /// its name.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        match self {
            Self::Cwe(entry) => entry.to_taxonomy_ref(),
            Self::Capec(entry) => entry.to_taxonomy_ref(),
            Self::Technique(entry) => entry.to_taxonomy_ref(),
            Self::Owasp(entry) => entry.to_taxonomy_ref(),
            Self::Asvs(entry) => entry.to_taxonomy_ref(),
        }
    }
}

/// Resolves an id written in a taxonomy's notation, strictly: the id must be
/// canonical (no surrounding whitespace, no lower case, no leading zeros) and
/// present in the embedded dataset.
///
/// This is the check for free-text tags, such as a SAST tool's `cwe` and
/// `owasp` rule fields.
///
/// ```
/// use rune_finding::Taxonomy;
/// use rune_taxonomy::{resolve_id, Error};
///
/// let entry = resolve_id(&Taxonomy::Cwe, "CWE-89")?;
/// assert_eq!(entry.id(), "CWE-89");
///
/// assert!(matches!(resolve_id(&Taxonomy::Cwe, "CWE-79 "), Err(Error::Malformed { .. })));
/// assert!(matches!(resolve_id(&Taxonomy::Cwe, ""), Err(Error::Empty { .. })));
/// assert!(matches!(resolve_id(&Taxonomy::Cwe, "CWE-99999"), Err(Error::Unknown { .. })));
/// assert!(matches!(
///     resolve_id(&Taxonomy::OwaspTop10_2021, "A03:2025"),
///     Err(Error::WrongTaxonomy { .. }),
/// ));
/// # Ok::<(), Error>(())
/// ```
pub fn resolve_id(taxonomy: &Taxonomy, id: &str) -> Result<Entry, Error> {
    match taxonomy {
        Taxonomy::Cwe => Ok(Entry::Cwe(id.parse::<CweId>()?.resolve()?)),
        Taxonomy::Capec => Ok(Entry::Capec(id.parse::<CapecId>()?.resolve()?)),
        Taxonomy::Attack => Ok(Entry::Technique(id.parse::<AttackId>()?.resolve()?)),
        Taxonomy::OwaspTop10_2021 | Taxonomy::OwaspTop10_2025 | Taxonomy::OwaspApi2023 => {
            let parsed: OwaspId = id.parse()?;
            if Some(parsed.list()) != OwaspList::from_taxonomy(taxonomy) {
                return Err(Error::WrongTaxonomy {
                    id: parsed.to_string(),
                    expected: taxonomy.clone(),
                });
            }
            Ok(Entry::Owasp(parsed.resolve()?))
        }
        Taxonomy::Asvs4 => Ok(Entry::Asvs(id.parse::<AsvsId>()?.resolve(AsvsVersion::V4)?)),
        Taxonomy::Asvs5 => Ok(Entry::Asvs(id.parse::<AsvsId>()?.resolve(AsvsVersion::V5)?)),
        // `TaxonomyRef::owasp` files ids it cannot place in a known list here.
        Taxonomy::Custom(name) if name == "owasp" => Err(id
            .parse::<OwaspId>()
            .err()
            .unwrap_or_else(|| Error::malformed(IdKind::Owasp, id))),
        other => Err(Error::Unsupported(other.clone())),
    }
}

/// Resolves a `rune-finding` reference with [`resolve_id`].
///
/// ```
/// use rune_finding::TaxonomyRef;
///
/// let entry = rune_taxonomy::resolve(&TaxonomyRef::owasp("A03:2021"))?;
/// assert_eq!(entry.name(), Some("Injection"));
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
pub fn resolve(reference: &TaxonomyRef) -> Result<Entry, Error> {
    resolve_id(&reference.framework, &reference.id)
}

/// The reference with its canonical id and the dataset's name filled in.
///
/// ```
/// use rune_finding::TaxonomyRef;
///
/// let named = rune_taxonomy::named(&TaxonomyRef::cwe(89))?;
/// assert_eq!(named.name.as_deref(), rune_taxonomy::cwe(89).map(|c| c.name));
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
pub fn named(reference: &TaxonomyRef) -> Result<TaxonomyRef, Error> {
    resolve(reference).map(|entry| entry.to_taxonomy_ref())
}

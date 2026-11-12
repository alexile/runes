//! OWASP Application Security Verification Standard 4.0.3 and 5.0.0.

use rune_finding::TaxonomyRef;

use crate::data;
use crate::{AsvsId, AsvsVersion, CweId, Error, IdKind};

/// An ASVS chapter, section or requirement.
///
/// Requirement text is not embedded (see the crate's NOTICE); link to the
/// standard for it.
///
/// ```
/// use rune_taxonomy::{AsvsId, AsvsVersion};
///
/// let chapter = rune_taxonomy::asvs(AsvsVersion::V4, AsvsId::chapter(5)).unwrap();
/// assert_eq!(chapter.name, Some("Validation, Sanitization and Encoding"));
/// let requirement = rune_taxonomy::asvs(AsvsVersion::V4, "V5.3.4".parse()?).unwrap();
/// assert_eq!(requirement.cwes.iter().map(|c| c.get()).collect::<Vec<_>>(), [89]);
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AsvsItem {
    /// The ASVS edition.
    pub version: AsvsVersion,
    /// The id, `V5.3.4`.
    pub id: AsvsId,
    /// The chapter or section title; `None` for requirements.
    pub name: Option<&'static str>,
    /// The lowest verification level (1 to 3) a requirement applies at.
    /// `None` for chapters and sections, and for requirements the edition
    /// keeps only as a placeholder (deleted or merged ones).
    pub level: Option<u8>,
    /// The CWEs a requirement is mapped to. ASVS 5.0 has no CWE mapping, so
    /// this is always empty there.
    pub cwes: &'static [CweId],
}

impl AsvsItem {
    /// The chapter this item is in (itself, for a chapter).
    #[must_use]
    pub fn chapter(&self) -> Option<&'static Self> {
        asvs(self.version, self.id.chapter_id())
    }

    /// The section this item is in (itself, for a section); `None` for a
    /// chapter.
    #[must_use]
    pub fn section(&self) -> Option<&'static Self> {
        asvs(self.version, self.id.section_id()?)
    }

    /// A `rune-finding` reference to this item, with its name if it has one.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        let reference = TaxonomyRef::new(self.version.taxonomy(), self.id.to_string());
        match self.name {
            Some(name) => reference.with_name(name),
            None => reference,
        }
    }
}

impl AsvsId {
    /// The item with this id in an ASVS edition.
    pub fn resolve(self, version: AsvsVersion) -> Result<&'static AsvsItem, Error> {
        asvs(version, self).ok_or_else(|| Error::Unknown {
            kind: IdKind::Asvs,
            id: format!("{self} (ASVS {})", version.release()),
        })
    }
}

/// The chapter, section or requirement with this id in an ASVS edition.
#[must_use]
pub fn asvs(version: AsvsVersion, id: AsvsId) -> Option<&'static AsvsItem> {
    let table = asvs_items(version);
    table
        .binary_search_by_key(&id, |item| item.id)
        .ok()
        .and_then(|index| table.get(index))
}

/// Every chapter, section and requirement of an ASVS edition, sorted by id.
#[must_use]
pub fn asvs_items(version: AsvsVersion) -> &'static [AsvsItem] {
    match version {
        AsvsVersion::V4 => data::asvs::ASVS_4,
        AsvsVersion::V5 => data::asvs::ASVS_5,
    }
}

/// The ASVS 4.0.3 requirements mapped to a CWE (5.0.0 has no CWE mapping).
///
/// ```
/// let ids: Vec<String> = rune_taxonomy::asvs_for_cwe(89).map(|r| r.id.to_string()).collect();
/// assert!(ids.contains(&"V5.3.4".to_owned()));
/// ```
pub fn asvs_for_cwe(id: impl Into<CweId>) -> impl Iterator<Item = &'static AsvsItem> {
    let id = id.into();
    asvs_items(AsvsVersion::V4)
        .iter()
        .filter(move |item| item.cwes.contains(&id))
}

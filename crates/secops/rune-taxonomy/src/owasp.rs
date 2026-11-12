//! OWASP Top 10 2021 and 2025 and OWASP API Security Top 10 2023.

use rune_finding::TaxonomyRef;

use crate::data;
use crate::{Cwe, CweId, Error, IdKind, OwaspId, OwaspList};

/// An OWASP Top 10 category and the CWEs mapped to it.
///
/// The 2021 mapping is MITRE's (the "OWASP Top Ten 2021" CWE categories),
/// the 2025 one is the "List of Mapped CWEs" of each category page, and the
/// API 2023 one is the CWE references of each category page.
///
/// ```
/// use rune_taxonomy::{OwaspId, OwaspList};
///
/// let id = OwaspId::new(OwaspList::Top10_2025, 5).unwrap();
/// let injection = rune_taxonomy::owasp(id).unwrap();
/// assert_eq!(injection.name, "Injection");
/// assert!(injection.cwes.iter().any(|cwe| cwe.get() == 89));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct OwaspCategory {
    /// The id, `A05:2025`.
    pub id: OwaspId,
    /// The category title, `Injection`.
    pub name: &'static str,
    /// The CWEs mapped to the category, by id. CWEs the embedded catalogue
    /// lacks are left out.
    pub cwes: &'static [CweId],
}

impl OwaspCategory {
    /// The CWE entries mapped to the category.
    pub fn weaknesses(&self) -> impl Iterator<Item = &'static Cwe> + use<> {
        self.cwes.iter().filter_map(|id| crate::cwe(*id))
    }

    /// A `rune-finding` reference to this category, with its name.
    #[must_use]
    pub fn to_taxonomy_ref(&self) -> TaxonomyRef {
        TaxonomyRef::new(self.id.list().taxonomy(), self.id.to_string()).with_name(self.name)
    }
}

impl OwaspId {
    /// The category with this id.
    pub fn resolve(self) -> Result<&'static OwaspCategory, Error> {
        owasp(self).ok_or_else(|| Error::unknown(IdKind::Owasp, self))
    }
}

/// The OWASP category with this id.
#[must_use]
pub fn owasp(id: OwaspId) -> Option<&'static OwaspCategory> {
    owasp_list(id.list()).get(usize::from(id.rank()).checked_sub(1)?)
}

/// The ten categories of an OWASP list, in rank order.
#[must_use]
pub fn owasp_list(list: OwaspList) -> &'static [OwaspCategory] {
    match list {
        OwaspList::Top10_2021 => data::owasp::TOP10_2021,
        OwaspList::Top10_2025 => data::owasp::TOP10_2025,
        OwaspList::Api2023 => data::owasp::API_2023,
    }
}

//! Typed ids, parsed strictly from their canonical notation.
//!
//! Parsing never trims, case-folds or accepts leading zeros, so each id has
//! exactly one text form and `id.to_string().parse() == Ok(id)`. Parsing only
//! checks the notation; whether the dataset has the entry is a lookup
//! ([`CweId::resolve`] and friends).

use core::fmt;
use core::str::FromStr;

use rune_finding::Taxonomy;

use crate::error::{Error, IdKind};

/// Parses `digits` as a decimal number: at least one ASCII digit, no sign, no
/// leading zero, not zero, and at most `max`.
fn positive(digits: &str, max: u32) -> Option<u32> {
    let bytes = digits.as_bytes();
    if bytes.is_empty() || bytes.len() > 10 || bytes[0] == b'0' {
        return None;
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|n| *n <= max)
}

/// Parses exactly `len` ASCII digits (leading zeros allowed).
fn fixed(digits: &str, len: usize) -> Option<u16> {
    if digits.len() != len || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

macro_rules! numbered_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal, $kind:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) u32);

        impl $name {
            /// The id with this number. Any number is accepted here; zero and
            /// numbers the dataset lacks simply do not resolve.
            #[must_use]
            pub const fn new(number: u32) -> Self {
                Self(number)
            }

            /// The id's number.
            #[must_use]
            pub const fn get(self) -> u32 {
                self.0
            }
        }

        impl From<u32> for $name {
            fn from(number: u32) -> Self {
                Self(number)
            }
        }

        impl From<$name> for u32 {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(input: &str) -> Result<Self, Error> {
                input
                    .strip_prefix($prefix)
                    .and_then(|digits| positive(digits, u32::MAX))
                    .map(Self)
                    .ok_or_else(|| Error::malformed($kind, input))
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_str(deserializer)
            }
        }
    };
}

numbered_id!(
    /// A CWE id, written `CWE-79`.
    ///
    /// ```
    /// use rune_taxonomy::CweId;
    ///
    /// let id: CweId = "CWE-79".parse()?;
    /// assert_eq!(id, CweId::new(79));
    /// assert_eq!(id.to_string(), "CWE-79");
    /// for bad in ["", "CWE-79 ", "cwe-79", "CWE-079", "79", "CWE-0"] {
    ///     assert!(bad.parse::<CweId>().is_err(), "{bad:?}");
    /// }
    /// # Ok::<(), rune_taxonomy::Error>(())
    /// ```
    CweId,
    "CWE-",
    IdKind::Cwe
);

numbered_id!(
    /// A CAPEC attack pattern id, written `CAPEC-66`.
    ///
    /// ```
    /// use rune_taxonomy::CapecId;
    ///
    /// assert_eq!("CAPEC-66".parse::<CapecId>()?, CapecId::new(66));
    /// assert!("CAPEC 66".parse::<CapecId>().is_err());
    /// # Ok::<(), rune_taxonomy::Error>(())
    /// ```
    CapecId,
    "CAPEC-",
    IdKind::Capec
);

/// A MITRE ATT&CK technique or sub-technique id, written `T1059` or
/// `T1059.007`.
///
/// Ids sort by technique number, with a technique before its sub-techniques.
///
/// ```
/// use rune_taxonomy::AttackId;
///
/// let id: AttackId = "T1059.007".parse()?;
/// assert_eq!(id, AttackId::subtechnique(1059, 7));
/// assert_eq!(id.parent(), Some(AttackId::technique(1059)));
/// assert_eq!(id.to_string(), "T1059.007");
/// for bad in ["T1059.7", "t1059", "T159", "TA0001", "T1059 "] {
///     assert!(bad.parse::<AttackId>().is_err(), "{bad:?}");
/// }
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttackId {
    pub(crate) technique: u16,
    /// Sub-technique number, 0 for a technique.
    pub(crate) sub: u16,
}

impl AttackId {
    /// Technique `T{number:04}`. Numbers above 9999 have no notation and are
    /// clamped to 9999.
    #[must_use]
    pub const fn technique(number: u16) -> Self {
        Self {
            technique: if number > 9999 { 9999 } else { number },
            sub: 0,
        }
    }

    /// Sub-technique `T{technique:04}.{sub:03}`. Out-of-range numbers are
    /// clamped to 9999 and 999.
    #[must_use]
    pub const fn subtechnique(technique: u16, sub: u16) -> Self {
        Self {
            technique: if technique > 9999 { 9999 } else { technique },
            sub: if sub > 999 { 999 } else { sub },
        }
    }

    /// The technique number, e.g. 1059 for `T1059.007`.
    #[must_use]
    pub const fn technique_number(self) -> u16 {
        self.technique
    }

    /// The sub-technique number, e.g. 7 for `T1059.007`.
    #[must_use]
    pub const fn subtechnique_number(self) -> Option<u16> {
        if self.sub == 0 { None } else { Some(self.sub) }
    }

    /// Whether this is a sub-technique.
    #[must_use]
    pub const fn is_subtechnique(self) -> bool {
        self.sub != 0
    }

    /// The parent technique of a sub-technique.
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        if self.sub == 0 {
            None
        } else {
            Some(Self::technique(self.technique))
        }
    }
}

impl fmt::Display for AttackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{:04}", self.technique)?;
        if self.sub != 0 {
            write!(f, ".{:03}", self.sub)?;
        }
        Ok(())
    }
}

impl FromStr for AttackId {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        let parse = || {
            let rest = input.strip_prefix('T')?;
            let (technique, sub) = match rest.split_once('.') {
                Some((technique, sub)) => (technique, Some(fixed(sub, 3).filter(|s| *s != 0)?)),
                None => (rest, None),
            };
            let technique = fixed(technique, 4).filter(|t| *t != 0)?;
            Some(Self {
                technique,
                sub: sub.unwrap_or(0),
            })
        };
        parse().ok_or_else(|| Error::malformed(IdKind::Attack, input))
    }
}

/// An OWASP Top 10 list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OwaspList {
    /// OWASP Top 10, 2021 edition (`A01:2021` …).
    #[cfg_attr(feature = "serde", serde(rename = "top10_2021"))]
    Top10_2021,
    /// OWASP Top 10, 2025 edition (`A01:2025` …).
    #[cfg_attr(feature = "serde", serde(rename = "top10_2025"))]
    Top10_2025,
    /// OWASP API Security Top 10, 2023 edition (`API1:2023` …).
    #[cfg_attr(feature = "serde", serde(rename = "api_2023"))]
    Api2023,
}

impl OwaspList {
    /// Every list.
    pub const ALL: [Self; 3] = [Self::Top10_2021, Self::Top10_2025, Self::Api2023];

    /// The matching `rune-finding` taxonomy.
    #[must_use]
    pub const fn taxonomy(self) -> Taxonomy {
        match self {
            Self::Top10_2021 => Taxonomy::OwaspTop10_2021,
            Self::Top10_2025 => Taxonomy::OwaspTop10_2025,
            Self::Api2023 => Taxonomy::OwaspApi2023,
        }
    }

    /// The list a `rune-finding` taxonomy names, if it is an OWASP Top 10.
    #[must_use]
    pub const fn from_taxonomy(taxonomy: &Taxonomy) -> Option<Self> {
        match taxonomy {
            Taxonomy::OwaspTop10_2021 => Some(Self::Top10_2021),
            Taxonomy::OwaspTop10_2025 => Some(Self::Top10_2025),
            Taxonomy::OwaspApi2023 => Some(Self::Api2023),
            _ => None,
        }
    }
}

/// An OWASP Top 10 category id: `A03:2021`, `A05:2025` or `API1:2023`.
///
/// The year picks the [`OwaspList`]. Ranks run from 1 to 10; the web lists
/// write them with two digits, the API list without padding.
///
/// ```
/// use rune_taxonomy::{OwaspId, OwaspList};
///
/// let id: OwaspId = "A03:2021".parse()?;
/// assert_eq!(id, OwaspId::new(OwaspList::Top10_2021, 3).unwrap());
/// assert_eq!("API1:2023".parse::<OwaspId>()?.list(), OwaspList::Api2023);
/// for bad in ["A3:2021", "A03:2017", "A11:2021", "API01:2023", "a03:2021", ""] {
///     assert!(bad.parse::<OwaspId>().is_err(), "{bad:?}");
/// }
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwaspId {
    pub(crate) list: OwaspList,
    pub(crate) rank: u8,
}

impl OwaspId {
    /// Category `rank` (1 to 10) of `list`.
    #[must_use]
    pub const fn new(list: OwaspList, rank: u8) -> Option<Self> {
        if rank >= 1 && rank <= 10 {
            Some(Self { list, rank })
        } else {
            None
        }
    }

    /// The list the category belongs to.
    #[must_use]
    pub const fn list(self) -> OwaspList {
        self.list
    }

    /// The category's rank, 1 to 10.
    #[must_use]
    pub const fn rank(self) -> u8 {
        self.rank
    }
}

impl fmt::Display for OwaspId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.list {
            OwaspList::Top10_2021 => write!(f, "A{:02}:2021", self.rank),
            OwaspList::Top10_2025 => write!(f, "A{:02}:2025", self.rank),
            OwaspList::Api2023 => write!(f, "API{}:2023", self.rank),
        }
    }
}

impl FromStr for OwaspId {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        let parse = || {
            let (category, year) = input.split_once(':')?;
            let (list, rank) = match year {
                "2021" | "2025" => {
                    let rank = fixed(category.strip_prefix('A')?, 2)?;
                    let list = if year == "2021" {
                        OwaspList::Top10_2021
                    } else {
                        OwaspList::Top10_2025
                    };
                    (list, rank)
                }
                "2023" => {
                    let rank = positive(category.strip_prefix("API")?, 10)?;
                    (OwaspList::Api2023, u16::try_from(rank).ok()?)
                }
                _ => return None,
            };
            Self::new(list, u8::try_from(rank).ok()?)
        };
        parse().ok_or_else(|| Error::malformed(IdKind::Owasp, input))
    }
}

/// An OWASP ASVS edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AsvsVersion {
    /// ASVS 4.0.3.
    #[cfg_attr(feature = "serde", serde(rename = "4.0.3"))]
    V4,
    /// ASVS 5.0.0.
    #[cfg_attr(feature = "serde", serde(rename = "5.0.0"))]
    V5,
}

impl AsvsVersion {
    /// Both editions.
    pub const ALL: [Self; 2] = [Self::V4, Self::V5];

    /// The release this crate embeds, e.g. `4.0.3`.
    #[must_use]
    pub const fn release(self) -> &'static str {
        match self {
            Self::V4 => "4.0.3",
            Self::V5 => "5.0.0",
        }
    }

    /// The matching `rune-finding` taxonomy.
    #[must_use]
    pub const fn taxonomy(self) -> Taxonomy {
        match self {
            Self::V4 => Taxonomy::Asvs4,
            Self::V5 => Taxonomy::Asvs5,
        }
    }

    /// The edition a `rune-finding` taxonomy names, if it is ASVS.
    #[must_use]
    pub const fn from_taxonomy(taxonomy: &Taxonomy) -> Option<Self> {
        match taxonomy {
            Taxonomy::Asvs4 => Some(Self::V4),
            Taxonomy::Asvs5 => Some(Self::V5),
            _ => None,
        }
    }
}

/// An ASVS chapter (`V5`), section (`V5.3`) or requirement (`V5.3.4`) id.
///
/// The id does not say which ASVS edition it is from: `V5` is "Validation,
/// Sanitization and Encoding" in 4.0.3 and "File Handling" in 5.0.0. Lookups
/// take an [`AsvsVersion`] as well.
///
/// ```
/// use rune_taxonomy::AsvsId;
///
/// let id: AsvsId = "V5.3.4".parse()?;
/// assert_eq!(id, AsvsId::requirement(5, 3, 4));
/// assert_eq!(id.chapter_id(), AsvsId::chapter(5));
/// assert_eq!(id.section_id(), Some(AsvsId::section(5, 3)));
/// for bad in ["5.3.4", "v5.3.4", "V5.3.4.1", "V05", "V5..4", "V0"] {
///     assert!(bad.parse::<AsvsId>().is_err(), "{bad:?}");
/// }
/// # Ok::<(), rune_taxonomy::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsvsId {
    pub(crate) chapter: u8,
    /// 0 for a chapter.
    pub(crate) section: u8,
    /// 0 for a chapter or section.
    pub(crate) requirement: u8,
}

/// What an [`AsvsId`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AsvsKind {
    /// A chapter, `V5`.
    Chapter,
    /// A section, `V5.3`.
    Section,
    /// A requirement, `V5.3.4`.
    Requirement,
}

impl AsvsId {
    /// Chapter `V{chapter}`.
    #[must_use]
    pub const fn chapter(chapter: u8) -> Self {
        Self {
            chapter,
            section: 0,
            requirement: 0,
        }
    }

    /// Section `V{chapter}.{section}`.
    #[must_use]
    pub const fn section(chapter: u8, section: u8) -> Self {
        Self {
            chapter,
            section,
            requirement: 0,
        }
    }

    /// Requirement `V{chapter}.{section}.{requirement}`.
    #[must_use]
    pub const fn requirement(chapter: u8, section: u8, requirement: u8) -> Self {
        Self {
            chapter,
            section,
            requirement,
        }
    }

    /// Whether this names a chapter, a section or a requirement.
    #[must_use]
    pub const fn kind(self) -> AsvsKind {
        if self.section == 0 {
            AsvsKind::Chapter
        } else if self.requirement == 0 {
            AsvsKind::Section
        } else {
            AsvsKind::Requirement
        }
    }

    /// The chapter this id is in (itself, for a chapter).
    #[must_use]
    pub const fn chapter_id(self) -> Self {
        Self::chapter(self.chapter)
    }

    /// The section this id is in (itself, for a section); `None` for a
    /// chapter.
    #[must_use]
    pub const fn section_id(self) -> Option<Self> {
        if self.section == 0 {
            None
        } else {
            Some(Self::section(self.chapter, self.section))
        }
    }
}

impl fmt::Display for AsvsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "V{}", self.chapter)?;
        if self.section != 0 {
            write!(f, ".{}", self.section)?;
            if self.requirement != 0 {
                write!(f, ".{}", self.requirement)?;
            }
        }
        Ok(())
    }
}

impl FromStr for AsvsId {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Error> {
        let parse = || {
            let mut parts = input.strip_prefix('V')?.split('.');
            let mut next = |required: bool| match parts.next() {
                Some(part) => positive(part, u32::from(u8::MAX)).and_then(|n| u8::try_from(n).ok()),
                None if required => None,
                None => Some(0),
            };
            let chapter = next(true)?;
            let section = next(false)?;
            let requirement = if section == 0 { 0 } else { next(false)? };
            if parts.next().is_some() {
                return None;
            }
            Some(Self::requirement(chapter, section, requirement))
        };
        parse().ok_or_else(|| Error::malformed(IdKind::Asvs, input))
    }
}

#[cfg(feature = "serde")]
fn deserialize_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr<Err = Error>,
{
    struct Visitor<T>(core::marker::PhantomData<T>);

    impl<T: FromStr<Err = Error>> serde::de::Visitor<'_> for Visitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a taxonomy id string")
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<T, E> {
            text.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_str(Visitor(core::marker::PhantomData))
}

#[cfg(feature = "serde")]
macro_rules! string_serde {
    ($($name:ident),*) => {$(
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_str(deserializer)
            }
        }
    )*};
}

#[cfg(feature = "serde")]
string_serde!(AttackId, OwaspId, AsvsId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_and_capec_ids() {
        assert_eq!("CWE-1".parse(), Ok(CweId(1)));
        assert_eq!("CWE-4294967295".parse(), Ok(CweId(u32::MAX)));
        assert_eq!("CAPEC-1000".parse(), Ok(CapecId(1000)));
        for bad in [
            "",
            "CWE",
            "CWE-",
            "CWE-0",
            "CWE-01",
            "CWE--1",
            "CWE-+1",
            "CWE-4294967296",
            "CWE-79 ",
            " CWE-79",
            "cwe-79",
            "Cwe-79",
            "CWE 79",
            "CWE-79x",
            "CWE-٧٩",
            "CAPEC-79",
        ] {
            assert!(bad.parse::<CweId>().is_err(), "{bad:?}");
        }
        assert!("CWE-66".parse::<CapecId>().is_err());
        assert_eq!(CweId::from(89).to_string(), "CWE-89");
        assert_eq!(u32::from(CapecId::new(66)), 66);
    }

    #[test]
    fn attack_ids() {
        assert_eq!("T0801".parse(), Ok(AttackId::technique(801)));
        assert_eq!(AttackId::technique(801).to_string(), "T0801");
        assert!(AttackId::technique(1059) < AttackId::subtechnique(1059, 1));
        assert!(AttackId::subtechnique(1059, 999) < AttackId::technique(1060));
        assert_eq!(AttackId::technique(60000).to_string(), "T9999");
        assert_eq!(AttackId::subtechnique(1, 5000).to_string(), "T0001.999");
        for bad in [
            "T0000",
            "T1059.000",
            "T10590",
            "T1059.0001",
            "T1059.",
            ".001",
            "T１０５９",
        ] {
            assert!(bad.parse::<AttackId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn owasp_ids() {
        for (text, list, rank) in [
            ("A01:2021", OwaspList::Top10_2021, 1),
            ("A10:2025", OwaspList::Top10_2025, 10),
            ("API10:2023", OwaspList::Api2023, 10),
        ] {
            let id: OwaspId = text.parse().unwrap();
            assert_eq!((id.list(), id.rank()), (list, rank));
            assert_eq!(id.to_string(), text);
        }
        for bad in [
            "A00:2021",
            "A1:2021",
            "A001:2021",
            "API0:2023",
            "API11:2023",
            "A01:2023",
            "API1:2021",
            "A01",
            ":2021",
        ] {
            assert!(bad.parse::<OwaspId>().is_err(), "{bad:?}");
        }
        assert_eq!(OwaspId::new(OwaspList::Api2023, 0), None);
        assert_eq!(OwaspId::new(OwaspList::Api2023, 11), None);
        for list in OwaspList::ALL {
            assert_eq!(OwaspList::from_taxonomy(&list.taxonomy()), Some(list));
        }
    }

    #[test]
    fn asvs_ids() {
        for text in ["V1", "V14.2", "V5.3.4", "V255.255.255"] {
            let id: AsvsId = text.parse().unwrap();
            assert_eq!(id.to_string(), text);
        }
        assert_eq!(AsvsId::chapter(3).kind(), AsvsKind::Chapter);
        assert_eq!(AsvsId::section(3, 1).kind(), AsvsKind::Section);
        assert_eq!(AsvsId::requirement(3, 1, 2).kind(), AsvsKind::Requirement);
        assert_eq!(AsvsId::chapter(3).section_id(), None);
        assert!(AsvsId::chapter(1) < AsvsId::section(1, 1));
        for bad in [
            "V", "V256", "V1.", "V1.0", "V.1", "V1.2.3.4", "V1.2 ", "V1,2",
        ] {
            assert!(bad.parse::<AsvsId>().is_err(), "{bad:?}");
        }
        for version in AsvsVersion::ALL {
            assert_eq!(
                AsvsVersion::from_taxonomy(&version.taxonomy()),
                Some(version)
            );
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ids_serialize_as_strings() {
        let json = serde_json::to_string(&(
            CweId(79),
            AttackId::subtechnique(1059, 7),
            AsvsId::section(2, 1),
        ))
        .unwrap();
        assert_eq!(json, r#"["CWE-79","T1059.007","V2.1"]"#);
        let back: (CweId, AttackId, AsvsId) = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back,
            (
                CweId(79),
                AttackId::subtechnique(1059, 7),
                AsvsId::section(2, 1)
            )
        );
        assert!(serde_json::from_str::<CweId>(r#""CWE-79 ""#).is_err());
        assert!(serde_json::from_str::<OwaspId>("3").is_err());
        assert_eq!(
            serde_json::to_string(&OwaspList::Top10_2025).unwrap(),
            r#""top10_2025""#
        );
        assert_eq!(
            serde_json::to_string(&AsvsVersion::V4).unwrap(),
            r#""4.0.3""#
        );
    }
}

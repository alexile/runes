//! [`Taxonomy`] and [`TaxonomyRef`]: where a finding sits in CWE, OWASP,
//! CAPEC, ATT&CK and the other security classifications.

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

/// A security taxonomy a finding can be classified in.
///
/// Serialized as a plain string: the [`as_str`](Self::as_str) name of a
/// known taxonomy, such as `"cwe"` or `"owasp_top10_2021"`, or the name of a
/// [`Custom`](Self::Custom) one as given. Any string deserializes: names this
/// version does not know become `Custom`, so a finding written by a newer
/// version still reads.
///
/// [`Taxonomy::parse`] (and [`FromStr`], which never fails) maps known names
/// to their variant. Build custom taxonomies with it rather than with
/// `Custom` directly, so that `Custom("cwe")` cannot shadow [`Cwe`](Self::Cwe).
///
/// # Examples
///
/// ```
/// use rune_finding::Taxonomy;
///
/// assert_eq!(Taxonomy::parse("cwe"), Taxonomy::Cwe);
/// assert_eq!(Taxonomy::parse("acme_rules"), Taxonomy::Custom("acme_rules".into()));
/// assert_eq!(Taxonomy::OwaspTop10_2021.display_name(), "OWASP Top 10 2021");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Taxonomy {
    /// MITRE Common Weakness Enumeration, ids like `CWE-79`.
    Cwe,
    /// MITRE Common Attack Pattern Enumeration and Classification, ids like
    /// `CAPEC-66`.
    Capec,
    /// MITRE ATT&CK, technique ids like `T1190` or `T1059.007`.
    Attack,
    /// OWASP Top 10 (2021), ids like `A03:2021`.
    OwaspTop10_2021,
    /// OWASP Top 10 (2025), ids like `A05:2025`.
    OwaspTop10_2025,
    /// OWASP API Security Top 10 (2023), ids like `API1:2023`.
    OwaspApi2023,
    /// OWASP Application Security Verification Standard 4.0, ids like
    /// `V5.3.4`.
    Asvs4,
    /// OWASP Application Security Verification Standard 5.0, ids like
    /// `V1.2.3`.
    Asvs5,
    /// PCI DSS 4.0 requirements, ids like `6.2.4`.
    PciDss4,
    /// OWASP Web Security Testing Guide, ids like `WSTG-INPV-01`.
    Wstg,
    /// Any other taxonomy, by name, e.g. a vendor's own rule catalogue.
    Custom(String),
}

impl Taxonomy {
    /// Every known (non-custom) taxonomy.
    pub const KNOWN: [Self; 10] = [
        Self::Cwe,
        Self::Capec,
        Self::Attack,
        Self::OwaspTop10_2021,
        Self::OwaspTop10_2025,
        Self::OwaspApi2023,
        Self::Asvs4,
        Self::Asvs5,
        Self::PciDss4,
        Self::Wstg,
    ];

    /// The taxonomy with this machine name: a known variant when the name
    /// matches one exactly, [`Custom`](Self::Custom) otherwise.
    #[must_use]
    pub fn parse(name: &str) -> Self {
        match name {
            "cwe" => Self::Cwe,
            "capec" => Self::Capec,
            "attack" => Self::Attack,
            "owasp_top10_2021" => Self::OwaspTop10_2021,
            "owasp_top10_2025" => Self::OwaspTop10_2025,
            "owasp_api_2023" => Self::OwaspApi2023,
            "asvs_4" => Self::Asvs4,
            "asvs_5" => Self::Asvs5,
            "pci_dss_4" => Self::PciDss4,
            "wstg" => Self::Wstg,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Stable machine name, the same as the serialized form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Cwe => "cwe",
            Self::Capec => "capec",
            Self::Attack => "attack",
            Self::OwaspTop10_2021 => "owasp_top10_2021",
            Self::OwaspTop10_2025 => "owasp_top10_2025",
            Self::OwaspApi2023 => "owasp_api_2023",
            Self::Asvs4 => "asvs_4",
            Self::Asvs5 => "asvs_5",
            Self::PciDss4 => "pci_dss_4",
            Self::Wstg => "wstg",
            Self::Custom(name) => name,
        }
    }

    /// Human name, e.g. for the SARIF `toolComponent.name`. A custom
    /// taxonomy's name is returned as is.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::Cwe => "CWE",
            Self::Capec => "CAPEC",
            Self::Attack => "MITRE ATT&CK",
            Self::OwaspTop10_2021 => "OWASP Top 10 2021",
            Self::OwaspTop10_2025 => "OWASP Top 10 2025",
            Self::OwaspApi2023 => "OWASP API Security Top 10 2023",
            Self::Asvs4 => "OWASP ASVS 4.0",
            Self::Asvs5 => "OWASP ASVS 5.0",
            Self::PciDss4 => "PCI DSS 4.0",
            Self::Wstg => "OWASP WSTG",
            Self::Custom(name) => name,
        }
    }

    /// The organization that publishes a known taxonomy.
    #[must_use]
    pub const fn organization(&self) -> Option<&'static str> {
        match self {
            Self::Cwe | Self::Capec | Self::Attack => Some("MITRE"),
            Self::PciDss4 => Some("PCI Security Standards Council"),
            Self::OwaspTop10_2021
            | Self::OwaspTop10_2025
            | Self::OwaspApi2023
            | Self::Asvs4
            | Self::Asvs5
            | Self::Wstg => Some("OWASP"),
            Self::Custom(_) => None,
        }
    }

    /// Home page of a known taxonomy.
    #[must_use]
    pub const fn information_uri(&self) -> Option<&'static str> {
        Some(match self {
            Self::Cwe => "https://cwe.mitre.org/",
            Self::Capec => "https://capec.mitre.org/",
            Self::Attack => "https://attack.mitre.org/",
            Self::OwaspTop10_2021 => "https://owasp.org/Top10/2021/",
            Self::OwaspTop10_2025 => "https://owasp.org/Top10/",
            Self::OwaspApi2023 => "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            Self::Asvs4 | Self::Asvs5 => {
                "https://owasp.org/www-project-application-security-verification-standard/"
            }
            Self::PciDss4 => "https://www.pcisecuritystandards.org/",
            Self::Wstg => "https://owasp.org/www-project-web-security-testing-guide/",
            Self::Custom(_) => return None,
        })
    }

    /// Whether this is a [`Custom`](Self::Custom) taxonomy.
    #[must_use]
    pub const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

impl fmt::Display for Taxonomy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Taxonomy {
    type Err = Infallible;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(name))
    }
}

impl From<&str> for Taxonomy {
    fn from(name: &str) -> Self {
        Self::parse(name)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Taxonomy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Taxonomy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = Taxonomy;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a taxonomy name")
            }

            fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<Taxonomy, E> {
                Ok(Taxonomy::parse(name))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Taxonomy {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Taxonomy".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let known: Vec<&str> = Self::KNOWN.iter().map(Self::as_str).collect();
        schemars::json_schema!({
            "type": "string",
            "description": "Taxonomy name: one of the known names, or any other string for a custom taxonomy.",
            "examples": known,
        })
    }
}

/// One classification of a finding inside a [`Taxonomy`].
///
/// JSON shape: `{"framework": "cwe", "id": "CWE-79", "name": "Cross-site
/// Scripting"}`, with `name` left out when unknown.
///
/// Ids are kept as text in the taxonomy's own notation (`CWE-79`,
/// `A03:2021`, `T1190`). Typed, validated ids are the job of `rune-taxonomy`.
///
/// # Examples
///
/// ```
/// use rune_finding::{Taxonomy, TaxonomyRef};
///
/// let cwe = TaxonomyRef::cwe(79).with_name("Cross-site Scripting");
/// assert_eq!(cwe.id, "CWE-79");
/// assert_eq!(cwe.cwe_number(), Some(79));
///
/// let owasp = TaxonomyRef::owasp("A03:2021");
/// assert_eq!(owasp.framework, Taxonomy::OwaspTop10_2021);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct TaxonomyRef {
    /// Which taxonomy.
    pub framework: Taxonomy,
    /// Entry id inside the taxonomy, e.g. `CWE-79` or `A05:2025`.
    pub id: String,
    /// Entry name, e.g. `Injection`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
}

impl TaxonomyRef {
    /// Reference an entry by id.
    pub fn new(framework: Taxonomy, id: impl Into<String>) -> Self {
        Self {
            framework,
            id: id.into(),
            name: None,
        }
    }

    /// Reference CWE entry `number`, with the id `CWE-{number}`.
    #[must_use]
    pub fn cwe(number: u32) -> Self {
        Self::new(Taxonomy::Cwe, format!("CWE-{number}"))
    }

    /// Reference an OWASP Top 10 category by id, picking the edition from
    /// the id's year: `A03:2021`, `A05:2025` and `API1:2023` land in
    /// [`OwaspTop10_2021`](Taxonomy::OwaspTop10_2021),
    /// [`OwaspTop10_2025`](Taxonomy::OwaspTop10_2025) and
    /// [`OwaspApi2023`](Taxonomy::OwaspApi2023). Anything else lands in
    /// `Custom("owasp")`, keeping the id as given.
    pub fn owasp(id: impl Into<String>) -> Self {
        let id = id.into();
        let framework = owasp_edition(id.trim());
        Self::new(framework, id)
    }

    /// Attach the entry's human name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The CWE number of a [`Taxonomy::Cwe`] reference whose id is `CWE-<n>`
    /// (case-insensitive) or a bare number.
    #[must_use]
    pub fn cwe_number(&self) -> Option<u32> {
        if self.framework != Taxonomy::Cwe {
            return None;
        }
        let id = self.id.trim();
        let digits = match id.get(..4) {
            Some(prefix) if prefix.eq_ignore_ascii_case("CWE-") => id.get(4..)?,
            _ => id,
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    }
}

/// The OWASP list an id like `A03:2021` or `API1:2023` belongs to.
fn owasp_edition(id: &str) -> Taxonomy {
    let Some((category, year)) = id.split_once(':') else {
        return Taxonomy::Custom("owasp".to_owned());
    };
    let numbered = |prefix: &str| {
        category.len() > prefix.len()
            && category
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && category
                .get(prefix.len()..)
                .is_some_and(|tail| tail.bytes().all(|byte| byte.is_ascii_digit()))
    };
    match year {
        "2023" if numbered("API") => Taxonomy::OwaspApi2023,
        "2021" if numbered("A") => Taxonomy::OwaspTop10_2021,
        "2025" if numbered("A") => Taxonomy::OwaspTop10_2025,
        _ => Taxonomy::Custom("owasp".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_round_trip() {
        for taxonomy in Taxonomy::KNOWN {
            assert_eq!(Taxonomy::parse(taxonomy.as_str()), taxonomy);
            assert!(!taxonomy.is_custom());
            assert!(taxonomy.organization().is_some());
            assert!(taxonomy.information_uri().is_some());
        }
        let custom = Taxonomy::parse("Cwe");
        assert_eq!(custom, Taxonomy::Custom("Cwe".to_owned()));
        assert_eq!(custom.display_name(), "Cwe");
        assert_eq!(custom.organization(), None);
        assert_eq!(custom.information_uri(), None);
        assert_eq!("wstg".parse::<Taxonomy>(), Ok(Taxonomy::Wstg));
    }

    #[test]
    fn owasp_picks_the_edition() {
        let cases = [
            ("A03:2021", Taxonomy::OwaspTop10_2021),
            ("A10:2025", Taxonomy::OwaspTop10_2025),
            ("API1:2023", Taxonomy::OwaspApi2023),
            ("api10:2023", Taxonomy::OwaspApi2023),
            ("A1:2017", Taxonomy::Custom("owasp".to_owned())),
            ("API1:2021", Taxonomy::Custom("owasp".to_owned())),
            ("A:2021", Taxonomy::Custom("owasp".to_owned())),
            ("Injection", Taxonomy::Custom("owasp".to_owned())),
            ("", Taxonomy::Custom("owasp".to_owned())),
        ];
        for (id, expected) in cases {
            let entry = TaxonomyRef::owasp(id);
            assert_eq!(entry.framework, expected, "{id}");
            assert_eq!(entry.id, id);
        }
    }

    #[test]
    fn cwe_numbers() {
        assert_eq!(TaxonomyRef::cwe(79).cwe_number(), Some(79));
        assert_eq!(
            TaxonomyRef::new(Taxonomy::Cwe, " cwe-89 ").cwe_number(),
            Some(89)
        );
        assert_eq!(
            TaxonomyRef::new(Taxonomy::Cwe, "352").cwe_number(),
            Some(352)
        );
        for id in ["", "CWE-", "CWE-79 x", "CWE--1", "CWE-99999999999", "é"] {
            assert_eq!(
                TaxonomyRef::new(Taxonomy::Cwe, id).cwe_number(),
                None,
                "{id}"
            );
        }
        assert_eq!(TaxonomyRef::new(Taxonomy::Capec, "79").cwe_number(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shape() {
        let entry = TaxonomyRef::owasp("A05:2025").with_name("Injection");
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            r#"{"framework":"owasp_top10_2025","id":"A05:2025","name":"Injection"}"#
        );
        let custom: TaxonomyRef =
            serde_json::from_str(r#"{"framework":"acme","id":"R-1"}"#).unwrap();
        assert_eq!(custom.framework, Taxonomy::Custom("acme".to_owned()));
        assert_eq!(custom.name, None);
        assert!(serde_json::from_str::<Taxonomy>("7").is_err());
    }
}

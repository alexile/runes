//! The root DSE: what an LDAP server says about itself.
//!
//! See [RFC 4512 §5.1](https://www.rfc-editor.org/rfc/rfc4512#section-5.1)
//! and, for Active Directory's additions,
//! [MS-ADTS §3.1.1.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db).

use rune_service_probe::banner::printable;

use crate::message::{Scope, SearchEntry, SearchRequest};

/// The attributes the probes ask the root DSE for.
///
/// Servers return the ones they have. Operational attributes must be named (`OpenLDAP` does not
/// return them for `*`, and Active Directory does not understand `+`).
pub const ROOT_DSE_ATTRIBUTES: &[&str] = &[
    "objectClass",
    "namingContexts",
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "subschemaSubentry",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
    "supportedExtension",
    "supportedControl",
    "supportedFeatures",
    "supportedCapabilities",
    "vendorName",
    "vendorVersion",
    "dnsHostName",
    "serverName",
    "ldapServiceName",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "isGlobalCatalogReady",
    "isSynchronized",
];

/// OID of the `StartTLS` extended operation (RFC 4511 §4.14).
pub const OID_STARTTLS: &str = "1.3.6.1.4.1.1466.20037";
/// OID of the "Who am I?" extended operation (RFC 4532).
pub const OID_WHOAMI: &str = "1.3.6.1.4.1.4203.1.11.3";
/// OID of the Password Modify extended operation (RFC 3062).
pub const OID_PASSWORD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";
/// `supportedCapabilities` OID of an Active Directory domain controller.
pub const OID_CAP_ACTIVE_DIRECTORY: &str = "1.2.840.113556.1.4.800";
/// `supportedCapabilities` OID of AD LDS (ADAM).
pub const OID_CAP_AD_LDS: &str = "1.2.840.113556.1.4.1851";

/// Longest value copied out of the root DSE.
const MAX_TEXT: usize = 256;
/// Most values of one attribute copied out.
const MAX_LIST: usize = 32;

/// The search that reads the root DSE: base `""`, scope base,
/// `(objectClass=*)`, [`ROOT_DSE_ATTRIBUTES`].
#[must_use]
pub fn root_dse_search() -> SearchRequest {
    SearchRequest::new("", Scope::Base)
        .with_size_limit(1)
        .with_time_limit(10)
        .with_attributes(ROOT_DSE_ATTRIBUTES.iter().copied())
}

/// A root DSE entry, with text accessors that bound and sanitise the
/// server's values.
///
/// ```
/// use rune_probe_ldap::{Attribute, RootDse, SearchEntry};
///
/// let dse = RootDse::new(SearchEntry::new("", vec![
///     Attribute::new("namingContexts", ["dc=example,dc=org"]),
///     Attribute::new("supportedExtension", ["1.3.6.1.4.1.1466.20037"]),
///     Attribute::new("objectClass", ["top", "OpenLDAProotDSE"]),
/// ]));
/// assert_eq!(dse.naming_contexts(), ["dc=example,dc=org"]);
/// assert!(dse.supports_starttls());
/// assert_eq!(dse.product(), Some(("OpenLDAP".to_owned(), None)));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootDse {
    entry: SearchEntry,
}

impl RootDse {
    /// Wrap the entry a root DSE search returned.
    #[must_use]
    pub const fn new(entry: SearchEntry) -> Self {
        Self { entry }
    }

    /// The raw entry.
    #[must_use]
    pub const fn entry(&self) -> &SearchEntry {
        &self.entry
    }

    /// The values of `name` (case-insensitive) as printable text, at most
    /// 32 values of at most 256 characters each.
    #[must_use]
    pub fn values(&self, name: &str) -> Vec<String> {
        self.entry
            .values(name)
            .iter()
            .take(MAX_LIST)
            .map(|v| printable(v, MAX_TEXT))
            .collect()
    }

    /// The first value of `name` as printable text.
    #[must_use]
    pub fn first(&self, name: &str) -> Option<String> {
        self.entry
            .values(name)
            .first()
            .map(|v| printable(v, MAX_TEXT))
    }

    fn has_value(&self, name: &str, value: &str) -> bool {
        self.entry
            .values(name)
            .iter()
            .any(|v| v.eq_ignore_ascii_case(value.as_bytes()))
    }

    /// `namingContexts`.
    #[must_use]
    pub fn naming_contexts(&self) -> Vec<String> {
        self.values("namingContexts")
    }

    /// The context to search for directory data: `defaultNamingContext`
    /// (Active Directory) or the first of `namingContexts`, skipping
    /// configuration, schema and monitoring contexts.
    #[must_use]
    pub fn default_naming_context(&self) -> Option<String> {
        self.first("defaultNamingContext").or_else(|| {
            self.naming_contexts().into_iter().find(|nc| {
                let lower = nc.to_ascii_lowercase();
                !nc.is_empty()
                    && ![
                        "cn=config",
                        "cn=monitor",
                        "cn=schema",
                        "cn=configuration",
                        "o=netscaperoot",
                    ]
                    .iter()
                    .any(|skip| lower.starts_with(skip))
            })
        })
    }

    /// `supportedLDAPVersion`, e.g. `["2", "3"]`.
    #[must_use]
    pub fn ldap_versions(&self) -> Vec<String> {
        self.values("supportedLDAPVersion")
    }

    /// `supportedSASLMechanisms`.
    #[must_use]
    pub fn sasl_mechanisms(&self) -> Vec<String> {
        self.values("supportedSASLMechanisms")
    }

    /// True when `supportedExtension` lists `StartTLS`.
    #[must_use]
    pub fn supports_starttls(&self) -> bool {
        self.has_value("supportedExtension", OID_STARTTLS)
    }

    /// True for an Active Directory domain controller.
    #[must_use]
    pub fn is_active_directory(&self) -> bool {
        self.has_value("supportedCapabilities", OID_CAP_ACTIVE_DIRECTORY)
    }

    /// The directory product and version, from `supportedCapabilities`,
    /// `vendorName`/`vendorVersion` or `OpenLDAP`'s root DSE object class.
    #[must_use]
    pub fn product(&self) -> Option<(String, Option<String>)> {
        if self.has_value("supportedCapabilities", OID_CAP_AD_LDS) {
            return Some(("Microsoft AD LDS".into(), None));
        }
        if self.is_active_directory() {
            return Some(("Microsoft Active Directory".into(), None));
        }
        if let Some(vendor) = self.first("vendorName").filter(|v| !v.is_empty()) {
            return Some((vendor, self.first("vendorVersion")));
        }
        if self.has_value("objectClass", "OpenLDAProotDSE") {
            return Some(("OpenLDAP".into(), None));
        }
        None
    }
}

/// The Windows Server release of an Active Directory functional level
/// (`domainFunctionality`, `forestFunctionality`,
/// `domainControllerFunctionality`).
///
/// ```
/// assert_eq!(rune_probe_ldap::functional_level_name(7), Some("Windows Server 2016"));
/// ```
#[must_use]
pub const fn functional_level_name(level: u32) -> Option<&'static str> {
    Some(match level {
        0 => "Windows 2000",
        1 => "Windows Server 2003 interim",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016",
        10 => "Windows Server 2025",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Attribute;

    #[test]
    fn active_directory_wins_over_vendor() {
        let dse = RootDse::new(SearchEntry::new(
            "",
            vec![
                Attribute::new("supportedCapabilities", [OID_CAP_ACTIVE_DIRECTORY]),
                Attribute::new("defaultNamingContext", ["DC=corp,DC=example"]),
                Attribute::new(
                    "namingContexts",
                    ["CN=Configuration,DC=corp,DC=example", "DC=corp,DC=example"],
                ),
            ],
        ));
        assert!(dse.is_active_directory());
        assert_eq!(dse.product().unwrap().0, "Microsoft Active Directory");
        assert_eq!(
            dse.default_naming_context().as_deref(),
            Some("DC=corp,DC=example")
        );
    }

    #[test]
    fn default_context_skips_config_and_sanitises() {
        let dse = RootDse::new(SearchEntry::new(
            "",
            vec![
                Attribute::new("namingContexts", ["cn=config", "o=evil\x1b[31m"]),
                Attribute::new("vendorName", ["389 Project"]),
                Attribute::new("vendorVersion", ["389-Directory/2.4.5"]),
            ],
        ));
        assert_eq!(
            dse.default_naming_context().as_deref(),
            Some("o=evil\\x1b[31m")
        );
        assert_eq!(
            dse.product(),
            Some(("389 Project".into(), Some("389-Directory/2.4.5".into())))
        );
        assert!(!dse.supports_starttls());
        assert_eq!(functional_level_name(8), None);
    }
}

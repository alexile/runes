//! What a probe learned about a service.

use std::collections::BTreeMap;

use rune_finding::Finding;

/// Whether and how the service offers TLS, as far as the probe could tell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TlsSupport {
    /// The probe could not tell.
    #[default]
    Unknown,
    /// The service speaks plaintext only and offers no TLS upgrade.
    NotOffered,
    /// The service offers an upgrade (`STARTTLS`, `SSLRequest`, an
    /// encryption flag) but also accepts plaintext.
    Optional,
    /// The service refuses to continue without TLS.
    Required,
    /// The port speaks TLS from the first byte (SMTPS, LDAPS, ...).
    Implicit,
}

/// Whether the service demands authentication, as far as the probe could
/// tell without attempting a login.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AuthRequirement {
    /// The probe could not tell.
    #[default]
    Unknown,
    /// The service demands credentials before it serves requests.
    Required,
    /// The service answered a read-only request without credentials, or
    /// accepts anonymous access.
    NotRequired,
}

/// What a probe learned about one service.
///
/// Probes fill in what their protocol reveals and leave the rest at its
/// default. Long or binary values are the probe's to bound and sanitise;
/// [`crate::banner::printable`] helps.
///
/// ```
/// use rune_service_probe::{AuthRequirement, ServiceInfo, TlsSupport};
///
/// let info = ServiceInfo::new("redis")
///     .with_product("Redis")
///     .with_version("7.2.4")
///     .with_auth(AuthRequirement::NotRequired)
///     .with_tls(TlsSupport::NotOffered)
///     .with_detail("redis.mode", "standalone");
/// assert_eq!(info.version.as_deref(), Some("7.2.4"));
/// assert_eq!(info.details["redis.mode"], "standalone");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ServiceInfo {
    /// The probe's [`id`](crate::ServiceProbe::id), e.g. `ssh`.
    pub service: String,
    /// The server software, e.g. `OpenSSH`, `MariaDB`, `Postfix`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub product: Option<String>,
    /// The software version, e.g. `9.6p1`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<String>,
    /// The banner or greeting, printable and bounded.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub banner: Option<String>,
    /// What the service advertises: algorithms, `EHLO` extensions, SMB
    /// dialects, LDAP controls and so on. Order is the server's.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub capabilities: Vec<String>,
    /// Whether and how the service offers TLS.
    #[cfg_attr(feature = "serde", serde(default))]
    pub tls: TlsSupport,
    /// Whether the service demands authentication.
    #[cfg_attr(feature = "serde", serde(default))]
    pub auth: AuthRequirement,
    /// Protocol-specific facts, keyed `<service>.<name>`, e.g.
    /// `smb.signing = required` or `mysql.auth_plugin = caching_sha2_password`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub details: BTreeMap<String, String>,
    /// Security findings, with check ids `<service>.<issue>` and a
    /// [`Location::Network`](rune_finding::Location::Network) location. See
    /// [`Target::finding`](crate::Target::finding).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub findings: Vec<Finding>,
}

impl ServiceInfo {
    /// Start a record for `service` with nothing known yet.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            ..Self::default()
        }
    }

    /// Set [`ServiceInfo::product`].
    #[must_use]
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Set [`ServiceInfo::version`].
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set [`ServiceInfo::banner`].
    #[must_use]
    pub fn with_banner(mut self, banner: impl Into<String>) -> Self {
        self.banner = Some(banner.into());
        self
    }

    /// Append one capability.
    #[must_use]
    pub fn push_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Set [`ServiceInfo::tls`].
    #[must_use]
    pub const fn with_tls(mut self, tls: TlsSupport) -> Self {
        self.tls = tls;
        self
    }

    /// Set [`ServiceInfo::auth`].
    #[must_use]
    pub const fn with_auth(mut self, auth: AuthRequirement) -> Self {
        self.auth = auth;
        self
    }

    /// Set one entry of [`ServiceInfo::details`].
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Append one finding.
    #[must_use]
    pub fn push_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::Target;
    use rune_finding::{Confidence, Severity};

    #[test]
    fn serde_round_trip_skips_empty_members() {
        let target = Target::new("db.test", 5432);
        let info = ServiceInfo::new("postgresql")
            .with_version("16.2")
            .with_tls(TlsSupport::Optional)
            .push_capability("SCRAM-SHA-256")
            .push_finding(target.finding(
                "postgresql.tls_optional",
                "TLS is optional",
                Severity::Low,
                Confidence::Firm,
            ));
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["tls"], "optional");
        assert_eq!(json["auth"], "unknown");
        assert!(json.get("product").is_none());
        assert!(json.get("details").is_none());
        let back: ServiceInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back, info);
        let minimal: ServiceInfo = serde_json::from_str(r#"{"service":"ssh"}"#).unwrap();
        assert_eq!(minimal, ServiceInfo::new("ssh"));
    }
}

//! The scan result and the findings derived from it.

use std::collections::BTreeMap;
use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{ServiceInfo, Target, TlsSupport};
use rune_tls_hello::{CipherSuite, DowngradeSentinel, ProtocolVersion};

use crate::suites::{Weakness, suite_label, weaknesses};

/// The result of a yes/no check that may not apply or may not be decidable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Observed {
    /// Observed.
    Yes,
    /// Observed not to be the case.
    No,
    /// The check does not apply (one version only, say).
    NotApplicable,
    /// The server's answer did not settle it.
    Inconclusive,
    /// Not tested (disabled, or the scan was cut short).
    #[default]
    NotTested,
}

impl fmt::Display for Observed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::NotApplicable => "not applicable",
            Self::Inconclusive => "inconclusive",
            Self::NotTested => "not tested",
        })
    }
}

/// What one protocol version gave.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionResult {
    /// The version.
    pub version: ProtocolVersion,
    /// Whether the server negotiated it.
    pub supported: bool,
    /// Accepted suites, in the order the server chose them (its preference
    /// among the suites offered).
    pub cipher_suites: Vec<CipherSuite>,
    /// Whether every suite of the registry was tried.
    pub complete: bool,
    /// RFC 5746 confirmation in the first accepting `ServerHello`.
    pub secure_renegotiation: Option<bool>,
    /// TLS 1.3 downgrade sentinel in the first accepting `ServerHello`.
    pub downgrade_sentinel: Option<DowngradeSentinel>,
}

impl VersionResult {
    pub(crate) const fn new(version: ProtocolVersion) -> Self {
        Self {
            version,
            supported: false,
            cipher_suites: Vec::new(),
            complete: false,
            secure_renegotiation: None,
            downgrade_sentinel: None,
        }
    }

    /// The accepted suites with a given weakness.
    pub fn suites_with(&self, weakness: Weakness) -> impl Iterator<Item = CipherSuite> + '_ {
        self.cipher_suites
            .iter()
            .copied()
            .filter(move |suite| weaknesses(*suite).contains(&weakness))
    }
}

/// What a scan found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// One entry per version probed, newest first.
    pub versions: Vec<VersionResult>,
    /// Whether the server refuses a downgraded hello carrying
    /// `TLS_FALLBACK_SCSV` (RFC 7507).
    pub fallback_scsv: Observed,
    /// Whether the server accepts DEFLATE compression (CRIME).
    pub compression: Observed,
    /// Whether the server confirms RFC 5746 secure renegotiation at its
    /// newest pre-TLS 1.3 version. Whether it allows client-initiated
    /// renegotiation needs a full handshake and is not tested.
    pub secure_renegotiation: Observed,
    /// Protocol violations and connection failures seen, bounded.
    pub anomalies: Vec<String>,
    /// Hellos sent.
    pub attempts: usize,
    /// The scan stopped at [`ScanOptions::max_attempts`](crate::ScanOptions::max_attempts).
    pub truncated: bool,
}

/// Findings for these weaknesses, most severe first.
const CIPHER_CHECKS: &[(Weakness, Severity, &str)] = &[
    (
        Weakness::NullCipher,
        Severity::High,
        "NULL cipher suites accepted (no encryption)",
    ),
    (
        Weakness::Anonymous,
        Severity::High,
        "Anonymous cipher suites accepted (no server authentication)",
    ),
    (
        Weakness::Export,
        Severity::High,
        "Export-grade cipher suites accepted (FREAK, Logjam)",
    ),
    (
        Weakness::Des,
        Severity::High,
        "DES or RC2 cipher suites accepted",
    ),
    (
        Weakness::Rc4,
        Severity::Medium,
        "RC4 cipher suites accepted",
    ),
    (
        Weakness::Sweet32,
        Severity::Medium,
        "64-bit block cipher suites accepted (Sweet32)",
    ),
    (
        Weakness::NoForwardSecrecy,
        Severity::Low,
        "Cipher suites without forward secrecy accepted",
    ),
];

impl Report {
    /// The versions the server negotiated, newest first.
    #[must_use]
    pub fn supported_versions(&self) -> Vec<ProtocolVersion> {
        self.versions
            .iter()
            .filter(|v| v.supported)
            .map(|v| v.version)
            .collect()
    }

    /// The result for one version, if it was probed.
    #[must_use]
    pub fn version(&self, version: ProtocolVersion) -> Option<&VersionResult> {
        self.versions.iter().find(|v| v.version == version)
    }

    /// Whether the server speaks TLS at all (some version was accepted).
    #[must_use]
    pub fn speaks_tls(&self) -> bool {
        self.versions.iter().any(|v| v.supported)
    }

    /// Security findings, located at `target`, with check ids
    /// `tls.<issue>`:
    ///
    /// | check id | severity |
    /// |---|---|
    /// | `tls.sslv3` | high |
    /// | `tls.tls1_0`, `tls.tls1_1` | medium |
    /// | `tls.no_modern_version` (neither TLS 1.2 nor 1.3) | medium |
    /// | `tls.cipher.null`, `.anon`, `.export`, `.des` | high |
    /// | `tls.cipher.rc4`, `.sweet32` | medium |
    /// | `tls.cipher.no_forward_secrecy` | low |
    /// | `tls.compression` (CRIME) | medium |
    /// | `tls.insecure_renegotiation` | medium |
    /// | `tls.no_fallback_scsv` | low |
    #[must_use]
    pub fn findings(&self, target: &Target) -> Vec<Finding> {
        let mut findings = Vec::new();
        let legacy = [
            (
                ProtocolVersion::SSL_3_0,
                "tls.sslv3",
                Severity::High,
                "SSLv3 supported (POODLE)",
            ),
            (
                ProtocolVersion::TLS_1_0,
                "tls.tls1_0",
                Severity::Medium,
                "Deprecated TLS 1.0 supported",
            ),
            (
                ProtocolVersion::TLS_1_1,
                "tls.tls1_1",
                Severity::Medium,
                "Deprecated TLS 1.1 supported",
            ),
        ];
        for (version, id, severity, title) in legacy {
            if let Some(result) = self.version(version).filter(|v| v.supported) {
                findings.push(
                    target
                        .finding(id, title, severity, Confidence::Certain)
                        .push_taxonomy(TaxonomyRef::cwe(327))
                        .push_evidence(Evidence::new("negotiated", version.to_string()))
                        .push_evidence(Evidence::new("cipher_suites", suite_list(&result.cipher_suites)))
                        .with_remediation(Remediation::new(
                            "Disable SSLv3, TLS 1.0 and TLS 1.1; offer TLS 1.2 and TLS 1.3 only (RFC 8996).",
                        ))
                        .push_remediation_ref("https://www.rfc-editor.org/rfc/rfc8996"),
                );
            }
        }
        let modern = [ProtocolVersion::TLS_1_2, ProtocolVersion::TLS_1_3];
        let probed_modern = modern.iter().all(|v| self.version(*v).is_some());
        if self.speaks_tls()
            && probed_modern
            && !modern
                .iter()
                .any(|v| self.version(*v).is_some_and(|r| r.supported))
        {
            findings.push(
                target
                    .finding(
                        "tls.no_modern_version",
                        "Neither TLS 1.2 nor TLS 1.3 supported",
                        Severity::Medium,
                        Confidence::Certain,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(327))
                    .push_evidence(Evidence::new(
                        "supported",
                        version_list(&self.supported_versions()),
                    )),
            );
        }

        for &(weakness, severity, title) in CIPHER_CHECKS {
            let mut evidence = Vec::new();
            for result in &self.versions {
                let suites: Vec<CipherSuite> = result.suites_with(weakness).collect();
                if !suites.is_empty() {
                    evidence.push(Evidence::new(
                        result.version.to_string(),
                        suite_list(&suites),
                    ));
                }
            }
            if !evidence.is_empty() {
                findings.push(
                    target
                        .finding(
                            format!("tls.cipher.{}", weakness.label()),
                            title,
                            severity,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(327))
                        .with_evidence(evidence)
                        .with_remediation(Remediation::new(format!(
                            "Remove {weakness} suites from the server's cipher list."
                        ))),
                );
            }
        }

        if self.compression == Observed::Yes {
            findings.push(
                target
                    .finding(
                        "tls.compression",
                        "TLS compression enabled (CRIME)",
                        Severity::Medium,
                        Confidence::Certain,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(310))
                    .push_evidence(Evidence::new("compression_method", "DEFLATE (1)"))
                    .with_remediation(Remediation::new("Disable TLS-level compression."))
                    .push_remediation_ref("https://nvd.nist.gov/vuln/detail/CVE-2012-4929"),
            );
        }
        if self.secure_renegotiation == Observed::No {
            findings.push(
                target
                    .finding(
                        "tls.insecure_renegotiation",
                        "Secure renegotiation (RFC 5746) not supported",
                        Severity::Medium,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(295))
                    .with_remediation(Remediation::new(
                        "Upgrade the TLS stack to one that implements RFC 5746, or disable renegotiation.",
                    ))
                    .push_remediation_ref("https://nvd.nist.gov/vuln/detail/CVE-2009-3555"),
            );
        }
        if self.fallback_scsv == Observed::No {
            findings.push(
                target
                    .finding(
                        "tls.no_fallback_scsv",
                        "TLS_FALLBACK_SCSV downgrade protection not supported",
                        Severity::Low,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(757))
                    .push_evidence(Evidence::new(
                        "supported",
                        version_list(&self.supported_versions()),
                    ))
                    .push_remediation_ref("https://www.rfc-editor.org/rfc/rfc7507"),
            );
        }
        findings
    }

    /// The report as a `rune-service-probe` [`ServiceInfo`] (service
    /// `tls`): supported versions as capabilities, per-version suites and
    /// the extra checks as details, and [`Report::findings`].
    #[must_use]
    pub fn service_info(&self, target: &Target) -> ServiceInfo {
        let mut info = ServiceInfo::new("tls");
        if self.speaks_tls() {
            info = info.with_tls(TlsSupport::Implicit);
        }
        for version in self.supported_versions() {
            info = info.push_capability(version.to_string());
        }
        let mut details = BTreeMap::new();
        for result in self.versions.iter().filter(|v| v.supported) {
            details.insert(
                format!("tls.{}.cipher_suites", result.version),
                suite_list(&result.cipher_suites),
            );
        }
        details.insert(
            "tls.fallback_scsv".to_owned(),
            self.fallback_scsv.to_string(),
        );
        details.insert("tls.compression".to_owned(), self.compression.to_string());
        details.insert(
            "tls.secure_renegotiation".to_owned(),
            self.secure_renegotiation.to_string(),
        );
        details.insert("tls.attempts".to_owned(), self.attempts.to_string());
        if self.truncated {
            details.insert("tls.truncated".to_owned(), "true".to_owned());
        }
        for (key, value) in details {
            info = info.with_detail(key, value);
        }
        for finding in self.findings(target) {
            info = info.push_finding(finding);
        }
        info
    }
}

fn suite_list(suites: &[CipherSuite]) -> String {
    suites
        .iter()
        .map(|s| suite_label(*s))
        .collect::<Vec<_>>()
        .join(", ")
}

fn version_list(versions: &[ProtocolVersion]) -> String {
    versions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

//! Server software detection from the identification string, and a small
//! table of notable CVEs by version range.
//!
//! **This is a heuristic.** The software version in the banner is whatever
//! the server chooses to send. Distributions backport security fixes
//! without changing the upstream version (`OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`
//! is patched against CVE-2024-6387 although 8.9p1 is in the affected
//! range), some products let the banner be edited, and the table only
//! covers a few well-known, remotely relevant issues. Treat a match as a
//! lead to confirm, never as proof; findings built from it carry
//! [`Confidence::Tentative`](rune_service_probe::rune_finding::Confidence::Tentative).

use std::fmt;

use rune_service_probe::rune_finding::Severity;

use crate::Identification;

/// A server implementation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Family {
    /// OpenSSH, portable or OpenBSD, including Microsoft's Windows port.
    OpenSsh,
    /// Dropbear SSH.
    Dropbear,
    /// libssh (`libssh.org`).
    Libssh,
    /// libssh2.
    Libssh2,
    /// The Erlang/OTP `ssh` application.
    Erlang,
    /// Apache MINA SSHD.
    ApacheMina,
    /// Paramiko (Python).
    Paramiko,
    /// `AsyncSSH` (Python).
    AsyncSsh,
    /// `golang.org/x/crypto/ssh`.
    Go,
    /// Cisco IOS / IOS XE.
    Cisco,
    /// wolfSSH.
    WolfSsh,
    /// `MikroTik` `RouterOS`.
    RouterOs,
    /// Anything else.
    Other,
}

impl Family {
    /// The usual display name, e.g. `OpenSSH`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenSsh => "OpenSSH",
            Self::Dropbear => "Dropbear",
            Self::Libssh => "libssh",
            Self::Libssh2 => "libssh2",
            Self::Erlang => "Erlang/OTP SSH",
            Self::ApacheMina => "Apache MINA SSHD",
            Self::Paramiko => "Paramiko",
            Self::AsyncSsh => "AsyncSSH",
            Self::Go => "Go x/crypto/ssh",
            Self::Cisco => "Cisco",
            Self::WolfSsh => "wolfSSH",
            Self::RouterOs => "MikroTik RouterOS",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Software identified from a banner.
///
/// ```
/// use rune_probe_ssh::Identification;
/// use rune_probe_ssh::software::{Family, Software};
///
/// let id = Identification::parse(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")?;
/// let sw = Software::detect(&id);
/// assert_eq!(sw.family, Family::OpenSsh);
/// assert_eq!(sw.version.as_deref(), Some("8.9p1"));
/// assert_eq!(sw.distribution.as_deref(), Some("Ubuntu-3ubuntu0.10"));
/// let ids: Vec<&str> = sw.known_cves().iter().map(|c| c.id).collect();
/// assert!(ids.contains(&"CVE-2024-6387"));
/// # Ok::<(), rune_probe_ssh::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Software {
    /// The implementation family.
    pub family: Family,
    /// The version text as the banner has it, e.g. `9.6p1` or `2022.83`.
    pub version: Option<String>,
    /// The banner comment when it names a distribution build (Ubuntu,
    /// Debian, FreeBSD, ...). Such builds often carry backported fixes, so
    /// version-range matches against them are even less certain.
    pub distribution: Option<String>,
}

/// Comment markers of distribution builds that backport fixes.
const DISTRIBUTION_MARKERS: [&str; 5] = ["Ubuntu", "Debian", "Raspbian", "FreeBSD", "deb"];

impl Software {
    /// Detect the family and version from an identification string.
    #[must_use]
    pub fn detect(ident: &Identification) -> Self {
        let sw = ident.software_version.as_str();
        let lower = sw.to_ascii_lowercase();
        let after = |prefix: &str| {
            sw.get(prefix.len()..)
                .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
                .map(str::to_owned)
        };
        let (family, version) = if lower.starts_with("openssh") {
            // OpenSSH_9.6p1, OpenSSH_for_Windows_8.1
            let version = sw
                .rfind('_')
                .and_then(|at| sw.get(at + 1..))
                .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
                .map(str::to_owned);
            (Family::OpenSsh, version)
        } else if lower.starts_with("dropbear") {
            (Family::Dropbear, after("dropbear_"))
        } else if lower.starts_with("libssh2") {
            (Family::Libssh2, after("libssh2_"))
        } else if lower.starts_with("libssh") {
            (Family::Libssh, after("libssh_"))
        } else if lower.starts_with("erlang/") {
            (Family::Erlang, after("Erlang/"))
        } else if lower.starts_with("apache-sshd-") {
            (Family::ApacheMina, after("APACHE-SSHD-"))
        } else if lower.starts_with("sshd-core-") {
            (Family::ApacheMina, after("SSHD-CORE-"))
        } else if lower.starts_with("paramiko_") {
            (Family::Paramiko, after("paramiko_"))
        } else if lower.starts_with("asyncssh_") {
            (Family::AsyncSsh, after("AsyncSSH_"))
        } else if lower == "go" {
            (Family::Go, None)
        } else if lower.starts_with("cisco-") {
            (Family::Cisco, after("Cisco-"))
        } else if lower.starts_with("wolfsshv") {
            (Family::WolfSsh, after("wolfSSHv"))
        } else if lower == "rosssh" {
            (Family::RouterOs, None)
        } else {
            (Family::Other, ident.product().1)
        };
        let distribution = ident
            .comments
            .as_ref()
            .filter(|c| DISTRIBUTION_MARKERS.iter().any(|m| c.contains(m)))
            .cloned();
        Self {
            family,
            version,
            distribution,
        }
    }

    /// The version as comparable numbers, when there is one.
    #[must_use]
    pub fn parsed_version(&self) -> Option<Version> {
        self.version
            .as_deref()
            .and_then(|v| Version::parse(self.family, v))
    }

    /// The entries of [`KNOWN_CVES`] whose ranges include this version.
    /// Empty when the version is unknown.
    #[must_use]
    pub fn known_cves(&self) -> Vec<&'static KnownCve> {
        let Some(version) = self.parsed_version() else {
            return Vec::new();
        };
        KNOWN_CVES
            .iter()
            .filter(|c| c.family == self.family && c.affects(&version))
            .collect()
    }
}

/// A version as a list of numbers, compared component by component with
/// missing components counting as zero (trailing zeros are dropped, so
/// `1.2` equals `1.2.0`).
///
/// OpenSSH's portable suffix becomes a third component (`9.6p1` is
/// `[9, 6, 1]`); a bare OpenBSD version counts as `p1`, the release it
/// matches.
///
/// ```
/// use rune_probe_ssh::software::{Family, Version};
///
/// let v = |s| Version::parse(Family::OpenSsh, s).unwrap();
/// assert!(v("9.3p2") > v("9.3p1"));
/// assert_eq!(v("9.8"), v("9.8p1"));
/// assert!(v("10.0p2") > v("9.9p2"));
/// assert!(Version::parse(Family::Dropbear, "2022.83").unwrap()
///     < Version::parse(Family::Dropbear, "2024.84").unwrap());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(Vec<u32>);

/// Components kept from a version string.
const MAX_COMPONENTS: usize = 6;

impl Version {
    /// Parse the leading numeric part of `text`: digit runs separated by
    /// `.` (and, for OpenSSH, one `p`). Parsing stops at the first other
    /// character. `None` when `text` does not start with a digit or a
    /// component overflows.
    #[must_use]
    pub fn parse(family: Family, text: &str) -> Option<Self> {
        let mut parts = Vec::new();
        let mut current: Option<u32> = None;
        let mut portable = false;
        for c in text.chars() {
            if let Some(d) = c.to_digit(10) {
                current = Some(current.unwrap_or(0).checked_mul(10)?.checked_add(d)?);
                continue;
            }
            let Some(n) = current.take() else { break };
            parts.push(n);
            if parts.len() >= MAX_COMPONENTS {
                break;
            }
            match c {
                '.' if !portable => {}
                'p' if family == Family::OpenSsh && !portable => portable = true,
                _ => break,
            }
        }
        if let Some(n) = current
            && parts.len() < MAX_COMPONENTS
        {
            parts.push(n);
        }
        if parts.is_empty() {
            return None;
        }
        if family == Family::OpenSsh && !portable {
            parts.truncate(2);
            parts.resize(2, 0);
            parts.push(1);
        }
        while parts.last() == Some(&0) {
            parts.pop();
        }
        Some(Self(parts))
    }

    /// The numbers, without trailing zeros.
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.0
    }
}

/// An affected version range: `from` (inclusive, `None` for "everything
/// before") up to the fixed release `fixed` (exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Range {
    /// First affected version, inclusive.
    pub from: Option<&'static str>,
    /// First fixed version, exclusive.
    pub fixed: &'static str,
}

/// One notable CVE and the versions it affects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KnownCve {
    /// The CVE id.
    pub id: &'static str,
    /// The implementation it affects.
    pub family: Family,
    /// Affected ranges.
    pub affected: &'static [Range],
    /// Severity to report on a match.
    pub severity: Severity,
    /// What the issue is, in one line.
    pub summary: &'static str,
    /// The advisory or release notes the ranges come from.
    pub source: &'static str,
}

impl KnownCve {
    /// True when `version` is inside one of the affected ranges.
    #[must_use]
    pub fn affects(&self, version: &Version) -> bool {
        self.affected.iter().any(|r| {
            let parse = |s| Version::parse(self.family, s);
            let after_start = r
                .from
                .is_none_or(|from| parse(from).is_some_and(|f| *version >= f));
            after_start && parse(r.fixed).is_some_and(|fixed| *version < fixed)
        })
    }

    /// The NVD page for the CVE.
    #[must_use]
    pub fn url(&self) -> String {
        format!("https://nvd.nist.gov/vuln/detail/{}", self.id)
    }
}

const fn range(from: Option<&'static str>, fixed: &'static str) -> Range {
    Range { from, fixed }
}

/// A short list of notable, remotely relevant server-side CVEs.
///
/// Ranges come from the vendors' release notes and advisories named in
/// each entry.
/// Client-only issues are left out, since a banner says nothing about the
/// client.
pub const KNOWN_CVES: &[KnownCve] = &[
    KnownCve {
        id: "CVE-2024-6387",
        family: Family::OpenSsh,
        affected: &[range(None, "4.4p1"), range(Some("8.5p1"), "9.8p1")],
        severity: Severity::High,
        summary: "regreSSHion: signal-handler race in sshd allows unauthenticated remote code execution (glibc Linux)",
        source: "OpenSSH 9.8 release notes; Qualys advisory",
    },
    KnownCve {
        id: "CVE-2025-26466",
        family: Family::OpenSsh,
        affected: &[range(Some("9.5p1"), "9.9p2")],
        severity: Severity::Medium,
        summary: "pre-authentication memory and CPU exhaustion (denial of service)",
        source: "OpenSSH 9.9p2 release notes",
    },
    KnownCve {
        id: "CVE-2023-25136",
        family: Family::OpenSsh,
        affected: &[range(Some("9.1p1"), "9.2p1")],
        severity: Severity::Medium,
        summary: "pre-authentication double free in sshd",
        source: "OpenSSH 9.2 release notes",
    },
    KnownCve {
        id: "CVE-2021-41617",
        family: Family::OpenSsh,
        affected: &[range(Some("6.2p1"), "8.8p1")],
        severity: Severity::Medium,
        summary: "AuthorizedKeysCommand / AuthorizedPrincipalsCommand helpers run with sshd's supplemental groups",
        source: "OpenSSH 8.8 release notes",
    },
    KnownCve {
        id: "CVE-2018-15473",
        family: Family::OpenSsh,
        affected: &[range(None, "7.8p1")],
        severity: Severity::Medium,
        summary: "username enumeration through malformed public-key authentication requests",
        source: "OpenSSH 7.8 release notes",
    },
    KnownCve {
        id: "CVE-2016-6210",
        family: Family::OpenSsh,
        affected: &[range(None, "7.3p1")],
        severity: Severity::Medium,
        summary: "username enumeration through password-hashing timing",
        source: "OpenSSH 7.3 release notes",
    },
    KnownCve {
        id: "CVE-2016-8858",
        family: Family::OpenSsh,
        affected: &[range(Some("6.0p1"), "7.4p1")],
        severity: Severity::Medium,
        summary: "pre-authentication memory exhaustion through repeated KEXINIT",
        source: "OpenSSH 7.4 release notes",
    },
    KnownCve {
        id: "CVE-2016-7406",
        family: Family::Dropbear,
        affected: &[range(None, "2016.74")],
        severity: Severity::High,
        summary: "format-string bug in user name handling allows remote code execution",
        source: "Dropbear 2016.74 changelog",
    },
    KnownCve {
        id: "CVE-2017-9078",
        family: Family::Dropbear,
        affected: &[range(None, "2017.75")],
        severity: Severity::Medium,
        summary: "double free in TCP forwarding cleanup after authentication",
        source: "Dropbear 2017.75 changelog",
    },
    KnownCve {
        id: "CVE-2018-15599",
        family: Family::Dropbear,
        affected: &[range(None, "2019.77")],
        severity: Severity::Medium,
        summary: "username enumeration in public-key authentication",
        source: "Dropbear 2019.77 changelog",
    },
    KnownCve {
        id: "CVE-2018-10933",
        family: Family::Libssh,
        affected: &[range(Some("0.6.0"), "0.7.6"), range(Some("0.8.0"), "0.8.4")],
        severity: Severity::Critical,
        summary: "server authentication bypass: the client sends USERAUTH_SUCCESS itself",
        source: "libssh 0.7.6 / 0.8.4 security advisory",
    },
    KnownCve {
        id: "CVE-2023-2283",
        family: Family::Libssh,
        affected: &[
            range(Some("0.9.0"), "0.9.8"),
            range(Some("0.10.0"), "0.10.5"),
        ],
        severity: Severity::Medium,
        summary: "authentication bypass in signature verification under memory pressure",
        source: "libssh 0.10.5 / 0.9.8 security advisory",
    },
    KnownCve {
        id: "CVE-2025-32433",
        family: Family::Erlang,
        affected: &[
            range(None, "4.15.3.12"),
            range(Some("5.0"), "5.1.4.8"),
            range(Some("5.2"), "5.2.10"),
        ],
        severity: Severity::Critical,
        summary: "unauthenticated remote code execution through connection-protocol messages sent before authentication",
        source: "Erlang/OTP advisory GHSA-37cp-fgq5-7wc2",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(banner: &str) -> Software {
        let id = Identification::parse(banner.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        Software::detect(&id)
    }

    fn cves(banner: &str) -> Vec<&'static str> {
        detect(banner).known_cves().iter().map(|c| c.id).collect()
    }

    #[test]
    fn families_and_versions() {
        let cases = [
            ("SSH-2.0-OpenSSH_9.6p1", Family::OpenSsh, Some("9.6p1")),
            (
                "SSH-2.0-OpenSSH_for_Windows_8.1",
                Family::OpenSsh,
                Some("8.1"),
            ),
            (
                "SSH-2.0-dropbear_2022.83",
                Family::Dropbear,
                Some("2022.83"),
            ),
            ("SSH-2.0-dropbear", Family::Dropbear, None),
            ("SSH-2.0-libssh_0.8.3", Family::Libssh, Some("0.8.3")),
            ("SSH-2.0-libssh-0.9.6", Family::Libssh, Some("0.9.6")),
            ("SSH-2.0-libssh2_1.10.0", Family::Libssh2, Some("1.10.0")),
            ("SSH-2.0-Erlang/5.2.9", Family::Erlang, Some("5.2.9")),
            (
                "SSH-2.0-APACHE-SSHD-2.12.0",
                Family::ApacheMina,
                Some("2.12.0"),
            ),
            ("SSH-2.0-paramiko_3.4.0", Family::Paramiko, Some("3.4.0")),
            ("SSH-2.0-AsyncSSH_2.14.2", Family::AsyncSsh, Some("2.14.2")),
            ("SSH-2.0-Go", Family::Go, None),
            ("SSH-2.0-Cisco-1.25", Family::Cisco, Some("1.25")),
            ("SSH-2.0-ROSSSH", Family::RouterOs, None),
            ("SSH-2.0-Foo_1.2", Family::Other, Some("1.2")),
        ];
        for (banner, family, version) in cases {
            let sw = detect(banner);
            assert_eq!(sw.family, family, "{banner}");
            assert_eq!(sw.version.as_deref(), version, "{banner}");
        }
    }

    #[test]
    fn version_parsing() {
        let v = |f, s| Version::parse(f, s).map(|v| v.0);
        assert_eq!(v(Family::OpenSsh, "9.6p1"), Some(vec![9, 6, 1]));
        assert_eq!(v(Family::OpenSsh, "7.4"), Some(vec![7, 4, 1]));
        assert_eq!(v(Family::OpenSsh, "8.2p1-hpn14v15"), Some(vec![8, 2, 1]));
        assert_eq!(v(Family::Libssh, "0.10.5"), Some(vec![0, 10, 5]));
        assert_eq!(v(Family::Libssh, "1.0.0"), Some(vec![1]));
        assert_eq!(v(Family::Libssh, "1.2p3"), Some(vec![1, 2]));
        assert_eq!(v(Family::Dropbear, "x"), None);
        assert_eq!(v(Family::Dropbear, "99999999999"), None);
        assert_eq!(
            v(Family::Erlang, "1.2.3.4.5.6.7.8").map(|p| p.len()),
            Some(6)
        );
    }

    #[test]
    fn cve_ranges() {
        assert_eq!(cves("SSH-2.0-OpenSSH_9.9p2"), Vec::<&str>::new());
        assert_eq!(cves("SSH-2.0-OpenSSH_9.8p1"), ["CVE-2025-26466"]);
        assert_eq!(
            cves("SSH-2.0-OpenSSH_9.1p1"),
            ["CVE-2024-6387", "CVE-2023-25136"]
        );
        assert_eq!(
            cves("SSH-2.0-OpenSSH_7.4"),
            ["CVE-2021-41617", "CVE-2018-15473"]
        );
        assert!(cves("SSH-2.0-OpenSSH_3.9p1").contains(&"CVE-2024-6387"));
        assert_eq!(
            cves("SSH-2.0-dropbear_2016.72"),
            ["CVE-2016-7406", "CVE-2017-9078", "CVE-2018-15599"]
        );
        assert_eq!(cves("SSH-2.0-libssh_0.8.3"), ["CVE-2018-10933"]);
        assert_eq!(cves("SSH-2.0-libssh_0.8.4"), Vec::<&str>::new());
        assert_eq!(cves("SSH-2.0-libssh-0.10.4"), ["CVE-2023-2283"]);
        assert_eq!(cves("SSH-2.0-Erlang/5.2.9"), ["CVE-2025-32433"]);
        assert_eq!(cves("SSH-2.0-Erlang/5.2.10"), Vec::<&str>::new());
        assert_eq!(cves("SSH-2.0-Erlang/4.15.3.11"), ["CVE-2025-32433"]);
        assert_eq!(cves("SSH-2.0-dropbear"), Vec::<&str>::new());
    }

    #[test]
    fn every_range_parses() {
        for cve in KNOWN_CVES {
            for r in cve.affected {
                let fixed = Version::parse(cve.family, r.fixed);
                assert!(fixed.is_some(), "{}", cve.id);
                if let Some(from) = r.from {
                    assert!(Version::parse(cve.family, from) < fixed, "{}", cve.id);
                }
            }
        }
    }
}

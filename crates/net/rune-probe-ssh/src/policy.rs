//! A sans-I/O policy grader for a server's identification string and
//! KEXINIT.
//!
//! A [`Policy`] gives every offered algorithm a [`Level`] (fail, warn or
//! info) with a reason, from the [algorithm table](crate::algorithms) under
//! a built-in [`Profile`] plus any allow/deny rules you add. Grading a
//! server also runs the [Terrapin check](crate::audit::Terrapin), detects
//! the [software](crate::software) and its notable CVEs (a heuristic), and
//! rolls everything into a letter [`Grade`]. [`Report::findings`] turns
//! the result into `rune-finding` findings.
//!
//! ```
//! use rune_probe_ssh::{Identification, KexInit};
//! use rune_probe_ssh::audit::Category;
//! use rune_probe_ssh::policy::{Grade, Level, Policy};
//!
//! let ident = Identification::parse(b"SSH-2.0-OpenSSH_9.9p2")?;
//! let mut offer = KexInit::default();
//! offer.kex_algorithms = vec!["curve25519-sha256".into(), "diffie-hellman-group14-sha1".into()];
//! offer.server_host_key_algorithms = vec!["ssh-ed25519".into()];
//! offer.encryption_server_to_client = vec!["aes256-gcm@openssh.com".into()];
//! offer.mac_server_to_client = vec!["hmac-sha2-256-etm@openssh.com".into()];
//!
//! let report = Policy::modern().grade(Some(&ident), Some(&offer));
//! assert_eq!(report.grade, Grade::C);
//! let failed: Vec<&str> = report.failures().map(|a| a.algorithm.as_str()).collect();
//! assert_eq!(failed, ["diffie-hellman-group14-sha1"]);
//!
//! // The compatible profile only warns about it.
//! let report = Policy::compatible().grade(Some(&ident), Some(&offer));
//! assert_eq!(report.grade, Grade::B);
//!
//! // So does a modern policy that explicitly allows it.
//! let report = Policy::modern()
//!     .allow(Category::Kex, "diffie-hellman-group14-sha1")
//!     .grade(Some(&ident), Some(&offer));
//! assert_eq!(report.grade, Grade::A);
//! # Ok::<(), rune_probe_ssh::Error>(())
//! ```

use std::fmt;
use std::str::FromStr;

use rune_service_probe::rune_finding::{
    Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef,
};

use crate::algorithms::{glob_match, is_signal, lookup};
use crate::audit::{Category, Terrapin};
use crate::software::{KnownCve, Software};
use crate::{Identification, KexInit};

/// How a policy judges one algorithm. Ordered from fine to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Acceptable; the reason is a note.
    Info,
    /// Allowed but discouraged.
    Warn,
    /// Should not be offered.
    Fail,
}

impl Level {
    /// `info`, `warn` or `fail`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A built-in starting point for a [`Policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Profile {
    /// Current best practice: post-quantum hybrids and X25519, Ed25519 and
    /// `rsa-sha2-*`, AEAD and CTR ciphers, encrypt-then-MAC SHA-2 MACs.
    /// SHA-1, CBC, 64-bit tags and the rest fail; NIST curves, 2048-bit
    /// groups and encrypt-and-MAC MACs draw a warning.
    #[default]
    Modern,
    /// For fleets that still serve old clients: only broken or prohibited
    /// algorithms (`none`, RC4, DES/3DES, MD5, DSA, 1024-bit groups) fail;
    /// SHA-1, CBC and `ssh-rsa` draw a warning.
    Compatible,
}

impl Profile {
    /// `modern` or `compatible`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::Compatible => "compatible",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error for an unknown profile name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProfile(pub String);

impl fmt::Display for UnknownProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown SSH policy profile {:?}", self.0)
    }
}

impl std::error::Error for UnknownProfile {}

impl FromStr for Profile {
    type Err = UnknownProfile;

    /// `modern` or `compatible`, ignoring ASCII case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("modern") {
            Ok(Self::Modern)
        } else if s.eq_ignore_ascii_case("compatible") {
            Ok(Self::Compatible)
        } else {
            Err(UnknownProfile(s.to_owned()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Rule {
    category: Category,
    pattern: String,
    level: Level,
}

/// A grading policy: a [`Profile`] plus your own rules.
///
/// Rules are checked before the profile, the most recently added first:
///
/// - [`allow`](Self::allow) and [`deny`](Self::deny) pin matching
///   algorithms to info or fail; [`set`](Self::set) pins any level.
/// - [`allow_only`](Self::allow_only) fails every algorithm of a category
///   that matches none of its patterns (extension signals such as
///   `ext-info-s` excepted). Explicit rules still win over it.
///
/// Patterns are exact names, or use a leading and/or trailing `*` (see
/// [`glob_match`]).
///
/// ```
/// use rune_probe_ssh::audit::Category;
/// use rune_probe_ssh::policy::{Level, Policy};
///
/// let policy = Policy::modern()
///     .allow_only(Category::Cipher, ["aes256-gcm@openssh.com", "chacha20-*"])
///     .deny(Category::Kex, "ecdh-sha2-*");
/// assert_eq!(policy.assess(Category::Cipher, "aes128-ctr").level, Level::Fail);
/// assert_eq!(policy.assess(Category::Cipher, "chacha20-poly1305@openssh.com").level, Level::Info);
/// assert_eq!(policy.assess(Category::Kex, "ecdh-sha2-nistp521").level, Level::Fail);
/// assert_eq!(policy.assess(Category::Kex, "curve25519-sha256").level, Level::Info);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Policy {
    profile: Profile,
    rules: Vec<Rule>,
    only: Vec<(Category, Vec<String>)>,
}

/// Reasons for rule-based levels.
const ALLOWED: &str = "allowed by the policy";
const DENIED: &str = "denied by the policy";
const WARNED: &str = "flagged by the policy";
const NOT_LISTED: &str = "not in the policy's allow list";
const UNKNOWN: &str = "not in the algorithm table; review by hand";

impl Policy {
    /// A policy with no rules on top of `profile`.
    #[must_use]
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    /// [`Profile::Modern`], the default.
    #[must_use]
    pub fn modern() -> Self {
        Self::new(Profile::Modern)
    }

    /// [`Profile::Compatible`].
    #[must_use]
    pub fn compatible() -> Self {
        Self::new(Profile::Compatible)
    }

    /// The profile underneath the rules.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// True when rules were added on top of the profile.
    #[must_use]
    pub const fn is_customised(&self) -> bool {
        !self.rules.is_empty() || !self.only.is_empty()
    }

    /// Pin algorithms matching `pattern` to `level`.
    #[must_use]
    pub fn set(mut self, category: Category, pattern: impl Into<String>, level: Level) -> Self {
        self.rules.push(Rule {
            category,
            pattern: pattern.into(),
            level,
        });
        self
    }

    /// Accept algorithms matching `pattern` ([`Level::Info`]).
    #[must_use]
    pub fn allow(self, category: Category, pattern: impl Into<String>) -> Self {
        self.set(category, pattern, Level::Info)
    }

    /// Reject algorithms matching `pattern` ([`Level::Fail`]).
    #[must_use]
    pub fn deny(self, category: Category, pattern: impl Into<String>) -> Self {
        self.set(category, pattern, Level::Fail)
    }

    /// Fail every algorithm of `category` that matches none of `patterns`.
    /// Calling it again for the same category replaces the list. The
    /// profile still judges the algorithms that are listed.
    #[must_use]
    pub fn allow_only<I, S>(mut self, category: Category, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let list: Vec<String> = patterns.into_iter().map(Into::into).collect();
        self.only.retain(|(c, _)| *c != category);
        self.only.push((category, list));
        self
    }

    /// Judge one algorithm.
    ///
    /// ```
    /// use rune_probe_ssh::audit::Category;
    /// use rune_probe_ssh::policy::{Level, Policy};
    ///
    /// let a = Policy::modern().assess(Category::Mac, "hmac-sha2-256");
    /// assert_eq!(a.level, Level::Warn);
    /// assert_eq!(a.reason, "encrypt-and-MAC; prefer the -etm@openssh.com variant");
    /// assert_eq!(a.source, Some("RFC 6668"));
    /// ```
    #[must_use]
    pub fn assess(&self, category: Category, name: &str) -> Assessment {
        let entry = lookup(category, name);
        let table_severity = entry.map_or(Severity::Informational, |e| e.severity);
        let mut out = entry.map_or_else(
            || Assessment {
                category,
                algorithm: name.to_owned(),
                level: Level::Info,
                severity: Severity::Informational,
                reason: UNKNOWN,
                source: None,
                known: false,
            },
            |e| {
                let level = e.level(self.profile);
                Assessment {
                    category,
                    algorithm: name.to_owned(),
                    level,
                    severity: severity_for(level, e.severity),
                    reason: e.reason,
                    source: Some(e.source),
                    known: true,
                }
            },
        );
        let rule = self
            .rules
            .iter()
            .rev()
            .find(|r| r.category == category && glob_match(&r.pattern, name));
        if let Some(rule) = rule {
            out.level = rule.level;
            out.reason = match rule.level {
                Level::Info => ALLOWED,
                Level::Warn => WARNED,
                Level::Fail => DENIED,
            };
            out.source = Some("policy");
            out.severity = severity_for(rule.level, table_severity);
        } else if let Some((_, list)) = self.only.iter().find(|(c, _)| *c == category)
            && !is_signal(category, name)
            && !list.iter().any(|p| glob_match(p, name))
        {
            out.level = Level::Fail;
            out.reason = NOT_LISTED;
            out.source = Some("policy");
            out.severity = severity_for(Level::Fail, table_severity);
        }
        out
    }

    /// Grade a server from what it sent. Either part may be missing (a
    /// server that only speaks SSH-1 sends no KEXINIT); the grade then
    /// reflects only what is there.
    #[must_use]
    pub fn grade(&self, ident: Option<&Identification>, kexinit: Option<&KexInit>) -> Report {
        let mut algorithms = Vec::new();
        if let Some(kexinit) = kexinit {
            for category in Category::ALL {
                for name in category.offered(kexinit) {
                    algorithms.push(self.assess(category, name));
                }
            }
        }
        let terrapin = kexinit.map(Terrapin::assess);
        let software = ident.map(Software::detect);
        let vulnerabilities = software
            .as_ref()
            .map(Software::known_cves)
            .unwrap_or_default();
        let mut report = Report {
            grade: Grade::A,
            grade_reason: "nothing the policy objects to",
            profile: self.profile,
            customised: self.is_customised(),
            protocol_v1: ident.is_some_and(Identification::offers_ssh1),
            ssh2: ident.is_none_or(Identification::speaks_ssh2),
            protocol_version: ident.map(|i| i.proto_version.clone()),
            algorithms,
            terrapin,
            software,
            vulnerabilities,
        };
        let (grade, reason) = report.compute_grade();
        report.grade = grade;
        report.grade_reason = reason;
        report
    }
}

/// Severity for a level: info is informational, warn is low, fail keeps
/// the table's severity (at least low).
fn severity_for(level: Level, table: Severity) -> Severity {
    match level {
        Level::Info => Severity::Informational,
        Level::Warn => Severity::Low,
        Level::Fail => table.max(Severity::Low),
    }
}

/// One algorithm as a policy sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Assessment {
    /// The list it was offered in.
    pub category: Category,
    /// The name as the server sent it.
    pub algorithm: String,
    /// The verdict.
    pub level: Level,
    /// Severity to report: informational for info, low for warn, the
    /// table's severity for fail.
    pub severity: Severity,
    /// Why.
    pub reason: &'static str,
    /// Where the verdict comes from: the table entry's citation, `policy`
    /// for your own rules, `None` for unknown names.
    pub source: Option<&'static str>,
    /// Whether the algorithm table knows the name.
    pub known: bool,
}

/// An overall letter grade, `A` best. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade {
    /// Nothing the policy objects to.
    A,
    /// Only discouraged algorithms, or the version matches a lesser
    /// known CVE.
    B,
    /// A failing algorithm, Terrapin exposure, or the version matches a
    /// serious known CVE.
    C,
    /// A badly broken algorithm (severity medium or worse), or every
    /// algorithm of a required category fails.
    D,
    /// No encryption or no integrity protection offered, or SSH-1.
    F,
}

impl Grade {
    /// `A` to `F`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of [`Policy::grade`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The overall grade.
    pub grade: Grade,
    /// The main reason for the grade.
    pub grade_reason: &'static str,
    /// The profile the policy is built on.
    pub profile: Profile,
    /// Whether the policy had rules on top of the profile.
    pub customised: bool,
    /// The server offers SSH-1 (`SSH-1.x` or `SSH-1.99`).
    pub protocol_v1: bool,
    /// The server speaks SSH-2 (true when no identification was given).
    pub ssh2: bool,
    /// The protocol version from the identification string, e.g. `2.0`.
    pub protocol_version: Option<String>,
    /// Every offered algorithm, by category and then in the server's order.
    pub algorithms: Vec<Assessment>,
    /// The Terrapin check, when a KEXINIT was graded.
    pub terrapin: Option<Terrapin>,
    /// The software detected from the banner.
    pub software: Option<Software>,
    /// Known CVEs whose version ranges include the banner's version. A
    /// heuristic: see [`software`](crate::software).
    pub vulnerabilities: Vec<&'static KnownCve>,
}

impl Report {
    /// Algorithms at [`Level::Fail`].
    pub fn failures(&self) -> impl Iterator<Item = &Assessment> {
        self.at(Level::Fail)
    }

    /// Algorithms at [`Level::Warn`].
    pub fn warnings(&self) -> impl Iterator<Item = &Assessment> {
        self.at(Level::Warn)
    }

    fn at(&self, level: Level) -> impl Iterator<Item = &Assessment> {
        self.algorithms.iter().filter(move |a| a.level == level)
    }

    /// True when the Terrapin check found the server exposed.
    #[must_use]
    pub fn terrapin_vulnerable(&self) -> bool {
        self.terrapin.is_some_and(|t| t.vulnerable())
    }

    fn compute_grade(&self) -> (Grade, &'static str) {
        let mut grade = (Grade::A, self.grade_reason);
        let mut cap = |to: Grade, why: &'static str| {
            if to > grade.0 {
                grade = (to, why);
            }
        };
        if self.protocol_v1 {
            cap(Grade::F, "offers SSH protocol 1");
        }
        if self.failures().any(|a| {
            a.algorithm == "none" && matches!(a.category, Category::Cipher | Category::Mac)
        }) {
            cap(Grade::F, "offers no encryption or no integrity protection");
        }
        if self.failures().any(|a| a.severity >= Severity::Medium) {
            cap(Grade::D, "offers a badly broken algorithm");
        }
        for category in [
            Category::Kex,
            Category::HostKey,
            Category::Cipher,
            Category::Mac,
        ] {
            // There is one assessment per offered name, so this checks the
            // offer without a lookup per name.
            let mut real = self
                .algorithms
                .iter()
                .filter(|a| a.category == category && !is_signal(category, &a.algorithm))
                .peekable();
            if real.peek().is_some() && real.all(|a| a.level == Level::Fail) {
                cap(Grade::D, "every algorithm of a required category fails");
            }
        }
        if self.failures().next().is_some() {
            cap(Grade::C, "offers an algorithm the policy rejects");
        }
        if self.terrapin_vulnerable() {
            cap(Grade::C, "exposed to the Terrapin attack (CVE-2023-48795)");
        }
        if self
            .vulnerabilities
            .iter()
            .any(|c| c.severity >= Severity::High)
        {
            cap(Grade::C, "version matches a serious known CVE (heuristic)");
        }
        if !self.vulnerabilities.is_empty() {
            cap(Grade::B, "version matches a known CVE (heuristic)");
        }
        if self.warnings().next().is_some() {
            cap(Grade::B, "offers discouraged algorithms");
        }
        grade
    }

    /// True when the graded algorithm `name` of `category` failed.
    /// The report as `rune-finding` findings at `location`:
    ///
    /// | Check id                        | Severity          | When                                        |
    /// | ------------------------------- | ----------------- | ------------------------------------------- |
    /// | `ssh.protocol_v1`               | medium / high     | SSH-1 offered (high when SSH-1 only)        |
    /// | `ssh.weak_<category>`           | worst of the list | algorithms at [`Level::Fail`]               |
    /// | `ssh.discouraged_<category>`    | low               | algorithms at [`Level::Warn`]               |
    /// | `ssh.terrapin`                  | medium            | Terrapin exposure                           |
    /// | `ssh.cve-<year>-<n>`            | from the table    | banner version in a known CVE's range       |
    ///
    /// Category check ids come from [`Category::check_id`] and
    /// [`Category::warn_check_id`]. CVE findings are
    /// [`Confidence::Tentative`]; the rest are certain, except Terrapin
    /// (firm: the server could still refuse the affected modes).
    ///
    /// ```
    /// use rune_probe_ssh::KexInit;
    /// use rune_probe_ssh::policy::Policy;
    /// use rune_service_probe::rune_finding::Location;
    ///
    /// let mut offer = KexInit::default();
    /// offer.encryption_server_to_client = vec!["chacha20-poly1305@openssh.com".into(), "aes128-cbc".into()];
    /// let report = Policy::modern().grade(None, Some(&offer));
    /// let findings = report.findings(&Location::network("db.internal", 22));
    /// let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    /// assert_eq!(ids, ["ssh.weak_cipher", "ssh.terrapin"]);
    /// ```
    #[must_use]
    pub fn findings(&self, location: &Location) -> Vec<Finding> {
        let mut out = Vec::new();
        let finding = |id: &str, title: String, severity, confidence| {
            Finding::<()>::new(id, title, severity, confidence, location.clone())
        };
        if self.protocol_v1 {
            let severity = if self.ssh2 {
                Severity::Medium
            } else {
                Severity::High
            };
            let version = self.protocol_version.clone().unwrap_or_default();
            out.push(
                finding(
                    "ssh.protocol_v1",
                    "SSH server offers protocol version 1".to_owned(),
                    severity,
                    Confidence::Certain,
                )
                .push_evidence(Evidence::new("protocol_version", version))
                .push_taxonomy(TaxonomyRef::cwe(327))
                .with_remediation(Remediation::new(
                    "Disable SSH protocol 1; it has known cryptographic weaknesses.",
                )),
            );
        }
        for category in Category::ALL {
            for (level, check_id, adjective, action) in [
                (Level::Fail, category.check_id(), "weak", "Remove"),
                (
                    Level::Warn,
                    category.warn_check_id(),
                    "discouraged",
                    "Consider removing",
                ),
            ] {
                let mine: Vec<&Assessment> =
                    self.at(level).filter(|a| a.category == category).collect();
                let Some(severity) = mine.iter().map(|a| a.severity).max() else {
                    continue;
                };
                let names: Vec<&str> = mine.iter().map(|a| a.algorithm.as_str()).collect();
                let mut f = finding(
                    check_id,
                    format!(
                        "SSH server offers {adjective} {} algorithms: {}",
                        category.title(),
                        names.join(", ")
                    ),
                    severity,
                    Confidence::Certain,
                )
                .push_taxonomy(TaxonomyRef::cwe(327))
                .with_remediation(Remediation::new(format!(
                    "{action} the listed {} algorithms from the server configuration.",
                    category.title()
                )));
                for a in mine {
                    f = f.push_evidence(Evidence::new(a.algorithm.clone(), a.reason));
                }
                out.push(f);
            }
        }
        if let Some(t) = self.terrapin.filter(Terrapin::vulnerable) {
            let mut modes = Vec::new();
            if t.chacha20 {
                modes.push("chacha20-poly1305@openssh.com");
            }
            if t.cbc_etm {
                modes.push("CBC cipher with an -etm MAC");
            }
            out.push(
                finding(
                    "ssh.terrapin",
                    "SSH server is exposed to the Terrapin attack (CVE-2023-48795)".to_owned(),
                    Severity::Medium,
                    Confidence::Firm,
                )
                .push_evidence(Evidence::new("strict_kex", "not offered"))
                .push_evidence(Evidence::new("affected_modes", modes.join(", ")))
                .push_taxonomy(TaxonomyRef::cwe(354))
                .with_remediation(
                    Remediation::new(
                        "Upgrade to a server that supports strict key exchange, or disable \
                         chacha20-poly1305@openssh.com and encrypt-then-MAC MACs with CBC ciphers.",
                    )
                    .push_reference("https://terrapin-attack.com/"),
                )
                .push_remediation_ref("https://nvd.nist.gov/vuln/detail/CVE-2023-48795"),
            );
        }
        if let Some(sw) = &self.software {
            let version = sw.version.as_deref().unwrap_or("?");
            for cve in &self.vulnerabilities {
                let mut f = finding(
                    &format!("ssh.{}", cve.id.to_ascii_lowercase()),
                    format!(
                        "{} {version} may be affected by {}: {}",
                        sw.family, cve.id, cve.summary
                    ),
                    cve.severity,
                    Confidence::Tentative,
                )
                .push_evidence(Evidence::new(
                    "software",
                    format!("{} {version}", sw.family),
                ))
                .push_evidence(Evidence::new(
                    "method",
                    "banner version in the affected range (heuristic)",
                ))
                .with_remediation(Remediation::new(format!(
                    "Confirm the installed build and upgrade {} if it lacks the fix ({}).",
                    sw.family, cve.source
                )))
                .push_remediation_ref(cve.url());
                if let Some(distribution) = &sw.distribution {
                    f = f.push_evidence(Evidence::new(
                        "distribution",
                        format!("{distribution}: fixes may be backported"),
                    ));
                }
                out.push(f);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_override_in_order() {
        let p = Policy::modern()
            .deny(Category::Cipher, "aes*")
            .allow(Category::Cipher, "aes256-gcm@openssh.com");
        assert_eq!(p.assess(Category::Cipher, "aes128-ctr").level, Level::Fail);
        assert_eq!(p.assess(Category::Cipher, "aes128-ctr").reason, DENIED);
        assert_eq!(
            p.assess(Category::Cipher, "aes256-gcm@openssh.com").level,
            Level::Info
        );
        // Rules are per category.
        assert_eq!(p.assess(Category::Mac, "aes128-ctr").level, Level::Info);
        let p = p.set(Category::Mac, "hmac-sha2-256", Level::Warn);
        assert_eq!(p.assess(Category::Mac, "hmac-sha2-256").reason, WARNED);
    }

    #[test]
    fn allow_only_spares_signals_and_yields_to_rules() {
        let p = Policy::compatible()
            .allow_only(Category::Kex, ["curve25519-sha256"])
            .allow(Category::Kex, "mlkem768x25519-sha256");
        assert_eq!(p.assess(Category::Kex, "ext-info-s").level, Level::Info);
        assert_eq!(
            p.assess(Category::Kex, "mlkem768x25519-sha256").level,
            Level::Info
        );
        let a = p.assess(Category::Kex, "ecdh-sha2-nistp256");
        assert_eq!((a.level, a.reason), (Level::Fail, NOT_LISTED));
        assert_eq!(a.severity, Severity::Low);
        // The listed algorithm is still judged by the profile.
        let p = Policy::modern().allow_only(Category::Kex, ["diffie-hellman-group1-sha1"]);
        let a = p.assess(Category::Kex, "diffie-hellman-group1-sha1");
        assert_eq!((a.level, a.severity), (Level::Fail, Severity::Medium));
        // A second call replaces the list.
        let p = p.allow_only(Category::Kex, ["*"]);
        assert_eq!(
            p.assess(Category::Kex, "curve25519-sha256").level,
            Level::Info
        );
    }

    #[test]
    fn unknown_names_are_info() {
        let a = Policy::modern().assess(Category::Cipher, "serpent256-ctr");
        assert!(!a.known);
        assert_eq!((a.level, a.source), (Level::Info, None));
    }

    #[test]
    fn profile_names() {
        assert_eq!("Modern".parse::<Profile>(), Ok(Profile::Modern));
        assert_eq!("compatible".parse::<Profile>(), Ok(Profile::Compatible));
        assert!("strict".parse::<Profile>().is_err());
        assert_eq!(Profile::default().to_string(), "modern");
        assert!(Grade::A < Grade::F);
    }

    #[test]
    fn grade_without_inputs() {
        let r = Policy::modern().grade(None, None);
        assert_eq!(r.grade, Grade::A);
        assert_eq!(r.findings(&Location::network("h", 22)).len(), 0);
        let id = Identification::parse(b"SSH-1.5-Cisco-1.25").unwrap_or_else(|e| panic!("{e}"));
        let r = Policy::modern().grade(Some(&id), None);
        assert_eq!(r.grade, Grade::F);
        let f = r.findings(&Location::network("h", 22));
        assert_eq!(f[0].severity, Severity::High);
    }
}

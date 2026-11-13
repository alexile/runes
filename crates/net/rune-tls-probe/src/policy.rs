//! A sans-I/O policy grader for a TLS scan [`Report`](crate::Report).
//!
//! A [`Policy`] gives every accepted protocol version, every accepted
//! cipher suite, the key exchange and a few configuration checks a
//! [`Level`] (good, ok, warn or fail) with a reason and a source, under a
//! built-in [`Profile`] that mirrors one of
//! [Mozilla's server-side TLS configurations](https://wiki.mozilla.org/Security/Server_Side_TLS)
//! plus any allow/deny rules you add, and rolls everything into a letter
//! [`Grade`]. [`Report::findings`] turns the result into `rune-finding`
//! findings.
//!
//! The verdicts follow [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325)
//! (BCP 195, recommendations for secure use of TLS) and Mozilla's
//! guidelines:
//!
//! | Item | modern | intermediate | old | Why |
//! | --- | --- | --- | --- | --- |
//! | SSL 3.0 | fail | fail | fail | POODLE; RFC 7568 |
//! | TLS 1.0, 1.1 | fail | fail | warn | RFC 8996 |
//! | TLS 1.2 | warn | ok | ok | modern is TLS 1.3 only |
//! | TLS 1.3 | good | good | good | RFC 8446 |
//! | NULL, anonymous, export suites | fail | fail | fail | RFC 9325 §4.1 |
//! | RC4 | fail | fail | fail | RFC 7465 |
//! | DES, RC2, IDEA, MD5 MAC | fail | fail | fail | RFC 9325 §4.1, RFC 6151 |
//! | 3DES | fail | fail | warn | under 128-bit security, Sweet32 |
//! | static RSA/DH/ECDH (no forward secrecy) | fail | fail | warn | RFC 9325 §4.1 |
//! | CBC (SHA-1 or SHA-2 MAC) | fail | warn | ok | RFC 9325 §4.2: AEAD only |
//! | ECDHE with AES-GCM or ChaCha20-Poly1305 | ok | good | good | Mozilla intermediate |
//! | DHE prime under 1024 bits | fail | fail | fail | Logjam |
//! | DHE prime under 2048 bits | fail | fail | warn | RFC 9325 §4.3 |
//! | no forward-secret suite at all | fail | fail | warn | RFC 9325 §4.1 |
//! | compression, no secure renegotiation | fail | fail | fail | RFC 9325 §3.3, §3.5 |
//! | no `TLS_FALLBACK_SCSV` | warn | warn | warn | RFC 7507 |
//!
//! ```
//! use rune_tls_hello::{CipherSuite, ProtocolVersion};
//! use rune_tls_probe::policy::{Category, Grade, Level, Policy};
//!
//! let policy = Policy::intermediate();
//! assert_eq!(policy.assess_version(ProtocolVersion::TLS_1_3).level, Level::Good);
//! assert_eq!(policy.assess_version(ProtocolVersion::TLS_1_0).level, Level::Fail);
//!
//! // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: tolerated by intermediate, not by modern.
//! let cbc = CipherSuite(0xc013);
//! assert_eq!(policy.assess_suite(cbc).level, Level::Warn);
//! assert_eq!(Policy::modern().assess_suite(cbc).level, Level::Fail);
//! assert_eq!(Policy::old().assess_suite(cbc).level, Level::Ok);
//!
//! // Your own rules win over the profile.
//! let strict = Policy::intermediate().deny(Category::Cipher, "*_CBC_*");
//! assert_eq!(strict.assess_suite(cbc).level, Level::Fail);
//! assert!(Grade::A < Grade::F);
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use rune_finding::{Confidence, Evidence, Finding, Remediation, Severity, TaxonomyRef};
use rune_service_probe::Target;
use rune_tls_hello::{CipherSuite, NamedGroup, ProtocolVersion};

use crate::kex::KeyExchange;
use crate::report::Observed;
use crate::suites::{is_tls13, suite_label, suite_name};

/// Mozilla's server-side TLS guidelines.
pub const MOZILLA_GUIDELINES: &str = "https://wiki.mozilla.org/Security/Server_Side_TLS";

/// How a policy judges one item. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Current best practice.
    Good,
    /// Acceptable.
    Ok,
    /// Allowed but discouraged.
    Warn,
    /// Should not be accepted.
    Fail,
}

impl Level {
    /// `good`, `ok`, `warn` or `fail`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Ok => "ok",
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

/// A built-in starting point for a [`Policy`], after Mozilla's three
/// server-side TLS configurations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Profile {
    /// TLS 1.3 only: anything older, and every pre-1.3 suite that is not
    /// AEAD with forward secrecy, fails; TLS 1.2 itself draws a warning.
    Modern,
    /// The general-purpose default: TLS 1.2 and 1.3, forward-secret AEAD
    /// suites. Legacy versions, 3DES, static RSA and DHE under 2048 bits
    /// fail; CBC suites draw a warning.
    #[default]
    Intermediate,
    /// For services that must serve very old clients: only what is broken
    /// or prohibited fails; TLS 1.0/1.1, 3DES, static RSA and 1024-bit DHE
    /// draw a warning.
    Old,
}

impl Profile {
    /// `modern`, `intermediate` or `old`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::Intermediate => "intermediate",
            Self::Old => "old",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Modern => 0,
            Self::Intermediate => 1,
            Self::Old => 2,
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
        write!(f, "unknown TLS policy profile {:?}", self.0)
    }
}

impl std::error::Error for UnknownProfile {}

impl FromStr for Profile {
    type Err = UnknownProfile;

    /// `modern`, `intermediate` or `old`, ignoring ASCII case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Modern, Self::Intermediate, Self::Old]
            .into_iter()
            .find(|p| s.eq_ignore_ascii_case(p.as_str()))
            .ok_or_else(|| UnknownProfile(s.to_owned()))
    }
}

/// What an [`Assessment`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Category {
    /// A protocol version (`SSLv3`, `TLSv1.2`...), or a missing one
    /// (`TLSv1.3 not supported`).
    Protocol,
    /// A cipher suite, by IANA name (or `0x....` for unknown codes).
    Cipher,
    /// The key exchange: `DHE <n>-bit`, `ECDHE <group>`, the TLS 1.3
    /// key-share group, and `forward secrecy`.
    KeyExchange,
    /// `compression`, `secure_renegotiation` and `fallback_scsv`.
    Configuration,
}

impl Category {
    /// Every category, in report order.
    pub const ALL: [Self; 4] = [
        Self::Protocol,
        Self::Cipher,
        Self::KeyExchange,
        Self::Configuration,
    ];

    /// Check id for failing items: `tls.weak_<category>`.
    #[must_use]
    pub const fn check_id(self) -> &'static str {
        match self {
            Self::Protocol => "tls.weak_protocol",
            Self::Cipher => "tls.weak_cipher",
            Self::KeyExchange => "tls.weak_key_exchange",
            Self::Configuration => "tls.weak_configuration",
        }
    }

    /// Check id for discouraged items: `tls.discouraged_<category>`.
    #[must_use]
    pub const fn warn_check_id(self) -> &'static str {
        match self {
            Self::Protocol => "tls.discouraged_protocol",
            Self::Cipher => "tls.discouraged_cipher",
            Self::KeyExchange => "tls.discouraged_key_exchange",
            Self::Configuration => "tls.discouraged_configuration",
        }
    }

    /// A short lowercase title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Protocol => "protocol version",
            Self::Cipher => "cipher suite",
            Self::KeyExchange => "key exchange",
            Self::Configuration => "configuration",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

/// One item as a policy sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Assessment {
    /// What kind of item.
    pub category: Category,
    /// The item: a version, a suite name, `DHE 1024-bit`...
    pub item: String,
    /// The verdict.
    pub level: Level,
    /// Severity to report: informational for good and ok, low for warn,
    /// the table's severity for fail.
    pub severity: Severity,
    /// Why.
    pub reason: &'static str,
    /// Where the verdict comes from (an RFC section, Mozilla's
    /// guidelines), `policy` for your own rules, `None` for unknown items.
    pub source: Option<&'static str>,
}

/// One row of the verdict table: the level per profile (modern,
/// intermediate, old), and the severity when it fails.
#[derive(Debug, Clone, Copy)]
struct Rate {
    levels: [Level; 3],
    severity: Severity,
    reason: &'static str,
    source: &'static str,
}

const fn rate(
    levels: [Level; 3],
    severity: Severity,
    reason: &'static str,
    source: &'static str,
) -> Rate {
    Rate {
        levels,
        severity,
        reason,
        source,
    }
}

use Level::{Fail as F, Good as G, Ok as O, Warn as W};

const SOURCE_9325_41: &str = "RFC 9325 §4.1";
const SOURCE_MOZILLA: &str = "Mozilla server-side TLS guidelines";

const NULL: Rate = rate(
    [F, F, F],
    Severity::Critical,
    "no encryption (NULL cipher)",
    SOURCE_9325_41,
);
const ANON: Rate = rate(
    [F, F, F],
    Severity::Critical,
    "anonymous key exchange: no server authentication",
    SOURCE_9325_41,
);
const EXPORT: Rate = rate(
    [F, F, F],
    Severity::Critical,
    "export-grade cryptography (FREAK, Logjam)",
    SOURCE_9325_41,
);
const DES: Rate = rate(
    [F, F, F],
    Severity::High,
    "DES or RC2: far below 112-bit security",
    SOURCE_9325_41,
);
const RC4: Rate = rate([F, F, F], Severity::Medium, "RC4 is prohibited", "RFC 7465");
const IDEA: Rate = rate(
    [F, F, F],
    Severity::Medium,
    "64-bit block cipher (Sweet32)",
    SOURCE_9325_41,
);
const TRIPLE_DES: Rate = rate(
    [F, F, W],
    Severity::Medium,
    "3DES: 64-bit blocks (Sweet32) and under 128-bit security; only the old profile lists it",
    SOURCE_9325_41,
);
const MD5: Rate = rate(
    [F, F, F],
    Severity::Medium,
    "HMAC-MD5 record MAC",
    "RFC 6151",
);
const STATIC: Rate = rate(
    [F, F, W],
    Severity::Low,
    "static key exchange: no forward secrecy",
    SOURCE_9325_41,
);
const CBC_SHA1: Rate = rate(
    [F, W, O],
    Severity::Low,
    "CBC with HMAC-SHA1 (MAC-then-encrypt, Lucky Thirteen); prefer AEAD",
    "RFC 9325 §4.2",
);
const CBC_SHA2: Rate = rate(
    [F, W, O],
    Severity::Low,
    "CBC mode (MAC-then-encrypt); prefer AEAD",
    "RFC 9325 §4.2",
);
const CCM_8: Rate = rate(
    [W, W, W],
    Severity::Low,
    "truncated 64-bit authentication tag (CCM_8)",
    "RFC 8446 appendix B.4",
);
const ECDHE_AEAD: Rate = rate(
    [O, G, G],
    Severity::Informational,
    "forward-secret AEAD suite",
    SOURCE_MOZILLA,
);
const OTHER_AEAD: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "AEAD suite",
    "RFC 9325 §4.2",
);
const TLS13_SUITE: Rate = rate(
    [G, G, G],
    Severity::Informational,
    "TLS 1.3 AEAD suite",
    SOURCE_MOZILLA,
);
const TLS13_CCM: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "TLS 1.3 AES-CCM: sound, but not in Mozilla's lists",
    "RFC 8446 §9.1",
);

const SSL3: Rate = rate(
    [F, F, F],
    Severity::High,
    "SSL 3.0 is broken (POODLE) and prohibited",
    "RFC 7568",
);
const TLS10: Rate = rate(
    [F, F, W],
    Severity::Medium,
    "deprecated; only the old profile still allows it",
    "RFC 8996",
);
const TLS12: Rate = rate(
    [W, O, O],
    Severity::Low,
    "fine with AEAD suites; the modern profile is TLS 1.3 only",
    "RFC 9325 §3.1",
);
const TLS13: Rate = rate(
    [G, G, G],
    Severity::Informational,
    "current version",
    "RFC 8446",
);
const NO_TLS13: Rate = rate(
    [F, W, O],
    Severity::Low,
    "TLS 1.3 should be supported",
    "RFC 9325 §3.1",
);
const NO_MODERN: Rate = rate(
    [F, F, F],
    Severity::Medium,
    "neither TLS 1.2 nor TLS 1.3: TLS 1.2 must be supported",
    "RFC 9325 §3.1",
);

const DH_TINY: Rate = rate(
    [F, F, F],
    Severity::High,
    "Diffie-Hellman prime under 1024 bits (Logjam)",
    "RFC 9325 §4.3",
);
const DH_SMALL: Rate = rate(
    [F, F, W],
    Severity::Medium,
    "Diffie-Hellman prime under 2048 bits",
    "RFC 9325 §4.3",
);
const DH_OK: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "Diffie-Hellman prime of at least 2048 bits",
    "RFC 9325 §4.3",
);
const GROUP_GOOD: Rate = rate(
    [G, G, G],
    Severity::Informational,
    "modern curve",
    SOURCE_MOZILLA,
);
const GROUP_OK: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "NIST curve",
    SOURCE_MOZILLA,
);
const GROUP_FFDHE: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "RFC 7919 finite-field group of at least 2048 bits",
    "RFC 7919",
);
const GROUP_LEGACY: Rate = rate(
    [W, W, W],
    Severity::Low,
    "curve not in Mozilla's lists",
    SOURCE_MOZILLA,
);
const NO_FS: Rate = rate(
    [F, F, W],
    Severity::Medium,
    "no accepted suite gives forward secrecy",
    SOURCE_9325_41,
);
const FS_PARTLY: Rate = rate(
    [O, O, O],
    Severity::Informational,
    "forward secrecy available; the static suites are judged on their own",
    SOURCE_9325_41,
);
const FS_ALWAYS: Rate = rate(
    [G, G, G],
    Severity::Informational,
    "every accepted suite gives forward secrecy",
    SOURCE_9325_41,
);
const COMPRESSION: Rate = rate(
    [F, F, F],
    Severity::Medium,
    "TLS compression enabled (CRIME)",
    "RFC 9325 §3.3",
);
const RENEGOTIATION: Rate = rate(
    [F, F, F],
    Severity::Medium,
    "no RFC 5746 secure renegotiation",
    "RFC 9325 §3.5",
);
const FALLBACK: Rate = rate(
    [W, W, W],
    Severity::Low,
    "TLS_FALLBACK_SCSV downgrade protection not honoured",
    "RFC 7507",
);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Rule {
    category: Category,
    pattern: String,
    level: Level,
}

/// A grading policy: a [`Profile`] plus your own rules.
///
/// Rules are checked before the profile, the most recently added first:
/// [`allow`](Self::allow) pins matching items to ok, [`deny`](Self::deny)
/// to fail, [`set`](Self::set) to any level, and
/// [`allow_only`](Self::allow_only) fails every item of a category that
/// matches none of its patterns. Patterns are exact item names, or use `*`
/// as a wildcard for any run of characters (`TLS_ECDHE_*_GCM_*`).
///
/// ```
/// use rune_tls_hello::{CipherSuite, ProtocolVersion};
/// use rune_tls_probe::policy::{Category, Level, Policy};
///
/// let policy = Policy::old()
///     .deny(Category::Protocol, "TLSv1.0")
///     .allow_only(Category::Cipher, ["TLS_ECDHE_*", "TLS_AES_*", "TLS_CHACHA20_*"]);
/// assert_eq!(policy.assess_version(ProtocolVersion::TLS_1_0).level, Level::Fail);
/// assert_eq!(policy.assess_version(ProtocolVersion::TLS_1_1).level, Level::Warn);
/// assert_eq!(policy.assess_suite(CipherSuite(0x002f)).level, Level::Fail); // static RSA
/// assert_eq!(policy.assess_suite(CipherSuite(0xc02f)).level, Level::Good);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Policy {
    profile: Profile,
    rules: Vec<Rule>,
    only: Vec<(Category, Vec<String>)>,
}

const ALLOWED: &str = "allowed by the policy";
const DENIED: &str = "denied by the policy";
const WARNED: &str = "flagged by the policy";
const BLESSED: &str = "preferred by the policy";
const NOT_LISTED: &str = "not in the policy's allow list";
const UNKNOWN: &str = "not in the verdict table; review by hand";

impl Policy {
    /// A policy with no rules on top of `profile`.
    #[must_use]
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    /// [`Profile::Modern`].
    #[must_use]
    pub fn modern() -> Self {
        Self::new(Profile::Modern)
    }

    /// [`Profile::Intermediate`], the default.
    #[must_use]
    pub fn intermediate() -> Self {
        Self::new(Profile::Intermediate)
    }

    /// [`Profile::Old`].
    #[must_use]
    pub fn old() -> Self {
        Self::new(Profile::Old)
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

    /// Pin items of `category` matching `pattern` to `level`.
    #[must_use]
    pub fn set(mut self, category: Category, pattern: impl Into<String>, level: Level) -> Self {
        self.rules.push(Rule {
            category,
            pattern: pattern.into(),
            level,
        });
        self
    }

    /// Accept items matching `pattern` ([`Level::Ok`]).
    #[must_use]
    pub fn allow(self, category: Category, pattern: impl Into<String>) -> Self {
        self.set(category, pattern, Level::Ok)
    }

    /// Reject items matching `pattern` ([`Level::Fail`]).
    #[must_use]
    pub fn deny(self, category: Category, pattern: impl Into<String>) -> Self {
        self.set(category, pattern, Level::Fail)
    }

    /// Fail every item of `category` that matches none of `patterns`.
    /// Calling it again for the same category replaces the list. The
    /// profile still judges the items that are listed, and explicit rules
    /// win over it.
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

    /// Judge a protocol version.
    ///
    /// ```
    /// use rune_tls_hello::ProtocolVersion;
    /// use rune_tls_probe::policy::{Level, Policy};
    ///
    /// let a = Policy::modern().assess_version(ProtocolVersion::TLS_1_2);
    /// assert_eq!(a.level, Level::Warn);
    /// assert_eq!(a.source, Some("RFC 9325 §3.1"));
    /// ```
    #[must_use]
    pub fn assess_version(&self, version: ProtocolVersion) -> Assessment {
        let table = match version {
            ProtocolVersion::TLS_1_3 => Some(TLS13),
            ProtocolVersion::TLS_1_2 => Some(TLS12),
            ProtocolVersion::TLS_1_1 | ProtocolVersion::TLS_1_0 => Some(TLS10),
            v if v <= ProtocolVersion::SSL_3_0 => Some(SSL3),
            _ => None,
        };
        self.judge(Category::Protocol, version.to_string(), table)
    }

    /// Judge a cipher suite on its own: the worst of its key exchange,
    /// cipher and MAC.
    ///
    /// ```
    /// use rune_tls_hello::CipherSuite;
    /// use rune_tls_probe::policy::{Level, Policy};
    ///
    /// // TLS_RSA_WITH_AES_128_GCM_SHA256: AEAD, but static RSA.
    /// let a = Policy::intermediate().assess_suite(CipherSuite(0x009c));
    /// assert_eq!((a.level, a.reason), (Level::Fail, "static key exchange: no forward secrecy"));
    /// assert_eq!(Policy::old().assess_suite(CipherSuite(0x009c)).level, Level::Warn);
    /// ```
    #[must_use]
    pub fn assess_suite(&self, suite: CipherSuite) -> Assessment {
        let table = suite_rates(suite).into_iter().max_by_key(|r| {
            (
                r.levels.get(self.profile.index()).copied().unwrap_or(O),
                r.severity,
            )
        });
        self.judge(Category::Cipher, suite_label(suite), table)
    }

    /// Judge `ServerKeyExchange` parameters.
    ///
    /// ```
    /// use rune_tls_probe::KeyExchange;
    /// use rune_tls_probe::policy::{Level, Policy};
    ///
    /// let dh1024 = KeyExchange::Dhe { prime_bits: 1024 };
    /// assert_eq!(Policy::intermediate().assess_key_exchange(dh1024).level, Level::Fail);
    /// assert_eq!(Policy::old().assess_key_exchange(dh1024).level, Level::Warn);
    /// ```
    #[must_use]
    pub fn assess_key_exchange(&self, key_exchange: KeyExchange) -> Assessment {
        let table = match key_exchange {
            KeyExchange::Dhe { prime_bits } if prime_bits < 1024 => DH_TINY,
            KeyExchange::Dhe { prime_bits } if prime_bits < 2048 => DH_SMALL,
            KeyExchange::Dhe { .. } => DH_OK,
            KeyExchange::Ecdhe { group } => group_rate(group),
        };
        self.judge(Category::KeyExchange, key_exchange.to_string(), Some(table))
    }

    /// Grade a scan. Versions, suites and checks that were not probed are
    /// not judged; [`Report::complete`] says whether the scan covered
    /// everything.
    ///
    /// ```
    /// use rune_tls_hello::{CipherSuite, ProtocolVersion, ServerHello};
    /// use rune_tls_probe::policy::{Grade, Policy};
    /// use rune_tls_probe::{ResponseReader, ScanOptions, Scanner};
    ///
    /// // A TLS 1.2-only server with one forward-secret GCM suite and one CBC suite.
    /// let accepted = [CipherSuite(0xc02f), CipherSuite(0xc013)];
    /// let mut scanner = Scanner::new(ScanOptions::default());
    /// while let Some(offer) = scanner.next_offer() {
    ///     let pick = accepted.iter().find(|s| offer.cipher_suites.contains(s));
    ///     let wire = match pick {
    ///         Some(&suite) if offer.version == ProtocolVersion::TLS_1_2 => ServerHello::new()
    ///             .with_cipher_suite(suite)
    ///             .with_extension(rune_tls_hello::Extension::renegotiation_info(&[]).unwrap())
    ///             .to_records(ProtocolVersion::TLS_1_2, 16_384)
    ///             .unwrap(),
    ///         _ => vec![21, 3, 3, 0, 2, 2, 40],
    ///     };
    ///     let mut reader = ResponseReader::new();
    ///     let outcome = reader.feed(&wire).unwrap_or_else(|| reader.finish());
    ///     scanner.record(&outcome);
    /// }
    /// let scan = scanner.finish();
    ///
    /// let report = Policy::intermediate().grade(&scan);
    /// assert_eq!(report.grade, Grade::B);
    /// let warned: Vec<&str> = report.warnings().map(|a| a.item.as_str()).collect();
    /// assert_eq!(warned, ["TLSv1.3 not supported", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]);
    ///
    /// assert_eq!(Policy::modern().grade(&scan).grade, Grade::C);
    /// assert_eq!(Policy::old().grade(&scan).grade, Grade::A);
    /// ```
    #[must_use]
    pub fn grade(&self, scan: &crate::Report) -> Report {
        let mut assessments = Vec::new();
        let supported = scan.supported_versions();
        for &version in &supported {
            assessments.push(self.assess_version(version));
        }
        let probed = |v: ProtocolVersion| scan.version(v).is_some();
        if scan.speaks_tls() {
            let has = |v: ProtocolVersion| supported.contains(&v);
            if !has(ProtocolVersion::TLS_1_2)
                && !has(ProtocolVersion::TLS_1_3)
                && probed(ProtocolVersion::TLS_1_2)
                && probed(ProtocolVersion::TLS_1_3)
            {
                assessments.push(self.judge(
                    Category::Protocol,
                    "no TLS 1.2 or 1.3".to_owned(),
                    Some(NO_MODERN),
                ));
            } else if !has(ProtocolVersion::TLS_1_3) && probed(ProtocolVersion::TLS_1_3) {
                assessments.push(self.judge(
                    Category::Protocol,
                    "TLSv1.3 not supported".to_owned(),
                    Some(NO_TLS13),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for result in scan.versions.iter().filter(|v| v.supported) {
            for &suite in &result.cipher_suites {
                if seen.insert(suite) {
                    assessments.push(self.assess_suite(suite));
                }
            }
        }

        for kx in &scan.key_exchanges {
            assessments.push(self.assess_key_exchange(kx.key_exchange));
        }
        let mut groups = BTreeSet::new();
        for result in scan.versions.iter().filter(|v| v.supported) {
            if let Some(group) = result.key_share_group
                && groups.insert(group)
            {
                let item = format!("TLS 1.3 key share {group}");
                assessments.push(self.judge(Category::KeyExchange, item, Some(group_rate(group))));
            }
        }
        if let Some(fs) = forward_secrecy(scan) {
            assessments.push(self.judge(
                Category::KeyExchange,
                "forward secrecy".to_owned(),
                Some(fs),
            ));
        }

        // Each check fails on the observation named here.
        for (observed, bad, item, table) in [
            (scan.compression, Observed::Yes, "compression", COMPRESSION),
            (
                scan.secure_renegotiation,
                Observed::No,
                "secure_renegotiation",
                RENEGOTIATION,
            ),
            (scan.fallback_scsv, Observed::No, "fallback_scsv", FALLBACK),
        ] {
            if observed == bad {
                assessments.push(self.judge(Category::Configuration, item.to_owned(), Some(table)));
            }
        }

        let complete = !scan.truncated
            && scan
                .versions
                .iter()
                .all(|v| v.complete || !v.supported || v.cipher_suites.is_empty());
        let mut report = Report {
            grade: Grade::A,
            grade_reason: String::new(),
            reasons: Vec::new(),
            profile: self.profile,
            customised: self.is_customised(),
            assessments,
            speaks_tls: scan.speaks_tls(),
            complete,
        };
        report.compute_grade();
        report
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "callers build the name just for this call"
    )]
    fn judge(&self, category: Category, item: String, table: Option<Rate>) -> Assessment {
        let table_severity = table.map_or(Severity::Informational, |t| t.severity);
        let mut out = table.map_or_else(
            || Assessment {
                category,
                item: item.clone(),
                level: Level::Ok,
                severity: Severity::Informational,
                reason: UNKNOWN,
                source: None,
            },
            |t| {
                let level = t
                    .levels
                    .get(self.profile.index())
                    .copied()
                    .unwrap_or(Level::Ok);
                Assessment {
                    category,
                    item: item.clone(),
                    level,
                    severity: severity_for(level, t.severity),
                    reason: t.reason,
                    source: Some(t.source),
                }
            },
        );
        let rule = self
            .rules
            .iter()
            .rev()
            .find(|r| r.category == category && glob_match(&r.pattern, &item));
        if let Some(rule) = rule {
            out.level = rule.level;
            out.reason = match rule.level {
                Level::Good => BLESSED,
                Level::Ok => ALLOWED,
                Level::Warn => WARNED,
                Level::Fail => DENIED,
            };
            out.source = Some("policy");
            out.severity = severity_for(rule.level, table_severity);
        } else if let Some((_, list)) = self.only.iter().find(|(c, _)| *c == category)
            && !list.iter().any(|p| glob_match(p, &item))
        {
            out.level = Level::Fail;
            out.reason = NOT_LISTED;
            out.source = Some("policy");
            out.severity = severity_for(Level::Fail, table_severity);
        }
        out
    }
}

/// Severity for a level: good and ok are informational, warn is low,
/// fail keeps the table's severity (at least low).
fn severity_for(level: Level, table: Severity) -> Severity {
    match level {
        Level::Good | Level::Ok => Severity::Informational,
        Level::Warn => Severity::Low,
        Level::Fail => table.max(Severity::Low),
    }
}

/// Every table row that applies to a suite; empty for unknown codes.
fn suite_rates(suite: CipherSuite) -> Vec<Rate> {
    let Some(name) = suite_name(suite) else {
        return Vec::new();
    };
    if is_tls13(suite) {
        return vec![match suite.0 {
            0x1304 => TLS13_CCM,
            0x1305 => CCM_8,
            _ => TLS13_SUITE,
        }];
    }
    let Some((kx, rest)) = name
        .strip_prefix("TLS_")
        .and_then(|body| body.split_once("_WITH_"))
    else {
        return Vec::new();
    };
    let mut rates = Vec::new();
    if rest.starts_with("NULL_") {
        rates.push(NULL);
    }
    if kx.contains("anon") {
        rates.push(ANON);
    }
    if kx.contains("EXPORT") {
        rates.push(EXPORT);
    }
    if rest.starts_with("RC4_") {
        rates.push(RC4);
    }
    if rest.starts_with("DES") || rest.starts_with("RC2_") {
        rates.push(DES);
    }
    if rest.starts_with("IDEA_") {
        rates.push(IDEA);
    }
    if rest.starts_with("3DES_") {
        rates.push(TRIPLE_DES);
    }
    if rest.ends_with("_MD5") {
        rates.push(MD5);
    }
    let ephemeral = kx.starts_with("DHE_") || kx.starts_with("ECDHE_");
    let pure_psk = kx == "PSK";
    if !ephemeral && !kx.contains("anon") && !pure_psk {
        rates.push(STATIC);
    }
    if rest.contains("_CBC_") {
        rates.push(if rest.ends_with("_SHA") {
            CBC_SHA1
        } else {
            CBC_SHA2
        });
    }
    if rest.contains("CCM_8") {
        rates.push(CCM_8);
    }
    let aead = rest.contains("_GCM_") || rest.contains("CHACHA20") || rest.contains("_CCM");
    if aead {
        let mozilla = kx.starts_with("ECDHE_")
            && (rest.starts_with("AES_") && rest.contains("_GCM_") || rest.starts_with("CHACHA20"));
        rates.push(if mozilla { ECDHE_AEAD } else { OTHER_AEAD });
    }
    if rates.is_empty() {
        rates.push(OTHER_AEAD);
    }
    rates
}

fn group_rate(group: NamedGroup) -> Rate {
    match group {
        NamedGroup::X25519 | NamedGroup::X448 | NamedGroup::X25519_MLKEM768 => GROUP_GOOD,
        NamedGroup::SECP256R1 | NamedGroup::SECP384R1 | NamedGroup::SECP521R1 => GROUP_OK,
        g if (0x0100..=0x0104).contains(&g.0) => GROUP_FFDHE,
        _ => GROUP_LEGACY,
    }
}

/// Whether a suite gives forward secrecy: every TLS 1.3 suite, and the
/// ephemeral (EC)DHE exchanges before it. Anonymous exchanges are ephemeral
/// but judged on their own.
fn is_forward_secret(suite: CipherSuite) -> bool {
    if is_tls13(suite) {
        return true;
    }
    suite_name(suite)
        .and_then(|name| name.strip_prefix("TLS_"))
        .is_some_and(|body| body.starts_with("DHE_") || body.starts_with("ECDHE_"))
}

fn forward_secrecy(scan: &crate::Report) -> Option<Rate> {
    let supported: Vec<_> = scan.versions.iter().filter(|v| v.supported).collect();
    let all: Vec<CipherSuite> = supported
        .iter()
        .flat_map(|v| v.cipher_suites.iter().copied())
        .filter(|s| suite_name(*s).is_some_and(|n| !n.contains("anon")))
        .collect();
    if all.is_empty() {
        return None;
    }
    if !all.iter().any(|s| is_forward_secret(*s)) {
        return Some(NO_FS);
    }
    // The scan enumerates suites in chunks, so their order is not the
    // server's full preference order; a preference check would guess.
    if all.iter().all(|s| is_forward_secret(*s)) {
        Some(FS_ALWAYS)
    } else {
        Some(FS_PARTLY)
    }
}

/// Matches `name` against a pattern where `*` stands for any run of
/// characters (possibly empty). No other metacharacters.
///
/// ```
/// use rune_tls_probe::policy::glob_match;
///
/// assert!(glob_match("TLS_ECDHE_*_GCM_*", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
/// assert!(glob_match("*", "anything"));
/// assert!(!glob_match("TLS_RSA_*", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
/// ```
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return name.is_empty();
    };
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = rest.get(at + part.len()..).unwrap_or(""),
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// An overall letter grade, `A` best. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade {
    /// Nothing the policy objects to.
    A,
    /// Only discouraged items.
    B,
    /// A failing item of low or medium severity: a deprecated version,
    /// RC4, 3DES, a small DH prime, compression, no forward secrecy...
    C,
    /// A failing item of high severity: SSL 3.0, DES, a DH prime under
    /// 1024 bits.
    D,
    /// A critical failure (NULL, anonymous or export suites), or no TLS
    /// at all.
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
    pub grade_reason: String,
    /// Every reason that lowered the grade, worst first; empty for an A.
    pub reasons: Vec<String>,
    /// The profile the policy is built on.
    pub profile: Profile,
    /// Whether the policy had rules on top of the profile.
    pub customised: bool,
    /// Every judged item: versions, suites, key exchange, configuration.
    pub assessments: Vec<Assessment>,
    /// Whether the server accepted any version.
    pub speaks_tls: bool,
    /// Whether the scan covered every version and suite it set out to
    /// (not truncated by the attempt budget).
    pub complete: bool,
}

impl Report {
    /// Items at [`Level::Fail`].
    pub fn failures(&self) -> impl Iterator<Item = &Assessment> {
        self.at(Level::Fail)
    }

    /// Items at [`Level::Warn`].
    pub fn warnings(&self) -> impl Iterator<Item = &Assessment> {
        self.at(Level::Warn)
    }

    fn at(&self, level: Level) -> impl Iterator<Item = &Assessment> {
        self.assessments.iter().filter(move |a| a.level == level)
    }

    fn compute_grade(&mut self) {
        let mut caps: Vec<(Grade, String)> = Vec::new();
        if !self.speaks_tls {
            caps.push((Grade::F, "accepts no SSL or TLS version".to_owned()));
        }
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut other = Vec::new();
        for a in self.failures() {
            let bucket = match a.severity {
                Severity::Critical => &mut critical,
                Severity::High => &mut high,
                _ => &mut other,
            };
            bucket.push(a.item.clone());
        }
        for (grade, what, items) in [
            (Grade::F, "critical failures", critical),
            (Grade::D, "badly broken items", high),
            (Grade::C, "items the policy rejects", other),
        ] {
            if !items.is_empty() {
                caps.push((grade, format!("{what}: {}", list(&items))));
            }
        }
        let warned: Vec<String> = self.warnings().map(|a| a.item.clone()).collect();
        if !warned.is_empty() {
            caps.push((Grade::B, format!("discouraged items: {}", list(&warned))));
        }
        // Caps were pushed worst first.
        if let Some((grade, reason)) = caps.first() {
            self.grade = *grade;
            self.grade_reason.clone_from(reason);
        } else {
            self.grade = Grade::A;
            "nothing the policy objects to".clone_into(&mut self.grade_reason);
        }
        self.reasons = caps.into_iter().map(|(_, r)| r).collect();
    }

    /// The report as `rune-finding` findings at `target`:
    ///
    /// | Check id | Severity | When |
    /// | --- | --- | --- |
    /// | `tls.weak_<category>` | worst of the list | items at [`Level::Fail`] |
    /// | `tls.discouraged_<category>` | low | items at [`Level::Warn`] |
    ///
    /// `<category>` is `protocol`, `cipher`, `key_exchange` or
    /// `configuration` ([`Category::check_id`]). Evidence lists each item
    /// with its reason.
    ///
    /// ```
    /// use rune_service_probe::Target;
    /// use rune_tls_hello::{CipherSuite, ProtocolVersion};
    /// use rune_tls_probe::policy::Policy;
    /// use rune_tls_probe::{Report, VersionResult};
    ///
    /// let mut scan = Report::default();
    /// let mut tls10 = VersionResult::new(ProtocolVersion::TLS_1_0);
    /// tls10.supported = true;
    /// // 3DES with static RSA, and ECDHE with AES-CBC.
    /// tls10.cipher_suites = vec![CipherSuite(0x000a), CipherSuite(0xc013)];
    /// scan.versions.push(tls10);
    ///
    /// let report = Policy::intermediate().grade(&scan);
    /// let ids: Vec<String> = report
    ///     .findings(&Target::new("app.test", 443))
    ///     .into_iter()
    ///     .map(|f| f.check_id)
    ///     .collect();
    /// assert_eq!(ids, ["tls.weak_protocol", "tls.weak_cipher", "tls.discouraged_cipher"]);
    /// ```
    #[must_use]
    pub fn findings(&self, target: &Target) -> Vec<Finding> {
        let mut out = Vec::new();
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
                let names: Vec<String> = mine.iter().map(|a| a.item.clone()).collect();
                let mut f = target
                    .finding(
                        check_id,
                        format!(
                            "TLS server has {adjective} {} settings under the {} policy: {}",
                            category.title(),
                            self.profile,
                            list(&names)
                        ),
                        severity,
                        Confidence::Certain,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(327))
                    .with_remediation(Remediation::new(format!(
                        "{action} the listed {} settings; see Mozilla's {} configuration.",
                        category.title(),
                        self.profile
                    )))
                    .push_remediation_ref(MOZILLA_GUIDELINES);
                for a in mine {
                    let why = a.source.map_or_else(
                        || a.reason.to_owned(),
                        |source| format!("{} ({source})", a.reason),
                    );
                    f = f.push_evidence(Evidence::new(a.item.clone(), why));
                }
                out.push(f);
            }
        }
        out
    }
}

/// Up to six items, then a count.
fn list(items: &[String]) -> String {
    const SHOWN: usize = 6;
    let head = items
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > SHOWN {
        format!("{head} and {} more", items.len() - SHOWN)
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level(policy: &Policy, code: u16) -> Level {
        policy.assess_suite(CipherSuite(code)).level
    }

    #[test]
    fn suite_table_known_answers() {
        let [m, i, o] = [Policy::modern(), Policy::intermediate(), Policy::old()];
        // (code, modern, intermediate, old)
        let cases: &[(u16, Level, Level, Level)] = &[
            (0x0001, F, F, F), // RSA_WITH_NULL_MD5
            (0x0003, F, F, F), // RSA_EXPORT_WITH_RC4_40_MD5
            (0x0005, F, F, F), // RSA_WITH_RC4_128_SHA
            (0x0009, F, F, F), // RSA_WITH_DES_CBC_SHA
            (0x0034, F, F, F), // DH_anon_WITH_AES_128_CBC_SHA
            (0x000a, F, F, W), // RSA_WITH_3DES_EDE_CBC_SHA
            (0x0016, F, F, W), // DHE_RSA_WITH_3DES_EDE_CBC_SHA
            (0x002f, F, F, W), // RSA_WITH_AES_128_CBC_SHA
            (0x009c, F, F, W), // RSA_WITH_AES_128_GCM_SHA256
            (0xc013, F, W, O), // ECDHE_RSA_WITH_AES_128_CBC_SHA
            (0xc027, F, W, O), // ECDHE_RSA_WITH_AES_128_CBC_SHA256
            (0xc02f, O, G, G), // ECDHE_RSA_WITH_AES_128_GCM_SHA256
            (0xcca8, O, G, G), // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            (0x009e, O, O, O), // DHE_RSA_WITH_AES_128_GCM_SHA256
            (0xc0ae, W, W, W), // ECDHE_ECDSA_WITH_AES_128_CCM_8
            (0x1301, G, G, G),
            (0x1304, O, O, O),
            (0x1305, W, W, W),
            (0xabcd, O, O, O), // unknown
        ];
        for &(code, lm, li, lo) in cases {
            assert_eq!(
                [level(&m, code), level(&i, code), level(&o, code)],
                [lm, li, lo],
                "{code:#06x}"
            );
        }
        let null = i.assess_suite(CipherSuite(0x0002));
        assert_eq!(null.severity, Severity::Critical);
        assert_eq!(null.reason, NULL.reason);
        assert!(i.assess_suite(CipherSuite(0xabcd)).source.is_none());
    }

    #[test]
    fn versions() {
        let i = Policy::intermediate();
        assert_eq!(
            i.assess_version(ProtocolVersion::SSL_3_0).severity,
            Severity::High
        );
        assert_eq!(
            i.assess_version(ProtocolVersion::TLS_1_1).level,
            Level::Fail
        );
        assert_eq!(i.assess_version(ProtocolVersion::TLS_1_2).level, Level::Ok);
        assert_eq!(
            Policy::old().assess_version(ProtocolVersion::TLS_1_0).level,
            Level::Warn
        );
        assert_eq!(i.assess_version(ProtocolVersion(0x0305)).reason, UNKNOWN);
    }

    #[test]
    fn key_exchange_levels() {
        let i = Policy::intermediate();
        let dh = |bits| i.assess_key_exchange(KeyExchange::Dhe { prime_bits: bits });
        assert_eq!(
            (dh(512).level, dh(512).severity),
            (Level::Fail, Severity::High)
        );
        assert_eq!(
            (dh(1024).level, dh(1024).severity),
            (Level::Fail, Severity::Medium)
        );
        assert_eq!(dh(2048).level, Level::Ok);
        let ec = |g| i.assess_key_exchange(KeyExchange::Ecdhe { group: g }).level;
        assert_eq!(ec(NamedGroup::X25519), Level::Good);
        assert_eq!(ec(NamedGroup::SECP384R1), Level::Ok);
        assert_eq!(ec(NamedGroup(0x0015)), Level::Warn);
    }

    #[test]
    fn rules() {
        let p = Policy::intermediate()
            .deny(Category::Cipher, "TLS_ECDHE_*")
            .allow(Category::Cipher, "TLS_ECDHE_ECDSA_*")
            .set(Category::Protocol, "TLSv1.2", Level::Good);
        assert_eq!(level(&p, 0xc02f), Level::Fail);
        assert_eq!(p.assess_suite(CipherSuite(0xc02f)).reason, DENIED);
        assert_eq!(level(&p, 0xc02b), Level::Ok);
        assert_eq!(p.assess_version(ProtocolVersion::TLS_1_2).reason, BLESSED);
        assert!(p.is_customised());
        let only = Policy::old().allow_only(Category::Protocol, ["TLSv1.3"]);
        let a = only.assess_version(ProtocolVersion::TLS_1_2);
        assert_eq!((a.level, a.reason), (Level::Fail, NOT_LISTED));
    }

    #[test]
    fn globs() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(glob_match("a*", "a"));
        assert!(glob_match("*c", "abc"));
        assert!(glob_match("a*b*c", "a-b-c"));
        assert!(!glob_match("a*b*c", "a-c-b"));
        assert!(!glob_match("ab*ba", "aba"));
        assert!(glob_match("**", ""));
    }

    #[test]
    fn profile_names() {
        assert_eq!("Modern".parse::<Profile>(), Ok(Profile::Modern));
        assert_eq!("OLD".parse::<Profile>(), Ok(Profile::Old));
        assert!("strict".parse::<Profile>().is_err());
        assert_eq!(Profile::default().to_string(), "intermediate");
        assert_eq!(Level::Warn.to_string(), "warn");
    }

    #[test]
    fn empty_scan_is_f() {
        let r = Policy::intermediate().grade(&crate::Report::default());
        assert_eq!(r.grade, Grade::F);
        assert_eq!(r.grade_reason, "accepts no SSL or TLS version");
        assert_eq!(r.findings(&Target::new("h", 443)), Vec::new());
    }

    #[test]
    fn long_lists_are_shortened() {
        let items: Vec<String> = (0..9).map(|i| i.to_string()).collect();
        assert_eq!(list(&items), "0, 1, 2, 3, 4, 5 and 3 more");
    }
}

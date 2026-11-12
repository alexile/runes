//! Chain building and path validation against a trust store.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cert::SignatureError;
use crate::policy::{Severity, Weakness, weaknesses};
use crate::{Certificate, Error, ExtendedKeyUsage, HostOptions, Policy};

/// A set of trust anchors (root certificates).
///
/// A certificate counts as trusted when the store holds one with the same
/// subject and public key, so a re-issued or cross-signed copy of a root
/// is recognised too.
///
/// ```
/// use rune_x509::TrustStore;
///
/// # let pem = include_bytes!("../tests/fixtures/root.pem");
/// let store = TrustStore::from_pem(pem)?;
/// assert_eq!(store.len(), 1);
/// # Ok::<(), rune_x509::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// A store of every certificate in a PEM bundle.
    ///
    /// # Errors
    ///
    /// Those of [`parse_pem`](crate::parse_pem).
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            anchors: crate::parse_pem(pem)?,
        })
    }

    /// Adds an anchor; duplicates (same subject and key) are ignored.
    pub fn add(&mut self, anchor: Certificate) {
        if !self.contains(&anchor) {
            self.anchors.push(anchor);
        }
    }

    /// Builder form of [`TrustStore::add`].
    #[must_use]
    pub fn with(mut self, anchor: Certificate) -> Self {
        self.add(anchor);
        self
    }

    /// Whether `cert` is an anchor: same subject and public key as one in
    /// the store.
    #[must_use]
    pub fn contains(&self, cert: &Certificate) -> bool {
        self.anchors.iter().any(|anchor| same_entity(anchor, cert))
    }

    /// Number of anchors.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The anchors.
    pub fn iter(&self) -> std::slice::Iter<'_, Certificate> {
        self.anchors.iter()
    }
}

impl<'a> IntoIterator for &'a TrustStore {
    type Item = &'a Certificate;
    type IntoIter = std::slice::Iter<'a, Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.anchors.iter()
    }
}

impl FromIterator<Certificate> for TrustStore {
    fn from_iter<I: IntoIterator<Item = Certificate>>(iter: I) -> Self {
        let mut store = Self::new();
        for anchor in iter {
            store.add(anchor);
        }
        store
    }
}

fn same_entity(a: &Certificate, b: &Certificate) -> bool {
    a.subject_der() == b.subject_der() && a.spki_der() == b.spki_der()
}

/// What the leaf certificate is used for, checked against its
/// `extendedKeyUsage` when that extension is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Purpose {
    /// No purpose check.
    Any,
    /// A TLS server (`id-kp-serverAuth`). The default.
    #[default]
    ServerAuth,
    /// A TLS client, as in mutual TLS (`id-kp-clientAuth`).
    ClientAuth,
}

impl Purpose {
    fn allowed_by(self, usages: &[ExtendedKeyUsage]) -> bool {
        let wanted = match self {
            Self::Any => return true,
            Self::ServerAuth => ExtendedKeyUsage::ServerAuth,
            Self::ClientAuth => ExtendedKeyUsage::ClientAuth,
        };
        usages
            .iter()
            .any(|usage| *usage == wanted || *usage == ExtendedKeyUsage::Any)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Any => "any",
            Self::ServerAuth => "serverAuth",
            Self::ClientAuth => "clientAuth",
        })
    }
}

/// Options for [`verify_chain`].
///
/// ```
/// use rune_x509::{Purpose, VerifyOptions};
///
/// let options = VerifyOptions::default()
///     .with_time(1_780_272_000) // 2026-06-01T00:00:00Z
///     .with_hostname("www.example.com")
///     .with_purpose(Purpose::ServerAuth);
/// assert_eq!(options.hostname.as_deref(), Some("www.example.com"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// Validation time in Unix seconds; `None` reads the system clock.
    pub time: Option<i64>,
    /// Host name or IP address the leaf must cover; `None` skips the
    /// name check.
    pub hostname: Option<String>,
    /// How [`VerifyOptions::hostname`] is matched.
    pub host_options: HostOptions,
    /// Required leaf purpose. Default [`Purpose::ServerAuth`].
    pub purpose: Purpose,
    /// Weak-crypto thresholds.
    pub policy: Policy,
    /// Longest path considered, counting leaf and anchor. Default 8.
    pub max_depth: usize,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            time: None,
            hostname: None,
            host_options: HostOptions::default(),
            purpose: Purpose::default(),
            policy: Policy::default(),
            max_depth: 8,
        }
    }
}

impl VerifyOptions {
    /// Sets [`VerifyOptions::time`].
    #[must_use]
    pub const fn with_time(mut self, unix_seconds: i64) -> Self {
        self.time = Some(unix_seconds);
        self
    }

    /// Sets [`VerifyOptions::hostname`].
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets [`VerifyOptions::host_options`].
    #[must_use]
    pub const fn with_host_options(mut self, host_options: HostOptions) -> Self {
        self.host_options = host_options;
        self
    }

    /// Sets [`VerifyOptions::purpose`].
    #[must_use]
    pub const fn with_purpose(mut self, purpose: Purpose) -> Self {
        self.purpose = purpose;
        self
    }

    /// Sets [`VerifyOptions::policy`].
    #[must_use]
    pub const fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets [`VerifyOptions::max_depth`].
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }
}

/// A problem found while validating a chain. `depth` counts from the
/// leaf (0) towards the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChainIssue {
    /// The certificate's `notAfter` is in the past.
    Expired {
        /// Position in the path.
        depth: usize,
        /// `notAfter`, Unix seconds.
        not_after: i64,
    },
    /// The certificate's `notBefore` is in the future.
    NotYetValid {
        /// Position in the path.
        depth: usize,
        /// `notBefore`, Unix seconds.
        not_before: i64,
    },
    /// The leaf is self-signed and not in the trust store.
    SelfSigned,
    /// The path ends at a self-signed root that is not in the trust store.
    UntrustedRoot {
        /// Position of the root in the path.
        depth: usize,
    },
    /// No issuer was found for the last certificate of the path: an
    /// intermediate is missing.
    Incomplete {
        /// Issuer name that could not be found.
        issuer: String,
    },
    /// The issuer's key does not verify this certificate's signature.
    BadSignature {
        /// Position of the signed certificate.
        depth: usize,
    },
    /// The signature algorithm, or the issuer key, is not supported.
    UnsupportedSignature {
        /// Position of the signed certificate.
        depth: usize,
    },
    /// An issuing certificate is not a CA (`basicConstraints` `cA`).
    NotCa {
        /// Position of the issuing certificate.
        depth: usize,
    },
    /// An issuing certificate's `keyUsage` lacks `keyCertSign`.
    MissingKeyCertSign {
        /// Position of the issuing certificate.
        depth: usize,
    },
    /// More intermediates follow a CA than its `pathLenConstraint` allows.
    PathLenExceeded {
        /// Position of the constraining CA.
        depth: usize,
    },
    /// The leaf does not cover the requested host.
    NameMismatch {
        /// The requested host.
        hostname: String,
    },
    /// The leaf's `extendedKeyUsage` does not allow the requested purpose.
    WrongPurpose {
        /// The requested purpose.
        purpose: Purpose,
    },
    /// A per-certificate [`Weakness`].
    Weak {
        /// Position in the path.
        depth: usize,
        /// The weakness.
        weakness: Weakness,
    },
}

impl ChainIssue {
    /// [`Severity::Error`] except for warning-level weaknesses.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Weak { weakness, .. } => weakness.severity(),
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for ChainIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { depth, .. } => write!(f, "certificate {depth} has expired"),
            Self::NotYetValid { depth, .. } => write!(f, "certificate {depth} is not yet valid"),
            Self::SelfSigned => f.write_str("self-signed certificate"),
            Self::UntrustedRoot { depth } => write!(f, "root certificate {depth} is not trusted"),
            Self::Incomplete { issuer } => write!(f, "incomplete chain: issuer {issuer} not found"),
            Self::BadSignature { depth } => {
                write!(f, "certificate {depth} has an invalid signature")
            }
            Self::UnsupportedSignature { depth } => {
                write!(f, "certificate {depth} has an unsupported signature")
            }
            Self::NotCa { depth } => write!(f, "certificate {depth} is not a CA"),
            Self::MissingKeyCertSign { depth } => {
                write!(
                    f,
                    "certificate {depth} may not sign certificates (keyUsage)"
                )
            }
            Self::PathLenExceeded { depth } => {
                write!(f, "path length constraint of certificate {depth} exceeded")
            }
            Self::NameMismatch { hostname } => write!(f, "certificate does not match {hostname}"),
            Self::WrongPurpose { purpose } => write!(f, "certificate not valid for {purpose}"),
            Self::Weak { depth, weakness } => write!(f, "certificate {depth}: {weakness}"),
        }
    }
}

/// The outcome of [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainReport {
    /// The path built, leaf first. When `anchored`, it ends at a
    /// certificate the trust store trusts; otherwise it is the longest
    /// partial path found.
    pub path: Vec<Certificate>,
    /// Whether the path reaches a trust anchor.
    pub anchored: bool,
    /// Every problem found, in path order.
    pub issues: Vec<ChainIssue>,
    /// The validation time used, Unix seconds.
    pub time: i64,
}

impl ChainReport {
    /// Whether the chain is trusted: anchored, with no error-level issue.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.anchored && self.errors().next().is_none()
    }

    /// The error-level issues.
    pub fn errors(&self) -> impl Iterator<Item = &ChainIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity() == Severity::Error)
    }

    /// The warning-level issues.
    pub fn warnings(&self) -> impl Iterator<Item = &ChainIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.severity() == Severity::Warning)
    }
}

/// Builds and validates a certification path from `leaf` to a trust
/// anchor.
///
/// The path uses `intermediates` (in any order, extra certificates
/// allowed) and the anchors of `store`. It is validated per
/// [RFC 5280 §6](https://www.rfc-editor.org/rfc/rfc5280#section-6):
/// signatures, validity periods, CA basic constraints, `keyUsage`,
/// path-length constraints, the leaf's purpose and host name, and the
/// [`Policy`] weak-crypto checks.
///
/// Path building tries every candidate issuer (same name, matching key
/// identifiers) depth first, preferring anchors, so cross-signed and
/// out-of-order chains work. Not checked: revocation, name constraints
/// and certificate policies.
///
/// ```
/// use rune_x509::{Certificate, ChainIssue, TrustStore, VerifyOptions, verify_chain};
///
/// # let leaf = Certificate::from_pem(include_bytes!("../tests/fixtures/leaf.pem"))?;
/// # let inter = Certificate::from_pem(include_bytes!("../tests/fixtures/inter.pem"))?;
/// # let root = Certificate::from_pem(include_bytes!("../tests/fixtures/root.pem"))?;
/// let store = TrustStore::new().with(root);
/// let options = VerifyOptions::default()
///     .with_time(1_780_272_000)
///     .with_hostname("www.example.com");
///
/// let report = verify_chain(&leaf, &[inter], &store, &options);
/// assert!(report.is_trusted());
/// assert_eq!(report.path.len(), 3);
///
/// // Without the intermediate the chain is incomplete.
/// let report = verify_chain(&leaf, &[], &store, &options);
/// assert!(!report.is_trusted());
/// assert!(matches!(report.issues[0], ChainIssue::Incomplete { .. }));
/// # Ok::<(), rune_x509::Error>(())
/// ```
#[must_use]
pub fn verify_chain(
    leaf: &Certificate,
    intermediates: &[Certificate],
    store: &TrustStore,
    options: &VerifyOptions,
) -> ChainReport {
    let time = options.time.unwrap_or_else(now);
    let mut builder = Builder {
        store,
        pool: store.iter().chain(intermediates).collect(),
        max_depth: options.max_depth.max(1),
        best: vec![leaf],
        signature_failure: None,
        signature_budget: SIGNATURE_BUDGET,
    };
    let mut path = vec![leaf];
    let anchored = builder.extend(&mut path);
    let path = if anchored { path } else { builder.best.clone() };

    let mut issues = Vec::new();
    if !anchored {
        issues.push(diagnose_unanchored(&path, builder.signature_failure));
    }
    check_path(&path, anchored, time, options, &mut issues);

    ChainReport {
        path: path.into_iter().cloned().collect(),
        anchored,
        issues,
        time,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Most signature checks one path search may make, so that a pool of
/// many same-named certificates cannot make the search exponential
/// (`rustls-webpki` uses the same bound).
const SIGNATURE_BUDGET: usize = 100;

struct Builder<'a> {
    store: &'a TrustStore,
    /// Candidate issuers: anchors first, then the supplied intermediates.
    pool: Vec<&'a Certificate>,
    max_depth: usize,
    best: Vec<&'a Certificate>,
    /// Deepest signature failure: (depth of the signed cert, error).
    signature_failure: Option<(usize, SignatureError)>,
    signature_budget: usize,
}

impl<'a> Builder<'a> {
    /// Extends `path` towards an anchor; true when one was reached, with
    /// `path` holding the anchored path.
    fn extend(&mut self, path: &mut Vec<&'a Certificate>) -> bool {
        let Some(&last) = path.last() else {
            return false;
        };
        if self.store.contains(last) {
            return true;
        }
        if path.len() > self.best.len() {
            self.best.clone_from(path);
        }
        if path.len() >= self.max_depth {
            return false;
        }
        let depth = path.len() - 1;
        let candidates: Vec<&'a Certificate> = self
            .pool
            .iter()
            .copied()
            .filter(|cand| last.may_be_issued_by(cand))
            .filter(|cand| !path.iter().any(|seen| same_entity(seen, cand)))
            .collect();
        for candidate in candidates {
            let Some(budget) = self.signature_budget.checked_sub(1) else {
                return false;
            };
            self.signature_budget = budget;
            if let Err(err) = last.verify_signed_by(candidate) {
                if self.signature_failure.is_none_or(|(at, _)| depth >= at) {
                    self.signature_failure = Some((depth, err));
                }
                continue;
            }
            path.push(candidate);
            if self.extend(path) {
                return true;
            }
            path.pop();
        }
        false
    }
}

fn diagnose_unanchored(
    path: &[&Certificate],
    signature_failure: Option<(usize, SignatureError)>,
) -> ChainIssue {
    let depth = path.len().saturating_sub(1);
    let Some(last) = path.last() else {
        return ChainIssue::Incomplete {
            issuer: String::new(),
        };
    };
    match signature_failure {
        Some((at, SignatureError::Unsupported)) if at == depth => {
            return ChainIssue::UnsupportedSignature { depth };
        }
        Some((at, _)) if at == depth => return ChainIssue::BadSignature { depth },
        _ => {}
    }
    if last.summary().self_signed {
        if depth == 0 {
            ChainIssue::SelfSigned
        } else {
            ChainIssue::UntrustedRoot { depth }
        }
    } else {
        ChainIssue::Incomplete {
            issuer: last.summary().issuer.clone(),
        }
    }
}

fn check_path(
    path: &[&Certificate],
    anchored: bool,
    time: i64,
    options: &VerifyOptions,
    issues: &mut Vec<ChainIssue>,
) {
    let anchor_depth = anchored.then(|| path.len().saturating_sub(1));
    for (depth, cert) in path.iter().enumerate() {
        let summary = cert.summary();
        let is_anchor = anchor_depth == Some(depth);
        if time > summary.not_after {
            issues.push(ChainIssue::Expired {
                depth,
                not_after: summary.not_after,
            });
        } else if time < summary.not_before {
            issues.push(ChainIssue::NotYetValid {
                depth,
                not_before: summary.not_before,
            });
        }
        for weakness in weaknesses(summary, &options.policy) {
            // An anchor is trusted by being in the store; its own
            // signature is never relied upon.
            if is_anchor && matches!(weakness, Weakness::WeakSignature(_)) {
                continue;
            }
            issues.push(ChainIssue::Weak { depth, weakness });
        }
        if depth > 0 && !is_anchor {
            check_issuer(path, depth, issues);
        }
    }
    let Some(leaf) = path.first() else {
        return;
    };
    if let Some(usages) = &leaf.summary().extended_key_usage
        && !options.purpose.allowed_by(usages)
    {
        issues.push(ChainIssue::WrongPurpose {
            purpose: options.purpose,
        });
    }
    if let Some(hostname) = &options.hostname
        && !leaf.matches_host_with(hostname, options.host_options)
    {
        issues.push(ChainIssue::NameMismatch {
            hostname: hostname.clone(),
        });
    }
}

/// CA checks for the intermediate at `depth`.
fn check_issuer(path: &[&Certificate], depth: usize, issues: &mut Vec<ChainIssue>) {
    let Some(summary) = path.get(depth).map(|cert| cert.summary()) else {
        return;
    };
    if !summary.is_ca() {
        issues.push(ChainIssue::NotCa { depth });
    }
    if summary.key_usage.is_some_and(|usage| !usage.key_cert_sign) {
        issues.push(ChainIssue::MissingKeyCertSign { depth });
    }
    if let Some(limit) = summary.basic_constraints.and_then(|bc| bc.path_len) {
        // Non-self-issued intermediates between this CA and the leaf.
        let below = path
            .get(1..depth)
            .unwrap_or_default()
            .iter()
            .filter(|cert| !cert.summary().self_issued)
            .count();
        if u32::try_from(below).map_or(true, |below| below > limit) {
            issues.push(ChainIssue::PathLenExceeded { depth });
        }
    }
}

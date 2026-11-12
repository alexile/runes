//! Correlation keys: [`Key`], the [`Correlate`] trait and the built-in
//! [`Strategy`].

use core::fmt;

use rune_finding::{Confidence, Finding, Location, Severity, Taxonomy};
use sha2::{Digest, Sha256};

/// Domain-separation prefix of the CWE-at-location key, version 1.
const CWE_PREFIX_V1: &[u8] = b"rune-finding-dedupe/cwe/v1";

/// One identity claim of a finding: two findings that share any key are the
/// same issue.
///
/// A key is `scheme:value`. Every finding has the key
/// [`Key::fingerprint`] of its [`Finding::fingerprint`]; a [`Correlate`]
/// implementation adds more, such as [`Strategy::FingerprintOrCwe`]'s
/// CWE-at-location key, so findings from tools with different check ids
/// meet.
///
/// With the `serde` feature a key serializes as its string.
///
/// # Examples
///
/// ```
/// use rune_finding_dedupe::Key;
///
/// let key = Key::new("sarif", "primaryLocationLineHash/abc:1");
/// assert_eq!(key.as_str(), "sarif:primaryLocationLineHash/abc:1");
/// assert_eq!(key.scheme(), "sarif");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Key(String);

impl Key {
    /// Scheme of [`Key::fingerprint`] keys.
    pub const FINGERPRINT: &'static str = "fp";
    /// Scheme of [`Strategy::FingerprintOrCwe`]'s CWE-at-location keys.
    pub const CWE_AT_LOCATION: &'static str = "cwe";

    /// A key in `scheme` with `value`. Pick a scheme of your own for custom
    /// keys so they cannot collide with the built-in ones.
    pub fn new(scheme: &str, value: impl AsRef<str>) -> Self {
        Self(format!("{scheme}:{}", value.as_ref()))
    }

    /// The key of a [`Finding::fingerprint`].
    #[must_use]
    pub fn fingerprint(fingerprint: &str) -> Self {
        Self::new(Self::FINGERPRINT, fingerprint)
    }

    /// The key as `scheme:value`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The scheme, before the first `:`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.0.split_once(':').map_or("", |(scheme, _)| scheme)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How findings are correlated: which keys, beyond the fingerprint, make two
/// findings the same issue, and how their extensions merge.
///
/// [`Strategy`] implements it for every extension type. Implement it
/// yourself to add keys a product knows about (a SARIF
/// `partialFingerprints` entry, a CVE and package for dependency findings)
/// or to merge extension data; delegate to a [`Strategy`] for the rest.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_finding_dedupe::{dedupe, Correlate, Key, Options, Strategy};
///
/// /// Same CVE in the same package is one issue, whichever scanner saw it.
/// struct ByCve;
///
/// impl Correlate<()> for ByCve {
///     fn keys(&self, finding: &Finding) -> Vec<Key> {
///         let mut keys = Strategy::Fingerprint.keys(finding);
///         if let Some(cve) = finding.check_id.strip_prefix("cve/") {
///             keys.push(Key::new("cve", format!("{cve}@{:?}", finding.location)));
///         }
///         keys
///     }
/// }
///
/// let at = |check: &str| {
///     Finding::new(check, "x", Severity::High, Confidence::Firm, Location::file("Cargo.lock"))
/// };
/// let groups = dedupe([at("cve/CVE-2024-1"), at("cve/CVE-2024-1")], &ByCve, &Options::default());
/// assert_eq!(groups.len(), 1);
/// ```
pub trait Correlate<X> {
    /// The keys of `finding`, in addition to its fingerprint key, which
    /// always counts. Findings sharing any key are one issue.
    fn keys(&self, finding: &Finding<X>) -> Vec<Key>;

    /// Merge the extension of a duplicate into the kept finding's. `into`
    /// belongs to the finding that ranks higher (severity, then
    /// confidence). The default keeps `into` and drops `from`.
    fn merge_ext(&self, into: &mut X, from: X) {
        let _ = (into, from);
    }
}

/// The built-in correlation strategies.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_finding_dedupe::{Correlate, Strategy};
///
/// let finding = Finding::<()>::new(
///     "semgrep.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("app.py").with_lines(42, 42),
/// )
/// .push_taxonomy(TaxonomyRef::cwe(89));
///
/// assert!(Strategy::Fingerprint.keys(&finding).is_empty());
/// assert_eq!(Strategy::FingerprintOrCwe.keys(&finding).len(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Strategy {
    /// Only [`Finding::fingerprint`]: same check id at the same normalized
    /// location. Right for repeated scans by one tool, and across tools that
    /// share check ids.
    #[default]
    Fingerprint,
    /// The fingerprint, or the same CWE at the same normalized location. It
    /// correlates tools with different check ids for one weakness, such as
    /// `CodeQL`'s and Semgrep's SQL injection rules on the same line. Findings
    /// without a CWE fall back to the fingerprint alone.
    FingerprintOrCwe,
}

impl<X> Correlate<X> for Strategy {
    fn keys(&self, finding: &Finding<X>) -> Vec<Key> {
        match self {
            Self::Fingerprint => Vec::new(),
            Self::FingerprintOrCwe => {
                let mut cwes: Vec<u32> = finding
                    .taxonomy_in(&Taxonomy::Cwe)
                    .filter_map(rune_finding::TaxonomyRef::cwe_number)
                    .collect();
                if cwes.is_empty() {
                    return Vec::new();
                }
                cwes.sort_unstable();
                cwes.dedup();
                let location = location_digest(&finding.location);
                cwes.into_iter()
                    .map(|cwe| cwe_at_location(cwe, &location))
                    .collect()
            }
        }
    }
}

/// The fingerprint of `location` alone, with an empty check id: the
/// normalized location, hashed, as `rune-finding` defines it.
fn location_digest(location: &Location) -> String {
    Finding::<()>::new(
        "",
        "",
        Severity::Informational,
        Confidence::Tentative,
        location.clone(),
    )
    .fingerprint()
}

/// `cwe:` + lowercase hex SHA-256 of
/// `"rune-finding-dedupe/cwe/v1" US "CWE-<n>" US location_digest`.
fn cwe_at_location(cwe: u32, location_digest: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(CWE_PREFIX_V1);
    hasher.update([0x1F]);
    hasher.update(format!("CWE-{cwe}").as_bytes());
    hasher.update([0x1F]);
    hasher.update(location_digest.as_bytes());
    Key::new(Key::CWE_AT_LOCATION, hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use rune_finding::TaxonomyRef;

    use super::*;

    fn finding(check: &str, location: Location) -> Finding {
        Finding::new(check, "t", Severity::High, Confidence::Firm, location)
    }

    #[test]
    fn key_parts() {
        let key = Key::fingerprint("ab");
        assert_eq!(key.as_str(), "fp:ab");
        assert_eq!(key.scheme(), "fp");
        assert_eq!(key.to_string(), "fp:ab");
        assert_eq!(Key(String::from("bare")).scheme(), "");
    }

    #[test]
    fn cwe_keys_ignore_check_id_and_follow_location() {
        let at = |check: &str, line: u32| {
            finding(check, Location::file("a.py").with_lines(line, line))
                .push_taxonomy(TaxonomyRef::cwe(89))
                .push_taxonomy(TaxonomyRef::new(Taxonomy::Cwe, "cwe-89"))
        };
        let codeql = Strategy::FingerprintOrCwe.keys(&at("py/sql-injection", 3));
        let semgrep = Strategy::FingerprintOrCwe.keys(&at("python.sqli", 3));
        let elsewhere = Strategy::FingerprintOrCwe.keys(&at("python.sqli", 4));
        assert_eq!(codeql.len(), 1, "duplicate CWE ids collapse");
        assert_eq!(codeql, semgrep);
        assert_ne!(codeql, elsewhere);
        assert_eq!(codeql[0].scheme(), Key::CWE_AT_LOCATION);
    }

    #[test]
    fn cwe_keys_need_a_cwe() {
        let plain = finding("x", Location::url("https://a.test/"));
        assert_eq!(Strategy::FingerprintOrCwe.keys(&plain).len(), 0);
        let bad = plain.push_taxonomy(TaxonomyRef::new(Taxonomy::Cwe, "not-a-cwe"));
        assert_eq!(Strategy::FingerprintOrCwe.keys(&bad).len(), 0);
    }

    /// Pins the v1 CWE-at-location key, so stored keys stay valid.
    #[test]
    fn golden_cwe_key() {
        let f = finding(
            "any",
            Location::url("https://Example.test/users/42?b=1&a=2"),
        )
        .push_taxonomy(TaxonomyRef::cwe(639));
        let keys = Strategy::FingerprintOrCwe.keys(&f);
        let mut hasher = Sha256::new();
        hasher.update(b"rune-finding-dedupe/cwe/v1\x1fCWE-639\x1f");
        hasher.update(location_digest(&f.location).as_bytes());
        assert_eq!(
            keys,
            [Key::new("cwe", hex_lower(&hasher.finalize()))],
            "algorithm"
        );
        assert_eq!(
            keys[0].as_str(),
            "cwe:ffa108f504c5c7cc03bae8f02c314d3f92a41e6d90cda03a9c60c9f3550c57a8",
            "golden value"
        );
    }
}

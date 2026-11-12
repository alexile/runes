//! The normalized result of a reputation check.

use std::fmt;
use std::net::IpAddr;

use crate::Error;

/// How a provider judges an address, worst last (so `max` picks the
/// worst of several verdicts, and any opinion beats [`Unknown`](Self::Unknown)).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Classification {
    /// The provider has no opinion (not seen, or data without a judgement).
    #[default]
    Unknown,
    /// Known-good: a business service, an allowlisted address.
    Benign,
    /// Some bad signals, below the provider's "malicious" bar.
    Suspicious,
    /// The provider considers the address malicious.
    Malicious,
}

impl Classification {
    /// Lowercase name: `unknown`, `benign`, `suspicious`, `malicious`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One provider's normalized answer for one address.
///
/// Fields a provider does not report stay empty. The provider's own JSON
/// answer is kept in [`raw`](Self::raw) for anything not normalized.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Verdict {
    /// Provider name, as [`ReputationProvider::name`](crate::ReputationProvider::name).
    pub provider: &'static str,
    /// The address checked.
    pub ip: IpAddr,
    /// The provider's judgement.
    pub classification: Classification,
    /// Risk score from 0 (clean) to 100, when the provider computes one.
    pub score: Option<u8>,
    /// Abuse categories (`SSH`, `Port Scan`, ...).
    pub categories: Vec<String>,
    /// Provider tags and labels (`tor`, `scanner`, `cloud`, ...).
    pub tags: Vec<String>,
    /// When the provider last saw activity, in Unix seconds.
    pub last_seen: Option<i64>,
    /// Number of abuse reports.
    pub reports: Option<u64>,
    /// Open ports the provider observed.
    pub open_ports: Vec<u16>,
    /// Host names (reverse DNS, certificates).
    pub hostnames: Vec<String>,
    /// Vulnerability identifiers (CVEs) the provider associates.
    pub vulns: Vec<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Operator, ISP or service name.
    pub organization: Option<String>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// The provider's JSON answer (`null` when it sent none).
    pub raw: serde_json::Value,
}

impl Verdict {
    /// An empty, [`Unknown`](Classification::Unknown) verdict.
    #[must_use]
    pub const fn new(provider: &'static str, ip: IpAddr) -> Self {
        Self {
            provider,
            ip,
            classification: Classification::Unknown,
            score: None,
            categories: Vec::new(),
            tags: Vec::new(),
            last_seen: None,
            reports: None,
            open_ports: Vec::new(),
            hostnames: Vec::new(),
            vulns: Vec::new(),
            asn: None,
            organization: None,
            country: None,
            raw: serde_json::Value::Null,
        }
    }
}

/// Several providers' verdicts on one address, merged.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Summary {
    /// The address checked.
    pub ip: IpAddr,
    /// The worst classification any provider gave.
    pub classification: Classification,
    /// The highest score any provider gave.
    pub score: Option<u8>,
    /// Union of the categories, sorted.
    pub categories: Vec<String>,
    /// Union of the tags, sorted.
    pub tags: Vec<String>,
    /// The most recent `last_seen`.
    pub last_seen: Option<i64>,
    /// Each provider's verdict, in provider order.
    pub verdicts: Vec<Verdict>,
    /// Providers that failed, with their error.
    pub errors: Vec<(&'static str, Error)>,
}

impl Summary {
    /// Merges verdicts on `ip`, keeping the errors alongside.
    #[must_use]
    pub fn new(ip: IpAddr, verdicts: Vec<Verdict>, errors: Vec<(&'static str, Error)>) -> Self {
        let union = |field: fn(&Verdict) -> &Vec<String>| {
            let mut all: Vec<String> = verdicts.iter().flat_map(field).cloned().collect();
            all.sort();
            all.dedup();
            all
        };
        Self {
            ip,
            classification: verdicts
                .iter()
                .map(|v| v.classification)
                .max()
                .unwrap_or_default(),
            score: verdicts.iter().filter_map(|v| v.score).max(),
            categories: union(|v| &v.categories),
            tags: union(|v| &v.tags),
            last_seen: verdicts.iter().filter_map(|v| v.last_seen).max(),
            verdicts,
            errors,
        }
    }

    /// The verdict of the named provider.
    #[must_use]
    pub fn verdict(&self, provider: &str) -> Option<&Verdict> {
        self.verdicts.iter().find(|v| v.provider == provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_takes_the_worst_and_unions() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut a = Verdict::new("a", ip);
        a.classification = Classification::Benign;
        a.tags = vec!["riot".into(), "cloud".into()];
        a.last_seen = Some(10);
        let mut b = Verdict::new("b", ip);
        b.classification = Classification::Suspicious;
        b.score = Some(40);
        b.tags = vec!["cloud".into()];
        b.last_seen = Some(5);
        let summary = Summary::new(ip, vec![a, b], Vec::new());
        assert_eq!(summary.classification, Classification::Suspicious);
        assert_eq!(summary.score, Some(40));
        assert_eq!(summary.tags, ["cloud", "riot"]);
        assert_eq!(summary.last_seen, Some(10));
        assert_eq!(summary.verdict("b").and_then(|v| v.score), Some(40));

        let empty = Summary::new(ip, Vec::new(), Vec::new());
        assert_eq!(empty.classification, Classification::Unknown);
        assert_eq!(empty.score, None);
    }

    #[test]
    fn classification_orders_worst_last() {
        assert!(Classification::Unknown < Classification::Benign);
        assert!(Classification::Benign < Classification::Suspicious);
        assert!(Classification::Suspicious < Classification::Malicious);
        assert_eq!(Classification::Malicious.to_string(), "malicious");
    }
}

//! [`Severity`] and [`Confidence`]: how much a finding matters, and how
//! sure the tool is that it is real.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// How much a finding matters.
///
/// Five levels, ordered from least to most severe, so `Severity::High >
/// Severity::Low` and a list of findings sorts by severity.
///
/// Serialized as the lowercase name: `"informational"`, `"low"`, `"medium"`,
/// `"high"`, `"critical"`. Deserialization also accepts `"info"`, the name
/// rune-leak uses. [`FromStr`] is case-insensitive and accepts
/// the same names.
///
/// # Examples
///
/// ```
/// use rune_finding::Severity;
///
/// assert!(Severity::Critical > Severity::High);
/// assert_eq!("INFO".parse::<Severity>()?, Severity::Informational);
/// assert_eq!(Severity::Medium.sarif_level(), "warning");
/// # Ok::<(), rune_finding::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum Severity {
    /// No security impact. Recorded for context.
    #[cfg_attr(feature = "serde", serde(rename = "informational", alias = "info"))]
    Informational,
    /// Minor impact or a hardening gap.
    #[cfg_attr(feature = "serde", serde(rename = "low"))]
    Low,
    /// Limited impact, or exploitable only under other conditions.
    #[cfg_attr(feature = "serde", serde(rename = "medium"))]
    Medium,
    /// Direct impact on confidentiality, integrity or availability.
    #[cfg_attr(feature = "serde", serde(rename = "high"))]
    High,
    /// Immediate, severe and broadly reachable impact.
    #[cfg_attr(feature = "serde", serde(rename = "critical"))]
    Critical,
}

impl Severity {
    /// Every level, least severe first.
    pub const ALL: [Self; 5] = [
        Self::Informational,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// The lowercase name, the same as the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// The SARIF 2.1.0 `result.level` for this severity (§3.27.10).
    ///
    /// `Informational` is `"note"`, `Low` and `Medium` are `"warning"`, and
    /// `High` and `Critical` are `"error"`.
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Informational => "note",
            Self::Low | Self::Medium => "warning",
            Self::High | Self::Critical => "error",
        }
    }

    /// The `security-severity` property GitHub code scanning reads from a
    /// SARIF rule or result: a CVSS-like score as a string.
    ///
    /// Each value sits inside the CVSS v3 band of the same name, so GitHub
    /// shows the same label: `"0.0"`, `"3.0"`, `"5.5"`, `"8.0"`, `"9.5"`.
    #[must_use]
    pub const fn security_severity(self) -> &'static str {
        match self {
            Self::Informational => "0.0",
            Self::Low => "3.0",
            Self::Medium => "5.5",
            Self::High => "8.0",
            Self::Critical => "9.5",
        }
    }

    /// The CVSS v3 qualitative rating of a base score.
    ///
    /// `0.0` (and anything below, or `NaN`) is `Informational` ("None" in
    /// CVSS), up to `3.9` is `Low`, up to `6.9` is `Medium`, up to `8.9` is
    /// `High`, and the rest is `Critical`.
    #[must_use]
    pub fn from_cvss_score(score: f64) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Informational
        }
    }
}

/// CVSS qualitative ratings map one to one; `None` is `Informational`.
#[cfg(feature = "cvss")]
impl From<rune_cvss::Severity> for Severity {
    fn from(severity: rune_cvss::Severity) -> Self {
        match severity {
            rune_cvss::Severity::Low => Self::Low,
            rune_cvss::Severity::Medium => Self::Medium,
            rune_cvss::Severity::High => Self::High,
            rune_cvss::Severity::Critical => Self::Critical,
            // `None`, and any rating a later CVSS version adds below Low.
            _ => Self::Informational,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "informational" | "info" => Ok(Self::Informational),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(Error::UnknownSeverity(text.to_owned())),
        }
    }
}

/// How sure the tool is that a finding is real.
///
/// Kept apart from [`Severity`], as in Burp: a tentative critical still needs
/// a human, a certain low does not. Ordered from least to most sure.
///
/// Serialized as the lowercase name: `"tentative"`, `"firm"`, `"certain"`.
/// Deserialization also accepts `"low"`, `"medium"` and
/// `"high"`, which map one to one onto the same three levels.
///
/// # Examples
///
/// ```
/// use rune_finding::Confidence;
///
/// assert!(Confidence::Certain > Confidence::Tentative);
/// assert_eq!("medium".parse::<Confidence>()?, Confidence::Firm);
/// # Ok::<(), rune_finding::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum Confidence {
    /// A pattern matched but was not exercised. A human should confirm.
    #[cfg_attr(feature = "serde", serde(rename = "tentative", alias = "low"))]
    Tentative,
    /// Behaviour consistent with the issue was observed once.
    #[cfg_attr(feature = "serde", serde(rename = "firm", alias = "medium"))]
    Firm,
    /// Reproduced, or confirmed out of band.
    #[cfg_attr(feature = "serde", serde(rename = "certain", alias = "high"))]
    Certain,
}

impl Confidence {
    /// Every level, least sure first.
    pub const ALL: [Self; 3] = [Self::Tentative, Self::Firm, Self::Certain];

    /// The lowercase name, the same as the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Firm => "firm",
            Self::Certain => "certain",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Confidence {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "tentative" | "low" => Ok(Self::Tentative),
            "firm" | "medium" => Ok(Self::Firm),
            "certain" | "high" => Ok(Self::Certain),
            _ => Err(Error::UnknownConfidence(text.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_names() {
        assert!(Severity::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        for severity in Severity::ALL {
            assert_eq!(severity.as_str().parse::<Severity>(), Ok(severity));
            assert_eq!(severity.to_string(), severity.as_str());
        }
        assert_eq!(" Info ".parse::<Severity>(), Ok(Severity::Informational));
        assert_eq!(
            "severe".parse::<Severity>(),
            Err(Error::UnknownSeverity("severe".to_owned()))
        );
    }

    #[test]
    fn severity_sarif_mappings() {
        let levels: Vec<_> = Severity::ALL.iter().map(|s| s.sarif_level()).collect();
        assert_eq!(levels, ["note", "warning", "warning", "error", "error"]);
        for severity in Severity::ALL {
            let score: f64 = severity.security_severity().parse().unwrap();
            assert_eq!(Severity::from_cvss_score(score), severity);
        }
    }

    #[cfg(feature = "cvss")]
    #[test]
    fn from_cvss_ratings_agrees_with_the_score_bands() {
        for tenths in 0..=100 {
            let score = rune_cvss::Score::from_tenths(tenths).unwrap();
            assert_eq!(
                Severity::from(score.severity()),
                Severity::from_cvss_score(score.value()),
                "{score}"
            );
        }
        assert_eq!(
            Severity::from(rune_cvss::Severity::None),
            Severity::Informational
        );
    }

    #[test]
    fn severity_from_cvss_bands() {
        let cases = [
            (f64::NAN, Severity::Informational),
            (-1.0, Severity::Informational),
            (0.0, Severity::Informational),
            (0.1, Severity::Low),
            (3.9, Severity::Low),
            (4.0, Severity::Medium),
            (6.9, Severity::Medium),
            (7.0, Severity::High),
            (8.9, Severity::High),
            (9.0, Severity::Critical),
            (10.0, Severity::Critical),
        ];
        for (score, expected) in cases {
            assert_eq!(Severity::from_cvss_score(score), expected, "{score}");
        }
    }

    #[test]
    fn confidence_orders_and_names() {
        assert!(Confidence::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        for confidence in Confidence::ALL {
            assert_eq!(confidence.as_str().parse::<Confidence>(), Ok(confidence));
            assert_eq!(confidence.to_string(), confidence.as_str());
        }
        assert_eq!("HIGH".parse::<Confidence>(), Ok(Confidence::Certain));
        assert!("sure".parse::<Confidence>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_names_and_aliases() {
        assert_eq!(
            serde_json::to_string(&Severity::Informational).unwrap(),
            r#""informational""#
        );
        let info: Severity = serde_json::from_str(r#""info""#).unwrap();
        assert_eq!(info, Severity::Informational);
        assert_eq!(
            serde_json::to_string(&Confidence::Firm).unwrap(),
            r#""firm""#
        );
        let high: Confidence = serde_json::from_str(r#""high""#).unwrap();
        assert_eq!(high, Confidence::Certain);
        assert!(serde_json::from_str::<Severity>(r#""High""#).is_err());
    }
}

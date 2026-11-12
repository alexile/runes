//! [`Score`] and its qualitative [`Severity`] rating.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// A CVSS score: 0.0 to 10.0 in steps of 0.1.
///
/// Every CVSS version rounds its scores to one decimal place, so a score is
/// stored exactly, as a whole number of tenths. Equality, ordering and
/// hashing are therefore exact, and [`Display`](fmt::Display) always prints
/// one decimal (`"9.8"`, `"10.0"`, `"0.0"`).
///
/// # Examples
///
/// ```
/// use rune_cvss::{Score, Severity};
///
/// let score = Score::try_from(9.8)?;
/// assert_eq!(score.tenths(), 98);
/// assert_eq!(score.value(), 9.8);
/// assert_eq!(score.to_string(), "9.8");
/// assert_eq!(score.severity(), Severity::Critical);
/// assert!(Score::try_from(9.85).is_err());
/// # Ok::<(), rune_cvss::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Score(u8);

impl Score {
    /// 0.0, the lowest score.
    pub const ZERO: Self = Self(0);
    /// 10.0, the highest score.
    pub const MAX: Self = Self(100);

    /// The score `tenths / 10`, or `None` above 10.0.
    #[must_use]
    pub const fn from_tenths(tenths: u8) -> Option<Self> {
        if tenths <= 100 {
            Some(Self(tenths))
        } else {
            None
        }
    }

    /// The score in tenths, 0 to 100.
    #[must_use]
    pub const fn tenths(self) -> u8 {
        self.0
    }

    /// The score as a number: the `f64` closest to its one-decimal value,
    /// so `value()` of 9.8 is exactly the literal `9.8`.
    #[must_use]
    pub fn value(self) -> f64 {
        f64::from(self.0) / 10.0
    }

    /// The qualitative severity rating of the score. CVSS v3.x and v4.0
    /// use the same bands.
    #[must_use]
    pub const fn severity(self) -> Severity {
        Severity::from_score(self)
    }

    /// The score of a value already rounded to one decimal by a scoring
    /// formula: the nearest tenth, clamped to 0.0..=10.0.
    pub(crate) fn from_rounded(value: f64) -> Self {
        let tenths = (value * 10.0).round();
        if tenths >= 100.0 {
            Self::MAX
        } else if tenths > 0.0 {
            // In 1..100 after the checks above (NaN fails both), so the
            // conversion is exact.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "tenths is a whole number in 1..100"
            )]
            Self(tenths as u8)
        } else {
            Self::ZERO
        }
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.0 / 10, self.0 % 10)
    }
}

impl fmt::Debug for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Score({self})")
    }
}

impl From<Score> for f64 {
    fn from(score: Score) -> Self {
        score.value()
    }
}

impl TryFrom<f64> for Score {
    type Error = Error;

    /// A score from a number that is a multiple of 0.1 from 0.0 to 10.0,
    /// such as a score read from JSON. `9.8` is accepted, `9.85`, `-1.0`
    /// and `NaN` are not.
    fn try_from(value: f64) -> Result<Self, Error> {
        if !(0.0..=10.0).contains(&value) {
            return Err(Error::InvalidScore(value));
        }
        let score = Self::from_rounded(value);
        #[allow(clippy::float_cmp, reason = "an exact multiple of 0.1 is required")]
        let exact = score.value() == value;
        if exact {
            Ok(score)
        } else {
            Err(Error::InvalidScore(value))
        }
    }
}

impl FromStr for Score {
    type Err = Error;

    /// Parses a decimal number such as `"9.8"` or `"10"`.
    fn from_str(text: &str) -> Result<Self, Error> {
        let value: f64 = text.parse().map_err(|_| Error::InvalidScore(f64::NAN))?;
        Self::try_from(value)
    }
}

/// The qualitative severity rating scale of CVSS v3.x and v4.0.
///
/// | Rating   | Scores     |
/// | -------- | ---------- |
/// | None     | 0.0        |
/// | Low      | 0.1 to 3.9 |
/// | Medium   | 4.0 to 6.9 |
/// | High     | 7.0 to 8.9 |
/// | Critical | 9.0 to 10.0 |
///
/// Ordered from `None` to `Critical`. With the `rune-finding` crate's `cvss`
/// feature, it converts into `rune_finding::Severity` (`None` becomes
/// `Informational`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Severity {
    /// 0.0.
    None,
    /// 0.1 to 3.9.
    Low,
    /// 4.0 to 6.9.
    Medium,
    /// 7.0 to 8.9.
    High,
    /// 9.0 to 10.0.
    Critical,
}

impl Severity {
    /// Every rating, from `None` to `Critical`.
    pub const ALL: [Self; 5] = [
        Self::None,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// The rating of a score.
    #[must_use]
    pub const fn from_score(score: Score) -> Self {
        match score.tenths() {
            0 => Self::None,
            1..=39 => Self::Low,
            40..=69 => Self::Medium,
            70..=89 => Self::High,
            _ => Self::Critical,
        }
    }

    /// The rating's name as the specifications write it: `"None"`, `"Low"`,
    /// `"Medium"`, `"High"` or `"Critical"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
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

    /// Parses a rating name, ignoring ASCII case (NVD writes `"CRITICAL"`).
    fn from_str(text: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|severity| severity.as_str().eq_ignore_ascii_case(text))
            .ok_or_else(|| Error::UnknownSeverity(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenths_round_trip_through_f64_and_text() {
        for tenths in 0..=100 {
            let score = Score::from_tenths(tenths).unwrap();
            assert_eq!(Score::try_from(score.value()), Ok(score));
            assert_eq!(score.to_string().parse::<Score>(), Ok(score));
            assert_eq!(score.to_string().parse::<f64>().unwrap(), score.value());
        }
        assert_eq!(Score::from_tenths(101), None);
        assert_eq!(Score::MAX.to_string(), "10.0");
        assert_eq!(Score::ZERO.to_string(), "0.0");
        assert_eq!(format!("{:?}", Score::MAX), "Score(10.0)");
    }

    #[test]
    fn rejects_numbers_that_are_not_scores() {
        for value in [-0.1, 10.1, 9.85, 0.05, f64::NAN, f64::INFINITY] {
            assert!(Score::try_from(value).is_err(), "{value}");
        }
        assert_eq!(Score::try_from(-0.0), Ok(Score::ZERO));
        assert!("high".parse::<Score>().is_err());
        assert_eq!("10".parse::<Score>(), Ok(Score::MAX));
    }

    #[test]
    fn severity_bands() {
        let cases = [
            (0, Severity::None),
            (1, Severity::Low),
            (39, Severity::Low),
            (40, Severity::Medium),
            (69, Severity::Medium),
            (70, Severity::High),
            (89, Severity::High),
            (90, Severity::Critical),
            (100, Severity::Critical),
        ];
        for (tenths, severity) in cases {
            assert_eq!(Score::from_tenths(tenths).unwrap().severity(), severity);
        }
        assert!(Severity::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        for severity in Severity::ALL {
            assert_eq!(severity.to_string().parse::<Severity>(), Ok(severity));
        }
        assert_eq!("CRITICAL".parse::<Severity>(), Ok(Severity::Critical));
        assert!("severe".parse::<Severity>().is_err());
    }
}

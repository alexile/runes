//! [`CveId`]: a validated CVE identifier.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// A CVE identifier such as `CVE-2021-44228`.
///
/// The format is `CVE-YYYY-NNNN…`: a four-digit year and a sequence number
/// of at least four digits ([CVE ID syntax](https://www.cve.org/ResourcesSupport/FAQs#pc_cve_recordscve_id_syntax)).
/// Parsing is case-insensitive and trims surrounding whitespace; the id is
/// stored and displayed in canonical upper case. Ids order by year, then
/// sequence number, so `CVE-2021-9999 < CVE-2021-10000`.
///
/// Serialized as its string form.
///
/// # Examples
///
/// ```
/// use rune_cve::CveId;
///
/// let id: CveId = "cve-2021-44228".parse()?;
/// assert_eq!(id.to_string(), "CVE-2021-44228");
/// assert_eq!((id.year(), id.sequence()), (2021, 44228));
/// assert!("CVE-21-1".parse::<CveId>().is_err());
/// # Ok::<(), rune_cve::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CveId {
    year: u16,
    sequence: u64,
    /// Digits in the sequence number (`0001` keeps its zeros).
    width: u8,
}

/// Longest sequence number accepted, in digits. CVE allows "arbitrary"
/// length; 19 digits always fit in a `u64`.
const MAX_SEQUENCE_DIGITS: usize = 19;

impl CveId {
    /// The id for `year` and `sequence`, padding the sequence to four
    /// digits as CVE does.
    ///
    /// Returns `None` if `year` is not four digits.
    #[must_use]
    pub fn new(year: u16, sequence: u64) -> Option<Self> {
        if !(1000..=9999).contains(&year) {
            return None;
        }
        let digits = sequence.checked_ilog10().map_or(1, |d| d + 1);
        // At most 20 digits for a u64.
        let width = u8::try_from(digits.max(4)).unwrap_or(u8::MAX);
        Some(Self {
            year,
            sequence,
            width,
        })
    }

    /// The year part.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The sequence number.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

impl FromStr for CveId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || Error::InvalidCveId(s.chars().take(64).collect());
        let t = s.trim();
        let rest = t
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("CVE-"))
            .map(|_| &t[4..])
            .ok_or_else(err)?;
        let (year, seq) = rest.split_once('-').ok_or_else(err)?;
        let all_digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        if year.len() != 4
            || !all_digits(year)
            || seq.len() < 4
            || seq.len() > MAX_SEQUENCE_DIGITS
            || !all_digits(seq)
        {
            return Err(err());
        }
        let year: u16 = year.parse().map_err(|_| err())?;
        if year < 1000 {
            return Err(err());
        }
        Ok(Self {
            year,
            sequence: seq.parse().map_err(|_| err())?,
            width: u8::try_from(seq.len()).map_err(|_| err())?,
        })
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CVE-{}-{:0width$}",
            self.year,
            self.sequence,
            width = usize::from(self.width)
        )
    }
}

impl serde::Serialize for CveId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for CveId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays() {
        for s in [
            "CVE-2014-0160",
            "CVE-2021-44228",
            "CVE-1999-0001",
            "CVE-2024-1234567",
        ] {
            assert_eq!(s.parse::<CveId>().unwrap().to_string(), s);
        }
        assert_eq!(
            " cve-2014-0160\n".parse::<CveId>().unwrap().to_string(),
            "CVE-2014-0160"
        );
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "CVE",
            "CVE-2021",
            "CVE-2021-123",
            "CVE-21-1234",
            "CVE-2021-12a4",
            "GHSA-2021-1234",
            "CVE-2021-+234",
            "CVE-0999-1234",
            "CVE-2021-12345678901234567890",
            "CVÉ-2021-1234",
        ] {
            assert!(s.parse::<CveId>().is_err(), "{s}");
        }
    }

    #[test]
    fn orders_numerically() {
        let a: CveId = "CVE-2021-9999".parse().unwrap();
        let b: CveId = "CVE-2021-10000".parse().unwrap();
        let c: CveId = "CVE-2022-0001".parse().unwrap();
        assert!(a < b && b < c);
    }

    #[test]
    fn new_pads_to_four_digits() {
        assert_eq!(CveId::new(2014, 160).unwrap().to_string(), "CVE-2014-0160");
        assert_eq!(
            CveId::new(2021, 44228).unwrap().to_string(),
            "CVE-2021-44228"
        );
        assert!(CveId::new(99, 1).is_none());
        assert_eq!(
            CveId::new(2014, 160),
            Some("CVE-2014-0160".parse().unwrap())
        );
    }

    #[test]
    fn serde_as_string() {
        let id: CveId = serde_json::from_str("\"CVE-2014-0160\"").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"CVE-2014-0160\"");
        assert!(serde_json::from_str::<CveId>("\"nope\"").is_err());
    }
}

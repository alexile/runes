//! [`Date`]: a calendar date as the EPSS and KEV feeds write it.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// A calendar date (proleptic Gregorian), written `YYYY-MM-DD`.
///
/// Parsing also accepts a longer ISO 8601 timestamp and keeps only its
/// date (`2025-03-15T00:00:00+0000` is 2025-03-15), which is how the EPSS
/// CSV header writes its score date. Serialized as `YYYY-MM-DD`.
///
/// # Examples
///
/// ```
/// use rune_epss::Date;
///
/// let added: Date = "2021-12-10".parse()?;
/// let due: Date = "2021-12-24".parse()?;
/// assert!(added < due);
/// assert_eq!(due.days_since(added), 14);
/// assert!("2021-02-29".parse::<Date>().is_err());
/// # Ok::<(), rune_epss::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

const fn is_leap(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Date {
    /// The date, if it exists.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        if year > 9999 || month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, 1 to 31.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Days since 1970-01-01 (negative before).
    #[must_use]
    pub const fn to_unix_days(self) -> i64 {
        // Howard Hinnant's days_from_civil.
        let y = self.year as i64 - if self.month <= 2 { 1 } else { 0 };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = self.month as i64;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + self.day as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The date `days` after 1970-01-01, if it is between years 0 and
    /// 9999.
    #[must_use]
    pub fn from_unix_days(days: i64) -> Option<Self> {
        // Howard Hinnant's civil_from_days.
        let z = days.checked_add(719_468)?;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self::new(
            u16::try_from(year).ok()?,
            u8::try_from(month).ok()?,
            u8::try_from(day).ok()?,
        )
    }

    /// Whole days from `earlier` to `self` (negative if `earlier` is
    /// later).
    #[must_use]
    pub const fn days_since(self, earlier: Self) -> i64 {
        self.to_unix_days() - earlier.to_unix_days()
    }
}

impl FromStr for Date {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || Error::InvalidDate(s.chars().take(40).collect());
        let t = s.trim();
        let b = t.as_bytes();
        if b.len() < 10 || b[4] != b'-' || b[7] != b'-' || (b.len() > 10 && b[10] != b'T') {
            return Err(err());
        }
        let num = |r: core::ops::Range<usize>| -> Option<u16> {
            let part = t.get(r)?;
            if part.bytes().all(|c| c.is_ascii_digit()) {
                part.parse().ok()
            } else {
                None
            }
        };
        let year = num(0..4).ok_or_else(err)?;
        let month = num(5..7)
            .and_then(|m| u8::try_from(m).ok())
            .ok_or_else(err)?;
        let day = num(8..10)
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(err)?;
        Self::new(year, month, day).ok_or_else(err)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl serde::Serialize for Date {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Date {
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
        let d: Date = "2024-02-29".parse().unwrap();
        assert_eq!((d.year(), d.month(), d.day()), (2024, 2, 29));
        assert_eq!(d.to_string(), "2024-02-29");
        let ts: Date = "2025-03-15T00:00:00+0000".parse().unwrap();
        assert_eq!(ts.to_string(), "2025-03-15");
        for bad in [
            "",
            "2024",
            "2024-2-29",
            "2023-02-29",
            "2024-13-01",
            "2024-00-10",
            "2024-01-32",
            "2024/01/01",
            "2024-01-01x",
            "+024-01-01",
            "2024-01-1é",
        ] {
            assert!(bad.parse::<Date>().is_err(), "{bad}");
        }
        assert_eq!(Date::new(1900, 2, 29), None);
        assert!(Date::new(2000, 2, 29).is_some());
    }

    #[test]
    fn unix_days() {
        let epoch = Date::new(1970, 1, 1).unwrap();
        assert_eq!(epoch.to_unix_days(), 0);
        let d = Date::new(2021, 12, 10).unwrap();
        assert_eq!(d.to_unix_days(), 18_971);
        for days in [-719_468, -1, 0, 1, 18_971, 2_932_896] {
            let date = Date::from_unix_days(days).unwrap();
            assert_eq!(date.to_unix_days(), days);
        }
        assert_eq!(Date::from_unix_days(2_932_897), None);
        assert_eq!(Date::from_unix_days(i64::MAX), None);
        assert_eq!(Date::from_unix_days(-719_528), Date::new(0, 1, 1));
        assert_eq!(Date::from_unix_days(-719_529), None);
    }
}

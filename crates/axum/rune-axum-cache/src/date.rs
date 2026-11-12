//! HTTP-date parsing and formatting ([RFC 9110 §5.6.7]).
//!
//! [RFC 9110 §5.6.7]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.7

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderValue;

use crate::Error;

const SECS_PER_DAY: u64 = 86_400;
/// `Fri, 31 Dec 9999 23:59:59 GMT`, the last instant a four-digit year holds.
const MAX_SECS: u64 = 253_402_300_799;

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const LONG_DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A timestamp with one-second resolution, as carried by `Last-Modified`,
/// `If-Modified-Since` and `If-Unmodified-Since`.
///
/// Covers `1970-01-01T00:00:00Z` through `9999-12-31T23:59:59Z`. Formatting
/// ([`Display`](fmt::Display)) always produces the preferred IMF-fixdate
/// form; parsing also accepts the two obsolete forms recipients must
/// understand (RFC 850 and C `asctime`). The day-of-week name must be a valid
/// name but is not checked against the date.
///
/// # Examples
///
/// ```rust
/// use rune_axum_cache::HttpDate;
///
/// let date: HttpDate = "Sun, 06 Nov 1994 08:49:37 GMT".parse()?;
/// assert_eq!(date.unix_secs(), 784_111_777);
/// assert_eq!(HttpDate::parse("Sunday, 06-Nov-94 08:49:37 GMT")?, date);
/// assert_eq!(HttpDate::parse("Sun Nov  6 08:49:37 1994")?, date);
/// assert_eq!(date.to_string(), "Sun, 06 Nov 1994 08:49:37 GMT");
/// # Ok::<(), rune_axum_cache::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpDate(u64);

impl HttpDate {
    /// The earliest representable date, the Unix epoch.
    pub const UNIX_EPOCH: Self = Self(0);

    /// Creates a date from whole seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`Error::DateOutOfRange`] after the end of year 9999.
    pub const fn from_unix_secs(secs: u64) -> Result<Self, Error> {
        if secs > MAX_SECS {
            Err(Error::DateOutOfRange)
        } else {
            Ok(Self(secs))
        }
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_secs(self) -> u64 {
        self.0
    }

    /// Parses any of the three HTTP-date forms. Surrounding whitespace is
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDate`] when the text is not a valid HTTP-date.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let b = text.trim_matches([' ', '\t']).as_bytes();
        parse_imf_fixdate(b)
            .or_else(|| parse_rfc850(b))
            .or_else(|| parse_asctime(b))
            .ok_or(Error::InvalidDate)
    }

    /// The date as a header value in IMF-fixdate form.
    #[must_use]
    pub fn to_header_value(self) -> HeaderValue {
        crate::ascii_header_value(&self.to_string())
    }
}

impl FromStr for HttpDate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<SystemTime> for HttpDate {
    type Error = Error;

    /// Converts a system time, truncating to whole seconds.
    ///
    /// Fails with [`Error::DateOutOfRange`] before 1970 or after 9999.
    fn try_from(time: SystemTime) -> Result<Self, Self::Error> {
        let secs = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::DateOutOfRange)?
            .as_secs();
        Self::from_unix_secs(secs)
    }
}

impl From<HttpDate> for SystemTime {
    fn from(date: HttpDate) -> Self {
        UNIX_EPOCH + Duration::from_secs(date.0)
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0 / SECS_PER_DAY;
        let rem = self.0 % SECS_PER_DAY;
        let (year, month, day) = civil_from_days(days);
        // 1970-01-01 was a Thursday.
        let weekday = DAYS[usize::try_from((days + 4) % 7).unwrap_or(0)];
        let month = MONTHS[usize::try_from(month - 1).unwrap_or(0)];
        write!(
            f,
            "{weekday}, {day:02} {month} {year:04} {:02}:{:02}:{:02} GMT",
            rem / 3600,
            rem / 60 % 60,
            rem % 60
        )
    }
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`
fn parse_imf_fixdate(b: &[u8]) -> Option<HttpDate> {
    if b.len() != 29 || &b[3..5] != b", " || b[7] != b' ' || b[11] != b' ' || b[16] != b' ' {
        return None;
    }
    if &b[25..] != b" GMT" || !DAYS.iter().any(|d| d.as_bytes() == &b[..3]) {
        return None;
    }
    let day = digits(&b[5..7])?;
    let month = month(&b[8..11])?;
    let year = digits(&b[12..16])?;
    let secs = time_of_day(&b[17..25])?;
    build(year, month, day, secs)
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`
fn parse_rfc850(b: &[u8]) -> Option<HttpDate> {
    let comma = b.iter().position(|&c| c == b',')?;
    if !LONG_DAYS.iter().any(|d| d.as_bytes() == &b[..comma]) {
        return None;
    }
    let r = b.get(comma + 1..)?;
    if r.len() != 23 || r[0] != b' ' || r[3] != b'-' || r[7] != b'-' || r[10] != b' ' {
        return None;
    }
    if &r[19..] != b" GMT" {
        return None;
    }
    let day = digits(&r[1..3])?;
    let month = month(&r[4..7])?;
    let yy = digits(&r[8..10])?;
    // Two-digit years: 70-99 are 19xx, 00-69 are 20xx (no clock in a
    // sans-I/O parser; this matches common practice).
    let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
    let secs = time_of_day(&r[11..19])?;
    build(year, month, day, secs)
}

/// `Sun Nov  6 08:49:37 1994`
fn parse_asctime(b: &[u8]) -> Option<HttpDate> {
    if b.len() != 24 || b[3] != b' ' || b[7] != b' ' || b[10] != b' ' || b[19] != b' ' {
        return None;
    }
    if !DAYS.iter().any(|d| d.as_bytes() == &b[..3]) {
        return None;
    }
    let month = month(&b[4..7])?;
    let day = match b[8] {
        b' ' => digits(&b[9..10])?,
        _ => digits(&b[8..10])?,
    };
    let secs = time_of_day(&b[11..19])?;
    let year = digits(&b[20..24])?;
    build(year, month, day, secs)
}

fn digits(b: &[u8]) -> Option<u64> {
    b.iter().try_fold(0u64, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + u64::from(c - b'0'))
    })
}

fn month(b: &[u8]) -> Option<u64> {
    let index = MONTHS.iter().position(|m| m.as_bytes() == b)?;
    u64::try_from(index + 1).ok()
}

/// `HH:MM:SS` as seconds since midnight. A leap second (`:60`) is folded
/// into `:59`, since the date has no way to represent it.
fn time_of_day(b: &[u8]) -> Option<u64> {
    if b.len() != 8 || b[2] != b':' || b[5] != b':' {
        return None;
    }
    let (h, m, s) = (digits(&b[..2])?, digits(&b[3..5])?, digits(&b[6..])?);
    (h < 24 && m < 60 && s <= 60).then(|| h * 3600 + m * 60 + s.min(59))
}

fn build(year: u64, month: u64, day: u64, secs: u64) -> Option<HttpDate> {
    if !(1970..=9999).contains(&year) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    HttpDate::from_unix_secs(days_from_civil(year, month, day) * SECS_PER_DAY + secs).ok()
}

const fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (year >= 1970).
///
/// Howard Hinnant's `days_from_civil`, restricted to non-negative values.
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]: `(year, month, day)`.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_EXAMPLE: u64 = 784_111_777;

    #[test]
    fn parses_all_three_forms_from_rfc_9110() {
        for text in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun Nov 06 08:49:37 1994",
            "  Sun, 06 Nov 1994 08:49:37 GMT\t",
        ] {
            assert_eq!(
                HttpDate::parse(text).unwrap().unix_secs(),
                RFC_EXAMPLE,
                "{text}"
            );
        }
    }

    #[test]
    fn formats_imf_fixdate() {
        let d = HttpDate::from_unix_secs(RFC_EXAMPLE).unwrap();
        assert_eq!(d.to_string(), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(
            HttpDate::UNIX_EPOCH.to_string(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        let max = HttpDate::from_unix_secs(MAX_SECS).unwrap();
        assert_eq!(max.to_string(), "Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(HttpDate::parse(&max.to_string()), Ok(max));
    }

    #[test]
    fn known_dates() {
        // Leap day, century leap year, and a post-2038 date.
        assert_eq!(
            HttpDate::parse("Tue, 29 Feb 2000 00:00:00 GMT")
                .unwrap()
                .unix_secs(),
            951_782_400
        );
        assert_eq!(
            HttpDate::parse("Sun, 07 Feb 2106 06:28:16 GMT")
                .unwrap()
                .unix_secs(),
            4_294_967_296
        );
        assert_eq!(
            HttpDate::parse("Wednesday, 01-Jan-69 00:00:00 GMT")
                .unwrap()
                .to_string(),
            "Tue, 01 Jan 2069 00:00:00 GMT"
        );
    }

    #[test]
    fn rejects_invalid_dates() {
        for text in [
            "",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 nov 1994 08:49:37 GMT",
            "Sun, 30 Feb 2000 00:00:00 GMT",
            "Sun, 29 Feb 1900 00:00:00 GMT",
            "Sun, 00 Jan 2000 00:00:00 GMT",
            "Sun, 01 Jan 1969 23:59:59 GMT",
            "Sun, 01 Jan 2000 24:00:00 GMT",
            "Sun, 01 Jan 2000 23:60:00 GMT",
            "Sun, 01 Jan 2000 23:59:61 GMT",
            "Sun, 01 Jan +200 23:59:59 GMT",
            "Sun, 06-Nov-94 08:49:37 GMT",
            "Sunday, 06 Nov 1994 08:49:37 GMT",
            "Sun Nov 6 08:49:37 1994",
            "Sün, 06 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(HttpDate::parse(text), Err(Error::InvalidDate), "{text:?}");
        }
    }

    #[test]
    fn leap_second_folds_into_59() {
        let d = HttpDate::parse("Sat, 31 Dec 2016 23:59:60 GMT").unwrap();
        assert_eq!(d.to_string(), "Sat, 31 Dec 2016 23:59:59 GMT");
    }

    #[test]
    fn range_and_system_time() {
        assert_eq!(
            HttpDate::from_unix_secs(MAX_SECS + 1),
            Err(Error::DateOutOfRange)
        );
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(HttpDate::try_from(before), Err(Error::DateOutOfRange));
        let t = UNIX_EPOCH + Duration::from_millis(1_500);
        let d = HttpDate::try_from(t).unwrap();
        assert_eq!(d.unix_secs(), 1);
        assert_eq!(SystemTime::from(d), UNIX_EPOCH + Duration::from_secs(1));
    }

    #[test]
    fn civil_round_trip_over_many_days() {
        for days in (0..2_932_897).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
            assert!(d >= 1 && d <= days_in_month(y, m));
        }
    }
}

//! Cookie dates: the lenient parser of [RFC 6265 §5.1.1] and the
//! IMF-fixdate serializer ([RFC 9110 §5.6.7]).
//!
//! [RFC 6265 §5.1.1]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1
//! [RFC 9110 §5.6.7]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.7

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Parses a cookie date (the value of an `Expires` attribute) with the
/// algorithm of [RFC 6265 §5.1.1].
///
/// The algorithm is deliberately lenient: it splits the input at delimiters
/// and picks the first token that looks like a time, a day of month, a
/// month and a year, in any order. Two-digit years `70`–`99` mean
/// 1970–1999 and `00`–`69` mean 2000–2069. Years before 1601 and dates
/// that do not exist (`31 Feb`) are rejected. Time zones are ignored: every
/// cookie date is UTC.
///
/// Returns `None` if the input is not a cookie date, or if the date cannot
/// be represented as a [`SystemTime`] on this platform.
///
/// ```
/// use rune_cookie::{format_cookie_date, parse_cookie_date};
///
/// let date = parse_cookie_date("Wednesday, 01-Jan-10 0:0:00 GMT").unwrap();
/// assert_eq!(format_cookie_date(date), "Fri, 01 Jan 2010 00:00:00 GMT");
/// assert_eq!(parse_cookie_date("IAintNoDateFool"), None);
/// ```
///
/// [RFC 6265 §5.1.1]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.1
#[must_use]
pub fn parse_cookie_date(input: &str) -> Option<SystemTime> {
    parse_unix(input).and_then(system_time_from_unix)
}

/// Formats `time` as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), the
/// preferred `Expires` format ([RFC 9110 §5.6.7]). Sub-second precision is
/// truncated.
///
/// Dates before year 1 or after year 9999 cannot be written with four year
/// digits; they are clamped to the nearest representable second.
///
/// [RFC 9110 §5.6.7]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.7
#[must_use]
pub fn format_cookie_date(time: SystemTime) -> String {
    format_unix(unix_from_system_time(time))
}

/// Seconds since the Unix epoch of the first second of year 1 and of the
/// last second of year 9999.
const MIN_UNIX: i64 = -62_135_596_800;
const MAX_UNIX: i64 = 253_402_300_799;

/// Seconds since the Unix epoch, negative before 1970, saturating.
pub fn unix_from_system_time(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => {
            let duration = before.duration();
            // Round towards negative infinity so that formatting truncates.
            let secs = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
            i64::try_from(secs).map_or(i64::MIN, |secs| -secs)
        }
    }
}

/// The [`SystemTime`] `secs` seconds after (or before) the Unix epoch.
pub fn system_time_from_unix(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

fn format_unix(secs: i64) -> String {
    let secs = secs.clamp(MIN_UNIX, MAX_UNIX);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
    let month_name = MONTH_NAMES
        .get(usize::try_from(month).unwrap_or(1).saturating_sub(1))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS.get(weekday).copied().unwrap_or("Sun"),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// The RFC 6265 §5.1.1 algorithm, returning seconds since the Unix epoch.
fn parse_unix(input: &str) -> Option<i64> {
    let mut time: Option<(u32, u32, u32)> = None;
    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<u32> = None;

    for token in input
        .as_bytes()
        .split(|&b| is_delimiter(b))
        .filter(|token| !token.is_empty())
    {
        if time.is_none()
            && let Some(found) = parse_time(token)
        {
            time = Some(found);
        } else if day.is_none()
            && let Some(found) = parse_digits(token, 1, 2)
        {
            day = Some(found);
        } else if month.is_none()
            && let Some(found) = parse_month(token)
        {
            month = Some(found);
        } else if year.is_none()
            && let Some(found) = parse_digits(token, 2, 4)
        {
            year = Some(found);
        }
    }

    let (hour, minute, second) = time?;
    let (day, month, mut year) = (day?, month?, year?);
    if (70..=99).contains(&year) {
        year += 1900;
    } else if year <= 69 {
        year += 2000;
    }
    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    Some(days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

/// `delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E`
const fn is_delimiter(b: u8) -> bool {
    matches!(b, 0x09 | 0x20..=0x2F | 0x3B..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E)
}

/// Reads `min..=max` leading digits of `token`; the next byte, if any, must
/// not be a digit (`n*mDIGIT ( non-digit *OCTET )`). Returns the value and
/// the rest of the token.
fn leading_digits(token: &[u8], min: usize, max: usize) -> Option<(u32, &[u8])> {
    let count = token.iter().take_while(|b| b.is_ascii_digit()).count();
    if count < min || count > max {
        return None;
    }
    let (digits, rest) = token.split_at(count);
    let value = digits
        .iter()
        .fold(0_u32, |acc, d| acc * 10 + u32::from(d - b'0'));
    Some((value, rest))
}

fn parse_digits(token: &[u8], min: usize, max: usize) -> Option<u32> {
    leading_digits(token, min, max).map(|(value, _)| value)
}

/// `hms-time ( non-digit *OCTET )` where
/// `hms-time = time-field ":" time-field ":" time-field` and
/// `time-field = 1*2DIGIT`.
fn parse_time(token: &[u8]) -> Option<(u32, u32, u32)> {
    let (hour, rest) = leading_digits(token, 1, 2)?;
    let rest = rest.strip_prefix(b":")?;
    let (minute, rest) = leading_digits(rest, 1, 2)?;
    let rest = rest.strip_prefix(b":")?;
    let (second, _) = leading_digits(rest, 1, 2)?;
    Some((hour, minute, second))
}

/// `month = ( "jan" / … / "dec" ) *OCTET`, case-insensitive; 1-based.
fn parse_month(token: &[u8]) -> Option<u32> {
    let prefix = token.get(..3)?;
    MONTHS
        .iter()
        .position(|month| prefix.eq_ignore_ascii_case(month.as_bytes()))
        .and_then(|index| u32::try_from(index + 1).ok())
}

const fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: `(year, month, day)`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> Option<String> {
        parse_unix(input).map(format_unix)
    }

    #[test]
    fn rfc_examples() {
        for (input, expected) in [
            (
                "Sun, 06 Nov 1994 08:49:37 GMT",
                "Sun, 06 Nov 1994 08:49:37 GMT",
            ),
            (
                "Sunday, 06-Nov-94 08:49:37 GMT",
                "Sun, 06 Nov 1994 08:49:37 GMT",
            ),
            ("Sun Nov  6 08:49:37 1994", "Sun, 06 Nov 1994 08:49:37 GMT"),
            (
                "Thu, 01 Jan 1970 00:00:00 GMT",
                "Thu, 01 Jan 1970 00:00:00 GMT",
            ),
            ("29 Feb 2000 1:2:3", "Tue, 29 Feb 2000 01:02:03 GMT"),
            (
                "Fri, 31 Dec 9999 23:59:59 GMT",
                "Fri, 31 Dec 9999 23:59:59 GMT",
            ),
            (
                "Mon, 01 Jan 1601 00:00:00 GMT",
                "Mon, 01 Jan 1601 00:00:00 GMT",
            ),
        ] {
            assert_eq!(parsed(input).as_deref(), Some(expected), "{input}");
        }
    }

    #[test]
    fn rejects_impossible_dates() {
        for input in [
            "29 Feb 1900 00:00:00",
            "31 Apr 2020 00:00:00",
            "1 Jan 1600 00:00:00",
            "1 Jan 2020 24:00:00",
            "1 Jan 2020 00:60:00",
            "1 Jan 2020 00:00:60",
            "0 Jan 2020 00:00:00",
            "1 Jan 2020",
            "1 2020 00:00:00",
            "",
            "Jan",
        ] {
            assert_eq!(parse_unix(input), None, "{input:?}");
        }
    }

    #[test]
    fn non_ascii_does_not_panic() {
        assert_eq!(parse_unix("1 Jän 2020 00:00:00"), None);
        assert_eq!(parse_unix("１ Jan 2020 00:00:00"), None);
    }

    #[test]
    fn civil_round_trip() {
        for days in [-719_162, -1, 0, 1, 10_957, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn system_time_round_trip_before_epoch() {
        let time = system_time_from_unix(-11_644_473_600).unwrap();
        assert_eq!(unix_from_system_time(time), -11_644_473_600);
        assert_eq!(format_cookie_date(time), "Mon, 01 Jan 1601 00:00:00 GMT");
        let sub = time + Duration::from_millis(500);
        assert_eq!(format_cookie_date(sub), "Mon, 01 Jan 1601 00:00:00 GMT");
        let before = time - Duration::from_millis(500);
        assert_eq!(format_cookie_date(before), "Sun, 31 Dec 1600 23:59:59 GMT");
    }

    #[test]
    fn clamps_out_of_range() {
        assert_eq!(format_unix(i64::MAX), "Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(format_unix(i64::MIN), "Mon, 01 Jan 0001 00:00:00 GMT");
    }
}

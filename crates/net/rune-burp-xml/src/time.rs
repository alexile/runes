//! Burp's `<time>` values: Java's `Date.toString()` form,
//! `EEE MMM dd HH:mm:ss zzz yyyy`, e.g. `Tue Jan 02 03:04:05 UTC 2024`.

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
/// Largest instant written: `9999-12-31T23:59:59Z`, in seconds.
const MAX_SECONDS: i64 = 253_402_300_799;

/// Zone abbreviations Java prints, with their offset in minutes.
const ZONES: [(&str, i64); 33] = [
    ("UTC", 0),
    ("GMT", 0),
    ("UT", 0),
    ("Z", 0),
    ("WET", 0),
    ("WEST", 60),
    ("BST", 60),
    ("CET", 60),
    ("CEST", 120),
    ("MET", 60),
    ("MEST", 120),
    ("EET", 120),
    ("EEST", 180),
    ("MSK", 180),
    ("IST", 330),
    ("SGT", 480),
    ("HKT", 480),
    ("CST", -360),
    ("CDT", -300),
    ("EST", -300),
    ("EDT", -240),
    ("MST", -420),
    ("MDT", -360),
    ("PST", -480),
    ("PDT", -420),
    ("AKST", -540),
    ("AKDT", -480),
    ("HST", -600),
    ("JST", 540),
    ("KST", 540),
    ("AEST", 600),
    ("AEDT", 660),
    ("NZST", 720),
];

/// Days since 1970-01-01 of a proleptic Gregorian date.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day count since 1970-01-01.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// An offset such as `+02:00`, `+0200`, `+2` or `-05:30`, in minutes.
fn numeric_offset(text: &str) -> Option<i64> {
    let (sign, digits) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => return None,
    };
    if !digits
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b':')
    {
        return None;
    }
    let (hours, minutes) = match digits.split_once(':') {
        Some((hours, minutes)) => (hours, minutes),
        None if digits.len() > 2 => digits.split_at(digits.len() - 2),
        None => (digits, "0"),
    };
    let hours: i64 = hours.parse().ok()?;
    let minutes: i64 = minutes.parse().ok()?;
    (hours <= 14 && minutes < 60).then_some(sign * (hours * 60 + minutes))
}

/// A zone's offset in minutes: an abbreviation, or `GMT±hh:mm` / `UTC±h`.
fn zone_offset(zone: &str) -> Option<i64> {
    if let Some((_, offset)) = ZONES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(zone))
    {
        return Some(*offset);
    }
    let rest = zone
        .strip_prefix("GMT")
        .or_else(|| zone.strip_prefix("UTC"))
        .unwrap_or(zone);
    numeric_offset(rest)
}

/// When a `<time>` value says, and whether its zone had to be assumed UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    /// Milliseconds since the Unix epoch.
    pub unix_milliseconds: u64,
    /// The zone was not recognised and read as UTC.
    pub zone_assumed: bool,
}

/// Parses `EEE MMM dd HH:mm:ss zzz yyyy`. The weekday is not checked.
pub fn parse(text: &str) -> Option<Parsed> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_weekday, month, day, clock, zone, year] = parts.as_slice() else {
        return None;
    };
    let month = MONTHS
        .iter()
        .position(|name| name.eq_ignore_ascii_case(month))?;
    let month = i64::try_from(month).ok()? + 1;
    let day: i64 = day.parse().ok()?;
    let year: i64 = year.parse().ok()?;
    if !(1970..=9999).contains(&year) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let mut clock = clock.split(':');
    let mut next = || clock.next().and_then(|part| part.parse::<i64>().ok());
    let (hour, minute, second) = (next()?, next()?, next()?);
    if hour > 23 || minute > 59 || second > 60 || clock.next().is_some() {
        return None;
    }
    let (offset, zone_assumed) = zone_offset(zone).map_or((0, true), |offset| (offset, false));
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset * 60;
    let seconds = u64::try_from(seconds.clamp(0, MAX_SECONDS)).ok()?;
    Some(Parsed {
        unix_milliseconds: seconds * 1000,
        zone_assumed,
    })
}

/// Formats an instant as Burp writes it, in UTC. Milliseconds are dropped
/// and instants past the year 9999 are clamped.
pub fn format(unix_milliseconds: u64) -> String {
    let seconds = i64::try_from(unix_milliseconds / 1000)
        .unwrap_or(MAX_SECONDS)
        .min(MAX_SECONDS);
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = WEEKDAYS[usize::try_from(days.rem_euclid(7)).unwrap_or(0)];
    let month = MONTHS[usize::try_from(month - 1).unwrap_or(0)];
    format!(
        "{weekday} {month} {day:02} {:02}:{:02}:{:02} UTC {year}",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(text: &str) -> Option<u64> {
        parse(text).map(|parsed| parsed.unix_milliseconds)
    }

    #[test]
    fn known_instants() {
        assert_eq!(millis("Thu Jan 01 00:00:00 UTC 1970"), Some(0));
        assert_eq!(
            millis("Tue Jan 02 03:04:05 UTC 2024"),
            Some(1_704_164_645_000)
        );
        assert_eq!(
            millis("Tue Jan 02 04:04:05 CET 2024"),
            Some(1_704_164_645_000)
        );
        assert_eq!(
            millis("Mon Jan 01 22:04:05 EST 2024"),
            Some(1_704_164_645_000)
        );
        assert_eq!(
            millis("Tue Jan 02 05:04:05 GMT+02:00 2024"),
            Some(1_704_164_645_000)
        );
        assert_eq!(
            millis("Thu Feb 29 12:00:00 UTC 2024"),
            Some(1_709_208_000_000)
        );
    }

    #[test]
    fn unknown_zones_are_assumed_utc() {
        let parsed = parse("Tue Jan 02 03:04:05 XYZT 2024").unwrap();
        assert!(parsed.zone_assumed);
        assert_eq!(parsed.unix_milliseconds, 1_704_164_645_000);
    }

    #[test]
    fn rejects_malformed() {
        for text in [
            "",
            "2024-01-02T03:04:05Z",
            "Tue Foo 02 03:04:05 UTC 2024",
            "Tue Feb 30 03:04:05 UTC 2024",
            "Tue Jan 02 24:00:00 UTC 2024",
            "Tue Jan 02 03:04 UTC 2024",
            "Tue Jan 02 03:04:05:06 UTC 2024",
            "Tue Jan 02 03:04:05 UTC 1969",
            "Tue Jan 02 03:04:05 UTC 99999",
        ] {
            assert_eq!(millis(text), None, "{text}");
        }
    }

    // Regression: an offset with a multi-byte
    // character was split inside it and panicked.
    #[test]
    fn non_ascii_offsets_are_rejected() {
        let parsed = parse("Tue Jan 02 03:04:05 GMT+1\u{fffd} 2024").unwrap();
        assert!(parsed.zone_assumed);
        assert_eq!(numeric_offset("+\u{e9}1"), None);
    }

    #[test]
    fn formats_and_round_trips() {
        assert_eq!(format(0), "Thu Jan 01 00:00:00 UTC 1970");
        assert_eq!(format(1_704_164_645_678), "Tue Jan 02 03:04:05 UTC 2024");
        assert_eq!(format(u64::MAX), "Fri Dec 31 23:59:59 UTC 9999");
        for seconds in [
            0_u64,
            951_782_400,
            1_709_208_000,
            4_102_444_800,
            253_402_300_799,
        ] {
            assert_eq!(millis(&format(seconds * 1000)), Some(seconds * 1000));
        }
    }
}

//! ISO 8601 / RFC 3339 timestamps for `startedDateTime`.
//!
//! HAR timestamps look like `2024-01-02T03:04:05.678Z` (Chrome) or
//! `2024-01-02T04:04:05.678+01:00` (Firefox, Charles). Parsing accepts any
//! number of fraction digits (kept to the millisecond), `Z`, `±hh:mm`,
//! `±hhmm`, `±hh` or no zone (read as UTC), and a space instead of `T`.

const MILLIS_PER_DAY: i64 = 86_400_000;
/// `9999-12-31T23:59:59.999Z`, the last instant with a four-digit year.
pub const MAX_UNIX_MILLIS: u64 = 253_402_300_799_999;

fn digits(bytes: &[u8], start: usize, len: usize) -> Option<i64> {
    let slice = bytes.get(start..start + len)?;
    slice.iter().try_fold(0_i64, |total, byte| {
        byte.is_ascii_digit()
            .then(|| total * 10 + i64::from(byte - b'0'))
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
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

/// Parses a timestamp to milliseconds since the Unix epoch.
///
/// Returns `None` for malformed text and for instants before 1970 or
/// after [`MAX_UNIX_MILLIS`].
pub fn parse_unix_millis(text: &str) -> Option<u64> {
    let bytes = text.trim().as_bytes();
    let year = digits(bytes, 0, 4)?;
    let month = digits(bytes, 5, 2)?;
    let day = digits(bytes, 8, 2)?;
    let hour = digits(bytes, 11, 2)?;
    let minute = digits(bytes, 14, 2)?;
    let second = digits(bytes, 17, 2)?;
    let separators = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|&(index, expected)| bytes.get(index) != Some(&expected))
        || !matches!(bytes.get(10), Some(b'T' | b't' | b' '))
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut index = 19;
    let mut millis = 0_i64;
    if matches!(bytes.get(index), Some(b'.' | b',')) {
        index += 1;
        let start = index;
        let mut scale = 100;
        while let Some(digit) = bytes.get(index).filter(|byte| byte.is_ascii_digit()) {
            millis += i64::from(digit - b'0') * scale;
            scale /= 10;
            index += 1;
        }
        if index == start {
            return None;
        }
    }
    let offset_minutes = match bytes.get(index) {
        None => 0,
        Some(b'Z' | b'z') if index + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) => {
            let rest = &bytes[index + 1..];
            let (hours, minutes) = match rest.len() {
                2 => (digits(rest, 0, 2)?, 0),
                4 => (digits(rest, 0, 2)?, digits(rest, 2, 2)?),
                5 if rest.get(2) == Some(&b':') => (digits(rest, 0, 2)?, digits(rest, 3, 2)?),
                _ => return None,
            };
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = hours * 60 + minutes;
            if *sign == b'+' { total } else { -total }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let seconds = hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    u64::try_from(days * MILLIS_PER_DAY + seconds * 1_000 + millis)
        .ok()
        .filter(|millis| *millis <= MAX_UNIX_MILLIS)
}

/// Formats milliseconds since the Unix epoch as `YYYY-MM-DDThh:mm:ss.sssZ`.
///
/// Instants after [`MAX_UNIX_MILLIS`] are clamped to it.
pub fn format_unix_millis(unix_millis: u64) -> String {
    let clamped = i64::try_from(unix_millis.min(MAX_UNIX_MILLIS)).unwrap_or_default();
    let (year, month, day) = civil_from_days(clamped.div_euclid(MILLIS_PER_DAY));
    let of_day = clamped.rem_euclid(MILLIS_PER_DAY);
    let (hour, minute) = (of_day / 3_600_000, of_day / 60_000 % 60);
    let (second, millis) = (of_day / 1_000 % 60, of_day % 1_000);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exporter_spellings() {
        let expected = Some(1_704_164_645_678);
        for text in [
            "2024-01-02T03:04:05.678Z",
            "2024-01-02T05:04:05.678+02:00",
            "2024-01-02T05:04:05.678+0200",
            "2024-01-02T05:04:05.678+02",
            "2024-01-01T22:04:05.678-05:00",
            "2024-01-02T03:04:05.678123456Z",
            "2024-01-02 03:04:05.678",
            " 2024-01-02t03:04:05,678z ",
        ] {
            assert_eq!(parse_unix_millis(text), expected, "{text}");
        }
        assert_eq!(parse_unix_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_unix_millis("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
    }

    #[test]
    fn rejects_malformed() {
        for text in [
            "",
            "garbage",
            "2024-13-01T00:00:00Z",
            "2024-01-02T03:04:05.Z",
            "2024-01-02T03:04:05Zjunk",
            "2024-01-02T03:04:05+2",
            "2024/01/02T03:04:05Z",
            "1969-12-31T23:59:59Z",
            "9999-12-31T23:59:59.999-01:00",
            "２０２４-01-02T03:04:05Z",
        ] {
            assert_eq!(parse_unix_millis(text), None, "{text}");
        }
    }

    #[test]
    fn formats_and_round_trips() {
        assert_eq!(format_unix_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_unix_millis(1_704_164_645_678),
            "2024-01-02T03:04:05.678Z"
        );
        assert_eq!(format_unix_millis(u64::MAX), "9999-12-31T23:59:59.999Z");
        for millis in [0, 1, 951_782_400_000, 1_709_164_800_000, MAX_UNIX_MILLIS] {
            assert_eq!(parse_unix_millis(&format_unix_millis(millis)), Some(millis));
        }
    }
}

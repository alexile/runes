//! RFC 3339 `date-time` values, as used by the `Expires` field.

use std::fmt;

use crate::Error;

const SECS_PER_DAY: i64 = 86_400;

/// A point in time, in whole seconds since the Unix epoch (UTC).
///
/// [`Timestamp::parse`] reads an [RFC 3339 §5.6](https://www.rfc-editor.org/rfc/rfc3339#section-5.6)
/// `date-time` (the format RFC 9116 requires for `Expires`), applying the
/// UTC offset and dropping fractional seconds. [`Display`](fmt::Display)
/// writes `YYYY-MM-DDTHH:MM:SSZ`.
///
/// ```
/// use rune_securitytxt::Timestamp;
///
/// let t = Timestamp::parse("2021-12-31T18:37:07.000Z")?;
/// assert_eq!(t.unix_seconds(), 1_640_975_827);
/// assert_eq!(Timestamp::parse("2021-12-31T20:37:07+02:00")?, t);
/// assert_eq!(t.to_string(), "2021-12-31T18:37:07Z");
/// # Ok::<(), rune_securitytxt::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// A timestamp `seconds` after the Unix epoch.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Parses an RFC 3339 `date-time`. `T` and `Z` may be lowercase; a
    /// leap second (`:60`) is accepted and counts as the following second.
    pub fn parse(text: &str) -> Result<Self, Error> {
        parse(text.as_bytes()).ok_or_else(|| Error::InvalidTimestamp {
            value: text.to_owned(),
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(SECS_PER_DAY);
        let secs = self.0.rem_euclid(SECS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

fn digits(b: &[u8], at: usize, n: usize) -> Option<i64> {
    let s = b.get(at..at + n)?;
    s.iter().try_fold(0i64, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + i64::from(c - b'0'))
    })
}

fn expect(b: &[u8], at: usize, c: u8) -> Option<()> {
    b.get(at)
        .is_some_and(|x| x.eq_ignore_ascii_case(&c))
        .then_some(())
}

fn parse(b: &[u8]) -> Option<Timestamp> {
    // full-date
    let year = digits(b, 0, 4)?;
    expect(b, 4, b'-')?;
    let month = digits(b, 5, 2)?;
    expect(b, 7, b'-')?;
    let day = digits(b, 8, 2)?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    expect(b, 10, b'T')?;
    // partial-time
    let hour = digits(b, 11, 2)?;
    expect(b, 13, b':')?;
    let minute = digits(b, 14, 2)?;
    expect(b, 16, b':')?;
    let second = digits(b, 17, 2)?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut at = 19;
    if b.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    // time-offset
    let offset = match b.get(at)? {
        b'Z' | b'z' => {
            at += 1;
            0
        }
        sign @ (b'+' | b'-') => {
            let oh = digits(b, at + 1, 2)?;
            expect(b, at + 3, b':')?;
            let om = digits(b, at + 4, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            at += 6;
            let o = oh * 3600 + om * 60;
            if *sign == b'-' { -o } else { o }
        }
        _ => return None,
    };
    if at != b.len() {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(Timestamp(
        days * SECS_PER_DAY + hour * 3600 + minute * 60 + second - offset,
    ))
}

const fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

const fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
const fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<i64> {
        Timestamp::parse(s).ok().map(Timestamp::unix_seconds)
    }

    #[test]
    fn known_answers() {
        assert_eq!(p("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(p("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(p("2021-12-31T18:37:07z"), Some(1_640_975_827));
        assert_eq!(p("2021-12-31t18:37:07.123456Z"), Some(1_640_975_827));
        assert_eq!(p("2021-12-31T10:37:07-08:00"), Some(1_640_975_827));
        // RFC 3339 §5.8 examples.
        assert_eq!(p("1985-04-12T23:20:50.52Z"), Some(482_196_050));
        assert_eq!(p("1996-12-19T16:39:57-08:00"), Some(851_042_397));
        assert_eq!(p("1990-12-31T23:59:60Z"), Some(662_688_000));
        assert_eq!(p("1937-01-01T12:00:27.87+00:20"), Some(-1_041_337_173));
    }

    #[test]
    fn rejects_invalid() {
        for s in [
            "",
            "2021-12-31",
            "2021-12-31 18:37:07Z",
            "2021-13-01T00:00:00Z",
            "2021-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2021-12-31T24:00:00Z",
            "2021-12-31T18:37:07",
            "2021-12-31T18:37:07.Z",
            "2021-12-31T18:37:07+0100",
            "2021-12-31T18:37:07Z ",
            "2021-12-31T18:37:07+24:00",
            "２021-12-31T18:37:07Z",
        ] {
            assert_eq!(p(s), None, "{s:?}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2024-02-29T23:59:59Z",
            "9999-12-31T23:59:59Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert_eq!(Timestamp::parse(s).map(|t| t.to_string()).as_deref(), Ok(s));
        }
    }
}

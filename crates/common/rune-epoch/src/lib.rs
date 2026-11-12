//! Unix timestamp conversions between epoch seconds and human-readable UTC strings.
//!
//! Converts Unix epoch values (seconds or milliseconds) to ISO 8601 UTC strings
//! and back, using pure Rust standard library arithmetic — no external time crates.
//! Handles the full signed 32-bit year range, including negative timestamps
//! (dates before 1970-01-01).
//!
//! # Features
//!
//! - [`now_secs`] — current Unix timestamp in seconds.
//! - [`now_millis`] — current Unix timestamp in milliseconds.
//! - [`to_utc_string`] — epoch seconds → `"YYYY-MM-DDTHH:MM:SSZ"`.
//! - [`from_utc_string`] — `"YYYY-MM-DDTHH:MM:SSZ"` → epoch seconds.
//! - [`EpochError`] — structured error for invalid datetime strings.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_epoch::{to_utc_string, from_utc_string};
//!
//! assert_eq!(to_utc_string(0), "1970-01-01T00:00:00Z");
//! assert_eq!(from_utc_string("1970-01-01T00:00:00Z").unwrap(), 0);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-epoch                          # print current epoch
//! rune-epoch 1704067200               # convert epoch to UTC
//! rune-epoch --millis                 # print current epoch in milliseconds
//! rune-epoch "2024-01-15T14:30:00Z"   # parse datetime string to epoch
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

/// Error returned when [`from_utc_string`] cannot parse its input.
///
/// Distinguish between a string that doesn't match the expected layout
/// (`InvalidFormat`), a date with out-of-range fields (`InvalidDate`), and
/// a time with out-of-range fields (`InvalidTime`).
///
/// # Examples
///
/// ```rust
/// use rune_epoch::{from_utc_string, EpochError};
///
/// assert!(matches!(from_utc_string("not-a-date"), Err(EpochError::InvalidFormat)));
/// assert!(matches!(from_utc_string("2024-13-01T00:00:00Z"), Err(EpochError::InvalidDate)));
/// assert!(matches!(from_utc_string("2024-01-01T25:00:00Z"), Err(EpochError::InvalidTime)));
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum EpochError {
    /// The string does not match `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DD HH:MM:SS`.
    InvalidFormat,
    /// Year, month, or day is outside the valid Gregorian calendar range.
    InvalidDate,
    /// Hour, minute, or second is outside 0–23/0–59/0–59.
    InvalidTime,
}

impl fmt::Display for EpochError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => {
                formatter.write_str("invalid datetime format — expected YYYY-MM-DDTHH:MM:SSZ")
            }
            Self::InvalidDate => formatter
                .write_str("invalid date — month must be 1–12 and day must be valid for the month"),
            Self::InvalidTime => {
                formatter.write_str("invalid time — hour 0–23, minute 0–59, second 0–59")
            }
        }
    }
}

impl core::error::Error for EpochError {}

/// Returns the current Unix timestamp in whole seconds, or `0` if the system
/// clock is set before the Unix epoch.
///
/// Available with the `std` feature (on by default).
///
/// # Examples
///
/// ```rust
/// use rune_epoch::now_secs;
///
/// assert!(now_secs() > 0);
/// ```
#[cfg(feature = "std")]
#[must_use]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns the current Unix timestamp in milliseconds, or `0` if the system
/// clock is set before the Unix epoch.
///
/// Available with the `std` feature (on by default).
///
/// # Examples
///
/// ```rust
/// use rune_epoch::now_millis;
///
/// assert!(now_millis() > 0);
/// ```
#[cfg(feature = "std")]
#[must_use]
pub fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Converts a Unix epoch (seconds) to a UTC datetime string in ISO 8601 format.
///
/// Handles negative timestamps (dates before 1970-01-01T00:00:00Z) using
/// pure Gregorian calendar arithmetic in the standard library — no external
/// time crates are required.
///
/// # Examples
///
/// ```rust
/// use rune_epoch::to_utc_string;
///
/// assert_eq!(to_utc_string(0),          "1970-01-01T00:00:00Z");
/// assert_eq!(to_utc_string(1704067200), "2024-01-01T00:00:00Z");
/// assert_eq!(to_utc_string(-86400),     "1969-12-31T00:00:00Z");
/// ```
#[must_use]
pub fn to_utc_string(epoch_secs: i64) -> String {
    let (year, month, day, hour, minute, second) = epoch_to_parts(epoch_secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parses a UTC datetime string and returns the Unix epoch in seconds.
///
/// Accepts both `"YYYY-MM-DDTHH:MM:SSZ"` (ISO 8601) and
/// `"YYYY-MM-DD HH:MM:SS"` (space separator, no trailing `Z`).
///
/// # Errors
///
/// Returns [`EpochError::InvalidFormat`] when the string layout does not match,
/// [`EpochError::InvalidDate`] for out-of-range date components, and
/// [`EpochError::InvalidTime`] for out-of-range time components.
///
/// # Examples
///
/// ```rust
/// use rune_epoch::from_utc_string;
///
/// assert_eq!(from_utc_string("1970-01-01T00:00:00Z").unwrap(), 0);
/// assert_eq!(from_utc_string("2024-01-01T00:00:00Z").unwrap(), 1704067200);
/// assert_eq!(from_utc_string("2024-01-01 00:00:00").unwrap(),  1704067200);
/// ```
pub fn from_utc_string(datetime: &str) -> Result<i64, EpochError> {
    let (date_part, time_part) = split_datetime(datetime)?;
    let (year, month, day) = parse_date(date_part)?;
    let (hour, minute, second) = parse_time(time_part)?;
    Ok(parts_to_epoch(year, month, day, hour, minute, second))
}

/// Returns `true` when `year` is a leap year in the proleptic Gregorian calendar.
///
/// A year is a leap year if it is divisible by 4, except that century years
/// (divisible by 100) are not leap years unless they are also divisible by 400.
///
/// # Examples
///
/// ```rust
/// use rune_epoch::is_leap_year;
///
/// assert!(is_leap_year(2000));
/// assert!(!is_leap_year(1900));
/// assert!(is_leap_year(2024));
/// assert!(!is_leap_year(2023));
/// ```
#[must_use]
pub const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)
}

/// Returns the number of days in `month` for the given `year`.
///
/// Accounts for leap years when `month` is February.
///
/// # Examples
///
/// ```rust
/// use rune_epoch::days_in_month;
///
/// assert_eq!(days_in_month(2, 2024), 29);
/// assert_eq!(days_in_month(2, 1900), 28);
/// assert_eq!(days_in_month(1, 2024), 31);
/// ```
#[must_use]
pub const fn days_in_month(month: u32, year: i32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_in_year(year: i32) -> i64 {
    if is_leap_year(year) { 366 } else { 365 }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn epoch_to_parts(epoch_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let total_seconds = epoch_secs;
    let second = total_seconds.rem_euclid(60) as u32;
    let total_minutes = total_seconds.div_euclid(60);
    let minute = total_minutes.rem_euclid(60) as u32;
    let total_hours = total_minutes.div_euclid(60);
    let hour = total_hours.rem_euclid(24) as u32;
    let mut remaining_days = total_hours.div_euclid(24);

    let mut year = 1970i32;
    if remaining_days >= 0 {
        loop {
            let year_days = days_in_year(year);
            if remaining_days < year_days {
                break;
            }
            remaining_days -= year_days;
            year += 1;
        }
    } else {
        loop {
            year -= 1;
            remaining_days += days_in_year(year);
            if remaining_days >= 0 {
                break;
            }
        }
    }

    let mut month = 1u32;
    loop {
        let month_days = i64::from(days_in_month(month, year));
        if remaining_days < month_days {
            break;
        }
        remaining_days -= month_days;
        month += 1;
    }

    let day = (remaining_days + 1) as u32;
    (year, month, day, hour, minute, second)
}

fn parts_to_epoch(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
    let mut days: i64 = 0;

    if year >= 1970 {
        for y in 1970..year {
            days += days_in_year(y);
        }
    } else {
        for y in year..1970 {
            days -= days_in_year(y);
        }
    }

    for m in 1..month {
        days += i64::from(days_in_month(m, year));
    }

    days += i64::from(day) - 1;

    days * 86400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
}

fn split_datetime(datetime: &str) -> Result<(&str, &str), EpochError> {
    let trimmed = datetime.trim_end_matches('Z');
    trimmed
        .find('T')
        .or_else(|| trimmed.find(' '))
        .map_or(Err(EpochError::InvalidFormat), |pos| {
            Ok((&trimmed[..pos], &trimmed[pos + 1..]))
        })
}

fn parse_date(date: &str) -> Result<(i32, u32, u32), EpochError> {
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() < 3 {
        return Err(EpochError::InvalidFormat);
    }

    let year: i32 = parts[0].parse().map_err(|_| EpochError::InvalidFormat)?;
    let month: u32 = parts[1].parse().map_err(|_| EpochError::InvalidFormat)?;
    let day: u32 = parts[2].parse().map_err(|_| EpochError::InvalidFormat)?;

    if !(1..=12).contains(&month) {
        return Err(EpochError::InvalidDate);
    }
    if day < 1 || day > days_in_month(month, year) {
        return Err(EpochError::InvalidDate);
    }

    Ok((year, month, day))
}

fn parse_time(time: &str) -> Result<(u32, u32, u32), EpochError> {
    let parts: Vec<&str> = time.split(':').collect();
    if parts.len() != 3 {
        return Err(EpochError::InvalidFormat);
    }

    let hour: u32 = parts[0].parse().map_err(|_| EpochError::InvalidFormat)?;
    let minute: u32 = parts[1].parse().map_err(|_| EpochError::InvalidFormat)?;
    let second: u32 = parts[2].parse().map_err(|_| EpochError::InvalidFormat)?;

    if hour > 23 {
        return Err(EpochError::InvalidTime);
    }
    if minute > 59 {
        return Err(EpochError::InvalidTime);
    }
    if second > 59 {
        return Err(EpochError::InvalidTime);
    }

    Ok((hour, minute, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn now_secs_is_positive() {
        assert!(now_secs() > 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn now_millis_is_positive() {
        assert!(now_millis() > 0);
    }

    #[test]
    fn epoch_zero_is_unix_epoch() {
        assert_eq!(to_utc_string(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_epoch_converts_correctly() {
        assert_eq!(to_utc_string(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn parse_unix_epoch_string() {
        assert_eq!(from_utc_string("1970-01-01T00:00:00Z").unwrap(), 0);
    }

    #[test]
    fn parse_known_date_to_epoch() {
        assert_eq!(
            from_utc_string("2024-01-01T00:00:00Z").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn space_separator_is_accepted() {
        assert_eq!(
            from_utc_string("2024-01-01 00:00:00").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn roundtrip_arbitrary_timestamp() {
        let timestamp: i64 = 1_700_000_042;
        assert_eq!(
            from_utc_string(&to_utc_string(timestamp)).unwrap(),
            timestamp
        );
    }

    #[test]
    fn negative_timestamp_before_1970() {
        assert_eq!(to_utc_string(-86400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn roundtrip_negative_timestamp() {
        let timestamp: i64 = -1_234_567;
        assert_eq!(
            from_utc_string(&to_utc_string(timestamp)).unwrap(),
            timestamp
        );
    }

    #[test]
    fn year_2000_is_leap() {
        assert!(is_leap_year(2000));
    }

    #[test]
    fn year_1900_is_not_leap() {
        assert!(!is_leap_year(1900));
    }

    #[test]
    fn year_2024_is_leap() {
        assert!(is_leap_year(2024));
    }

    #[test]
    fn year_2023_is_not_leap() {
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn invalid_format_returns_error() {
        assert_eq!(
            from_utc_string("not-a-date").unwrap_err(),
            EpochError::InvalidFormat
        );
    }

    #[test]
    fn invalid_month_returns_error() {
        assert_eq!(
            from_utc_string("2024-13-01T00:00:00Z").unwrap_err(),
            EpochError::InvalidDate
        );
    }

    #[test]
    fn invalid_hour_returns_error() {
        assert_eq!(
            from_utc_string("2024-01-01T25:00:00Z").unwrap_err(),
            EpochError::InvalidTime
        );
    }

    #[test]
    fn feb_29_leap_year_is_valid() {
        assert!(from_utc_string("2024-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn feb_29_non_leap_year_is_invalid() {
        assert_eq!(
            from_utc_string("1900-02-29T00:00:00Z").unwrap_err(),
            EpochError::InvalidDate
        );
    }

    #[test]
    fn days_in_february_leap_year() {
        assert_eq!(days_in_month(2, 2024), 29);
    }

    #[test]
    fn days_in_february_non_leap_year() {
        assert_eq!(days_in_month(2, 1900), 28);
    }
}

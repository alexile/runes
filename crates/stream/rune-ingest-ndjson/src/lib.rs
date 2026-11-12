//! Streaming NDJSON reader with a time-compression replay clock (Nx speed).
//!
//! Demo and test scenarios often want to replay a recorded NDJSON event log as if
//! it were arriving live, but faster (or slower) than it originally happened.
//! [`NdjsonReplay`] reads one JSON object per line, sleeps the appropriately
//! compressed real-time delay between records based on the gap between their
//! timestamps, and yields the parsed value — so a downstream consumer sees the
//! same pacing it would from a live feed, at whatever speed multiplier you choose.
//!
//! # Features
//!
//! - [`delay_for`] — the pure timing function: given two timestamps and a speed
//!   multiplier, the real-time delay to sleep before emitting the second record.
//! - [`NdjsonReplay`] — an iterator wrapping any [`BufRead`] that applies
//!   [`delay_for`] automatically between reads.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_ingest_ndjson::NdjsonReplay;
//! use std::io::Cursor;
//!
//! let data = "{\"ts\":0,\"v\":1}\n{\"ts\":0,\"v\":2}\n";
//! let reader = Cursor::new(data.as_bytes());
//! let replay = NdjsonReplay::new(reader, "ts", 1.0);
//!
//! let values: Vec<_> = replay.map(|r| r.unwrap()).collect();
//! assert_eq!(values.len(), 2);
//! assert_eq!(values[1]["v"], 2);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-ingest-ndjson --speed 10 --ts-field ts events.ndjson
//! ```

use std::fmt;
use std::io::{self, BufRead};
use std::time::Duration;

/// Computes the real-time delay to sleep before emitting the current record.
///
/// Takes the previous record's timestamp, the current record's timestamp (both
/// in milliseconds, any consistent unit works), and a speed multiplier.
///
/// `speed = 1.0` replays in real time. `speed = 10.0` replays ten times faster
/// (a tenth of the original delay). A non-positive `speed`, or a non-positive
/// (including out-of-order) timestamp delta, yields [`Duration::ZERO`] rather
/// than panicking or producing a negative delay. So does a NaN `speed`. A
/// delay too long for [`Duration`] saturates at [`Duration::MAX`].
///
/// # Example
///
/// ```rust
/// use rune_ingest_ndjson::delay_for;
/// use std::time::Duration;
///
/// assert_eq!(delay_for(0, 1000, 1.0), Duration::from_secs(1));
/// assert_eq!(delay_for(0, 1000, 10.0), Duration::from_millis(100));
/// assert_eq!(delay_for(1000, 500, 1.0), Duration::ZERO); // out of order
/// assert_eq!(delay_for(0, 1000, 0.0), Duration::ZERO); // non-positive speed
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "a delay is a float anyway; millisecond precision is lost only beyond 2^53 ms (285 000 years)"
)]
#[must_use]
pub fn delay_for(prev_ts_ms: i64, curr_ts_ms: i64, speed: f64) -> Duration {
    // i128 so that timestamps at opposite ends of the i64 range cannot
    // overflow the subtraction.
    let delta_ms = i128::from(curr_ts_ms) - i128::from(prev_ts_ms);
    if delta_ms <= 0 || speed.is_nan() || speed <= 0.0 {
        return Duration::ZERO;
    }
    let compressed_secs = (delta_ms as f64 / speed) / 1000.0;
    // A tiny speed can push the delay past what `Duration` holds; saturate.
    Duration::try_from_secs_f64(compressed_secs).unwrap_or(Duration::MAX)
}

/// An error encountered while replaying an NDJSON stream.
#[derive(Debug)]
pub enum ReplayError {
    /// The underlying reader failed.
    Io(io::Error),
    /// A line was not valid JSON.
    Parse(serde_json::Error),
    /// A line parsed as JSON but was missing the configured timestamp field, or
    /// the field wasn't an integer.
    MissingTimestamp,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "read error: {err}"),
            Self::Parse(err) => write!(f, "parse error: {err}"),
            Self::MissingTimestamp => write!(f, "missing or non-integer timestamp field"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Iterator that reads NDJSON records from `R`, one per line, sleeping between
/// records to replay the original pacing at a chosen speed multiplier.
///
/// Malformed lines yield `Err` without stopping the iterator or advancing the
/// internal clock — the next successful record's delay is still computed against
/// the last successfully parsed timestamp.
pub struct NdjsonReplay<R> {
    reader: R,
    ts_field: String,
    speed: f64,
    prev_ts: Option<i64>,
    line_buf: String,
}

impl<R: BufRead> NdjsonReplay<R> {
    /// Creates a replay iterator over `reader`, reading the timestamp from field
    /// `ts_field` on each JSON line, at `speed` times real-time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_ingest_ndjson::NdjsonReplay;
    /// use std::io::Cursor;
    ///
    /// let replay = NdjsonReplay::new(Cursor::new(&b""[..]), "ts", 5.0);
    /// ```
    pub fn new(reader: R, ts_field: impl Into<String>, speed: f64) -> Self {
        Self {
            reader,
            ts_field: ts_field.into(),
            speed,
            prev_ts: None,
            line_buf: String::new(),
        }
    }
}

impl<R: BufRead> Iterator for NdjsonReplay<R> {
    type Item = Result<serde_json::Value, ReplayError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buf.clear();
            let bytes_read = match self.reader.read_line(&mut self.line_buf) {
                Ok(n) => n,
                Err(err) => return Some(Err(ReplayError::Io(err))),
            };
            if bytes_read == 0 {
                return None;
            }

            let trimmed = self.line_buf.trim();
            if trimmed.is_empty() {
                continue;
            }

            let value: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(err) => return Some(Err(ReplayError::Parse(err))),
            };

            let Some(ts) = value
                .get(&self.ts_field)
                .and_then(serde_json::Value::as_i64)
            else {
                return Some(Err(ReplayError::MissingTimestamp));
            };

            if let Some(prev) = self.prev_ts {
                std::thread::sleep(delay_for(prev, ts, self.speed));
            }
            self.prev_ts = Some(ts);

            return Some(Ok(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Instant;

    #[test]
    fn delay_for_real_time() {
        assert_eq!(delay_for(0, 1000, 1.0), Duration::from_secs(1));
    }

    #[test]
    fn delay_for_compresses_with_speed() {
        assert_eq!(delay_for(0, 1000, 10.0), Duration::from_millis(100));
        assert_eq!(delay_for(0, 2000, 4.0), Duration::from_millis(500));
    }

    #[test]
    fn delay_for_non_positive_speed_is_zero() {
        assert_eq!(delay_for(0, 1000, 0.0), Duration::ZERO);
        assert_eq!(delay_for(0, 1000, -5.0), Duration::ZERO);
    }

    #[test]
    fn delay_for_out_of_order_timestamps_is_zero() {
        assert_eq!(delay_for(1000, 500, 1.0), Duration::ZERO);
        assert_eq!(delay_for(1000, 1000, 1.0), Duration::ZERO);
    }

    #[test]
    fn iterator_decodes_records_in_order_with_zero_delay() {
        let data = "{\"ts\":0,\"v\":1}\n{\"ts\":0,\"v\":2}\n{\"ts\":0,\"v\":3}\n";
        let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 1.0);
        let values: Vec<i64> = replay.map(|r| r.unwrap()["v"].as_i64().unwrap()).collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn iterator_skips_blank_lines() {
        let data = "{\"ts\":0,\"v\":1}\n\n{\"ts\":0,\"v\":2}\n";
        let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 1.0);
        let values: Vec<i64> = replay.map(|r| r.unwrap()["v"].as_i64().unwrap()).collect();
        assert_eq!(values, vec![1, 2]);
    }

    #[test]
    fn iterator_reports_malformed_line_without_stopping() {
        let data = "{\"ts\":0,\"v\":1}\nnot json\n{\"ts\":0,\"v\":2}\n";
        let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 1.0);
        let results: Vec<_> = replay.collect();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(matches!(results[1], Err(ReplayError::Parse(_))));
        assert!(results[2].is_ok());
    }

    #[test]
    fn iterator_reports_missing_timestamp_field() {
        let data = "{\"v\":1}\n";
        let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 1.0);
        let results: Vec<_> = replay.collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(ReplayError::MissingTimestamp)));
    }

    #[test]
    fn iterator_actually_sleeps_between_records() {
        let data = "{\"ts\":0,\"v\":1}\n{\"ts\":30,\"v\":2}\n";
        let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 1.0);
        let start = Instant::now();
        let _values: Vec<_> = replay.map(|r| r.unwrap()).collect();
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn empty_input_yields_no_records() {
        let replay = NdjsonReplay::new(Cursor::new(&b""[..]), "ts", 1.0);
        assert_eq!(replay.count(), 0);
    }

    // Regressions: the timestamp subtraction overflowed,
    // and `Duration::from_secs_f64` panicked on a NaN or huge delay.
    #[test]
    fn extreme_inputs_do_not_panic() {
        // 2^64 ms is about 1.8e16 s.
        assert!(delay_for(i64::MIN, i64::MAX, 1.0) > Duration::from_secs(1 << 53));
        assert_eq!(delay_for(i64::MAX, i64::MIN, 1.0), Duration::ZERO);
        assert_eq!(delay_for(0, 1000, f64::NAN), Duration::ZERO);
        assert_eq!(delay_for(0, 1000, f64::INFINITY), Duration::ZERO);
        assert_eq!(delay_for(0, i64::MAX, f64::MIN_POSITIVE), Duration::MAX);
    }
}

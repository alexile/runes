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
/// the last successfully parsed timestamp. A line that isn't valid UTF-8, or is
/// longer than [`max_line_bytes`](Self::max_line_bytes), yields
/// [`ReplayError::Io`] with [`io::ErrorKind::InvalidData`] and is skipped the
/// same way. Any other read error ends the iterator after it is returned, so a
/// reader that fails on every call can't make a `for` loop spin forever.
pub struct NdjsonReplay<R> {
    reader: R,
    ts_field: String,
    speed: f64,
    prev_ts: Option<i64>,
    line_buf: Vec<u8>,
    max_line_bytes: usize,
    finished: bool,
}

impl<R: BufRead> NdjsonReplay<R> {
    /// Creates a replay iterator over `reader`, reading the timestamp from field
    /// `ts_field` on each JSON line, at `speed` times real-time.
    ///
    /// Lines are not length-limited by default; see
    /// [`max_line_bytes`](Self::max_line_bytes) for untrusted input.
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
            line_buf: Vec::new(),
            max_line_bytes: usize::MAX,
            finished: false,
        }
    }

    /// Caps how many bytes a single line may hold (not counting its `\n`).
    ///
    /// A longer line is drained from the reader without being buffered and is
    /// reported as an [`io::ErrorKind::InvalidData`] error, so a file with no
    /// newlines can't make the reader hold it all in memory.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_ingest_ndjson::{NdjsonReplay, ReplayError};
    /// use std::io::Cursor;
    ///
    /// let data = "{\"ts\":0,\"pad\":\"xxxxxxxxxxxxxxxx\"}\n{\"ts\":0}\n";
    /// let mut replay = NdjsonReplay::new(Cursor::new(data), "ts", 1.0).max_line_bytes(16);
    /// assert!(matches!(replay.next(), Some(Err(ReplayError::Io(_)))));
    /// assert!(replay.next().unwrap().is_ok());
    /// ```
    #[must_use]
    pub const fn max_line_bytes(mut self, max: usize) -> Self {
        self.max_line_bytes = max;
        self
    }

    /// Reads the next line into `line_buf`, without its `\n`. Returns
    /// `Ok(None)` at end of input, otherwise whether the line went over the cap
    /// (in which case nothing of it is kept).
    fn read_line(&mut self) -> io::Result<Option<bool>> {
        self.line_buf.clear();
        let mut read_any = false;
        let mut too_long = false;
        loop {
            let available = match self.reader.fill_buf() {
                Ok(buf) => buf,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            if available.is_empty() {
                break;
            }
            read_any = true;
            let newline = available.iter().position(|&b| b == b'\n');
            let content = &available[..newline.unwrap_or(available.len())];
            if !too_long {
                if content.len() > self.max_line_bytes - self.line_buf.len() {
                    too_long = true;
                    self.line_buf = Vec::new();
                } else {
                    self.line_buf.extend_from_slice(content);
                }
            }
            let used = newline.map_or(available.len(), |i| i + 1);
            self.reader.consume(used);
            if newline.is_some() {
                break;
            }
        }
        Ok(read_any.then_some(too_long))
    }
}

impl<R: BufRead> Iterator for NdjsonReplay<R> {
    type Item = Result<serde_json::Value, ReplayError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            let too_long = match self.read_line() {
                Ok(Some(too_long)) => too_long,
                Ok(None) => return None,
                Err(err) => {
                    self.finished = true;
                    return Some(Err(ReplayError::Io(err)));
                }
            };
            if too_long {
                return Some(Err(ReplayError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line longer than {} bytes", self.max_line_bytes),
                ))));
            }
            let Ok(line) = std::str::from_utf8(&self.line_buf) else {
                return Some(Err(ReplayError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "line is not valid UTF-8",
                ))));
            };

            let trimmed = line.trim();
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
        None
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

    struct BrokenReader;

    impl io::Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
    }

    #[test]
    fn a_persistent_read_error_ends_the_stream() {
        let replay = NdjsonReplay::new(io::BufReader::new(BrokenReader), "ts", 1.0);
        let results: Vec<_> = replay.take(5).collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(ReplayError::Io(_))));
    }

    #[test]
    fn invalid_utf8_line_is_reported_and_skipped() {
        let data = b"{\"ts\":0,\"v\":1}\n\xff\xfe\n{\"ts\":0,\"v\":2}\n";
        let results: Vec<_> = NdjsonReplay::new(Cursor::new(&data[..]), "ts", 1.0).collect();
        assert_eq!(results.len(), 3);
        assert!(
            matches!(&results[1], Err(ReplayError::Io(e)) if e.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(results[2].as_ref().unwrap()["v"], 2);
    }

    #[test]
    fn overlong_line_is_reported_and_skipped() {
        let long = format!("{{\"ts\":0,\"pad\":\"{}\"}}", "x".repeat(10_000));
        let data = format!("{long}\n{{\"ts\":0,\"v\":2}}");
        let reader = io::BufReader::with_capacity(64, Cursor::new(data.into_bytes()));
        let mut replay = NdjsonReplay::new(reader, "ts", 1.0).max_line_bytes(100);
        assert!(
            matches!(replay.next(), Some(Err(ReplayError::Io(e))) if e.kind() == io::ErrorKind::InvalidData)
        );
        assert!(replay.line_buf.capacity() <= 200);
        assert_eq!(replay.next().unwrap().unwrap()["v"], 2);
        assert!(replay.next().is_none());
    }

    #[test]
    fn line_exactly_at_the_cap_is_accepted() {
        let line = "{\"ts\":0}";
        let data = format!("{line}\r\n");
        let mut replay = NdjsonReplay::new(Cursor::new(data.into_bytes()), "ts", 1.0)
            .max_line_bytes(line.len() + 1);
        assert!(replay.next().unwrap().is_ok());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
            cap in 0usize..64,
        ) {
            let reader = io::BufReader::with_capacity(7, Cursor::new(bytes));
            for r in NdjsonReplay::new(reader, "ts", 0.0).max_line_bytes(cap).take(600) {
                let _ = r;
            }
        }
    }
}

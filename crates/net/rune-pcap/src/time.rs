//! Packet timestamps and pcapng timestamp resolutions.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

const NANOS_PER_SEC: u32 = 1_000_000_000;

/// When a packet was captured: seconds and nanoseconds since the Unix
/// epoch (1970-01-01T00:00:00Z).
///
/// Classic pcap stores microseconds or nanoseconds; pcapng stores ticks
/// at a per-interface [`TsResolution`]. Both are converted to this
/// common form when read, rounding toward zero where the file is finer
/// than a nanosecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Whole seconds since the epoch.
    pub secs: u64,
    /// Nanoseconds past `secs`, below 1 000 000 000.
    pub nanos: u32,
}

impl Timestamp {
    /// A timestamp, carrying whole seconds out of `nanos`.
    #[must_use]
    pub const fn new(secs: u64, nanos: u32) -> Self {
        Self {
            secs: secs.saturating_add((nanos / NANOS_PER_SEC) as u64),
            nanos: nanos % NANOS_PER_SEC,
        }
    }

    /// The timestamp `micros` microseconds past `secs`.
    #[must_use]
    pub const fn from_micros(secs: u64, micros: u32) -> Self {
        Self::new(secs, 0).add_nanos(micros as u64 * 1_000)
    }

    /// Nanoseconds since the epoch.
    #[must_use]
    pub const fn as_nanos(&self) -> u128 {
        self.secs as u128 * NANOS_PER_SEC as u128 + self.nanos as u128
    }

    /// The equivalent [`SystemTime`], or `None` if the platform cannot
    /// represent it.
    #[must_use]
    pub fn to_system_time(&self) -> Option<SystemTime> {
        UNIX_EPOCH.checked_add(Duration::new(self.secs, self.nanos))
    }

    /// The timestamp of a [`SystemTime`], or `None` before the epoch.
    #[must_use]
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        let d = time.duration_since(UNIX_EPOCH).ok()?;
        Some(Self::new(d.as_secs(), d.subsec_nanos()))
    }

    /// Shift by a signed number of seconds, saturating at the ends of the
    /// range.
    #[must_use]
    pub const fn offset_secs(self, offset: i64) -> Self {
        Self {
            secs: self.secs.saturating_add_signed(offset),
            nanos: self.nanos,
        }
    }

    const fn add_nanos(self, nanos: u64) -> Self {
        let total = self.nanos as u64 + nanos;
        Self {
            secs: self.secs.saturating_add(total / NANOS_PER_SEC as u64),
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the remainder is below 10^9"
            )]
            nanos: (total % NANOS_PER_SEC as u64) as u32,
        }
    }
}

impl fmt::Display for Timestamp {
    /// `secs.nanos`, as `tcpdump -tt --nano` prints it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.secs, self.nanos)
    }
}

/// The unit of a pcapng interface's timestamps (`if_tsresol`).
///
/// A tick is 10<sup>-n</sup> seconds ([`Decimal`](Self::Decimal)) or
/// 2<sup>-n</sup> seconds ([`Binary`](Self::Binary)). Without the
/// option, pcapng uses microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TsResolution {
    /// Ticks of 10<sup>-n</sup> seconds (`n` below 128).
    Decimal(u8),
    /// Ticks of 2<sup>-n</sup> seconds (`n` below 128).
    Binary(u8),
}

impl Default for TsResolution {
    fn default() -> Self {
        Self::MICROS
    }
}

impl TsResolution {
    /// Microseconds, the pcapng default.
    pub const MICROS: Self = Self::Decimal(6);
    /// Nanoseconds.
    pub const NANOS: Self = Self::Decimal(9);

    /// Decode the one-byte `if_tsresol` option value.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        if b & 0x80 == 0 {
            Self::Decimal(b)
        } else {
            Self::Binary(b & 0x7f)
        }
    }

    /// Encode as the one-byte `if_tsresol` option value.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Decimal(n) => n & 0x7f,
            Self::Binary(n) => 0x80 | (n & 0x7f),
        }
    }

    /// Convert a tick count to a timestamp, rounding toward zero below a
    /// nanosecond.
    #[must_use]
    pub fn to_timestamp(self, ticks: u64) -> Timestamp {
        let ticks = u128::from(ticks);
        let nanos = u128::from(NANOS_PER_SEC);
        let (secs, frac_nanos) = match self.to_byte() {
            b if b & 0x80 == 0 => {
                let n = u32::from(b);
                // A tick count below 2^64 can't reach a second at 10^-39
                // or finer, nor a nanosecond at 10^-29.
                10u128.checked_pow(n).map_or((0, 0), |per_sec| {
                    let rem = ticks % per_sec;
                    let frac = if n <= 9 {
                        rem * 10u128.pow(9 - n)
                    } else {
                        rem / 10u128.pow(n - 9)
                    };
                    (ticks / per_sec, frac)
                })
            }
            b => {
                let n = u32::from(b & 0x7f);
                // n < 128, and rem * 10^9 < 2^94: no overflow.
                let rem = ticks & ((1u128 << n) - 1);
                (ticks >> n, (rem * nanos) >> n)
            }
        };
        Timestamp {
            secs: u64::try_from(secs).unwrap_or(u64::MAX),
            nanos: u32::try_from(frac_nanos).unwrap_or(0),
        }
    }

    /// Convert a timestamp to a tick count, rounding toward zero.
    ///
    /// # Errors
    ///
    /// [`Error::TimestampOutOfRange`] when the tick count does not fit in
    /// 64 bits.
    pub fn to_ticks(self, ts: Timestamp) -> Result<u64, Error> {
        let secs = u128::from(ts.secs);
        let nanos = u128::from(ts.nanos);
        let ticks = match self.to_byte() {
            b if b & 0x80 == 0 => {
                let n = u32::from(b);
                let per_sec = 10u128.checked_pow(n).ok_or(Error::TimestampOutOfRange)?;
                let frac = if n <= 9 {
                    nanos / 10u128.pow(9 - n)
                } else {
                    // per_sec fits, so 10^(n-9) does too.
                    nanos
                        .checked_mul(10u128.pow(n - 9))
                        .ok_or(Error::TimestampOutOfRange)?
                };
                secs.checked_mul(per_sec).and_then(|s| s.checked_add(frac))
            }
            b => {
                let n = u32::from(b & 0x7f);
                let whole = if secs == 0 {
                    Some(0)
                } else if n >= 64 {
                    None
                } else {
                    secs.checked_mul(1u128 << n)
                };
                // nanos < 2^30, so nanos << n overflows u128 only for n > 98.
                let frac = (nanos.checked_shl(n).filter(|_| n <= 98))
                    .map(|v| v / u128::from(NANOS_PER_SEC));
                match (whole, frac) {
                    (Some(w), Some(f)) => w.checked_add(f),
                    (Some(w), None) if nanos == 0 => Some(w),
                    _ => None,
                }
            }
        };
        ticks
            .and_then(|t| u64::try_from(t).ok())
            .ok_or(Error::TimestampOutOfRange)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_basics() {
        assert_eq!(
            Timestamp::new(1, 2_500_000_000),
            Timestamp {
                secs: 3,
                nanos: 500_000_000
            }
        );
        assert_eq!(
            Timestamp::from_micros(5, 1_500_000),
            Timestamp {
                secs: 6,
                nanos: 500_000_000
            }
        );
        let ts = Timestamp::new(1_700_000_000, 123);
        assert_eq!(ts.to_string(), "1700000000.000000123");
        assert_eq!(
            Timestamp::from_system_time(ts.to_system_time().unwrap()),
            Some(ts)
        );
        assert_eq!(ts.as_nanos(), 1_700_000_000_000_000_123);
        assert_eq!(ts.offset_secs(-1_700_000_001).secs, 0);
        assert_eq!(ts.offset_secs(10).secs, 1_700_000_010);
    }

    #[test]
    fn resolution_byte() {
        assert_eq!(TsResolution::from_byte(6), TsResolution::MICROS);
        assert_eq!(TsResolution::from_byte(0x8a), TsResolution::Binary(10));
        assert_eq!(TsResolution::Binary(10).to_byte(), 0x8a);
        assert_eq!(TsResolution::default(), TsResolution::Decimal(6));
    }

    #[test]
    fn decimal_ticks() {
        let us = TsResolution::MICROS;
        let ts = us.to_timestamp(1_700_000_000_123_456);
        assert_eq!(ts, Timestamp::new(1_700_000_000, 123_456_000));
        assert_eq!(us.to_ticks(ts).unwrap(), 1_700_000_000_123_456);
        let ns = TsResolution::NANOS;
        assert_eq!(
            ns.to_timestamp(1_500_000_001),
            Timestamp::new(1, 500_000_001)
        );
        // Finer than a nanosecond rounds toward zero.
        let ps = TsResolution::Decimal(12);
        assert_eq!(ps.to_timestamp(1_000_000_001_999), Timestamp::new(1, 1));
        assert_eq!(
            ps.to_ticks(Timestamp::new(1, 1)).unwrap(),
            1_000_000_001_000
        );
        // Seconds.
        assert_eq!(
            TsResolution::Decimal(0).to_timestamp(42),
            Timestamp::new(42, 0)
        );
        // Absurd resolutions don't panic.
        assert_eq!(
            TsResolution::Decimal(127).to_timestamp(u64::MAX),
            Timestamp::default()
        );
        assert_eq!(
            TsResolution::Decimal(25).to_timestamp(u64::MAX),
            Timestamp::new(0, 1844)
        );
        assert!(
            TsResolution::Decimal(127)
                .to_ticks(Timestamp::new(1, 0))
                .is_err()
        );
        assert!(ns.to_ticks(Timestamp::new(u64::MAX, 0)).is_err());
    }

    #[test]
    fn binary_ticks() {
        let b = TsResolution::Binary(10);
        assert_eq!(
            b.to_timestamp(1024 * 3 + 512),
            Timestamp::new(3, 500_000_000)
        );
        assert_eq!(
            b.to_ticks(Timestamp::new(3, 500_000_000)).unwrap(),
            1024 * 3 + 512
        );
        assert_eq!(
            TsResolution::Binary(0).to_timestamp(7),
            Timestamp::new(7, 0)
        );
        assert_eq!(
            TsResolution::Binary(127).to_timestamp(u64::MAX),
            Timestamp::new(0, 0)
        );
        assert_eq!(
            TsResolution::Binary(64).to_timestamp(1 << 63),
            Timestamp::new(0, 500_000_000)
        );
        assert_eq!(
            TsResolution::Binary(64)
                .to_ticks(Timestamp::new(0, 500_000_000))
                .unwrap(),
            1 << 63
        );
        assert!(
            TsResolution::Binary(64)
                .to_ticks(Timestamp::new(1, 0))
                .is_err()
        );
        assert!(
            TsResolution::Binary(120)
                .to_ticks(Timestamp::new(0, 1))
                .is_err()
        );
        assert_eq!(
            TsResolution::Binary(120)
                .to_ticks(Timestamp::default())
                .unwrap(),
            0
        );
    }
}

//! Limit values and soft/hard pairs, with their conversion to and from the
//! kernel's `struct rlimit`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// One limit value: a number in the resource's [`Unit`](crate::Unit), or no
/// limit at all.
///
/// [`Value::Unlimited`] orders above every [`Value::Limited`] amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Value {
    /// At most this many units.
    ///
    /// The kernel reserves its largest value for "unlimited" (on Linux,
    /// `u64::MAX`), so an amount that large (or one that does not fit the
    /// platform's `rlim_t`) is applied as [`Value::Unlimited`].
    Limited(u64),
    /// No limit (`RLIM_INFINITY`).
    Unlimited,
}

impl Value {
    /// The value in the kernel's representation.
    pub(crate) fn to_raw(self) -> libc::rlim_t {
        match self {
            Self::Limited(n) => libc::rlim_t::try_from(n).unwrap_or(libc::RLIM_INFINITY),
            Self::Unlimited => libc::RLIM_INFINITY,
        }
    }

    /// The value from the kernel's representation.
    #[allow(
        clippy::useless_conversion,
        reason = "`rlim_t` is `u64` on most targets but not all"
    )]
    pub(crate) fn from_raw(raw: libc::rlim_t) -> Self {
        if raw == libc::RLIM_INFINITY {
            Self::Unlimited
        } else {
            u64::try_from(raw).map_or(Self::Unlimited, Self::Limited)
        }
    }

    /// The amount, or `None` for [`Value::Unlimited`].
    #[must_use]
    pub const fn get(self) -> Option<u64> {
        match self {
            Self::Limited(n) => Some(n),
            Self::Unlimited => None,
        }
    }

    /// `true` for [`Value::Unlimited`].
    #[must_use]
    pub const fn is_unlimited(self) -> bool {
        matches!(self, Self::Unlimited)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Self::Limited(n)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limited(n) => fmt::Display::fmt(n, f),
            Self::Unlimited => f.pad("unlimited"),
        }
    }
}

impl FromStr for Value {
    type Err = Error;

    /// Parses a decimal amount or `unlimited`/`infinity` (ASCII case
    /// ignored).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("unlimited") || s.eq_ignore_ascii_case("infinity") {
            return Ok(Self::Unlimited);
        }
        // `u64::from_str` accepts a leading `+`; a limit never has one.
        if !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = s.parse()
        {
            return Ok(Self::Limited(n));
        }
        Err(Error::InvalidValue { text: s.to_owned() })
    }
}

/// A soft and hard limit pair for one resource.
///
/// The kernel enforces the *soft* limit. A process may raise its soft limit
/// up to the *hard* limit and lower its hard limit, but only a privileged
/// process (`CAP_SYS_RESOURCE`) may raise the hard limit. The soft limit
/// never exceeds the hard one; [`Rlimit::new`] checks that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rlimit {
    soft: Value,
    hard: Value,
}

impl Rlimit {
    /// No limit, soft or hard.
    pub const UNLIMITED: Self = Self {
        soft: Value::Unlimited,
        hard: Value::Unlimited,
    };

    /// A soft and hard limit.
    ///
    /// # Errors
    ///
    /// [`Error::SoftAboveHard`] if `soft` exceeds `hard`.
    pub fn new(soft: impl Into<Value>, hard: impl Into<Value>) -> Result<Self, Error> {
        let (soft, hard) = (soft.into(), hard.into());
        if soft > hard {
            return Err(Error::SoftAboveHard { soft, hard });
        }
        Ok(Self { soft, hard })
    }

    /// The same value as both the soft and the hard limit, so the process
    /// cannot raise it again.
    #[must_use]
    pub fn fixed(value: impl Into<Value>) -> Self {
        let value = value.into();
        Self {
            soft: value,
            hard: value,
        }
    }

    /// The soft limit, which the kernel enforces.
    #[must_use]
    pub const fn soft(self) -> Value {
        self.soft
    }

    /// The hard limit, the ceiling for the soft one.
    #[must_use]
    pub const fn hard(self) -> Value {
        self.hard
    }

    /// Lowers both limits to at most `ceiling`, so applying the result
    /// cannot fail for want of privilege when `ceiling` is the current hard
    /// limit.
    #[must_use]
    pub fn clamped_to(self, ceiling: Value) -> Self {
        Self {
            soft: self.soft.min(ceiling),
            hard: self.hard.min(ceiling),
        }
    }

    /// The kernel's `struct rlimit`.
    pub(crate) fn to_raw(self) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: self.soft.to_raw(),
            rlim_max: self.hard.to_raw(),
        }
    }

    /// From the kernel's `struct rlimit`. Not validated: the kernel keeps
    /// soft at or below hard itself.
    pub(crate) fn from_raw(raw: libc::rlimit) -> Self {
        Self {
            soft: Value::from_raw(raw.rlim_cur),
            hard: Value::from_raw(raw.rlim_max),
        }
    }
}

impl fmt::Display for Rlimit {
    /// `soft:hard`, the `prlimit(1)` notation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.soft, self.hard)
    }
}

impl FromStr for Rlimit {
    type Err = Error;

    /// Parses `prlimit(1)` notation: `soft:hard`, or one value for both.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some((soft, hard)) => Self::new(soft.parse::<Value>()?, hard.parse::<Value>()?),
            None => Ok(Self::fixed(s.parse::<Value>()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infinity_maps_to_unlimited() {
        assert_eq!(Value::from_raw(libc::RLIM_INFINITY), Value::Unlimited);
        assert_eq!(Value::Unlimited.to_raw(), libc::RLIM_INFINITY);
    }

    #[test]
    fn small_values_round_trip_through_raw() {
        for n in [0, 1, 1024, 512 * 1024 * 1024] {
            assert_eq!(
                Value::from_raw(Value::Limited(n).to_raw()),
                Value::Limited(n)
            );
        }
    }

    #[test]
    fn rlimit_raw_round_trip() {
        let limit = Rlimit::new(256, 4096).unwrap();
        let raw = limit.to_raw();
        assert_eq!(raw.rlim_cur, 256);
        assert_eq!(raw.rlim_max, 4096);
        assert_eq!(Rlimit::from_raw(raw), limit);
    }

    #[test]
    fn unlimited_orders_above_every_amount() {
        assert!(Value::Unlimited > Value::Limited(u64::MAX));
        assert!(Value::Limited(1) < Value::Limited(2));
    }

    #[test]
    fn soft_above_hard_is_rejected() {
        assert!(matches!(
            Rlimit::new(10, 5),
            Err(Error::SoftAboveHard { .. })
        ));
        assert!(Rlimit::new(Value::Unlimited, 5).is_err());
        assert!(Rlimit::new(5, Value::Unlimited).is_ok());
    }

    #[test]
    fn clamping_lowers_to_the_ceiling() {
        let clamped = Rlimit::UNLIMITED.clamped_to(Value::Limited(100));
        assert_eq!(clamped, Rlimit::fixed(100));
        let untouched = Rlimit::new(10, 50).unwrap().clamped_to(Value::Unlimited);
        assert_eq!(untouched, Rlimit::new(10, 50).unwrap());
    }

    #[test]
    fn prlimit_notation() {
        assert_eq!(
            "1024:4096".parse::<Rlimit>().ok(),
            Rlimit::new(1024, 4096).ok()
        );
        assert_eq!("unlimited".parse::<Rlimit>().ok(), Some(Rlimit::UNLIMITED));
        assert_eq!(
            Rlimit::new(1, Value::Unlimited).unwrap().to_string(),
            "1:unlimited"
        );
        assert!("+5".parse::<Rlimit>().is_err());
        assert!("5:1".parse::<Rlimit>().is_err());
        assert!(":".parse::<Rlimit>().is_err());
    }
}

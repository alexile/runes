//! Pack versions.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A pack version, `MAJOR.MINOR.PATCH`, ordered numerically.
///
/// Updates only move forward: a [`Store`](crate::Store) refuses to replace a
/// pack with an older or equal version unless asked to, which stops a
/// rollback to an older (validly signed) pack.
///
/// ```
/// use rune_wordlist::Version;
///
/// let v: Version = "1.10.0".parse()?;
/// assert!(v > "1.9.3".parse()?);
/// assert_eq!(v.to_string(), "1.10.0");
/// assert!("1.2".parse::<Version>().is_err());
/// # Ok::<(), rune_wordlist::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Incompatible changes to the lists' meaning.
    pub major: u32,
    /// Entries added.
    pub minor: u32,
    /// Fixes.
    pub patch: u32,
}

impl Version {
    /// A version from its three parts.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidVersion(s.to_owned());
        let part = |p: &str| -> Result<u32, Error> {
            // Canonical decimal only: no sign, no leading zeros, no spaces.
            if p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return Err(invalid());
            }
            p.parse().map_err(|_| invalid())
        };
        let mut parts = s.split('.');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        Ok(Self::new(part(a)?, part(b)?, part(c)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_orders() {
        let v: Version = "0.0.0".parse().unwrap();
        assert_eq!(v, Version::new(0, 0, 0));
        assert!(Version::new(2, 0, 0) > Version::new(1, 99, 99));
        assert!(Version::new(1, 2, 10) > Version::new(1, 2, 9));
    }

    #[test]
    fn rejects_non_canonical() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.2.-3",
            "1.2.+3",
            " 1.2.3",
            "1..3",
            "a.b.c",
            "4294967296.0.0",
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad}");
        }
    }
}

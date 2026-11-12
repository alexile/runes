//! CVSS v3.0, v3.1 and v4.0 vector parsing and scoring, exactly as the FIRST
//! specifications and reference calculators define it.
//!
//! - [`Vector`] parses any supported vector string; [`Vector3`] and
//!   [`Vector4`] are the version-specific types, with every metric typed.
//! - Scores are [`Score`]s, kept exactly as tenths, with the qualitative
//!   [`Severity`] rating. v3 vectors have base, temporal and environmental
//!   scores; v4.0 vectors one score covering whatever groups they define
//!   (CVSS-B, -BT, -BE or -BTE) and a CVSS-B base score.
//! - [`Display`](core::fmt::Display) writes the canonical vector string:
//!   specification order, Not Defined (`X`) metrics left out. Every vector
//!   that parses round-trips: `display(parse(s))` parses back to the same
//!   vector.
//!
//! Specifications: [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document),
//! [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) and
//! [CVSS v3.0](https://www.first.org/cvss/v3.0/specification-document).
//!
//! # Correctness
//!
//! The scores are bit-for-bit those of FIRST's reference calculators: the
//! formulas run in `f64` with the same operations in the same order as the
//! JavaScript, including v3.1's `Roundup` (Appendix A) and v4.0's
//! `MacroVector` interpolation over the vendored lookup table. The test suite
//! checks the FIRST example documents and thousands of vectors scored by
//! the reference calculators. Nothing depends on the platform's `libm`.
//!
//! The crate is sans-I/O and has no dependencies besides `thiserror` and an
//! optional `serde`.
//!
//! # Features
//!
//! - `serde`: vectors serialize as their canonical string and deserialize
//!   from any valid vector string; [`Score`] as a number such as `9.8`;
//!   [`Severity`] and [`Version`] as strings.
//!
//! # Example
//!
//! ```
//! use rune_cvss::{Severity, Vector, Version};
//!
//! let vector: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".parse()?;
//! assert_eq!(vector.version(), Version::V3_1);
//! assert_eq!(vector.base_score().to_string(), "6.1");
//! assert_eq!(vector.severity(), Severity::Medium);
//!
//! let vector: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".parse()?;
//! assert_eq!(vector.score().value(), 9.3);
//! assert_eq!(vector.severity(), Severity::Critical);
//!
//! // The canonical form drops Not Defined metrics.
//! let vector: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X".parse()?;
//! assert_eq!(vector.to_string(), "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
//!
//! // Invalid vectors are errors, never panics.
//! assert!("CVSS:4.0/AV:N".parse::<Vector>().is_err());
//! # Ok::<(), rune_cvss::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod math;
mod metric;
mod score;
#[cfg(feature = "serde")]
mod serde_impl;
pub mod v3;
pub mod v4;

use core::fmt;
use core::str::FromStr;

pub use error::Error;
pub use score::{Score, Severity};
pub use v3::Vector3;
pub use v4::Vector4;

/// A CVSS version this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Version {
    /// CVSS v3.0.
    V3_0,
    /// CVSS v3.1.
    V3_1,
    /// CVSS v4.0.
    V4_0,
}

impl Version {
    /// The version number, such as `"3.1"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V3_0 => "3.0",
            Self::V3_1 => "3.1",
            Self::V4_0 => "4.0",
        }
    }

    /// The vector string prefix, such as `"CVSS:3.1"`.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::V3_0 => "CVSS:3.0",
            Self::V3_1 => "CVSS:3.1",
            Self::V4_0 => "CVSS:4.0",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed CVSS vector of any supported version.
///
/// See [`Vector3`] and [`Vector4`] for the metrics and the version-specific
/// scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Vector {
    /// A CVSS v3.0 or v3.1 vector.
    V3(Vector3),
    /// A CVSS v4.0 vector.
    V4(Vector4),
}

impl Vector {
    /// The vector's CVSS version.
    #[must_use]
    pub const fn version(&self) -> Version {
        match self {
            Self::V3(vector) => vector.version(),
            Self::V4(vector) => vector.version(),
        }
    }

    /// The base score: for v3, the Base Score; for v4.0, the CVSS-B score
    /// (base metrics only, ignoring threat and environmental metrics). This
    /// is what NVD and the CVSS JSON schemas call `baseScore`.
    #[must_use]
    pub fn base_score(&self) -> Score {
        match self {
            Self::V3(vector) => vector.base_score(),
            Self::V4(vector) => vector.base_score(),
        }
    }

    /// The most specific score the vector supports. For v3: environmental
    /// if any environmental metric is defined, else temporal if any
    /// temporal metric is defined, else base. For v4.0: the score of the
    /// whole vector (CVSS-B, -BT, -BE or -BTE).
    #[must_use]
    pub fn score(&self) -> Score {
        match self {
            Self::V3(vector) => vector.score(),
            Self::V4(vector) => vector.score(),
        }
    }

    /// The qualitative rating of [`score`](Self::score).
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.score().severity()
    }

    /// The v3 vector, if this is one.
    #[must_use]
    pub const fn as_v3(&self) -> Option<&Vector3> {
        match self {
            Self::V3(vector) => Some(vector),
            Self::V4(_) => None,
        }
    }

    /// The v4.0 vector, if this is one.
    #[must_use]
    pub const fn as_v4(&self) -> Option<&Vector4> {
        match self {
            Self::V4(vector) => Some(vector),
            Self::V3(_) => None,
        }
    }
}

impl FromStr for Vector {
    type Err = Error;

    /// Parses a CVSS v3.0, v3.1 or v4.0 vector string. The version comes
    /// from the `CVSS:<version>/` prefix, which is mandatory.
    fn from_str(text: &str) -> Result<Self, Error> {
        let (version, metrics) = metric::split(text)?;
        match version {
            Version::V3_0 => Vector3::parse_metrics(v3::Minor::V3_0, metrics).map(Self::V3),
            Version::V3_1 => Vector3::parse_metrics(v3::Minor::V3_1, metrics).map(Self::V3),
            Version::V4_0 => Vector4::parse_metrics(metrics).map(Self::V4),
        }
    }
}

impl fmt::Display for Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V3(vector) => vector.fmt(f),
            Self::V4(vector) => vector.fmt(f),
        }
    }
}

impl From<Vector3> for Vector {
    fn from(vector: Vector3) -> Self {
        Self::V3(vector)
    }
}

impl From<Vector4> for Vector {
    fn from(vector: Vector4) -> Self {
        Self::V4(vector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_on_the_prefix() {
        let v3: Vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            .parse()
            .unwrap();
        assert_eq!(v3.version(), Version::V3_0);
        assert!(v3.as_v3().is_some() && v3.as_v4().is_none());
        assert_eq!(
            v3.to_string(),
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        let v4: Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
            .parse()
            .unwrap();
        assert_eq!(v4.version(), Version::V4_0);
        assert_eq!(v4.base_score(), Score::MAX);
        assert!(v4.as_v4().is_some() && v4.as_v3().is_none());
        assert_eq!(
            "CVSS:2.0/AV:N".parse::<Vector>(),
            Err(Error::UnsupportedVersion("2.0".into()))
        );
        assert_eq!("".parse::<Vector>(), Err(Error::MissingPrefix));
        assert_eq!(
            "CVSS:".parse::<Vector>(),
            Err(Error::UnsupportedVersion(String::new()))
        );
    }

    #[test]
    fn version_names() {
        assert_eq!(Version::V3_1.to_string(), "3.1");
        assert_eq!(Version::V4_0.prefix(), "CVSS:4.0");
    }
}

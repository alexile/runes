//! Coarse classification of a single Shannon entropy score.

use core::fmt;

use crate::analysis::{HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD};

/// Upper bound of [`EntropyClass::TextOrStructured`].
pub const BINARY_ENTROPY_THRESHOLD: f64 = 5.5;

/// Coarse class of a Shannon entropy score, from [`classify`].
///
/// The ranges overlap in the real world, so read the class as "typical of",
/// not "is". Order-0 entropy alone cannot separate compressed from encrypted
/// data, or text from some binary formats; [`Analysis::assess`] uses more
/// evidence when you have the bytes.
///
/// | Range     | Variant | Typical content |
/// |-----------|---------|-----------------|
/// | 0.0 – 3.0 | [`Low`](Self::Low) | padding, zero fill, sparse tables, long runs |
/// | 3.0 – 5.5 | [`TextOrStructured`](Self::TextOrStructured) | prose (~4.0–4.7), source code, JSON/XML, binary headers |
/// | 5.5 – 7.0 | [`BinaryOrEncoded`](Self::BinaryOrEncoded) | machine code (~5.5–6.5), base64 (≤ 6.0), mixed binaries |
/// | 7.0 – 8.0 | [`High`](Self::High) | compressed, encrypted, or random data; packed executables |
///
/// [`Analysis::assess`]: crate::Analysis::assess
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{classify, entropy, EntropyClass};
///
/// let class = classify(entropy(b"hello world"));
/// assert_eq!(class, EntropyClass::Low); // too short to score higher
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntropyClass {
    /// Below 3.0 bits per byte.
    Low,
    /// 3.0 up to 5.5 bits per byte.
    TextOrStructured,
    /// 5.5 up to 7.0 bits per byte.
    BinaryOrEncoded,
    /// 7.0 bits per byte and above.
    High,
}

impl EntropyClass {
    /// Short machine-friendly label, e.g. `"text/structured"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::EntropyClass::High.as_str(), "high");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::TextOrStructured => "text/structured",
            Self::BinaryOrEncoded => "binary/encoded",
            Self::High => "high",
        }
    }
}

impl fmt::Display for EntropyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies a Shannon entropy score (bits per byte) into an
/// [`EntropyClass`]. `NaN` is treated as [`EntropyClass::Low`].
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{classify, EntropyClass};
///
/// assert_eq!(classify(1.5), EntropyClass::Low);
/// assert_eq!(classify(4.4), EntropyClass::TextOrStructured);
/// assert_eq!(classify(6.1), EntropyClass::BinaryOrEncoded);
/// assert_eq!(classify(7.9), EntropyClass::High);
/// ```
#[must_use]
pub fn classify(score: f64) -> EntropyClass {
    if score >= HIGH_ENTROPY_THRESHOLD {
        EntropyClass::High
    } else if score >= BINARY_ENTROPY_THRESHOLD {
        EntropyClass::BinaryOrEncoded
    } else if score >= LOW_ENTROPY_THRESHOLD {
        EntropyClass::TextOrStructured
    } else {
        EntropyClass::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        assert_eq!(classify(f64::NAN), EntropyClass::Low);
        assert_eq!(classify(2.999), EntropyClass::Low);
        assert_eq!(classify(3.0), EntropyClass::TextOrStructured);
        assert_eq!(classify(5.5), EntropyClass::BinaryOrEncoded);
        assert_eq!(classify(7.0), EntropyClass::High);
        assert_eq!(classify(8.0), EntropyClass::High);
    }
}

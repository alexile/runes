//! An owned bit sequence.

use std::ops::Deref;

use crate::Error;

/// An owned sequence of bits, `ε₁ ε₂ … εₙ` in SP 800-22's notation.
///
/// It dereferences to `&[bool]`, which is what the individual tests take.
///
/// ```
/// use rune_randomness::Bits;
///
/// let bits = Bits::from_bytes(&[0b1010_0000]);
/// assert_eq!(bits.len(), 8);
/// assert_eq!(bits.count_ones(), 2);
///
/// let parsed = Bits::parse("1010 0000")?;
/// assert_eq!(parsed, bits);
/// # Ok::<(), rune_randomness::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bits {
    bits: Vec<bool>,
}

impl Bits {
    /// An empty sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: Vec::new() }
    }

    /// The bits of `bytes`, most significant bit of each byte first.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut bits = Self {
            bits: Vec::with_capacity(bytes.len() * 8),
        };
        for &byte in bytes {
            bits.push_bits(u64::from(byte), 8);
        }
        bits
    }

    /// Parses a string of `0` and `1` characters, ignoring ASCII
    /// whitespace.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidBitChar`] for any other character.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bits = Vec::with_capacity(text.len());
        for (offset, found) in text.char_indices() {
            match found {
                '0' => bits.push(false),
                '1' => bits.push(true),
                c if c.is_ascii_whitespace() => {}
                _ => return Err(Error::InvalidBitChar { offset, found }),
            }
        }
        Ok(Self { bits })
    }

    /// Appends one bit.
    pub fn push(&mut self, bit: bool) {
        self.bits.push(bit);
    }

    /// Appends the low `width` bits of `value`, most significant first.
    /// Widths above 64 are treated as 64.
    pub fn push_bits(&mut self, value: u64, width: u32) {
        for shift in (0..width.min(64)).rev() {
            self.bits.push((value >> shift) & 1 == 1);
        }
    }

    /// Number of one bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        count_ones(&self.bits)
    }

    /// The bits as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[bool] {
        &self.bits
    }

    /// Consumes the sequence and returns its bits.
    #[must_use]
    pub fn into_vec(self) -> Vec<bool> {
        self.bits
    }
}

/// Number of `true` values in `bits`.
pub fn count_ones(bits: &[bool]) -> usize {
    bits.iter().filter(|&&bit| bit).count()
}

impl Deref for Bits {
    type Target = [bool];

    fn deref(&self) -> &[bool] {
        &self.bits
    }
}

impl AsRef<[bool]> for Bits {
    fn as_ref(&self) -> &[bool] {
        &self.bits
    }
}

impl From<Vec<bool>> for Bits {
    fn from(bits: Vec<bool>) -> Self {
        Self { bits }
    }
}

impl From<&[bool]> for Bits {
    fn from(bits: &[bool]) -> Self {
        Self {
            bits: bits.to_vec(),
        }
    }
}

impl FromIterator<bool> for Bits {
    fn from_iter<I: IntoIterator<Item = bool>>(iter: I) -> Self {
        Self {
            bits: iter.into_iter().collect(),
        }
    }
}

impl Extend<bool> for Bits {
    fn extend<I: IntoIterator<Item = bool>>(&mut self, iter: I) {
        self.bits.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_msb_first() {
        let bits = Bits::from_bytes(&[0x80, 0x01]);
        assert!(bits[0]);
        assert!(bits[15]);
        assert_eq!(bits.count_ones(), 2);
    }

    #[test]
    fn parse_rejects_other_characters() {
        assert_eq!(
            Bits::parse("01 2"),
            Err(Error::InvalidBitChar {
                offset: 3,
                found: '2'
            })
        );
        assert_eq!(Bits::parse(" 0\n1\t").map(|b| b.len()), Ok(2));
    }

    #[test]
    fn push_bits_width() {
        let mut bits = Bits::new();
        bits.push_bits(0b101, 3);
        bits.push_bits(1, 0);
        assert_eq!(bits, Bits::parse("101").unwrap_or_default());
    }
}

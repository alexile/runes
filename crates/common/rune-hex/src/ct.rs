//! Decoding for secrets: keys, tokens, seeds.
//!
//! The regular decoder stops at the first bad byte and reports where it is,
//! so its running time and its error reveal something about the input. The
//! functions here look at every byte the same way, using only arithmetic
//! (no lookup tables, no branches on the data), and on failure return
//! [`HexError::Invalid`] without a position. Only the input length affects
//! timing, and lengths are checked before any data is touched.
//!
//! They accept strict hex only: digits in either case, no prefix, no
//! whitespace. On error the output buffer is zeroed so no partial secret is
//! left behind.
//!
//! This is written to avoid data-dependent timing, but the final machine
//! code is up to the compiler and the hardware; treat it as a careful best
//! effort rather than a verified guarantee.
//!
//! Encoding needs no separate variant: [`encode`](crate::encode) and friends
//! already use the same table-free, branch-free arithmetic.
//!
//! # Examples
//!
//! ```rust
//! use rune_hex::{ct, HexError};
//!
//! let key: [u8; 4] = ct::decode_array("00ff10EF")?;
//! assert_eq!(key, [0x00, 0xff, 0x10, 0xef]);
//!
//! assert_eq!(ct::decode_array::<2>("00zz"), Err(HexError::Invalid));
//! # Ok::<(), HexError>(())
//! ```

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use crate::{HexError, decode::decode_ct};

/// Decodes `hex` into `out` and returns the written part.
///
/// # Errors
///
/// [`HexError::OddLength`], [`HexError::BufferTooSmall`], or
/// [`HexError::Invalid`]; after the last one the written part of `out` is
/// zeroed.
///
/// # Examples
///
/// ```rust
/// let mut buf = [0u8; 32];
/// let key = rune_hex::ct::decode_to_slice("a1b2", &mut buf)?;
/// assert_eq!(key, [0xa1, 0xb2]);
/// # Ok::<(), rune_hex::HexError>(())
/// ```
pub fn decode_to_slice(hex: impl AsRef<[u8]>, out: &mut [u8]) -> Result<&mut [u8], HexError> {
    let hex = hex.as_ref();
    if hex.len() % 2 == 1 {
        return Err(HexError::OddLength);
    }
    let needed = hex.len() / 2;
    let available = out.len();
    let out = out
        .get_mut(..needed)
        .ok_or(HexError::BufferTooSmall { needed, available })?;
    if decode_ct(hex, out) {
        Ok(out)
    } else {
        out.fill(0);
        Err(HexError::Invalid)
    }
}

/// Decodes `hex` into a new vector.
///
/// # Errors
///
/// [`HexError::OddLength`] or [`HexError::Invalid`].
///
/// # Examples
///
/// ```rust
/// assert_eq!(rune_hex::ct::decode("0aFF")?, [0x0a, 0xff]);
/// # Ok::<(), rune_hex::HexError>(())
/// ```
#[cfg(feature = "alloc")]
pub fn decode(hex: impl AsRef<[u8]>) -> Result<Vec<u8>, HexError> {
    let hex = hex.as_ref();
    if hex.len() % 2 == 1 {
        return Err(HexError::OddLength);
    }
    let mut out = vec![0; hex.len() / 2];
    decode_to_slice(hex, &mut out)?;
    Ok(out)
}

/// Decodes `hex` into an array of exactly `N` bytes.
///
/// # Errors
///
/// [`HexError::OddLength`], [`HexError::WrongLength`], or
/// [`HexError::Invalid`].
///
/// # Examples
///
/// ```rust
/// let nonce: [u8; 2] = rune_hex::ct::decode_array("beef")?;
/// assert_eq!(nonce, [0xbe, 0xef]);
/// # Ok::<(), rune_hex::HexError>(())
/// ```
pub fn decode_array<const N: usize>(hex: impl AsRef<[u8]>) -> Result<[u8; N], HexError> {
    let hex = hex.as_ref();
    if hex.len() % 2 == 1 {
        return Err(HexError::OddLength);
    }
    if hex.len() / 2 != N {
        return Err(HexError::WrongLength {
            expected: N,
            actual: hex.len() / 2,
        });
    }
    let mut out = [0u8; N];
    decode_to_slice(hex, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroes_output_on_error() {
        let mut buf = [0x55u8; 4];
        assert_eq!(decode_to_slice("0102zz", &mut buf), Err(HexError::Invalid));
        assert_eq!(buf, [0, 0, 0, 0x55]);
    }

    #[test]
    fn length_errors() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(
            decode_to_slice("abcd", &mut [0u8; 1]),
            Err(HexError::BufferTooSmall {
                needed: 2,
                available: 1
            })
        );
        assert_eq!(
            decode_array::<3>("abcd"),
            Err(HexError::WrongLength {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(decode("0x00"), Err(HexError::Invalid));
    }
}

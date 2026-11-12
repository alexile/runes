//! Hex encoding and decoding for byte slices, buffers and streams.
//!
//! - [`encode`] / [`encode_upper`] turn bytes into a hex [`String`].
//! - [`decode`] turns hex text back into bytes. It accepts lowercase,
//!   uppercase and mixed case, plus an optional `0x` prefix.
//! - [`encode_to_slice`], [`decode_to_slice`] and [`decode_array`] work on
//!   caller-provided buffers and never allocate.
//! - [`display`] formats bytes as hex straight into a formatter.
//! - [`DecodeOptions`] opts into tolerant decoding: whitespace, separators
//!   such as `:` or `-`, and the `0x` prefix, each switched on explicitly.
//! - [`ct`] decodes secrets without data-dependent branches or table lookups.
//! - [`io`] (feature `std`) wraps any [`std::io::Read`] or [`std::io::Write`]
//!   to encode or decode on the fly with fixed-size buffers.
//! - [`serde`] (feature `serde`) serializes byte fields as hex
//!   strings.
//!
//! Errors carry the byte offset of the offending input, see [`HexError`].
//!
//! # Quick start
//!
//! ```rust
//! use rune_hex::{decode, encode};
//!
//! let hex = encode(b"hello");
//! assert_eq!(hex, "68656c6c6f");
//!
//! let bytes = decode(&hex)?;
//! assert_eq!(bytes, b"hello");
//! # Ok::<(), rune_hex::HexError>(())
//! ```
//!
//! # Without allocation
//!
//! ```rust
//! let mut text = [0u8; 8];
//! assert_eq!(rune_hex::encode_to_slice(b"\xde\xad\xbe\xef", &mut text)?, "deadbeef");
//!
//! let digest: [u8; 4] = rune_hex::decode_array("deadbeef")?;
//! assert_eq!(digest, [0xde, 0xad, 0xbe, 0xef]);
//! # Ok::<(), rune_hex::HexError>(())
//! ```
//!
//! # Cargo features
//!
//! - `std` (default): implies `alloc` and adds the [`io`] adapters.
//! - `alloc`: the functions that return [`String`] or [`Vec`]. Without it
//!   the crate only needs `core`.
//! - `serde`: the [`serde`] helper module.
//! - `cli`: builds the `rune-hex` command-line tool.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec, vec::Vec};

pub mod ct;
mod decode;
mod encode;
mod error;
#[cfg(feature = "std")]
pub mod io;
#[cfg(feature = "serde")]
pub mod serde;

pub use decode::DecodeOptions;
pub use encode::Display;
pub use error::HexError;

/// Encodes bytes as a lowercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_hex::encode;
///
/// assert_eq!(encode(b"\xde\xad\xbe\xef"), "deadbeef");
/// assert_eq!(encode(b""), "");
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    encode_string(bytes.as_ref(), encode::LOWER)
}

/// Encodes bytes as an uppercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_hex::encode_upper;
///
/// assert_eq!(encode_upper(b"\xde\xad\xbe\xef"), "DEADBEEF");
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn encode_upper(bytes: impl AsRef<[u8]>) -> String {
    encode_string(bytes.as_ref(), encode::UPPER)
}

#[cfg(feature = "alloc")]
fn encode_string(bytes: &[u8], case: u8) -> String {
    let mut buf = vec![0u8; bytes.len() * 2];
    encode::encode_into(bytes, &mut buf, case);
    // The buffer holds only ASCII hex digits, so this never falls back.
    String::from_utf8(buf).unwrap_or_default()
}

/// Encodes bytes as lowercase hex into `out` and returns the written part as
/// a `&mut str`.
///
/// `out` must hold at least `2 * bytes.len()` bytes; anything after that is
/// left untouched.
///
/// # Errors
///
/// [`HexError::BufferTooSmall`] if `out` is shorter than needed.
///
/// # Examples
///
/// ```rust
/// let mut buf = [0u8; 16];
/// let hex = rune_hex::encode_to_slice([0x01, 0xab], &mut buf)?;
/// assert_eq!(hex, "01ab");
/// # Ok::<(), rune_hex::HexError>(())
/// ```
pub fn encode_to_slice(bytes: impl AsRef<[u8]>, out: &mut [u8]) -> Result<&mut str, HexError> {
    encode_slice(bytes.as_ref(), out, encode::LOWER)
}

/// Encodes bytes as uppercase hex into `out`; otherwise the same as
/// [`encode_to_slice`].
///
/// # Errors
///
/// [`HexError::BufferTooSmall`] if `out` is shorter than `2 * bytes.len()`.
///
/// # Examples
///
/// ```rust
/// let mut buf = [0u8; 4];
/// assert_eq!(rune_hex::encode_upper_to_slice([0x01, 0xab], &mut buf)?, "01AB");
/// # Ok::<(), rune_hex::HexError>(())
/// ```
pub fn encode_upper_to_slice(
    bytes: impl AsRef<[u8]>,
    out: &mut [u8],
) -> Result<&mut str, HexError> {
    encode_slice(bytes.as_ref(), out, encode::UPPER)
}

fn encode_slice<'o>(bytes: &[u8], out: &'o mut [u8], case: u8) -> Result<&'o mut str, HexError> {
    let needed = bytes.len() * 2;
    let available = out.len();
    let out = out
        .get_mut(..needed)
        .ok_or(HexError::BufferTooSmall { needed, available })?;
    encode::encode_into(bytes, out, case);
    // Only ASCII hex digits were written, so validation always succeeds.
    core::str::from_utf8_mut(out).map_err(|_| HexError::BufferTooSmall { needed, available })
}

/// Returns a value that formats `bytes` as hex without allocating.
///
/// `{}` and `{:x}` print lowercase, `{:X}` prints uppercase. Width, fill and
/// alignment flags apply to the whole string.
///
/// # Examples
///
/// ```rust
/// let digest = [0xca, 0xfe];
/// assert_eq!(format!("{}", rune_hex::display(&digest)), "cafe");
/// assert_eq!(format!("{:X}", rune_hex::display(&digest)), "CAFE");
/// assert_eq!(format!("[{:>6}]", rune_hex::display(&digest)), "[  cafe]");
/// ```
#[must_use]
pub fn display<T: AsRef<[u8]> + ?Sized>(bytes: &T) -> Display<'_> {
    Display::new(bytes.as_ref())
}

/// Decodes hex text to bytes.
///
/// Accepts lowercase, uppercase and mixed-case digits. A single leading `0x`
/// or `0X` is skipped. Anything else, including whitespace, is an error; use
/// [`DecodeOptions`] for more forgiving input.
///
/// # Errors
///
/// - [`HexError::OddLength`] if the number of digits is odd.
/// - [`HexError::InvalidByte`] for the first byte that is not a hex digit,
///   with its offset in `hex` (counting the prefix).
///
/// # Examples
///
/// ```rust
/// use rune_hex::{decode, HexError};
///
/// assert_eq!(decode("deadbeef")?, b"\xde\xad\xbe\xef");
/// assert_eq!(decode("0xDeAdBeEf")?, b"\xde\xad\xbe\xef");
/// assert_eq!(decode("")?, b"");
///
/// assert_eq!(decode("abc"), Err(HexError::OddLength));
/// assert_eq!(decode("0xag"), Err(HexError::InvalidByte { byte: b'g', offset: 3 }));
/// # Ok::<(), HexError>(())
/// ```
#[cfg(feature = "alloc")]
pub fn decode(hex: impl AsRef<[u8]>) -> Result<Vec<u8>, HexError> {
    DecodeOptions::new().allow_prefix(true).decode(hex)
}

/// Decodes hex text into `out` and returns the written part.
///
/// Accepts the same input as [`decode`]. `out` must hold at least half the
/// number of digits; anything after that is left untouched.
///
/// # Errors
///
/// Those of [`decode`], plus [`HexError::BufferTooSmall`] if `out` is too
/// short. The contents of `out` are unspecified after an error.
///
/// # Examples
///
/// ```rust
/// let mut buf = [0u8; 8];
/// assert_eq!(rune_hex::decode_to_slice("0x0102", &mut buf)?, [1, 2]);
/// # Ok::<(), rune_hex::HexError>(())
/// ```
pub fn decode_to_slice(hex: impl AsRef<[u8]>, out: &mut [u8]) -> Result<&mut [u8], HexError> {
    DecodeOptions::new()
        .allow_prefix(true)
        .decode_to_slice(hex, out)
}

/// Decodes hex text into a fixed-size array, for digests, keys and ids.
///
/// Accepts the same input as [`decode`].
///
/// # Errors
///
/// Those of [`decode`], plus [`HexError::WrongLength`] if the text does not
/// decode to exactly `N` bytes.
///
/// # Examples
///
/// ```rust
/// use rune_hex::{decode_array, HexError};
///
/// let id: [u8; 2] = decode_array("beef")?;
/// assert_eq!(id, [0xbe, 0xef]);
///
/// assert_eq!(
///     decode_array::<4>("beef"),
///     Err(HexError::WrongLength { expected: 4, actual: 2 }),
/// );
/// # Ok::<(), HexError>(())
/// ```
pub fn decode_array<const N: usize>(hex: impl AsRef<[u8]>) -> Result<[u8; N], HexError> {
    DecodeOptions::new().allow_prefix(true).decode_array(hex)
}

// Compile and run the README examples as doctests.
#[cfg(all(doctest, feature = "std", feature = "serde"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

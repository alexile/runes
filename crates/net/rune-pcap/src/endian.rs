//! Byte order of a capture file, and helpers to read and write fields in it.

use crate::error::Error;

/// Byte order of the fields in a pcap file or pcapng section.
///
/// Both formats are written in the byte order of the machine that wrote
/// them; readers detect it from the magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Endian {
    /// Least significant byte first (x86, most ARM). The default for
    /// writing.
    #[default]
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// The byte order of the machine running this code.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "big") {
            Self::Big
        } else {
            Self::Little
        }
    }

    pub(crate) const fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }

    pub(crate) const fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }

    pub(crate) const fn u64(self, b: [u8; 8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(b),
            Self::Big => u64::from_be_bytes(b),
        }
    }

    pub(crate) fn put_u16(self, out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        });
    }

    pub(crate) fn put_u32(self, out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        });
    }

    pub(crate) fn put_u64(self, out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        });
    }

    /// Read a `u16` at `at`, or report `what` as truncated.
    pub(crate) fn read_u16(self, data: &[u8], at: usize, what: &'static str) -> Result<u16, Error> {
        array(data, at, what).map(|b| self.u16(b))
    }

    /// Read a `u32` at `at`, or report `what` as truncated.
    pub(crate) fn read_u32(self, data: &[u8], at: usize, what: &'static str) -> Result<u32, Error> {
        array(data, at, what).map(|b| self.u32(b))
    }

    /// Read a `u64` at `at`, or report `what` as truncated.
    pub(crate) fn read_u64(self, data: &[u8], at: usize, what: &'static str) -> Result<u64, Error> {
        array(data, at, what).map(|b| self.u64(b))
    }
}

/// Copy `N` bytes starting at `at` out of `data`.
pub fn array<const N: usize>(data: &[u8], at: usize, what: &'static str) -> Result<[u8; N], Error> {
    data.get(at..)
        .and_then(<[u8]>::first_chunk::<N>)
        .copied()
        .ok_or_else(|| Error::truncated(what, at.saturating_add(N), data.len()))
}

/// Round `len` up to a multiple of four (pcapng's alignment), saturating.
pub const fn pad4(len: usize) -> usize {
    len.saturating_add(3) & !3
}

/// Convert a length to the `u32` a header field holds.
pub fn len_u32(len: usize, what: &'static str) -> Result<u32, Error> {
    u32::try_from(len).map_err(|_| Error::TooLarge {
        what,
        len: len as u64,
        max: u64::from(u32::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_orders() {
        let data = [0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(Endian::Little.read_u16(&data, 1, "x").unwrap(), 0x0201);
        assert_eq!(Endian::Big.read_u16(&data, 1, "x").unwrap(), 0x0102);
        assert_eq!(Endian::Big.read_u32(&data, 0, "x").unwrap(), 0x0001_0203);
        assert_eq!(
            Endian::Little.read_u64(&data, 1, "x").unwrap(),
            0x0807_0605_0403_0201
        );
        assert!(
            Endian::Big
                .read_u32(&data, 6, "x")
                .unwrap_err()
                .is_truncated()
        );
        assert!(Endian::Big.read_u32(&data, usize::MAX, "x").is_err());
    }

    #[test]
    fn writes_both_orders() {
        let mut out = Vec::new();
        Endian::Little.put_u16(&mut out, 0x0102);
        Endian::Big.put_u32(&mut out, 0x0304_0506);
        Endian::Big.put_u64(&mut out, 7);
        assert_eq!(out, [2, 1, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 7]);
    }

    #[test]
    fn padding() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 4);
        assert_eq!(pad4(4), 4);
        assert_eq!(pad4(5), 8);
        assert_eq!(pad4(usize::MAX), usize::MAX & !3);
    }
}

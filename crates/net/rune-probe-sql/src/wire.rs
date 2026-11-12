//! Bounds-checked readers shared by the protocol parsers.

use crate::Error;

/// A cursor over untrusted bytes. Every read is bounds-checked and fails
/// with [`Error::Truncated`] naming the structure being read.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub const fn rest(&self) -> &'a [u8] {
        self.buf
    }

    const fn truncated(&self) -> Error {
        Error::Truncated { what: self.what }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let head = self.buf.get(..n).ok_or_else(|| self.truncated())?;
        self.buf = self.buf.get(n..).unwrap_or_default();
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        let (&byte, rest) = self.buf.split_first().ok_or_else(|| self.truncated())?;
        self.buf = rest;
        Ok(byte)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u16_le(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u16_be(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    pub fn u32_le(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    pub fn u32_be(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    /// A NUL-terminated string, without the NUL.
    pub fn cstr(&mut self) -> Result<&'a [u8], Error> {
        let end = self
            .buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| self.truncated())?;
        let s = self.take(end)?;
        self.take(1)?;
        Ok(s)
    }
}

/// Lossy UTF-8 of untrusted text, with control characters escaped and the
/// length bounded.
pub fn text(bytes: &[u8]) -> String {
    rune_service_probe::banner::printable(bytes, MAX_TEXT)
}

/// Upper bound on any string a probe copies out of a reply.
pub const MAX_TEXT: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let mut r = Reader::new(b"\x01\x02\x03ab\0c", "test");
        assert_eq!(r.u16_le().unwrap(), 0x0201);
        assert_eq!(r.u8().unwrap(), 3);
        assert_eq!(r.cstr().unwrap(), b"ab");
        assert!(matches!(r.cstr(), Err(Error::Truncated { what: "test" })));
        assert!(matches!(r.u32_be(), Err(Error::Truncated { .. })));
        assert_eq!(r.rest(), b"c");
    }
}

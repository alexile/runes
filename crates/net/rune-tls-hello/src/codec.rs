//! Bounds-checked big-endian reader and length-prefixed writer helpers.
//!
//! Every read checks the remaining length first, so malformed input turns
//! into [`Error::Truncated`] instead of a panic.

use crate::Error;

/// Cursor over a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Takes the next `n` bytes.
    pub const fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        if n > self.buf.len() {
            return Err(Error::Truncated { what });
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        let bytes = self.take(1, what)?;
        Ok(bytes.first().copied().unwrap_or_default())
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, Error> {
        match *self.take(2, what)? {
            [a, b] => Ok(u16::from_be_bytes([a, b])),
            _ => Err(Error::Truncated { what }),
        }
    }

    pub fn u24(&mut self, what: &'static str) -> Result<usize, Error> {
        match *self.take(3, what)? {
            [a, b, c] => Ok(usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c)),
            _ => Err(Error::Truncated { what }),
        }
    }

    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Error> {
        let bytes = self.take(N, what)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// A vector with a one-byte length prefix.
    pub fn vec8(&mut self, what: &'static str) -> Result<Self, Error> {
        let len = usize::from(self.u8(what)?);
        Ok(Reader::new(self.take(len, what)?))
    }

    /// A vector with a two-byte length prefix.
    pub fn vec16(&mut self, what: &'static str) -> Result<Self, Error> {
        let len = usize::from(self.u16(what)?);
        Ok(Reader::new(self.take(len, what)?))
    }

    /// The bytes not read yet.
    pub const fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// Reads the rest as a list of big-endian `u16`s.
    pub fn u16_list(mut self, what: &'static str) -> Result<Vec<u16>, Error> {
        if !self.buf.len().is_multiple_of(2) {
            return Err(Error::Malformed {
                what,
                reason: "odd length for a list of 16-bit values",
            });
        }
        let mut out = Vec::with_capacity(self.buf.len() / 2);
        while !self.is_empty() {
            out.push(self.u16(what)?);
        }
        Ok(out)
    }

    /// Fails unless every byte was read.
    pub const fn finish(self, what: &'static str) -> Result<(), Error> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes {
                what,
                count: self.buf.len(),
            })
        }
    }
}

pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

const fn too_long(what: &'static str, len: usize, max: usize) -> Error {
    Error::TooLong { what, len, max }
}

/// Appends `data` with a one-byte length prefix.
pub fn put_vec8(out: &mut Vec<u8>, data: &[u8], what: &'static str) -> Result<(), Error> {
    let len = u8::try_from(data.len()).map_err(|_| too_long(what, data.len(), 0xff))?;
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

/// Appends `data` with a two-byte length prefix.
pub fn put_vec16(out: &mut Vec<u8>, data: &[u8], what: &'static str) -> Result<(), Error> {
    let len = u16::try_from(data.len()).map_err(|_| too_long(what, data.len(), 0xffff))?;
    put_u16(out, len);
    out.extend_from_slice(data);
    Ok(())
}

/// Appends `data` with a three-byte length prefix.
pub fn put_vec24(out: &mut Vec<u8>, data: &[u8], what: &'static str) -> Result<(), Error> {
    const MAX: usize = 0x00ff_ffff;
    if data.len() > MAX {
        return Err(too_long(what, data.len(), MAX));
    }
    let len = data.len().to_be_bytes();
    let [.., a, b, c] = len;
    out.extend_from_slice(&[a, b, c]);
    out.extend_from_slice(data);
    Ok(())
}

/// Encodes a list of `u16`s as the body of a vector.
pub fn u16_body(values: impl IntoIterator<Item = u16>) -> Vec<u8> {
    values.into_iter().flat_map(u16::to_be_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u24("x"), Ok(0x01_0203));
        assert_eq!(r.u8("x"), Err(Error::Truncated { what: "x" }));
        let mut r = Reader::new(&[3, 1, 2]);
        assert!(r.vec8("v").is_err());
    }

    #[test]
    fn writes_check_lengths() {
        let mut out = Vec::new();
        assert!(put_vec8(&mut out, &[0; 256], "v").is_err());
        put_vec24(&mut out, &[7], "v").unwrap();
        assert_eq!(out, [0, 0, 1, 7]);
    }
}

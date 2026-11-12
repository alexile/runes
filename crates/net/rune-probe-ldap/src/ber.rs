//! The subset of BER that LDAP uses (RFC 4511 §5.1): definite lengths,
//! single-byte tags.

use crate::Error;

/// Universal `BOOLEAN`.
pub const BOOLEAN: u8 = 0x01;
/// Universal `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// Universal `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// Universal `ENUMERATED`.
pub const ENUMERATED: u8 = 0x0a;
/// Universal constructed `SEQUENCE`.
pub const SEQUENCE: u8 = 0x30;
/// Universal constructed `SET`.
pub const SET: u8 = 0x31;

/// Longest element content accepted. LDAP replies the probes read are a
/// few kilobytes; anything near this is hostile.
const MAX_LEN: usize = 16 * 1024 * 1024;

/// A cursor over BER elements in untrusted bytes.
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

    /// Bytes not yet read.
    pub const fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Read one element: its tag and content, and the total length of the
    /// encoding.
    pub fn tlv(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let (tag, header, len) = header(self.buf, self.what)?;
        let end = header
            .checked_add(len)
            .ok_or_else(|| Error::malformed(self.what, "length overflow"))?;
        let content = self
            .buf
            .get(header..end)
            .ok_or(Error::Truncated { what: self.what })?;
        self.buf = self.buf.get(end..).unwrap_or_default();
        Ok((tag, content))
    }

    /// Read one element and check its tag.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let (actual, content) = self.tlv()?;
        if actual != tag {
            return Err(Error::malformed(
                self.what,
                format!("expected tag {tag:#04x}, got {actual:#04x}"),
            ));
        }
        Ok(content)
    }

    /// An `INTEGER` or `ENUMERATED` (by `tag`) that fits an `i64`.
    pub fn integer(&mut self, tag: u8) -> Result<i64, Error> {
        let content = self.expect(tag)?;
        decode_integer(content).ok_or_else(|| Error::malformed(self.what, "integer out of range"))
    }
}

/// Parse an element header at the start of `buf`: tag, header length,
/// content length.
pub fn header(buf: &[u8], what: &'static str) -> Result<(u8, usize, usize), Error> {
    let truncated = || Error::Truncated { what };
    let &tag = buf.first().ok_or_else(truncated)?;
    if tag & 0x1f == 0x1f {
        return Err(Error::malformed(what, "multi-byte tag"));
    }
    let &first = buf.get(1).ok_or_else(truncated)?;
    if first & 0x80 == 0 {
        return Ok((tag, 2, usize::from(first)));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 {
        return Err(Error::malformed(what, "indefinite length"));
    }
    if n > 4 {
        return Err(Error::malformed(what, "length too long"));
    }
    let bytes = buf.get(2..2 + n).ok_or_else(truncated)?;
    let len = bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    if len > MAX_LEN {
        return Err(Error::malformed(what, format!("length {len}")));
    }
    Ok((tag, 2 + n, len))
}

/// Two's-complement big-endian integer content.
pub fn decode_integer(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let negative = content.first().is_some_and(|b| b & 0x80 != 0);
    let init: i64 = if negative { -1 } else { 0 };
    Some(
        content
            .iter()
            .fold(init, |acc, &b| (acc << 8) | i64::from(b)),
    )
}

/// Encode one element.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0x7f));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// Encode an `INTEGER` or `ENUMERATED` (by `tag`), minimally.
pub fn integer(tag: u8, value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (Some(&b), Some(&next)) = (bytes.get(start), bytes.get(start + 1)) else {
            break;
        };
        let redundant = (b == 0 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    tlv(tag, bytes.get(start..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_minimally() {
        for (value, encoded) in [
            (0i64, &[0x02, 1, 0][..]),
            (127, &[0x02, 1, 0x7f]),
            (128, &[0x02, 2, 0, 0x80]),
            (-1, &[0x02, 1, 0xff]),
            (-129, &[0x02, 2, 0xff, 0x7f]),
            (65_536, &[0x02, 3, 1, 0, 0]),
        ] {
            assert_eq!(integer(INTEGER, value), encoded, "{value}");
            let mut r = Reader::new(encoded, "test");
            assert_eq!(r.integer(INTEGER).unwrap(), value);
        }
    }

    #[test]
    fn long_form_lengths() {
        let content = vec![7; 300];
        let enc = tlv(OCTET_STRING, &content);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let mut r = Reader::new(&enc, "test");
        assert_eq!(r.expect(OCTET_STRING).unwrap(), &content[..]);
        assert!(r.is_empty());
    }

    #[test]
    fn rejects_hostile_headers() {
        assert!(header(&[0x30, 0x80], "t").is_err_and(|e| !e.is_truncated()));
        assert!(header(&[0x1f, 0x01], "t").is_err_and(|e| !e.is_truncated()));
        assert!(header(&[0x30, 0x85, 1, 1, 1, 1, 1], "t").is_err_and(|e| !e.is_truncated()));
        assert!(
            header(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff], "t").is_err_and(|e| !e.is_truncated())
        );
        assert!(header(&[0x30, 0x82, 1], "t").is_err_and(|e| e.is_truncated()));
        assert!(
            Reader::new(&[0x04, 5, 1], "t")
                .tlv()
                .is_err_and(|e| e.is_truncated())
        );
        assert_eq!(decode_integer(&[]), None);
        assert_eq!(decode_integer(&[0; 9]), None);
    }
}

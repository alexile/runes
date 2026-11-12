//! The TLS record layer ([RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1),
//! [RFC 5246 §6.2](https://www.rfc-editor.org/rfc/rfc5246#section-6.2)) and
//! alerts ([RFC 8446 §6](https://www.rfc-editor.org/rfc/rfc8446#section-6)).

use crate::codec::{Reader, put_u16, put_vec16};
use crate::{AlertDescription, AlertLevel, ContentType, Error, ProtocolVersion};

/// Length of a record header: type, version and length.
pub const RECORD_HEADER_LEN: usize = 5;

/// Largest plaintext fragment a record may carry (2^14 bytes).
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;

/// Largest fragment [`Record::parse`] accepts: 2^14 + 2048 bytes, the
/// TLS 1.2 ciphertext limit, which also covers TLS 1.3's 2^14 + 256.
pub const MAX_FRAGMENT_LEN: usize = MAX_PLAINTEXT_LEN + 2048;

/// One TLS record, borrowing its fragment from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record<'a> {
    /// What the fragment holds.
    pub content_type: ContentType,
    /// The record-layer version (`legacy_record_version` in TLS 1.3).
    pub version: ProtocolVersion,
    /// The payload; ciphertext once encryption is on.
    pub fragment: &'a [u8],
}

impl<'a> Record<'a> {
    /// A record with the given parts.
    #[must_use]
    pub const fn new(
        content_type: ContentType,
        version: ProtocolVersion,
        fragment: &'a [u8],
    ) -> Self {
        Self {
            content_type,
            version,
            fragment,
        }
    }

    /// Parses the record at the start of `buf` and returns it with the
    /// number of bytes it took.
    ///
    /// Checks fail as early as the bytes allow, so the first byte is
    /// enough to tell a TLS stream from, say, plain HTTP.
    ///
    /// # Errors
    ///
    /// [`Error::Incomplete`] if `buf` ends before the record does;
    /// [`Error::Sslv2`] for an SSL 2.0 header; [`Error::Malformed`] for an
    /// unknown content type or a major version other than 3;
    /// [`Error::TooLong`] if the length exceeds [`MAX_FRAGMENT_LEN`].
    pub fn parse(buf: &'a [u8]) -> Result<(Self, usize), Error> {
        let incomplete = |have: usize, want: usize| Error::Incomplete {
            needed: want.saturating_sub(have),
        };
        let Some(&first) = buf.first() else {
            return Err(incomplete(0, RECORD_HEADER_LEN));
        };
        if first & 0x80 != 0 {
            return Err(Error::Sslv2);
        }
        let content_type = ContentType(first);
        if content_type.name().is_none() {
            return Err(Error::Malformed {
                what: "record",
                reason: "unknown content type",
            });
        }
        if let Some(&major) = buf.get(1)
            && major != 3
        {
            return Err(Error::Malformed {
                what: "record",
                reason: "version major is not 3",
            });
        }
        if buf.len() < RECORD_HEADER_LEN {
            return Err(incomplete(buf.len(), RECORD_HEADER_LEN));
        }
        let mut r = Reader::new(buf);
        r.u8("record header")?;
        let version = ProtocolVersion(r.u16("record header")?);
        let len = usize::from(r.u16("record header")?);
        if len > MAX_FRAGMENT_LEN {
            return Err(Error::TooLong {
                what: "record fragment",
                len,
                max: MAX_FRAGMENT_LEN,
            });
        }
        let total = RECORD_HEADER_LEN + len;
        if buf.len() < total {
            return Err(incomplete(buf.len(), total));
        }
        let fragment = r.take(len, "record fragment")?;
        Ok((Self::new(content_type, version, fragment), total))
    }

    /// Appends the encoded record to `out`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if the fragment exceeds [`MAX_FRAGMENT_LEN`].
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.fragment.len() > MAX_FRAGMENT_LEN {
            return Err(Error::TooLong {
                what: "record fragment",
                len: self.fragment.len(),
                max: MAX_FRAGMENT_LEN,
            });
        }
        out.push(self.content_type.0);
        put_u16(out, self.version.0);
        put_vec16(out, self.fragment, "record fragment")
    }
}

/// Splits `payload` into records of at most `max_fragment_len` bytes each
/// (clamped to between 1 and [`MAX_PLAINTEXT_LEN`]) and returns their encoding.
/// An empty payload gives one empty record.
///
/// Small fragments are useful to test how a peer reassembles handshake
/// messages that span records.
///
/// # Errors
///
/// None in practice: every fragment is within limits by construction.
pub fn encode_records(
    content_type: ContentType,
    version: ProtocolVersion,
    payload: &[u8],
    max_fragment_len: usize,
) -> Result<Vec<u8>, Error> {
    let size = max_fragment_len.clamp(1, MAX_PLAINTEXT_LEN);
    let mut out = Vec::with_capacity(payload.len() + RECORD_HEADER_LEN);
    if payload.is_empty() {
        Record::new(content_type, version, payload).encode(&mut out)?;
    }
    for chunk in payload.chunks(size) {
        Record::new(content_type, version, chunk).encode(&mut out)?;
    }
    Ok(out)
}

/// An alert message: level and description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Alert {
    /// `warning` or `fatal`.
    pub level: AlertLevel,
    /// Why the alert was sent.
    pub description: AlertDescription,
}

impl Alert {
    /// An alert with the given parts.
    #[must_use]
    pub const fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    /// Parses a two-byte alert.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] or [`Error::TrailingBytes`] unless `bytes` is
    /// exactly two bytes long.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let level = AlertLevel(r.u8("alert")?);
        let description = AlertDescription(r.u8("alert")?);
        r.finish("alert")?;
        Ok(Self::new(level, description))
    }

    /// The two-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 2] {
        [self.level.0, self.description.0]
    }

    /// Whether the level is `fatal`.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        self.level.0 == AlertLevel::FATAL.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_encodes_a_record() {
        let bytes = [22, 3, 1, 0, 2, 0xaa, 0xbb, 0xff];
        let (record, used) = Record::parse(&bytes).unwrap();
        assert_eq!(used, 7);
        assert_eq!(record.content_type, ContentType::HANDSHAKE);
        assert_eq!(record.version, ProtocolVersion::TLS_1_0);
        assert_eq!(record.fragment, [0xaa, 0xbb]);
        let mut out = Vec::new();
        record.encode(&mut out).unwrap();
        assert_eq!(out, bytes[..7]);
    }

    #[test]
    fn reports_how_much_is_missing() {
        assert_eq!(Record::parse(&[]), Err(Error::Incomplete { needed: 5 }));
        assert_eq!(
            Record::parse(&[22, 3, 3]),
            Err(Error::Incomplete { needed: 2 })
        );
        assert_eq!(
            Record::parse(&[22, 3, 3, 0, 4, 1]),
            Err(Error::Incomplete { needed: 3 })
        );
    }

    #[test]
    fn rejects_non_tls_early() {
        assert!(matches!(Record::parse(b"G"), Err(Error::Malformed { .. })));
        assert!(matches!(
            Record::parse(&[22, 4]),
            Err(Error::Malformed { .. })
        ));
        assert_eq!(Record::parse(&[0x80, 0x2e, 0x01]), Err(Error::Sslv2));
        assert!(matches!(
            Record::parse(&[23, 3, 3, 0xff, 0xff]),
            Err(Error::TooLong { .. })
        ));
    }

    #[test]
    fn fragments_a_payload() {
        let out = encode_records(
            ContentType::HANDSHAKE,
            ProtocolVersion::TLS_1_2,
            &[1, 2, 3],
            2,
        )
        .unwrap();
        assert_eq!(out, [22, 3, 3, 0, 2, 1, 2, 22, 3, 3, 0, 1, 3]);
        let empty = encode_records(ContentType::ALERT, ProtocolVersion::TLS_1_2, &[], 0).unwrap();
        assert_eq!(empty, [21, 3, 3, 0, 0]);
    }

    #[test]
    fn alerts() {
        let alert = Alert::parse(&[2, 86]).unwrap();
        assert!(alert.is_fatal());
        assert_eq!(alert.description, AlertDescription::INAPPROPRIATE_FALLBACK);
        assert_eq!(alert.to_bytes(), [2, 86]);
        assert!(Alert::parse(&[2]).is_err());
        assert!(Alert::parse(&[2, 1, 0]).is_err());
    }
}

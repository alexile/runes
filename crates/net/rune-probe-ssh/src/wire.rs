//! SSH transport-layer framing: the identification string, the binary
//! packet protocol and the RFC 4251 §5 data types.

use std::fmt;

use crate::Error;

/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
pub const MSG_DISCONNECT: u8 = 1;
/// `SSH_MSG_IGNORE` (RFC 4253 §11.2).
pub const MSG_IGNORE: u8 = 2;
/// `SSH_MSG_UNIMPLEMENTED` (RFC 4253 §11.4).
pub const MSG_UNIMPLEMENTED: u8 = 3;
/// `SSH_MSG_DEBUG` (RFC 4253 §11.3).
pub const MSG_DEBUG: u8 = 4;
/// `SSH_MSG_KEXINIT` (RFC 4253 §7.1).
pub const MSG_KEXINIT: u8 = 20;
/// `SSH_MSG_KEXDH_INIT` (RFC 4253 §8), also `SSH_MSG_KEX_ECDH_INIT`
/// (RFC 5656 §4) and the curve25519 init (RFC 8731).
pub const MSG_KEX_INIT: u8 = 30;
/// `SSH_MSG_KEXDH_REPLY` (RFC 4253 §8), also `SSH_MSG_KEX_ECDH_REPLY`
/// (RFC 5656 §4) and the curve25519 reply (RFC 8731).
pub const MSG_KEX_REPLY: u8 = 31;

/// The largest `packet_length` [`parse_packet`] accepts.
///
/// RFC 4253 §6.1 requires support for 35000-byte packets; this allows some
/// headroom for servers with long algorithm lists.
pub const MAX_PACKET_LEN: u32 = 65_536;

/// The longest identification string RFC 4253 §4.2 allows, CR LF included.
pub const MAX_IDENTIFICATION_LEN: usize = 255;

/// A parsed identification string, `SSH-protoversion-softwareversion SP
/// comments` ([RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)).
///
/// ```
/// use rune_probe_ssh::Identification;
///
/// let id = Identification::parse(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")?;
/// assert_eq!(id.proto_version, "2.0");
/// assert_eq!(id.software_version, "OpenSSH_9.6p1");
/// assert_eq!(id.comments.as_deref(), Some("Ubuntu-3ubuntu13"));
/// assert_eq!(id.product(), ("OpenSSH".to_owned(), Some("9.6p1".to_owned())));
/// assert!(id.speaks_ssh2());
/// assert_eq!(id.to_string(), "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13");
/// # Ok::<(), rune_probe_ssh::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Identification {
    /// The protocol version: `2.0`, `1.99` (SSH-1 and SSH-2) or `1.5`.
    pub proto_version: String,
    /// The software name and version, e.g. `OpenSSH_9.6p1`.
    pub software_version: String,
    /// The optional free-form comment after the first space.
    pub comments: Option<String>,
}

impl Identification {
    /// Parse one identification line. A trailing CR LF (or bare LF) is
    /// allowed and ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Identification`] when the line does not start with `SSH-`,
    /// is longer than [`MAX_IDENTIFICATION_LEN`], has no software version,
    /// or contains bytes outside printable ASCII.
    pub fn parse(line: &[u8]) -> Result<Self, Error> {
        if line.len() > MAX_IDENTIFICATION_LEN {
            return Err(Error::Identification("longer than 255 bytes"));
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let rest = line
            .strip_prefix(b"SSH-")
            .ok_or(Error::Identification("does not start with SSH-"))?;
        if !rest.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::Identification("not printable ASCII"));
        }
        let (main, comments) = rest
            .iter()
            .position(|&b| b == b' ')
            .map_or((rest, None), |at| {
                (
                    rest.get(..at).unwrap_or_default(),
                    rest.get(at + 1..).map(ascii),
                )
            });
        let dash = main
            .iter()
            .position(|&b| b == b'-')
            .ok_or(Error::Identification("no software version"))?;
        let proto = main.get(..dash).unwrap_or_default();
        let software = main.get(dash + 1..).unwrap_or_default();
        if proto.is_empty() {
            return Err(Error::Identification("empty protocol version"));
        }
        if software.is_empty() {
            return Err(Error::Identification("empty software version"));
        }
        Ok(Self {
            proto_version: ascii(proto),
            software_version: ascii(software),
            comments: comments.filter(|c| !c.is_empty()),
        })
    }

    /// True for protocol `2.0` and for `1.99`, which offers both versions.
    #[must_use]
    pub fn speaks_ssh2(&self) -> bool {
        self.proto_version == "2.0" || self.proto_version == "1.99"
    }

    /// True when the server offers the obsolete SSH-1 protocol (`1.x`,
    /// including `1.99`).
    #[must_use]
    pub fn offers_ssh1(&self) -> bool {
        self.proto_version.starts_with("1.")
    }

    /// Split [`software_version`](Self::software_version) into a product
    /// name and a version: the version starts after the last `_` or `-`
    /// that is followed by a digit (`OpenSSH_9.6p1`, `dropbear_2022.83`,
    /// `Cisco-1.25`, `OpenSSH_for_Windows_8.1`). Underscores in the product
    /// become spaces, and well-known lowercase names are capitalised.
    #[must_use]
    pub fn product(&self) -> (String, Option<String>) {
        let software = self.software_version.as_str();
        let bytes = software.as_bytes();
        let split = bytes
            .windows(2)
            .rposition(|pair| matches!(pair, [b'_' | b'-', d] if d.is_ascii_digit()));
        let (name, version) = match split {
            Some(at) if at > 0 => (
                software.get(..at).unwrap_or(software),
                software.get(at + 1..).map(str::to_owned),
            ),
            _ => (software, None),
        };
        let name = match name {
            "dropbear" => "Dropbear".to_owned(),
            other => other.replace('_', " "),
        };
        (name, version)
    }
}

impl fmt::Display for Identification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SSH-{}-{}", self.proto_version, self.software_version)?;
        if let Some(comments) = &self.comments {
            write!(f, " {comments}")?;
        }
        Ok(())
    }
}

/// Bytes already checked to be printable ASCII, as a `String`.
fn ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Split one complete binary packet off the front of `buf`
/// ([RFC 4253 §6](https://www.rfc-editor.org/rfc/rfc4253#section-6)),
/// before any cipher or MAC is in effect.
///
/// Returns the payload and the number of bytes the packet took, or `None`
/// while the packet is incomplete.
///
/// ```
/// use rune_probe_ssh::{encode_packet, parse_packet};
///
/// let packet = encode_packet(&[2, 0, 0, 0, 0]); // SSH_MSG_IGNORE ""
/// assert_eq!(packet.len() % 8, 0);
/// assert_eq!(parse_packet(&packet)?, Some((&[2, 0, 0, 0, 0][..], packet.len())));
/// assert_eq!(parse_packet(&packet[..7])?, None);
/// # Ok::<(), rune_probe_ssh::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::PacketLength`] when `packet_length` is below 5 or above
/// [`MAX_PACKET_LEN`], and [`Error::Malformed`] when the padding length
/// leaves no payload.
pub fn parse_packet(buf: &[u8]) -> Result<Option<(&[u8], usize)>, Error> {
    let Some(header) = buf.get(..5) else {
        return Ok(None);
    };
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let padding = usize::from(header[4]);
    if !(5..=MAX_PACKET_LEN).contains(&length) {
        return Err(Error::PacketLength(length));
    }
    let length = length as usize;
    if padding + 1 >= length {
        return Err(Error::Malformed("packet padding length"));
    }
    let total = 4 + length;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = buf
        .get(5..total - padding)
        .ok_or(Error::Truncated("packet"))?;
    Ok(Some((payload, total)))
}

/// Frame `payload` as an unencrypted binary packet: 8-byte aligned, with
/// 4 to 11 zero bytes of padding.
#[must_use]
pub fn encode_packet(payload: &[u8]) -> Vec<u8> {
    let unpadded = 4 + 1 + payload.len();
    let mut padding = 8 - unpadded % 8;
    if padding < 4 {
        padding += 8;
    }
    let length = 1 + payload.len() + padding;
    let mut out = Vec::with_capacity(4 + length);
    out.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes());
    out.push(u8::try_from(padding).unwrap_or(4));
    out.extend_from_slice(payload);
    out.resize(4 + length, 0);
    out
}

/// A cursor over RFC 4251 §5 data types.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let head = self.buf.get(..n).ok_or(Error::Truncated(what))?;
        self.buf = self.buf.get(n..).unwrap_or_default();
        Ok(head)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        Ok(self.bytes(1, what)?.first().copied().unwrap_or_default())
    }

    pub fn boolean(&mut self, what: &'static str) -> Result<bool, Error> {
        Ok(self.u8(what)? != 0)
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, Error> {
        let b = self.bytes(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// An RFC 4251 `string` (also used for `mpint`).
    pub fn string(&mut self, what: &'static str) -> Result<&'a [u8], Error> {
        let len = self.u32(what)? as usize;
        self.bytes(len, what)
    }

    /// An RFC 4251 `name-list`: comma-separated, non-empty names of
    /// printable ASCII other than comma.
    pub fn name_list(&mut self, what: &'static str) -> Result<Vec<String>, Error> {
        let raw = self.string(what)?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        raw.split(|&b| b == b',')
            .map(|name| {
                if name.is_empty() || !name.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
                    Err(Error::Malformed(what))
                } else {
                    Ok(ascii(name))
                }
            })
            .collect()
    }
}

/// Append an RFC 4251 `uint32`.
pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append an RFC 4251 `string`.
pub fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, u32::try_from(value.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(value);
}

/// Append an RFC 4251 `name-list`.
pub fn put_name_list(out: &mut Vec<u8>, names: &[String]) {
    put_string(out, names.join(",").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification_variants() {
        let id = Identification::parse(b"SSH-1.99-Cisco-1.25\r\n").unwrap();
        assert!(id.offers_ssh1() && id.speaks_ssh2());
        assert_eq!(id.product(), ("Cisco".to_owned(), Some("1.25".to_owned())));

        let id = Identification::parse(b"SSH-2.0-dropbear_2022.83").unwrap();
        assert_eq!(
            id.product(),
            ("Dropbear".to_owned(), Some("2022.83".to_owned()))
        );
        let id = Identification::parse(b"SSH-2.0-OpenSSH_for_Windows_8.1").unwrap();
        assert_eq!(
            id.product(),
            ("OpenSSH for Windows".to_owned(), Some("8.1".to_owned()))
        );
        let id = Identification::parse(b"SSH-2.0-RomSShell").unwrap();
        assert_eq!(id.product(), ("RomSShell".to_owned(), None));

        let id = Identification::parse(b"SSH-1.5-1.2.27\n").unwrap();
        assert!(!id.speaks_ssh2());

        for bad in [
            &b"HTTP/1.1 400"[..],
            b"SSH-2.0",
            b"SSH--x",
            b"SSH-2.0-",
            b"SSH-2.0-a\x1b[0m",
        ] {
            assert!(Identification::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Identification::parse(&[b'S'; 300]).is_err());
    }

    #[test]
    fn packet_framing() {
        for len in 0..40 {
            let payload = vec![7u8; len + 1];
            let packet = encode_packet(&payload);
            assert_eq!(packet.len() % 8, 0);
            let pad = usize::from(packet[4]);
            assert!((4..=11).contains(&pad));
            let (got, used) = parse_packet(&packet).unwrap().unwrap();
            assert_eq!(got, &payload[..]);
            assert_eq!(used, packet.len());
        }
        assert_eq!(parse_packet(&[0, 0, 0, 1, 0]), Err(Error::PacketLength(1)));
        assert_eq!(
            parse_packet(&[0xff, 0, 0, 0, 0]),
            Err(Error::PacketLength(0xff00_0000))
        );
        assert!(matches!(
            parse_packet(&[0, 0, 0, 8, 7]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn name_lists() {
        let mut out = Vec::new();
        put_string(&mut out, b"a,b@c.d");
        put_string(&mut out, b"");
        put_string(&mut out, b"a,,b");
        let mut r = Reader::new(&out);
        assert_eq!(r.name_list("x").unwrap(), ["a", "b@c.d"]);
        assert_eq!(r.name_list("x").unwrap(), Vec::<String>::new());
        assert_eq!(r.name_list("x"), Err(Error::Malformed("x")));
        assert_eq!(r.u32("y"), Err(Error::Truncated("y")));
    }
}

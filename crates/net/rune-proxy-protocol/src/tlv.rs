//! v2 TLV extensions: raw TLVs, the `PP2_TYPE_SSL` structure and CRC32C.

use crate::Error;

/// `PP2_TYPE_ALPN`: the negotiated application protocol.
pub const PP2_TYPE_ALPN: u8 = 0x01;
/// `PP2_TYPE_AUTHORITY`: the host name the client asked for (TLS SNI).
pub const PP2_TYPE_AUTHORITY: u8 = 0x02;
/// `PP2_TYPE_CRC32C`: a CRC32C checksum of the whole header.
pub const PP2_TYPE_CRC32C: u8 = 0x03;
/// `PP2_TYPE_NOOP`: padding, to be ignored.
pub const PP2_TYPE_NOOP: u8 = 0x04;
/// `PP2_TYPE_UNIQUE_ID`: an opaque connection identifier (up to 128 bytes).
pub const PP2_TYPE_UNIQUE_ID: u8 = 0x05;
/// `PP2_TYPE_SSL`: TLS details of the client connection, see [`Ssl`].
pub const PP2_TYPE_SSL: u8 = 0x20;
/// `PP2_SUBTYPE_SSL_VERSION`: the TLS version, as text (`TLSv1.3`).
pub const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
/// `PP2_SUBTYPE_SSL_CN`: the client certificate's Common Name.
pub const PP2_SUBTYPE_SSL_CN: u8 = 0x22;
/// `PP2_SUBTYPE_SSL_CIPHER`: the cipher suite name.
pub const PP2_SUBTYPE_SSL_CIPHER: u8 = 0x23;
/// `PP2_SUBTYPE_SSL_SIG_ALG`: the certificate signature algorithm.
pub const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24;
/// `PP2_SUBTYPE_SSL_KEY_ALG`: the certificate key algorithm.
pub const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25;
/// `PP2_TYPE_NETNS`: the network namespace name.
pub const PP2_TYPE_NETNS: u8 = 0x30;

/// [`Ssl::client`] flag: the client connected over TLS.
pub const PP2_CLIENT_SSL: u8 = 0x01;
/// [`Ssl::client`] flag: the client sent a certificate on this connection.
pub const PP2_CLIENT_CERT_CONN: u8 = 0x02;
/// [`Ssl::client`] flag: the client sent a certificate in this TLS session.
pub const PP2_CLIENT_CERT_SESS: u8 = 0x04;

/// One type-length-value extension. Values are at most 65 535 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tlv {
    /// The type byte (`PP2_TYPE_*`).
    pub kind: u8,
    /// The value bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// A TLV from its type and value.
    #[must_use]
    pub fn new(kind: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

/// Decodes a sequence of TLVs that fills `bytes` exactly.
pub(crate) fn decode_all(mut bytes: &[u8]) -> Result<Vec<Tlv>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let [kind, hi, lo, rest @ ..] = bytes else {
            return Err(Error::TruncatedTlv);
        };
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        let (value, rest) = rest.split_at_checked(len).ok_or(Error::TruncatedTlv)?;
        out.push(Tlv::new(*kind, value));
        bytes = rest;
    }
    Ok(out)
}

/// Appends `tlvs` to `out` in wire form.
pub(crate) fn encode_all(tlvs: &[Tlv], out: &mut Vec<u8>) -> Result<(), Error> {
    for tlv in tlvs {
        let len = u16::try_from(tlv.value.len()).map_err(|_| Error::TooLong("TLV value"))?;
        out.push(tlv.kind);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&tlv.value);
    }
    Ok(())
}

/// The `PP2_TYPE_SSL` TLV: TLS details of the client connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Ssl {
    /// Bit field of `PP2_CLIENT_*` flags.
    pub client: u8,
    /// Zero if the client certificate was verified successfully.
    pub verify: u32,
    /// Sub-TLVs (`PP2_SUBTYPE_SSL_*`), in wire order.
    pub sub_tlvs: Vec<Tlv>,
}

impl Ssl {
    /// An SSL TLV from its flags and verification result, with no sub-TLVs.
    #[must_use]
    pub const fn new(client: u8, verify: u32) -> Self {
        Self {
            client,
            verify,
            sub_tlvs: Vec::new(),
        }
    }

    /// Appends a sub-TLV.
    #[must_use]
    pub fn with_sub_tlv(mut self, tlv: Tlv) -> Self {
        self.sub_tlvs.push(tlv);
        self
    }

    /// Decodes the value of a `PP2_TYPE_SSL` TLV.
    ///
    /// # Errors
    ///
    /// [`Error::TruncatedTlv`] if the value is shorter than 5 bytes or a
    /// sub-TLV is truncated.
    pub fn decode(value: &[u8]) -> Result<Self, Error> {
        let [client, v0, v1, v2, v3, rest @ ..] = value else {
            return Err(Error::TruncatedTlv);
        };
        Ok(Self {
            client: *client,
            verify: u32::from_be_bytes([*v0, *v1, *v2, *v3]),
            sub_tlvs: decode_all(rest)?,
        })
    }

    /// Encodes this structure as a complete `PP2_TYPE_SSL` TLV.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a sub-TLV value does not fit its length field.
    pub fn to_tlv(&self) -> Result<Tlv, Error> {
        let mut value = vec![self.client];
        value.extend_from_slice(&self.verify.to_be_bytes());
        encode_all(&self.sub_tlvs, &mut value)?;
        Ok(Tlv::new(PP2_TYPE_SSL, value))
    }

    /// Whether the client connected over TLS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.client & PP2_CLIENT_SSL != 0
    }

    /// Whether a client certificate was presented and verified.
    #[must_use]
    pub const fn client_cert_verified(&self) -> bool {
        self.client & (PP2_CLIENT_CERT_CONN | PP2_CLIENT_CERT_SESS) != 0 && self.verify == 0
    }

    fn text(&self, kind: u8) -> Option<&str> {
        self.sub_tlvs
            .iter()
            .find(|t| t.kind == kind)
            .and_then(|t| std::str::from_utf8(&t.value).ok())
    }

    /// The TLS version (`PP2_SUBTYPE_SSL_VERSION`), e.g. `TLSv1.3`.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.text(PP2_SUBTYPE_SSL_VERSION)
    }

    /// The client certificate's Common Name (`PP2_SUBTYPE_SSL_CN`).
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.text(PP2_SUBTYPE_SSL_CN)
    }

    /// The cipher suite (`PP2_SUBTYPE_SSL_CIPHER`).
    #[must_use]
    pub fn cipher(&self) -> Option<&str> {
        self.text(PP2_SUBTYPE_SSL_CIPHER)
    }

    /// The certificate signature algorithm (`PP2_SUBTYPE_SSL_SIG_ALG`).
    #[must_use]
    pub fn signature_algorithm(&self) -> Option<&str> {
        self.text(PP2_SUBTYPE_SSL_SIG_ALG)
    }

    /// The certificate key algorithm (`PP2_SUBTYPE_SSL_KEY_ALG`).
    #[must_use]
    pub fn key_algorithm(&self) -> Option<&str> {
        self.text(PP2_SUBTYPE_SSL_KEY_ALG)
    }
}

/// CRC32C (Castagnoli, reflected polynomial `0x82F63B78`) of `data`, as used
/// by `PP2_TYPE_CRC32C`.
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_answers() {
        // RFC 3720 appendix B.4 and the classic check value.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFF; 32]), 0x62A8_AB43);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn tlv_sequence_round_trips() {
        let tlvs = vec![Tlv::new(1, b"h2".to_vec()), Tlv::new(4, Vec::new())];
        let mut bytes = Vec::new();
        encode_all(&tlvs, &mut bytes).unwrap();
        assert_eq!(bytes, b"\x01\x00\x02h2\x04\x00\x00");
        assert_eq!(decode_all(&bytes).unwrap(), tlvs);
    }

    #[test]
    fn truncated_tlvs_are_rejected() {
        assert!(matches!(decode_all(b"\x01\x00"), Err(Error::TruncatedTlv)));
        assert!(matches!(
            decode_all(b"\x01\x00\x03h2"),
            Err(Error::TruncatedTlv)
        ));
    }

    #[test]
    fn oversized_tlv_is_rejected() {
        let tlv = Tlv::new(1, vec![0; 65_536]);
        assert!(matches!(
            encode_all(&[tlv], &mut Vec::new()),
            Err(Error::TooLong(_))
        ));
    }

    #[test]
    fn ssl_round_trips_and_exposes_fields() {
        let ssl = Ssl::new(PP2_CLIENT_SSL | PP2_CLIENT_CERT_CONN, 0)
            .with_sub_tlv(Tlv::new(PP2_SUBTYPE_SSL_VERSION, b"TLSv1.3".to_vec()))
            .with_sub_tlv(Tlv::new(PP2_SUBTYPE_SSL_CN, b"client.example".to_vec()))
            .with_sub_tlv(Tlv::new(
                PP2_SUBTYPE_SSL_CIPHER,
                b"TLS_AES_128_GCM_SHA256".to_vec(),
            ))
            .with_sub_tlv(Tlv::new(PP2_SUBTYPE_SSL_SIG_ALG, b"SHA256".to_vec()))
            .with_sub_tlv(Tlv::new(PP2_SUBTYPE_SSL_KEY_ALG, b"RSA2048".to_vec()));
        let tlv = ssl.to_tlv().unwrap();
        assert_eq!(tlv.kind, PP2_TYPE_SSL);
        let back = Ssl::decode(&tlv.value).unwrap();
        assert_eq!(back, ssl);
        assert!(back.is_tls());
        assert!(back.client_cert_verified());
        assert_eq!(back.version(), Some("TLSv1.3"));
        assert_eq!(back.common_name(), Some("client.example"));
        assert_eq!(back.cipher(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(back.signature_algorithm(), Some("SHA256"));
        assert_eq!(back.key_algorithm(), Some("RSA2048"));
        assert!(matches!(Ssl::decode(b"\x01\0\0"), Err(Error::TruncatedTlv)));
    }
}

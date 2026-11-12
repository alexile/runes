//! Hello extensions ([RFC 8446 §4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2)).
//!
//! An [`Extension`] keeps its raw bytes, so hellos re-encode exactly and
//! unknown or GREASE extensions pass through untouched. [`Extension::decode`]
//! gives the typed view of the extensions this crate knows.

use std::collections::HashSet;

use crate::codec::{Reader, put_u16, put_vec8, put_vec16, u16_body};
use crate::{Error, ExtensionType, NamedGroup, ProtocolVersion, SignatureScheme};

/// Which message an extension appears in. Some extensions have a different
/// body in each (`supported_versions`, `key_share`, `server_name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HelloKind {
    /// A `ClientHello`.
    ClientHello,
    /// A `ServerHello` that is not a `HelloRetryRequest`.
    ServerHello,
    /// A TLS 1.3 `HelloRetryRequest` (a `ServerHello` with the special random).
    HelloRetryRequest,
}

/// One extension: its type and raw body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Extension {
    /// The extension type.
    pub extension_type: ExtensionType,
    /// The body (`extension_data`), without the length prefix.
    pub data: Vec<u8>,
}

/// One entry of the `server_name` extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServerName {
    /// `NameType`; 0 is `host_name`, the only registered type.
    pub name_type: u8,
    /// The name as sent.
    pub name: Vec<u8>,
}

impl ServerName {
    /// The `host_name` name type.
    pub const HOST_NAME: u8 = 0;

    /// The name as text, if this is a `host_name` entry in UTF-8. The name
    /// is not checked to be a valid DNS name.
    #[must_use]
    pub fn host_name(&self) -> Option<&str> {
        if self.name_type == Self::HOST_NAME {
            std::str::from_utf8(&self.name).ok()
        } else {
            None
        }
    }
}

/// One `KeyShareEntry`: a group and the public key share for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KeyShareEntry {
    /// The group the key belongs to.
    pub group: NamedGroup,
    /// The public key, opaque to this crate.
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    /// An entry with the given parts.
    #[must_use]
    pub const fn new(group: NamedGroup, key_exchange: Vec<u8>) -> Self {
        Self {
            group,
            key_exchange,
        }
    }
}

/// The decoded body of a known extension ([`Extension::decode`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtensionData {
    /// `server_name` in a `ClientHello`: the names, in order.
    ServerNames(Vec<ServerName>),
    /// `supported_groups`, in preference order.
    SupportedGroups(Vec<NamedGroup>),
    /// `ec_point_formats`.
    EcPointFormats(Vec<u8>),
    /// `signature_algorithms`, in preference order.
    SignatureAlgorithms(Vec<SignatureScheme>),
    /// `signature_algorithms_cert`, in preference order.
    SignatureAlgorithmsCert(Vec<SignatureScheme>),
    /// `application_layer_protocol_negotiation`: the protocol names. A
    /// `ServerHello` holds exactly the one it selected.
    Alpn(Vec<Vec<u8>>),
    /// `supported_versions` in a `ClientHello`: the offered versions.
    SupportedVersions(Vec<ProtocolVersion>),
    /// `supported_versions` in a `ServerHello` or `HelloRetryRequest`: the
    /// selected version.
    SelectedVersion(ProtocolVersion),
    /// `key_share` in a `ClientHello`: the offered shares.
    KeyShares(Vec<KeyShareEntry>),
    /// `key_share` in a `ServerHello`: the server's share.
    KeyShare(KeyShareEntry),
    /// `key_share` in a `HelloRetryRequest`: the group the server wants.
    KeyShareRequest(NamedGroup),
    /// `renegotiation_info`: the `renegotiated_connection` bytes (empty on
    /// an initial handshake).
    RenegotiationInfo(Vec<u8>),
    /// A known extension whose body is empty in this message, such as
    /// `extended_master_secret`, or `server_name` in a `ServerHello`.
    Empty,
}

impl Extension {
    /// An extension with a raw body, for anything the typed constructors
    /// do not cover: GREASE, padding, or deliberately malformed bodies.
    #[must_use]
    pub const fn new(extension_type: ExtensionType, data: Vec<u8>) -> Self {
        Self {
            extension_type,
            data,
        }
    }

    /// An extension with an empty body, such as `extended_master_secret`.
    #[must_use]
    pub const fn empty(extension_type: ExtensionType) -> Self {
        Self::new(extension_type, Vec::new())
    }

    /// `server_name` holding one `host_name`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if the name does not fit the length prefixes.
    pub fn server_name(host: &str) -> Result<Self, Error> {
        let mut entry = vec![ServerName::HOST_NAME];
        put_vec16(&mut entry, host.as_bytes(), "server name")?;
        let mut data = Vec::new();
        put_vec16(&mut data, &entry, "server name list")?;
        Ok(Self::new(ExtensionType::SERVER_NAME, data))
    }

    /// `application_layer_protocol_negotiation` with the given protocol
    /// names, such as `b"h2"` and `b"http/1.1"`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a name or the list does not fit its length
    /// prefix.
    pub fn alpn<P: AsRef<[u8]>>(protocols: impl IntoIterator<Item = P>) -> Result<Self, Error> {
        let mut list = Vec::new();
        for protocol in protocols {
            put_vec8(&mut list, protocol.as_ref(), "ALPN protocol name")?;
        }
        let mut data = Vec::new();
        put_vec16(&mut data, &list, "ALPN protocol list")?;
        Ok(Self::new(ExtensionType::ALPN, data))
    }

    /// `supported_versions` as a client sends it: the offered versions.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] for more than 127 versions.
    pub fn supported_versions(versions: &[ProtocolVersion]) -> Result<Self, Error> {
        let mut data = Vec::new();
        put_vec8(
            &mut data,
            &u16_body(versions.iter().map(|v| v.0)),
            "supported versions",
        )?;
        Ok(Self::new(ExtensionType::SUPPORTED_VERSIONS, data))
    }

    /// `supported_versions` as a server sends it: the selected version.
    #[must_use]
    pub fn selected_version(version: ProtocolVersion) -> Self {
        Self::new(
            ExtensionType::SUPPORTED_VERSIONS,
            version.0.to_be_bytes().to_vec(),
        )
    }

    /// `supported_groups`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if the list does not fit its length prefix.
    pub fn supported_groups(groups: &[NamedGroup]) -> Result<Self, Error> {
        Self::u16_list(
            ExtensionType::SUPPORTED_GROUPS,
            groups.iter().map(|g| g.0),
            "supported groups",
        )
    }

    /// `signature_algorithms`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if the list does not fit its length prefix.
    pub fn signature_algorithms(schemes: &[SignatureScheme]) -> Result<Self, Error> {
        Self::u16_list(
            ExtensionType::SIGNATURE_ALGORITHMS,
            schemes.iter().map(|s| s.0),
            "signature algorithms",
        )
    }

    /// `ec_point_formats`; `[0]` is `uncompressed`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] for more than 255 formats.
    pub fn ec_point_formats(formats: &[u8]) -> Result<Self, Error> {
        let mut data = Vec::new();
        put_vec8(&mut data, formats, "EC point formats")?;
        Ok(Self::new(ExtensionType::EC_POINT_FORMATS, data))
    }

    /// `key_share` as a client sends it.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a key or the list does not fit its length
    /// prefix.
    pub fn key_shares(entries: &[KeyShareEntry]) -> Result<Self, Error> {
        let mut list = Vec::new();
        for entry in entries {
            encode_key_share(&mut list, entry)?;
        }
        let mut data = Vec::new();
        put_vec16(&mut data, &list, "key share list")?;
        Ok(Self::new(ExtensionType::KEY_SHARE, data))
    }

    /// `key_share` as a server sends it in a `ServerHello`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if the key does not fit its length prefix.
    pub fn key_share(entry: &KeyShareEntry) -> Result<Self, Error> {
        let mut data = Vec::new();
        encode_key_share(&mut data, entry)?;
        Ok(Self::new(ExtensionType::KEY_SHARE, data))
    }

    /// `key_share` as a server sends it in a `HelloRetryRequest`.
    #[must_use]
    pub fn key_share_request(group: NamedGroup) -> Self {
        Self::new(ExtensionType::KEY_SHARE, group.0.to_be_bytes().to_vec())
    }

    /// `renegotiation_info`; pass `&[]` on an initial handshake.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] for more than 255 bytes.
    pub fn renegotiation_info(renegotiated_connection: &[u8]) -> Result<Self, Error> {
        let mut data = Vec::new();
        put_vec8(&mut data, renegotiated_connection, "renegotiation info")?;
        Ok(Self::new(ExtensionType::RENEGOTIATION_INFO, data))
    }

    fn u16_list(
        extension_type: ExtensionType,
        values: impl IntoIterator<Item = u16>,
        what: &'static str,
    ) -> Result<Self, Error> {
        let mut data = Vec::new();
        put_vec16(&mut data, &u16_body(values), what)?;
        Ok(Self::new(extension_type, data))
    }

    /// Decodes the body of a known extension as it appears in `kind`.
    ///
    /// Returns `Ok(None)` for extension types without a typed form here;
    /// their bytes are in [`Extension::data`].
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], [`Error::TrailingBytes`] or
    /// [`Error::Malformed`] if the body does not match the extension's
    /// format.
    pub fn decode(&self, kind: HelloKind) -> Result<Option<ExtensionData>, Error> {
        let mut r = Reader::new(&self.data);
        let client = kind == HelloKind::ClientHello;
        let data = match self.extension_type {
            ExtensionType::SERVER_NAME if client => {
                let mut list = r.vec16("server name list")?;
                let mut names = Vec::new();
                while !list.is_empty() {
                    let name_type = list.u8("server name")?;
                    let name = list.vec16("server name")?.rest().to_vec();
                    names.push(ServerName { name_type, name });
                }
                ExtensionData::ServerNames(names)
            }
            ExtensionType::SERVER_NAME
            | ExtensionType::EXTENDED_MASTER_SECRET
            | ExtensionType::ENCRYPT_THEN_MAC => ExtensionData::Empty,
            ExtensionType::SUPPORTED_GROUPS => ExtensionData::SupportedGroups(
                r.vec16("supported groups")?
                    .u16_list("supported groups")?
                    .into_iter()
                    .map(NamedGroup)
                    .collect(),
            ),
            ExtensionType::EC_POINT_FORMATS => {
                ExtensionData::EcPointFormats(r.vec8("EC point formats")?.rest().to_vec())
            }
            ExtensionType::SIGNATURE_ALGORITHMS => {
                ExtensionData::SignatureAlgorithms(signature_schemes(&mut r)?)
            }
            ExtensionType::SIGNATURE_ALGORITHMS_CERT => {
                ExtensionData::SignatureAlgorithmsCert(signature_schemes(&mut r)?)
            }
            ExtensionType::ALPN => {
                let mut list = r.vec16("ALPN protocol list")?;
                let mut protocols = Vec::new();
                while !list.is_empty() {
                    protocols.push(list.vec8("ALPN protocol name")?.rest().to_vec());
                }
                ExtensionData::Alpn(protocols)
            }
            ExtensionType::SUPPORTED_VERSIONS if client => ExtensionData::SupportedVersions(
                r.vec8("supported versions")?
                    .u16_list("supported versions")?
                    .into_iter()
                    .map(ProtocolVersion)
                    .collect(),
            ),
            ExtensionType::SUPPORTED_VERSIONS => {
                ExtensionData::SelectedVersion(ProtocolVersion(r.u16("supported versions")?))
            }
            ExtensionType::KEY_SHARE => match kind {
                HelloKind::ClientHello => {
                    let mut list = r.vec16("key share list")?;
                    let mut entries = Vec::new();
                    while !list.is_empty() {
                        entries.push(decode_key_share(&mut list)?);
                    }
                    ExtensionData::KeyShares(entries)
                }
                HelloKind::ServerHello => ExtensionData::KeyShare(decode_key_share(&mut r)?),
                HelloKind::HelloRetryRequest => {
                    ExtensionData::KeyShareRequest(NamedGroup(r.u16("key share")?))
                }
            },
            ExtensionType::RENEGOTIATION_INFO => {
                ExtensionData::RenegotiationInfo(r.vec8("renegotiation info")?.rest().to_vec())
            }
            _ => return Ok(None),
        };
        r.finish(self.extension_type.name().unwrap_or("extension"))?;
        Ok(Some(data))
    }
}

fn signature_schemes(r: &mut Reader<'_>) -> Result<Vec<SignatureScheme>, Error> {
    Ok(r.vec16("signature algorithms")?
        .u16_list("signature algorithms")?
        .into_iter()
        .map(SignatureScheme)
        .collect())
}

fn decode_key_share(r: &mut Reader<'_>) -> Result<KeyShareEntry, Error> {
    let group = NamedGroup(r.u16("key share entry")?);
    let key_exchange = r.vec16("key share entry")?.rest().to_vec();
    Ok(KeyShareEntry::new(group, key_exchange))
}

fn encode_key_share(out: &mut Vec<u8>, entry: &KeyShareEntry) -> Result<(), Error> {
    put_u16(out, entry.group.0);
    put_vec16(out, &entry.key_exchange, "key exchange")
}

/// Reads the optional extension block that ends a hello. Each extension
/// must be unique and, if known, well formed for `kind`.
pub fn parse_block(r: &mut Reader<'_>, kind: HelloKind) -> Result<Option<Vec<Extension>>, Error> {
    if r.is_empty() {
        return Ok(None);
    }
    let mut block = r.vec16("extensions")?;
    let mut seen = HashSet::new();
    let mut extensions = Vec::new();
    while !block.is_empty() {
        let extension_type = ExtensionType(block.u16("extension")?);
        let data = block.vec16("extension")?.rest().to_vec();
        if !seen.insert(extension_type) {
            return Err(Error::DuplicateExtension(extension_type));
        }
        let extension = Extension::new(extension_type, data);
        extension.decode(kind)?;
        extensions.push(extension);
    }
    Ok(Some(extensions))
}

/// Appends the extension block, if any.
pub fn encode_block(out: &mut Vec<u8>, extensions: Option<&[Extension]>) -> Result<(), Error> {
    let Some(extensions) = extensions else {
        return Ok(());
    };
    let mut block = Vec::new();
    for extension in extensions {
        put_u16(&mut block, extension.extension_type.0);
        put_vec16(&mut block, &extension.data, "extension")?;
    }
    put_vec16(out, &block, "extensions")
}

/// The decoded body of the first extension of `extension_type`, if it is
/// present and well formed.
pub fn find_decoded(
    extensions: &[Extension],
    extension_type: ExtensionType,
    kind: HelloKind,
) -> Option<ExtensionData> {
    extensions
        .iter()
        .find(|e| e.extension_type == extension_type)
        .and_then(|e| e.decode(kind).ok().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_constructors_decode_back() {
        let sni = Extension::server_name("example.com").unwrap();
        let Ok(Some(ExtensionData::ServerNames(names))) = sni.decode(HelloKind::ClientHello) else {
            panic!("server_name decodes");
        };
        assert_eq!(
            names.first().and_then(ServerName::host_name),
            Some("example.com")
        );
        assert_eq!(
            sni.decode(HelloKind::ServerHello),
            Err(Error::TrailingBytes {
                what: "server_name",
                count: 16
            })
        );

        let alpn = Extension::alpn(["h2", "http/1.1"]).unwrap();
        assert_eq!(
            alpn.decode(HelloKind::ClientHello),
            Ok(Some(ExtensionData::Alpn(vec![
                b"h2".to_vec(),
                b"http/1.1".to_vec()
            ])))
        );

        let versions =
            Extension::supported_versions(&[ProtocolVersion::TLS_1_3, ProtocolVersion::TLS_1_2])
                .unwrap();
        assert_eq!(versions.data, [4, 3, 4, 3, 3]);
        assert_eq!(
            Extension::selected_version(ProtocolVersion::TLS_1_3).decode(HelloKind::ServerHello),
            Ok(Some(ExtensionData::SelectedVersion(
                ProtocolVersion::TLS_1_3
            )))
        );

        let share = KeyShareEntry::new(NamedGroup::X25519, vec![9; 32]);
        assert_eq!(
            Extension::key_share(&share)
                .unwrap()
                .decode(HelloKind::ServerHello),
            Ok(Some(ExtensionData::KeyShare(share.clone())))
        );
        assert_eq!(
            Extension::key_shares(std::slice::from_ref(&share))
                .unwrap()
                .decode(HelloKind::ClientHello),
            Ok(Some(ExtensionData::KeyShares(vec![share])))
        );
        assert_eq!(
            Extension::key_share_request(NamedGroup::SECP256R1)
                .decode(HelloKind::HelloRetryRequest),
            Ok(Some(ExtensionData::KeyShareRequest(NamedGroup::SECP256R1)))
        );
        assert_eq!(Extension::renegotiation_info(&[]).unwrap().data, [0]);
        assert_eq!(
            Extension::new(ExtensionType::PADDING, vec![0; 3]).decode(HelloKind::ClientHello),
            Ok(None)
        );
    }

    #[test]
    fn malformed_bodies_are_errors() {
        let odd = Extension::new(ExtensionType::SUPPORTED_GROUPS, vec![0, 3, 0, 29, 0]);
        assert!(matches!(
            odd.decode(HelloKind::ClientHello),
            Err(Error::Malformed { .. })
        ));
        let ems = Extension::new(ExtensionType::EXTENDED_MASTER_SECRET, vec![1]);
        assert!(ems.decode(HelloKind::ClientHello).is_err());
        let short = Extension::new(ExtensionType::ALPN, vec![0, 3, 2, b'h']);
        assert!(short.decode(HelloKind::ClientHello).is_err());
    }
}

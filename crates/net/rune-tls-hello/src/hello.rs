//! `ClientHello` ([RFC 8446 §4.1.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2),
//! [RFC 5246 §7.4.1.2](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2))
//! and `ServerHello` ([RFC 8446 §4.1.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3),
//! [RFC 5246 §7.4.1.3](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3)).

use crate::codec::{Reader, put_u16, put_vec8, put_vec16, u16_body};
use crate::extension::{encode_block, find_decoded, parse_block};
use crate::handshake::{encode_message, first_message, parse_message_header};
use crate::{
    CipherSuite, ContentType, Error, Extension, ExtensionData, ExtensionType, HandshakeType,
    HelloKind, KeyShareEntry, NamedGroup, ProtocolVersion, SignatureScheme, encode_records,
};

/// Longest `legacy_session_id` the RFCs allow.
pub const MAX_SESSION_ID_LEN: usize = 32;

/// The `random` of a `ServerHello` that is really a TLS 1.3
/// `HelloRetryRequest`: SHA-256 of `"HelloRetryRequest"`
/// ([RFC 8446 §4.1.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3)).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// `"DOWNGRD"`, the start of a downgrade sentinel.
const DOWNGRADE_PREFIX: &[u8; 7] = b"DOWNGRD";

/// A `ClientHello`.
///
/// Fields hold the message exactly as sent, in wire order, including
/// GREASE values, so [`ClientHello::to_body`] re-encodes a parsed hello to
/// the same bytes. Start a hello to send from [`ClientHello::new`] and the
/// `with_*` methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ClientHello {
    /// `legacy_version` (`client_version` before TLS 1.3). TLS 1.3 clients
    /// send TLS 1.2 here and list their versions in `supported_versions`;
    /// see [`ClientHello::max_version`].
    pub legacy_version: ProtocolVersion,
    /// The 32-byte client random.
    pub random: [u8; 32],
    /// `legacy_session_id`, at most 32 bytes.
    pub session_id: Vec<u8>,
    /// Offered cipher suites, in preference order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Offered compression methods; `[0]` (null) in any modern client.
    pub compression_methods: Vec<u8>,
    /// The extensions in wire order, or `None` when the hello has no
    /// extension block at all (some SSL 3.0 and TLS 1.0 clients).
    pub extensions: Option<Vec<Extension>>,
}

impl Default for ClientHello {
    fn default() -> Self {
        Self {
            legacy_version: ProtocolVersion::TLS_1_2,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suites: Vec::new(),
            compression_methods: vec![0],
            extensions: Some(Vec::new()),
        }
    }
}

impl ClientHello {
    /// An empty hello: `legacy_version` TLS 1.2, an all-zero random, no
    /// session id, no cipher suites, null compression and an empty
    /// extension block.
    ///
    /// Set a real random with [`ClientHello::with_random`] before sending
    /// it; this crate does no cryptography and has no random source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `legacy_version`.
    #[must_use]
    pub const fn with_legacy_version(mut self, version: ProtocolVersion) -> Self {
        self.legacy_version = version;
        self
    }

    /// Sets the client random.
    #[must_use]
    pub const fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = random;
        self
    }

    /// Sets `legacy_session_id`.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<Vec<u8>>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Replaces the cipher suites.
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: impl IntoIterator<Item = CipherSuite>) -> Self {
        self.cipher_suites = suites.into_iter().collect();
        self
    }

    /// Replaces the compression methods.
    #[must_use]
    pub fn with_compression_methods(mut self, methods: impl Into<Vec<u8>>) -> Self {
        self.compression_methods = methods.into();
        self
    }

    /// Appends an extension, creating the extension block if there is
    /// none. Order is kept, and duplicates are not checked here (a peer
    /// should reject them, which is sometimes the point of a probe).
    #[must_use]
    pub fn with_extension(mut self, extension: Extension) -> Self {
        self.extensions.get_or_insert_with(Vec::new).push(extension);
        self
    }

    /// Replaces the extensions with `extensions`.
    #[must_use]
    pub fn with_extensions(mut self, extensions: impl IntoIterator<Item = Extension>) -> Self {
        self.extensions = Some(extensions.into_iter().collect());
        self
    }

    /// Removes the extension block entirely, as an SSL 3.0 client would.
    #[must_use]
    pub fn without_extensions(mut self) -> Self {
        self.extensions = None;
        self
    }

    /// Parses a `ClientHello` body: the handshake message without its
    /// four-byte header.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], [`Error::TrailingBytes`],
    /// [`Error::Malformed`], [`Error::TooLong`] (session id) or
    /// [`Error::DuplicateExtension`] if the body is not a well-formed
    /// `ClientHello`. Known extensions must have well-formed bodies.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let legacy_version = ProtocolVersion(r.u16("client hello")?);
        let random = r.array("client hello random")?;
        let session_id = session_id(&mut r)?;
        let cipher_suites = r
            .vec16("cipher suites")?
            .u16_list("cipher suites")?
            .into_iter()
            .map(CipherSuite)
            .collect();
        let compression_methods = r.vec8("compression methods")?.rest().to_vec();
        let extensions = parse_block(&mut r, HelloKind::ClientHello)?;
        r.finish("client hello")?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Parses a complete `ClientHello` handshake message, header included.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::parse`], plus [`Error::UnexpectedHandshakeType`]
    /// for another message type, [`Error::Incomplete`] if `message` is
    /// shorter than its header says, and [`Error::TrailingBytes`] if longer.
    pub fn parse_message(message: &[u8]) -> Result<Self, Error> {
        let body = parse_message_header(message, HandshakeType::CLIENT_HELLO)?;
        Self::parse(body)
    }

    /// Parses the `ClientHello` at the start of a TLS byte stream, such as
    /// the first bytes a client sends to a server or proxy. The hello may
    /// span several records; bytes after it are ignored.
    ///
    /// This is the call for SNI routing: peek at the stream until it
    /// returns something other than [`Error::Incomplete`].
    ///
    /// # Errors
    ///
    /// [`Error::Incomplete`] if more bytes are needed; the record errors
    /// of [`crate::Record::parse`]; [`Error::UnexpectedContentType`] or
    /// [`Error::UnexpectedHandshakeType`] if the stream does not start with
    /// a `ClientHello`; [`Error::TooLong`] if the message exceeds
    /// [`crate::DEFAULT_MAX_HANDSHAKE_LEN`]; and the errors of
    /// [`ClientHello::parse`].
    pub fn parse_records(stream: &[u8]) -> Result<Self, Error> {
        let body = first_message(stream, HandshakeType::CLIENT_HELLO)?;
        Self::parse(&body)
    }

    /// The encoded body (the message without its handshake header).
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a field does not fit its length prefix.
    pub fn to_body(&self) -> Result<Vec<u8>, Error> {
        if self.session_id.len() > MAX_SESSION_ID_LEN {
            return Err(session_id_too_long(self.session_id.len()));
        }
        let mut out = Vec::new();
        put_u16(&mut out, self.legacy_version.0);
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id, "session id")?;
        put_vec16(
            &mut out,
            &u16_body(self.cipher_suites.iter().map(|c| c.0)),
            "cipher suites",
        )?;
        put_vec8(&mut out, &self.compression_methods, "compression methods")?;
        encode_block(&mut out, self.extensions.as_deref())?;
        Ok(out)
    }

    /// The encoded handshake message, header included.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::to_body`].
    pub fn to_message(&self) -> Result<Vec<u8>, Error> {
        encode_message(HandshakeType::CLIENT_HELLO, &self.to_body()?)
    }

    /// The hello as handshake records, ready to write to a socket. Use
    /// TLS 1.0 as `record_version` for the widest compatibility (what most
    /// clients send), or SSL 3.0 to probe SSL 3.0 servers. The message is
    /// split into records of at most `max_fragment_len` bytes.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::to_body`].
    pub fn to_records(
        &self,
        record_version: ProtocolVersion,
        max_fragment_len: usize,
    ) -> Result<Vec<u8>, Error> {
        encode_records(
            ContentType::HANDSHAKE,
            record_version,
            &self.to_message()?,
            max_fragment_len,
        )
    }

    /// The extensions in wire order; empty if there is no extension block.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.as_deref().unwrap_or_default()
    }

    /// The extension of the given type, if present.
    #[must_use]
    pub fn extension(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.extensions()
            .iter()
            .find(|e| e.extension_type == extension_type)
    }

    /// The extension types in wire order, GREASE included.
    pub fn extension_types(&self) -> impl Iterator<Item = ExtensionType> + '_ {
        self.extensions().iter().map(|e| e.extension_type)
    }

    fn decoded(&self, extension_type: ExtensionType) -> Option<ExtensionData> {
        find_decoded(self.extensions(), extension_type, HelloKind::ClientHello)
    }

    /// The first `host_name` in `server_name` (SNI), if any and if it is
    /// UTF-8. Not checked to be a valid DNS name.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        let extension = self.extension(ExtensionType::SERVER_NAME)?;
        let mut list = Reader::new(&extension.data)
            .vec16("server name list")
            .ok()?;
        while !list.is_empty() {
            let name_type = list.u8("server name").ok()?;
            let name = list.vec16("server name").ok()?.rest();
            if name_type == crate::ServerName::HOST_NAME {
                return std::str::from_utf8(name).ok();
            }
        }
        None
    }

    /// The ALPN protocol names, in preference order.
    #[must_use]
    pub fn alpn_protocols(&self) -> Option<Vec<Vec<u8>>> {
        match self.decoded(ExtensionType::ALPN)? {
            ExtensionData::Alpn(protocols) => Some(protocols),
            _ => None,
        }
    }

    /// The versions in `supported_versions`, in wire order.
    #[must_use]
    pub fn supported_versions(&self) -> Option<Vec<ProtocolVersion>> {
        match self.decoded(ExtensionType::SUPPORTED_VERSIONS)? {
            ExtensionData::SupportedVersions(versions) => Some(versions),
            _ => None,
        }
    }

    /// The groups in `supported_groups`, in wire order.
    #[must_use]
    pub fn supported_groups(&self) -> Option<Vec<NamedGroup>> {
        match self.decoded(ExtensionType::SUPPORTED_GROUPS)? {
            ExtensionData::SupportedGroups(groups) => Some(groups),
            _ => None,
        }
    }

    /// The schemes in `signature_algorithms`, in wire order.
    #[must_use]
    pub fn signature_algorithms(&self) -> Option<Vec<SignatureScheme>> {
        match self.decoded(ExtensionType::SIGNATURE_ALGORITHMS)? {
            ExtensionData::SignatureAlgorithms(schemes) => Some(schemes),
            _ => None,
        }
    }

    /// The formats in `ec_point_formats`, in wire order.
    #[must_use]
    pub fn ec_point_formats(&self) -> Option<Vec<u8>> {
        match self.decoded(ExtensionType::EC_POINT_FORMATS)? {
            ExtensionData::EcPointFormats(formats) => Some(formats),
            _ => None,
        }
    }

    /// The entries in `key_share`, in wire order.
    #[must_use]
    pub fn key_shares(&self) -> Option<Vec<KeyShareEntry>> {
        match self.decoded(ExtensionType::KEY_SHARE)? {
            ExtensionData::KeyShares(entries) => Some(entries),
            _ => None,
        }
    }

    /// The highest version offered: the largest non-GREASE entry of
    /// `supported_versions` if there is one, else `legacy_version`.
    #[must_use]
    pub fn max_version(&self) -> ProtocolVersion {
        self.supported_versions()
            .and_then(|versions| versions.into_iter().filter(|v| !v.is_grease()).max())
            .unwrap_or(self.legacy_version)
    }

    /// Whether `suite` is among the offered cipher suites.
    #[must_use]
    pub fn offers(&self, suite: CipherSuite) -> bool {
        self.cipher_suites.contains(&suite)
    }

    /// Whether the client signals a fallback connection with
    /// `TLS_FALLBACK_SCSV` ([RFC 7507](https://www.rfc-editor.org/rfc/rfc7507)).
    #[must_use]
    pub fn offers_fallback_scsv(&self) -> bool {
        self.offers(CipherSuite::TLS_FALLBACK_SCSV)
    }

    /// Whether the client signals secure renegotiation, by the SCSV or the
    /// `renegotiation_info` extension ([RFC 5746](https://www.rfc-editor.org/rfc/rfc5746)).
    #[must_use]
    pub fn offers_secure_renegotiation(&self) -> bool {
        self.offers(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            || self.extension(ExtensionType::RENEGOTIATION_INFO).is_some()
    }
}

/// A TLS 1.3 downgrade sentinel in a `ServerHello` random
/// ([RFC 8446 §4.1.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3)):
/// the server supports a higher version than it negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DowngradeSentinel {
    /// `DOWNGRD\x01`: TLS 1.2 negotiated by a TLS 1.3 server.
    Tls12,
    /// `DOWNGRD\x00`: TLS 1.1 or below negotiated by a TLS 1.2 or 1.3
    /// server.
    Tls11OrBelow,
}

/// A `ServerHello`, or a TLS 1.3 `HelloRetryRequest`, which shares its format.
///
/// As with [`ClientHello`], fields hold the message as sent and
/// [`ServerHello::to_body`] re-encodes a parsed hello exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServerHello {
    /// `legacy_version` (`server_version` before TLS 1.3); see
    /// [`ServerHello::selected_version`].
    pub legacy_version: ProtocolVersion,
    /// The 32-byte server random; [`HELLO_RETRY_REQUEST_RANDOM`] for a
    /// `HelloRetryRequest`.
    pub random: [u8; 32],
    /// `legacy_session_id_echo` (`session_id` before TLS 1.3).
    pub session_id: Vec<u8>,
    /// The selected cipher suite.
    pub cipher_suite: CipherSuite,
    /// The selected compression method; 0 is null, 1 is DEFLATE (which
    /// exposes the connection to CRIME).
    pub compression_method: u8,
    /// The extensions in wire order, or `None` without an extension block.
    pub extensions: Option<Vec<Extension>>,
}

impl Default for ServerHello {
    fn default() -> Self {
        Self {
            legacy_version: ProtocolVersion::TLS_1_2,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suite: CipherSuite(0),
            compression_method: 0,
            extensions: Some(Vec::new()),
        }
    }
}

impl ServerHello {
    /// A `ServerHello` with `legacy_version` TLS 1.2, an all-zero random, no
    /// session id, cipher suite `0x0000`, null compression and an empty
    /// extension block. Useful for tests and fake servers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `legacy_version`.
    #[must_use]
    pub const fn with_legacy_version(mut self, version: ProtocolVersion) -> Self {
        self.legacy_version = version;
        self
    }

    /// Sets the server random.
    #[must_use]
    pub const fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = random;
        self
    }

    /// Sets the session id.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<Vec<u8>>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Sets the cipher suite.
    #[must_use]
    pub const fn with_cipher_suite(mut self, suite: CipherSuite) -> Self {
        self.cipher_suite = suite;
        self
    }

    /// Sets the compression method.
    #[must_use]
    pub const fn with_compression_method(mut self, method: u8) -> Self {
        self.compression_method = method;
        self
    }

    /// Appends an extension, creating the extension block if needed.
    #[must_use]
    pub fn with_extension(mut self, extension: Extension) -> Self {
        self.extensions.get_or_insert_with(Vec::new).push(extension);
        self
    }

    /// Removes the extension block entirely.
    #[must_use]
    pub fn without_extensions(mut self) -> Self {
        self.extensions = None;
        self
    }

    /// Parses a `ServerHello` body: the handshake message without its
    /// four-byte header.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::parse`].
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let legacy_version = ProtocolVersion(r.u16("server hello")?);
        let random = r.array("server hello random")?;
        let session_id = session_id(&mut r)?;
        let cipher_suite = CipherSuite(r.u16("server hello")?);
        let compression_method = r.u8("server hello")?;
        let kind = kind_of(&random);
        let extensions = parse_block(&mut r, kind)?;
        r.finish("server hello")?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Parses a complete `ServerHello` handshake message, header included.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::parse_message`].
    pub fn parse_message(message: &[u8]) -> Result<Self, Error> {
        let body = parse_message_header(message, HandshakeType::SERVER_HELLO)?;
        Self::parse(body)
    }

    /// Parses the `ServerHello` at the start of a server's byte stream.
    /// Bytes after it (Certificate, …) are ignored. An alert in place of
    /// the hello gives [`Error::UnexpectedContentType`]; use
    /// [`crate::MessageReader`] to read the alert itself.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::parse_records`].
    pub fn parse_records(stream: &[u8]) -> Result<Self, Error> {
        let body = first_message(stream, HandshakeType::SERVER_HELLO)?;
        Self::parse(&body)
    }

    /// The encoded body (the message without its handshake header).
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a field does not fit its length prefix.
    pub fn to_body(&self) -> Result<Vec<u8>, Error> {
        if self.session_id.len() > MAX_SESSION_ID_LEN {
            return Err(session_id_too_long(self.session_id.len()));
        }
        let mut out = Vec::new();
        put_u16(&mut out, self.legacy_version.0);
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id, "session id")?;
        put_u16(&mut out, self.cipher_suite.0);
        out.push(self.compression_method);
        encode_block(&mut out, self.extensions.as_deref())?;
        Ok(out)
    }

    /// The encoded handshake message, header included.
    ///
    /// # Errors
    ///
    /// As [`ServerHello::to_body`].
    pub fn to_message(&self) -> Result<Vec<u8>, Error> {
        encode_message(HandshakeType::SERVER_HELLO, &self.to_body()?)
    }

    /// The hello as handshake records (see [`ClientHello::to_records`]).
    ///
    /// # Errors
    ///
    /// As [`ServerHello::to_body`].
    pub fn to_records(
        &self,
        record_version: ProtocolVersion,
        max_fragment_len: usize,
    ) -> Result<Vec<u8>, Error> {
        encode_records(
            ContentType::HANDSHAKE,
            record_version,
            &self.to_message()?,
            max_fragment_len,
        )
    }

    /// Whether this is a TLS 1.3 `HelloRetryRequest`.
    #[must_use]
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    /// [`HelloKind::HelloRetryRequest`] or [`HelloKind::ServerHello`].
    #[must_use]
    pub fn kind(&self) -> HelloKind {
        kind_of(&self.random)
    }

    /// The extensions in wire order; empty if there is no extension block.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        self.extensions.as_deref().unwrap_or_default()
    }

    /// The extension of the given type, if present.
    #[must_use]
    pub fn extension(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.extensions()
            .iter()
            .find(|e| e.extension_type == extension_type)
    }

    /// The extension types in wire order.
    pub fn extension_types(&self) -> impl Iterator<Item = ExtensionType> + '_ {
        self.extensions().iter().map(|e| e.extension_type)
    }

    fn decoded(&self, extension_type: ExtensionType) -> Option<ExtensionData> {
        find_decoded(self.extensions(), extension_type, self.kind())
    }

    /// The negotiated version: `supported_versions` if present (TLS 1.3),
    /// else `legacy_version`.
    #[must_use]
    pub fn selected_version(&self) -> ProtocolVersion {
        match self.decoded(ExtensionType::SUPPORTED_VERSIONS) {
            Some(ExtensionData::SelectedVersion(version)) => version,
            _ => self.legacy_version,
        }
    }

    /// The ALPN protocol the server selected.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        match self.decoded(ExtensionType::ALPN)? {
            ExtensionData::Alpn(protocols) => protocols.into_iter().next(),
            _ => None,
        }
    }

    /// The key-share group: the server's share in a `ServerHello`, the
    /// requested group in a `HelloRetryRequest`.
    #[must_use]
    pub fn key_share_group(&self) -> Option<NamedGroup> {
        match self.decoded(ExtensionType::KEY_SHARE)? {
            ExtensionData::KeyShare(entry) => Some(entry.group),
            ExtensionData::KeyShareRequest(group) => Some(group),
            _ => None,
        }
    }

    /// The downgrade sentinel in the last eight bytes of the random, if
    /// any.
    #[must_use]
    pub fn downgrade_sentinel(&self) -> Option<DowngradeSentinel> {
        let (prefix, last) = self.random.get(24..31).zip(self.random.get(31))?;
        if prefix != DOWNGRADE_PREFIX {
            return None;
        }
        match last {
            1 => Some(DowngradeSentinel::Tls12),
            0 => Some(DowngradeSentinel::Tls11OrBelow),
            _ => None,
        }
    }

    /// Whether the server confirms secure renegotiation with
    /// `renegotiation_info` ([RFC 5746](https://www.rfc-editor.org/rfc/rfc5746)).
    #[must_use]
    pub fn secure_renegotiation(&self) -> bool {
        self.extension(ExtensionType::RENEGOTIATION_INFO).is_some()
    }
}

fn kind_of(random: &[u8; 32]) -> HelloKind {
    if *random == HELLO_RETRY_REQUEST_RANDOM {
        HelloKind::HelloRetryRequest
    } else {
        HelloKind::ServerHello
    }
}

fn session_id(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
    let id = r.vec8("session id")?.rest();
    if id.len() > MAX_SESSION_ID_LEN {
        return Err(session_id_too_long(id.len()));
    }
    Ok(id.to_vec())
}

const fn session_id_too_long(len: usize) -> Error {
    Error::TooLong {
        what: "session id",
        len,
        max: MAX_SESSION_ID_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientHello {
        ClientHello::new()
            .with_random([7; 32])
            .with_session_id(vec![1; 32])
            .with_cipher_suites([
                CipherSuite(0x0a0a),
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ])
            .with_extension(Extension::new(ExtensionType(0x1a1a), Vec::new()))
            .with_extension(Extension::server_name("example.com").unwrap())
            .with_extension(Extension::alpn(["h2"]).unwrap())
            .with_extension(
                Extension::supported_versions(&[
                    ProtocolVersion(0x2a2a),
                    ProtocolVersion::TLS_1_3,
                    ProtocolVersion::TLS_1_2,
                ])
                .unwrap(),
            )
            .with_extension(Extension::supported_groups(&[NamedGroup::X25519]).unwrap())
            .with_extension(Extension::signature_algorithms(&[SignatureScheme::ED25519]).unwrap())
            .with_extension(Extension::ec_point_formats(&[0]).unwrap())
            .with_extension(
                Extension::key_shares(&[KeyShareEntry::new(NamedGroup::X25519, vec![5; 32])])
                    .unwrap(),
            )
    }

    #[test]
    fn client_hello_round_trip_and_accessors() {
        let hello = sample();
        let body = hello.to_body().unwrap();
        let parsed = ClientHello::parse(&body).unwrap();
        assert_eq!(parsed, hello);
        assert_eq!(parsed.server_name(), Some("example.com"));
        assert_eq!(parsed.alpn_protocols(), Some(vec![b"h2".to_vec()]));
        assert_eq!(parsed.max_version(), ProtocolVersion::TLS_1_3);
        assert_eq!(parsed.supported_groups(), Some(vec![NamedGroup::X25519]));
        assert_eq!(
            parsed.signature_algorithms(),
            Some(vec![SignatureScheme::ED25519])
        );
        assert_eq!(parsed.ec_point_formats(), Some(vec![0]));
        assert_eq!(parsed.key_shares().map(|k| k.len()), Some(1));
        assert!(parsed.offers_secure_renegotiation());
        assert!(!parsed.offers_fallback_scsv());
        assert_eq!(parsed.extension_types().count(), 8);

        let message = hello.to_message().unwrap();
        assert_eq!(ClientHello::parse_message(&message).unwrap(), hello);
        let records = hello.to_records(ProtocolVersion::TLS_1_0, 10).unwrap();
        assert_eq!(ClientHello::parse_records(&records).unwrap(), hello);
    }

    #[test]
    fn extension_block_presence_is_kept() {
        let bare = ClientHello::new()
            .with_legacy_version(ProtocolVersion::SSL_3_0)
            .with_cipher_suites([CipherSuite(0x000a)])
            .without_extensions();
        let body = bare.to_body().unwrap();
        assert_eq!(body.len(), 2 + 32 + 1 + 4 + 2);
        let parsed = ClientHello::parse(&body).unwrap();
        assert_eq!(parsed.extensions, None);
        assert_eq!(parsed.max_version(), ProtocolVersion::SSL_3_0);
        let empty = ClientHello::new();
        assert_eq!(
            ClientHello::parse(&empty.to_body().unwrap())
                .unwrap()
                .extensions,
            Some(Vec::new())
        );
    }

    #[test]
    fn client_hello_rejects_malformed_input() {
        let body = sample().to_body().unwrap();
        // Every prefix fails, except the one that drops the whole extension
        // block: that is a valid hello without extensions.
        let bare = sample().without_extensions().to_body().unwrap().len();
        for len in 0..body.len() {
            let parsed = ClientHello::parse(&body[..len]);
            assert_eq!(parsed.is_ok(), len == bare, "prefix {len}");
        }
        let mut long = body;
        long.push(0);
        assert!(ClientHello::parse(&long).is_err());

        let dup = sample()
            .with_extension(Extension::alpn(["h3"]).unwrap())
            .to_body()
            .unwrap();
        assert_eq!(
            ClientHello::parse(&dup),
            Err(Error::DuplicateExtension(ExtensionType::ALPN))
        );
        let big_id = sample().with_session_id(vec![0; 33]);
        assert!(matches!(big_id.to_body(), Err(Error::TooLong { .. })));
        let broken = sample()
            .with_extension(Extension::new(ExtensionType::SUPPORTED_VERSIONS, vec![1]))
            .with_extensions([Extension::new(ExtensionType::SUPPORTED_VERSIONS, vec![1])]);
        assert!(ClientHello::parse(&broken.to_body().unwrap()).is_err());
    }

    #[test]
    fn server_hello_round_trip_and_accessors() {
        let mut random = [3; 32];
        random[24..].copy_from_slice(b"DOWNGRD\x01");
        let hello = ServerHello::new()
            .with_random(random)
            .with_session_id(vec![9; 32])
            .with_cipher_suite(CipherSuite(0xc02f))
            .with_extension(Extension::renegotiation_info(&[]).unwrap())
            .with_extension(Extension::alpn(["h2"]).unwrap())
            .with_extension(Extension::empty(ExtensionType::SERVER_NAME));
        let parsed = ServerHello::parse(&hello.to_body().unwrap()).unwrap();
        assert_eq!(parsed, hello);
        assert_eq!(parsed.selected_version(), ProtocolVersion::TLS_1_2);
        assert_eq!(parsed.downgrade_sentinel(), Some(DowngradeSentinel::Tls12));
        assert_eq!(parsed.alpn_protocol(), Some(b"h2".to_vec()));
        assert!(parsed.secure_renegotiation());
        assert!(!parsed.is_hello_retry_request());
        assert_eq!(parsed.kind(), HelloKind::ServerHello);

        let tls13 = ServerHello::new()
            .with_random([1; 32])
            .with_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256)
            .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
            .with_extension(
                Extension::key_share(&KeyShareEntry::new(NamedGroup::X25519, vec![4; 32])).unwrap(),
            );
        let message = tls13.to_message().unwrap();
        let parsed = ServerHello::parse_message(&message).unwrap();
        assert_eq!(parsed.selected_version(), ProtocolVersion::TLS_1_3);
        assert_eq!(parsed.key_share_group(), Some(NamedGroup::X25519));
        assert_eq!(parsed.downgrade_sentinel(), None);
        assert_eq!(
            ClientHello::parse_message(&message),
            Err(Error::UnexpectedHandshakeType {
                expected: HandshakeType::CLIENT_HELLO,
                found: HandshakeType::SERVER_HELLO
            })
        );
    }

    #[test]
    fn hello_retry_request() {
        let hrr = ServerHello::new()
            .with_random(HELLO_RETRY_REQUEST_RANDOM)
            .with_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256)
            .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
            .with_extension(Extension::key_share_request(NamedGroup::SECP256R1));
        let parsed = ServerHello::parse(&hrr.to_body().unwrap()).unwrap();
        assert!(parsed.is_hello_retry_request());
        assert_eq!(parsed.key_share_group(), Some(NamedGroup::SECP256R1));
        // The two-byte HRR key_share body is not a valid ServerHello share.
        let not_hrr = hrr.with_random([0; 32]);
        assert!(ServerHello::parse(&not_hrr.to_body().unwrap()).is_err());
    }
}

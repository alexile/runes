//! NTLM over HTTP: the NEGOTIATE / CHALLENGE / AUTHENTICATE messages of
//! [MS-NLMP] §2.2.1, their `NTLM` / `Negotiate` header framing
//! ([MS-NTHT]), and the `NTLMv2` response computation of [MS-NLMP] §3.3.2.
//!
//! Sans-I/O: the caller supplies the client challenge and the timestamp.
//! SPNEGO-wrapped (Kerberos) `Negotiate` tokens are not decoded; message
//! integrity (MIC) and session security are not computed.
//!
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
//! [MS-NTHT]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ntht/

use std::fmt;
use std::ops::BitOr;

use crate::{AuthError, Challenge};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// `NegotiateFlags` ([MS-NLMP] §2.2.2.5).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NegotiateFlags(pub u32);

impl NegotiateFlags {
    /// `NTLMSSP_NEGOTIATE_UNICODE`: strings are UTF-16LE.
    pub const UNICODE: Self = Self(0x0000_0001);
    /// `NTLM_NEGOTIATE_OEM`: strings are in the OEM code page.
    pub const OEM: Self = Self(0x0000_0002);
    /// `NTLMSSP_REQUEST_TARGET`.
    pub const REQUEST_TARGET: Self = Self(0x0000_0004);
    /// `NTLMSSP_NEGOTIATE_SIGN`.
    pub const SIGN: Self = Self(0x0000_0010);
    /// `NTLMSSP_NEGOTIATE_SEAL`.
    pub const SEAL: Self = Self(0x0000_0020);
    /// `NTLMSSP_NEGOTIATE_LM_KEY`.
    pub const LM_KEY: Self = Self(0x0000_0080);
    /// `NTLMSSP_NEGOTIATE_NTLM`.
    pub const NTLM: Self = Self(0x0000_0200);
    /// `NTLMSSP_ANONYMOUS`.
    pub const ANONYMOUS: Self = Self(0x0000_0800);
    /// `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED`.
    pub const OEM_DOMAIN_SUPPLIED: Self = Self(0x0000_1000);
    /// `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED`.
    pub const OEM_WORKSTATION_SUPPLIED: Self = Self(0x0000_2000);
    /// `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`.
    pub const ALWAYS_SIGN: Self = Self(0x0000_8000);
    /// `NTLMSSP_TARGET_TYPE_DOMAIN`.
    pub const TARGET_TYPE_DOMAIN: Self = Self(0x0001_0000);
    /// `NTLMSSP_TARGET_TYPE_SERVER`.
    pub const TARGET_TYPE_SERVER: Self = Self(0x0002_0000);
    /// `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.
    pub const EXTENDED_SESSIONSECURITY: Self = Self(0x0008_0000);
    /// `NTLMSSP_NEGOTIATE_IDENTIFY`.
    pub const IDENTIFY: Self = Self(0x0010_0000);
    /// `NTLMSSP_REQUEST_NON_NT_SESSION_KEY`.
    pub const REQUEST_NON_NT_SESSION_KEY: Self = Self(0x0040_0000);
    /// `NTLMSSP_NEGOTIATE_TARGET_INFO`.
    pub const TARGET_INFO: Self = Self(0x0080_0000);
    /// `NTLMSSP_NEGOTIATE_VERSION`.
    pub const VERSION: Self = Self(0x0200_0000);
    /// `NTLMSSP_NEGOTIATE_128`.
    pub const KEY_128: Self = Self(0x2000_0000);
    /// `NTLMSSP_NEGOTIATE_KEY_EXCH`.
    pub const KEY_EXCH: Self = Self(0x4000_0000);
    /// `NTLMSSP_NEGOTIATE_56`.
    pub const KEY_56: Self = Self(0x8000_0000);

    /// The flags a typical HTTP client sends: Unicode and OEM, request
    /// target, NTLM, always-sign, extended session security, 128 and 56.
    pub const CLIENT_DEFAULT: Self = Self(
        Self::UNICODE.0
            | Self::OEM.0
            | Self::REQUEST_TARGET.0
            | Self::NTLM.0
            | Self::ALWAYS_SIGN.0
            | Self::EXTENDED_SESSIONSECURITY.0
            | Self::KEY_128.0
            | Self::KEY_56.0,
    );

    /// `true` if every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for NegotiateFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The `VERSION` structure ([MS-NLMP] §2.2.2.10).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version {
    /// Major OS version.
    pub major: u8,
    /// Minor OS version.
    pub minor: u8,
    /// OS build number.
    pub build: u16,
    /// NTLM revision, 15 for `NTLMv2`-capable peers.
    pub revision: u8,
}

impl Version {
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.major, self.minor]);
        out.extend_from_slice(&self.build.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, self.revision]);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..8)?;
        Some(Self {
            major: b[0],
            minor: b[1],
            build: u16::from_le_bytes([b[2], b[3]]),
            revision: b[7],
        })
    }
}

/// One `AV_PAIR` of a CHALLENGE message's target information
/// ([MS-NLMP] §2.2.2.1).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AvPair {
    /// The `AvId`.
    pub id: u16,
    /// The raw value.
    pub value: Vec<u8>,
}

impl AvPair {
    /// `MsvAvEOL`, the terminator.
    pub const EOL: u16 = 0;
    /// `MsvAvNbComputerName`.
    pub const NB_COMPUTER_NAME: u16 = 1;
    /// `MsvAvNbDomainName`.
    pub const NB_DOMAIN_NAME: u16 = 2;
    /// `MsvAvDnsComputerName`.
    pub const DNS_COMPUTER_NAME: u16 = 3;
    /// `MsvAvDnsDomainName`.
    pub const DNS_DOMAIN_NAME: u16 = 4;
    /// `MsvAvDnsTreeName`.
    pub const DNS_TREE_NAME: u16 = 5;
    /// `MsvAvFlags`.
    pub const FLAGS: u16 = 6;
    /// `MsvAvTimestamp`: a FILETIME.
    pub const TIMESTAMP: u16 = 7;
    /// `MsvAvSingleHost`.
    pub const SINGLE_HOST: u16 = 8;
    /// `MsvAvTargetName`.
    pub const TARGET_NAME: u16 = 9;
    /// `MsvAvChannelBindings`.
    pub const CHANNEL_BINDINGS: u16 = 10;

    /// A pair with a UTF-16LE string value (the name pairs).
    #[must_use]
    pub fn text(id: u16, value: &str) -> Self {
        Self {
            id,
            value: utf16le(value),
        }
    }

    /// The value as a UTF-16LE string, if it is one.
    #[must_use]
    pub fn as_text(&self) -> Option<String> {
        from_utf16le(&self.value)
    }

    /// Parses `AV_PAIR`s up to `MsvAvEOL` (which is not returned). A
    /// missing terminator at the end of the input is tolerated.
    ///
    /// # Errors
    ///
    /// [`AuthError::NtlmTruncated`] if a pair runs past the input.
    pub fn parse_list(mut bytes: &[u8]) -> Result<Vec<Self>, AuthError> {
        let truncated = AuthError::NtlmTruncated("target info");
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let header = bytes.get(..4).ok_or_else(|| truncated.clone())?;
            let id = u16::from_le_bytes([header[0], header[1]]);
            let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
            if id == Self::EOL {
                break;
            }
            let value = bytes.get(4..4 + len).ok_or_else(|| truncated.clone())?;
            out.push(Self {
                id,
                value: value.to_vec(),
            });
            bytes = bytes.get(4 + len..).unwrap_or_default();
        }
        Ok(out)
    }

    /// Encodes pairs followed by `MsvAvEOL`.
    ///
    /// # Errors
    ///
    /// [`AuthError::NtlmFieldTooLong`] for a value over 65535 bytes.
    pub fn encode_list(pairs: &[Self]) -> Result<Vec<u8>, AuthError> {
        let mut out = Vec::new();
        for pair in pairs {
            let len = u16::try_from(pair.value.len())
                .map_err(|_| AuthError::NtlmFieldTooLong("AV_PAIR"))?;
            out.extend_from_slice(&pair.id.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&pair.value);
        }
        out.extend_from_slice(&[0, 0, 0, 0]);
        Ok(out)
    }
}

/// The NEGOTIATE message (type 1), sent by the client first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NegotiateMessage {
    /// Requested flags.
    pub flags: NegotiateFlags,
    /// OEM domain name, if supplied.
    pub domain: Option<String>,
    /// OEM workstation name, if supplied.
    pub workstation: Option<String>,
    /// The client version, if sent.
    pub version: Option<Version>,
}

impl NegotiateMessage {
    /// A NEGOTIATE message with [`NegotiateFlags::CLIENT_DEFAULT`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_flags(NegotiateFlags::CLIENT_DEFAULT)
    }

    /// A NEGOTIATE message with the given flags and nothing else.
    #[must_use]
    pub const fn with_flags(flags: NegotiateFlags) -> Self {
        Self {
            flags,
            domain: None,
            workstation: None,
            version: None,
        }
    }
}

impl Default for NegotiateMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// The CHALLENGE message (type 2), sent by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChallengeMessage {
    /// Negotiated flags.
    pub flags: NegotiateFlags,
    /// The target (domain or server) name.
    pub target_name: Option<String>,
    /// The 8-byte server challenge.
    pub server_challenge: [u8; 8],
    /// Target information pairs (without the terminator).
    pub target_info: Vec<AvPair>,
    /// The server version, if sent.
    pub version: Option<Version>,
}

impl ChallengeMessage {
    /// A challenge with the given flags and server challenge.
    #[must_use]
    pub const fn new(flags: NegotiateFlags, server_challenge: [u8; 8]) -> Self {
        Self {
            flags,
            target_name: None,
            server_challenge,
            target_info: Vec::new(),
            version: None,
        }
    }

    /// The `MsvAvTimestamp` of the target information, as a FILETIME.
    #[must_use]
    pub fn timestamp(&self) -> Option<u64> {
        let pair = self
            .target_info
            .iter()
            .find(|p| p.id == AvPair::TIMESTAMP)?;
        let bytes: [u8; 8] = pair.value.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

/// The AUTHENTICATE message (type 3), the client's answer.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticateMessage {
    /// Negotiated flags.
    pub flags: NegotiateFlags,
    /// `LmChallengeResponse`.
    pub lm_response: Vec<u8>,
    /// `NtChallengeResponse`.
    pub nt_response: Vec<u8>,
    /// The user's domain.
    pub domain: String,
    /// The user name.
    pub user: String,
    /// The client workstation name.
    pub workstation: String,
    /// `EncryptedRandomSessionKey` (empty without key exchange).
    pub encrypted_session_key: Vec<u8>,
    /// The client version, if sent.
    pub version: Option<Version>,
    /// The message integrity code, if sent.
    pub mic: Option<[u8; 16]>,
}

impl fmt::Debug for AuthenticateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticateMessage")
            .field("flags", &self.flags)
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("workstation", &self.workstation)
            .field("lm_response_len", &self.lm_response.len())
            .field("nt_response_len", &self.nt_response.len())
            .field("version", &self.version)
            .field("mic", &self.mic.is_some())
            .finish_non_exhaustive()
    }
}

/// Any of the three NTLM messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NtlmMessage {
    /// Type 1.
    Negotiate(NegotiateMessage),
    /// Type 2.
    Challenge(ChallengeMessage),
    /// Type 3.
    Authenticate(AuthenticateMessage),
}

/// The HTTP auth scheme carrying an NTLM message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NtlmScheme {
    /// `NTLM`.
    Ntlm,
    /// `Negotiate` (raw NTLMSSP, not SPNEGO).
    Negotiate,
}

impl NtlmScheme {
    /// The scheme name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM",
            Self::Negotiate => "Negotiate",
        }
    }
}

impl NtlmMessage {
    /// Decodes an NTLMSSP message.
    ///
    /// # Errors
    ///
    /// [`AuthError::NtlmSignature`], [`AuthError::NtlmMessageType`],
    /// [`AuthError::NtlmTruncated`] or [`AuthError::NtlmString`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.get(..8) != Some(SIGNATURE.as_slice()) {
            return Err(AuthError::NtlmSignature);
        }
        match read_u32(bytes, 8, "MessageType")? {
            1 => decode_negotiate(bytes).map(Self::Negotiate),
            2 => decode_challenge(bytes).map(Self::Challenge),
            3 => decode_authenticate(bytes).map(Self::Authenticate),
            other => Err(AuthError::NtlmMessageType(other)),
        }
    }

    /// Encodes the message.
    ///
    /// # Errors
    ///
    /// [`AuthError::NtlmFieldTooLong`] if a field exceeds 65535 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, AuthError> {
        match self {
            Self::Negotiate(m) => encode_negotiate(m),
            Self::Challenge(m) => encode_challenge(m),
            Self::Authenticate(m) => encode_authenticate(m),
        }
    }

    /// The header value: `NTLM <base64>` or `Negotiate <base64>`.
    ///
    /// # Errors
    ///
    /// As [`encode`](Self::encode).
    pub fn to_header(&self, scheme: NtlmScheme) -> Result<String, AuthError> {
        Ok(format!(
            "{} {}",
            scheme.name(),
            rune_base64::encode(&self.encode()?)
        ))
    }

    /// Decodes the message of an `Authorization`, `WWW-Authenticate` or
    /// `Proxy-Authenticate` value. In a list of challenges, the first
    /// `NTLM` or `Negotiate` challenge with a token is used.
    ///
    /// ```
    /// use rune_http_auth::{NegotiateMessage, NtlmMessage, NtlmScheme};
    ///
    /// let message = NtlmMessage::Negotiate(NegotiateMessage::new());
    /// let header = message.to_header(NtlmScheme::Ntlm).unwrap();
    /// assert!(header.starts_with("NTLM TlRMTVNTUAAB"));
    /// assert_eq!(NtlmMessage::from_header(&header).unwrap(), (NtlmScheme::Ntlm, message));
    /// ```
    ///
    /// # Errors
    ///
    /// A syntax error, [`AuthError::WrongScheme`] without an NTLM token,
    /// [`AuthError::Base64`], or any error of [`decode`](Self::decode).
    pub fn from_header(header: &str) -> Result<(NtlmScheme, Self), AuthError> {
        let list = Challenge::parse_list(header)?;
        Self::from_challenges(&list)
    }

    /// As [`from_header`](Self::from_header), for parsed challenges.
    ///
    /// # Errors
    ///
    /// As [`from_header`](Self::from_header).
    pub fn from_challenges(challenges: &[Challenge]) -> Result<(NtlmScheme, Self), AuthError> {
        let found = challenges.iter().find_map(|c| {
            let scheme = if c.is_scheme("NTLM") {
                NtlmScheme::Ntlm
            } else if c.is_scheme("Negotiate") {
                NtlmScheme::Negotiate
            } else {
                return None;
            };
            c.token68.as_deref().map(|token| (scheme, token))
        });
        let (scheme, token) = found.ok_or_else(|| AuthError::WrongScheme {
            expected: "NTLM",
            found: challenges
                .first()
                .map(|c| c.scheme.clone())
                .unwrap_or_default(),
        })?;
        let bytes = rune_base64::decode(token).map_err(|_| AuthError::Base64)?;
        Ok((scheme, Self::decode(&bytes)?))
    }
}

// ---------------------------------------------------------------- decoding

fn read_u16(bytes: &[u8], at: usize, field: &'static str) -> Result<u16, AuthError> {
    let b = bytes
        .get(at..at + 2)
        .ok_or(AuthError::NtlmTruncated(field))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(bytes: &[u8], at: usize, field: &'static str) -> Result<u32, AuthError> {
    let b = bytes
        .get(at..at + 4)
        .ok_or(AuthError::NtlmTruncated(field))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A `(Len, MaxLen, BufferOffset)` field descriptor.
#[derive(Clone, Copy)]
struct Field {
    len: usize,
    offset: usize,
}

fn read_field(bytes: &[u8], at: usize, field: &'static str) -> Result<Field, AuthError> {
    Ok(Field {
        len: usize::from(read_u16(bytes, at, field)?),
        offset: usize::try_from(read_u32(bytes, at + 4, field)?)
            .map_err(|_| AuthError::NtlmTruncated(field))?,
    })
}

fn field_bytes<'a>(bytes: &'a [u8], f: Field, name: &'static str) -> Result<&'a [u8], AuthError> {
    if f.len == 0 {
        return Ok(&[]);
    }
    bytes
        .get(f.offset..f.offset.saturating_add(f.len))
        .ok_or(AuthError::NtlmTruncated(name))
}

fn field_string(
    bytes: &[u8],
    f: Field,
    unicode: bool,
    name: &'static str,
) -> Result<String, AuthError> {
    let raw = field_bytes(bytes, f, name)?;
    if unicode {
        from_utf16le(raw).ok_or(AuthError::NtlmString(name))
    } else {
        Ok(raw.iter().map(|&b| char::from(b)).collect())
    }
}

/// Lowest payload offset of the non-empty fields: where the fixed header
/// (and so the optional Version / MIC) ends.
fn payload_start(fields: &[Field], len: usize) -> usize {
    fields
        .iter()
        .filter(|f| f.len > 0)
        .map(|f| f.offset)
        .min()
        .unwrap_or(len)
}

fn decode_negotiate(bytes: &[u8]) -> Result<NegotiateMessage, AuthError> {
    let flags = NegotiateFlags(read_u32(bytes, 12, "NegotiateFlags")?);
    // Very old clients send a 16-byte message without name fields.
    let (domain, workstation) = if bytes.len() >= 32 {
        (
            read_field(bytes, 16, "DomainName")?,
            read_field(bytes, 24, "Workstation")?,
        )
    } else {
        let empty = Field { len: 0, offset: 0 };
        (empty, empty)
    };
    let start = payload_start(&[domain, workstation], bytes.len());
    let version = if flags.contains(NegotiateFlags::VERSION) && start >= 40 {
        bytes.get(32..40).and_then(Version::decode)
    } else {
        None
    };
    let optional = |f: Field, name| {
        (f.len > 0)
            .then(|| field_string(bytes, f, false, name))
            .transpose()
    };
    Ok(NegotiateMessage {
        flags,
        domain: optional(domain, "DomainName")?,
        workstation: optional(workstation, "Workstation")?,
        version,
    })
}

fn decode_challenge(bytes: &[u8]) -> Result<ChallengeMessage, AuthError> {
    let target_name = read_field(bytes, 12, "TargetName")?;
    let flags = NegotiateFlags(read_u32(bytes, 20, "NegotiateFlags")?);
    let server_challenge: [u8; 8] = bytes
        .get(24..32)
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::NtlmTruncated("ServerChallenge"))?;
    let target_info = if bytes.len() >= 48 {
        read_field(bytes, 40, "TargetInfo")?
    } else {
        Field { len: 0, offset: 0 }
    };
    let start = payload_start(&[target_name, target_info], bytes.len());
    let version = if flags.contains(NegotiateFlags::VERSION) && start >= 56 {
        bytes.get(48..56).and_then(Version::decode)
    } else {
        None
    };
    let unicode = flags.contains(NegotiateFlags::UNICODE);
    Ok(ChallengeMessage {
        flags,
        target_name: (target_name.len > 0)
            .then(|| field_string(bytes, target_name, unicode, "TargetName"))
            .transpose()?,
        server_challenge,
        target_info: AvPair::parse_list(field_bytes(bytes, target_info, "TargetInfo")?)?,
        version,
    })
}

fn decode_authenticate(bytes: &[u8]) -> Result<AuthenticateMessage, AuthError> {
    let lm = read_field(bytes, 12, "LmChallengeResponse")?;
    let nt = read_field(bytes, 20, "NtChallengeResponse")?;
    let domain = read_field(bytes, 28, "DomainName")?;
    let user = read_field(bytes, 36, "UserName")?;
    let workstation = read_field(bytes, 44, "Workstation")?;
    let key = read_field(bytes, 52, "EncryptedRandomSessionKey")?;
    let flags = NegotiateFlags(read_u32(bytes, 60, "NegotiateFlags")?);
    let start = payload_start(&[lm, nt, domain, user, workstation, key], bytes.len());
    let version = if start >= 72 {
        bytes.get(64..72).and_then(Version::decode)
    } else {
        None
    };
    let mic = if start >= 88 {
        bytes.get(72..88).and_then(|b| b.try_into().ok())
    } else {
        None
    };
    let unicode = flags.contains(NegotiateFlags::UNICODE);
    Ok(AuthenticateMessage {
        flags,
        lm_response: field_bytes(bytes, lm, "LmChallengeResponse")?.to_vec(),
        nt_response: field_bytes(bytes, nt, "NtChallengeResponse")?.to_vec(),
        domain: field_string(bytes, domain, unicode, "DomainName")?,
        user: field_string(bytes, user, unicode, "UserName")?,
        workstation: field_string(bytes, workstation, unicode, "Workstation")?,
        encrypted_session_key: field_bytes(bytes, key, "EncryptedRandomSessionKey")?.to_vec(),
        version,
        mic,
    })
}

// ---------------------------------------------------------------- encoding

/// Builds a message: fixed header bytes, then payloads appended with their
/// field descriptors patched in.
struct Writer {
    out: Vec<u8>,
    payload: Vec<u8>,
    header_len: usize,
}

impl Writer {
    fn new(message_type: u32, header_len: usize) -> Self {
        let mut out = Vec::with_capacity(header_len + 64);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&message_type.to_le_bytes());
        Self {
            out,
            payload: Vec::new(),
            header_len,
        }
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    /// Writes a field descriptor for `data` and queues `data`.
    fn field(&mut self, data: &[u8], name: &'static str) -> Result<(), AuthError> {
        let len = u16::try_from(data.len()).map_err(|_| AuthError::NtlmFieldTooLong(name))?;
        let offset = u32::try_from(self.header_len + self.payload.len())
            .map_err(|_| AuthError::NtlmFieldTooLong(name))?;
        self.out.extend_from_slice(&len.to_le_bytes());
        self.out.extend_from_slice(&len.to_le_bytes());
        self.out.extend_from_slice(&offset.to_le_bytes());
        self.payload.extend_from_slice(data);
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        self.out.resize(self.header_len, 0);
        self.out.extend_from_slice(&self.payload);
        self.out
    }
}

fn encode_string(value: &str, unicode: bool) -> Vec<u8> {
    if unicode {
        utf16le(value)
    } else {
        value
            .chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .collect()
    }
}

fn encode_negotiate(m: &NegotiateMessage) -> Result<Vec<u8>, AuthError> {
    let header_len = if m.version.is_some() { 40 } else { 32 };
    let mut w = Writer::new(1, header_len);
    w.u32(m.flags.0);
    w.field(
        &encode_string(m.domain.as_deref().unwrap_or_default(), false),
        "DomainName",
    )?;
    w.field(
        &encode_string(m.workstation.as_deref().unwrap_or_default(), false),
        "Workstation",
    )?;
    if let Some(version) = m.version {
        version.encode(&mut w.out);
    }
    Ok(w.finish())
}

fn encode_challenge(m: &ChallengeMessage) -> Result<Vec<u8>, AuthError> {
    let header_len = if m.version.is_some() { 56 } else { 48 };
    let unicode = m.flags.contains(NegotiateFlags::UNICODE);
    let mut w = Writer::new(2, header_len);
    w.field(
        &encode_string(m.target_name.as_deref().unwrap_or_default(), unicode),
        "TargetName",
    )?;
    w.u32(m.flags.0);
    w.bytes(&m.server_challenge);
    w.bytes(&[0; 8]);
    let info = if m.target_info.is_empty() {
        Vec::new()
    } else {
        AvPair::encode_list(&m.target_info)?
    };
    w.field(&info, "TargetInfo")?;
    if let Some(version) = m.version {
        version.encode(&mut w.out);
    }
    Ok(w.finish())
}

fn encode_authenticate(m: &AuthenticateMessage) -> Result<Vec<u8>, AuthError> {
    let header_len = match (m.version, m.mic) {
        (_, Some(_)) => 88,
        (Some(_), None) => 72,
        (None, None) => 64,
    };
    let unicode = m.flags.contains(NegotiateFlags::UNICODE);
    let mut w = Writer::new(3, header_len);
    w.field(&m.lm_response, "LmChallengeResponse")?;
    w.field(&m.nt_response, "NtChallengeResponse")?;
    w.field(&encode_string(&m.domain, unicode), "DomainName")?;
    w.field(&encode_string(&m.user, unicode), "UserName")?;
    w.field(&encode_string(&m.workstation, unicode), "Workstation")?;
    w.field(&m.encrypted_session_key, "EncryptedRandomSessionKey")?;
    w.u32(m.flags.0);
    if header_len > 64 {
        match m.version {
            Some(version) => version.encode(&mut w.out),
            None => w.bytes(&[0; 8]),
        }
    }
    if let Some(mic) = m.mic {
        w.bytes(&mic);
    }
    Ok(w.finish())
}

fn utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn from_utf16le(bytes: &[u8]) -> Option<String> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    char::decode_utf16(units.iter().map(|&u| u16::from_le_bytes(u)))
        .collect::<Result<String, _>>()
        .ok()
}

// ------------------------------------------------------------------ crypto

/// MD4 ([RFC 1320]), needed only for the NT hash.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320
#[allow(clippy::many_single_char_names, reason = "RFC 1320 notation")]
fn md4(data: &[u8]) -> [u8; 16] {
    const R2: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const R3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    let mut message = data.to_vec();
    let bit_len = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let (blocks, _) = message.as_chunks::<64>();
    for block in blocks {
        let (words, _) = block.as_chunks::<4>();
        let x: Vec<u32> = words.iter().map(|&w| u32::from_le_bytes(w)).collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..16 {
            let (k, s) = (i, [3, 7, 11, 19][i % 4]);
            let t = a
                .wrapping_add((b & c) | (!b & d))
                .wrapping_add(x[k])
                .rotate_left(s);
            (a, b, c, d) = (d, t, b, c);
        }
        for i in 0..16 {
            let (k, s) = (R2[i], [3, 5, 9, 13][i % 4]);
            let t = a
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(x[k])
                .wrapping_add(0x5a82_7999)
                .rotate_left(s);
            (a, b, c, d) = (d, t, b, c);
        }
        for i in 0..16 {
            let (k, s) = (R3[i], [3, 9, 11, 15][i % 4]);
            let t = a
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(x[k])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(s);
            (a, b, c, d) = (d, t, b, c);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0; 16];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *chunk = word.to_le_bytes();
    }
    out
}

/// HMAC-MD5 ([RFC 2104]).
///
/// [RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&rune_md5::hash_raw(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    for part in parts {
        inner.extend_from_slice(part);
    }
    let mut outer: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&rune_md5::hash_raw(&inner));
    rune_md5::hash_raw(&outer)
}

/// The NT hash: MD4 of the UTF-16LE password (`NTOWFv1`).
///
/// ```
/// use rune_http_auth::nt_hash;
///
/// // [MS-NLMP] §4.2.2.1.2.
/// assert_eq!(nt_hash("Password")[..4], [0xa4, 0xf4, 0x9c, 0x40]);
/// ```
#[must_use]
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4(&utf16le(password))
}

/// `NTOWFv2`: HMAC-MD5 keyed with the NT hash over the UTF-16LE of the
/// uppercased user name followed by the domain ([MS-NLMP] §3.3.2).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[must_use]
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let identity = utf16le(&format!("{}{domain}", user.to_uppercase()));
    hmac_md5(&nt_hash(password), &[&identity])
}

/// The `NTLMv2` responses and session base key.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ntlmv2Response {
    /// `NtChallengeResponse`: `NTProofStr` followed by the client blob.
    pub nt_response: Vec<u8>,
    /// `LmChallengeResponse` (`LMv2`): HMAC followed by the client challenge.
    pub lm_response: Vec<u8>,
    /// `SessionBaseKey`.
    pub session_base_key: [u8; 16],
}

impl fmt::Debug for Ntlmv2Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ntlmv2Response").finish_non_exhaustive()
    }
}

/// Computes the `NTLMv2` responses ([MS-NLMP] §3.3.2) from the `NTOWFv2`
/// key, the server and client challenges, a FILETIME timestamp and the
/// raw target information (including its terminator).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[must_use]
pub fn ntlmv2_response(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    target_info: &[u8],
) -> Ntlmv2Response {
    let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&[0; 4]);
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0; 4]);
    let proof = hmac_md5(response_key, &[server_challenge, &blob]);
    let mut nt_response = proof.to_vec();
    nt_response.extend_from_slice(&blob);
    let mut lm_response = hmac_md5(response_key, &[server_challenge, client_challenge]).to_vec();
    lm_response.extend_from_slice(client_challenge);
    Ntlmv2Response {
        nt_response,
        lm_response,
        session_base_key: hmac_md5(response_key, &[&proof]),
    }
}

/// NTLM credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct NtlmCredentials {
    /// The user's domain (may be empty).
    pub domain: String,
    /// The user name.
    pub user: String,
    /// The password.
    pub password: String,
}

impl fmt::Debug for NtlmCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmCredentials")
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl NtlmCredentials {
    /// Credentials for `domain\user`.
    #[must_use]
    pub fn new(
        domain: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            user: user.into(),
            password: password.into(),
        }
    }
}

/// Answers a CHALLENGE with an `NTLMv2` AUTHENTICATE message.
///
/// The timestamp is the challenge's `MsvAvTimestamp` when present (and the
/// `LMv2` response is then zeroed, per [MS-NLMP] §3.1.5.1.2), otherwise
/// `timestamp` (a FILETIME: 100 ns ticks since 1601). `client_challenge`
/// must be random. No MIC and no key exchange.
///
/// ```
/// use rune_http_auth::{
///     ChallengeMessage, NegotiateFlags, NtlmCredentials, NtlmMessage, NtlmScheme, authenticate,
/// };
///
/// let challenge = ChallengeMessage::new(NegotiateFlags::CLIENT_DEFAULT, [1; 8]);
/// let creds = NtlmCredentials::new("CORP", "alice", "s3cret");
/// let auth = authenticate(&challenge, &creds, "WS01", [2; 8], 0);
/// assert_eq!(auth.user, "alice");
/// let header = NtlmMessage::Authenticate(auth).to_header(NtlmScheme::Ntlm).unwrap();
/// assert!(header.starts_with("NTLM TlRMTVNTUAAD"));
/// ```
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
#[must_use]
pub fn authenticate(
    challenge: &ChallengeMessage,
    credentials: &NtlmCredentials,
    workstation: &str,
    client_challenge: [u8; 8],
    timestamp: u64,
) -> AuthenticateMessage {
    let key = ntowf_v2(
        &credentials.password,
        &credentials.user,
        &credentials.domain,
    );
    let server_timestamp = challenge.timestamp();
    let target_info = if challenge.target_info.is_empty() {
        Vec::new()
    } else {
        AvPair::encode_list(&challenge.target_info).unwrap_or_default()
    };
    let response = ntlmv2_response(
        &key,
        &challenge.server_challenge,
        &client_challenge,
        server_timestamp.unwrap_or(timestamp),
        &target_info,
    );
    let mut flags = NegotiateFlags(challenge.flags.0 & NegotiateFlags::CLIENT_DEFAULT.0);
    if !flags.contains(NegotiateFlags::UNICODE) && !flags.contains(NegotiateFlags::OEM) {
        flags = flags | NegotiateFlags::UNICODE;
    }
    AuthenticateMessage {
        flags,
        lm_response: if server_timestamp.is_some() {
            vec![0; 24]
        } else {
            response.lm_response
        },
        nt_response: response.nt_response,
        domain: credentials.domain.clone(),
        user: credentials.user.clone(),
        workstation: workstation.to_owned(),
        encrypted_session_key: Vec::new(),
        version: None,
        mic: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn md4_rfc1320_vectors() {
        for (input, expected) in [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ] {
            assert_eq!(hex(&md4(input.as_bytes())), expected, "{input:?}");
        }
    }

    #[test]
    fn hmac_md5_rfc2202() {
        assert_eq!(
            hex(&hmac_md5(b"Jefe", &[b"what do ya want ", b"for nothing?"])),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex(&hmac_md5(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
    }

    /// [MS-NLMP] §4.2.4: `NTLMv2` authentication.
    #[test]
    fn ms_nlmp_ntlmv2_vectors() {
        assert_eq!(
            hex(&nt_hash("Password")),
            "a4f49c406510bdcab6824ee7c30fd852"
        );
        let key = ntowf_v2("Password", "User", "Domain");
        assert_eq!(hex(&key), "0c868a403bfd7a93a3001ef22ef02e3f");
        let info = AvPair::encode_list(&[
            AvPair::text(AvPair::NB_DOMAIN_NAME, "Domain"),
            AvPair::text(AvPair::NB_COMPUTER_NAME, "Server"),
        ])
        .unwrap();
        let server = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let response = ntlmv2_response(&key, &server, &[0xaa; 8], 0, &info);
        assert_eq!(
            hex(&response.nt_response[..16]),
            "68cd0ab851e51c96aabc927bebef6a1c"
        );
        assert_eq!(
            hex(&response.lm_response),
            "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            hex(&response.session_base_key),
            "8de40ccadbc14a82f15cb0ad0de95ca3"
        );
    }

    #[test]
    fn messages_round_trip() {
        let version = Some(Version {
            major: 10,
            minor: 0,
            build: 19041,
            revision: 15,
        });
        let mut negotiate =
            NegotiateMessage::with_flags(NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::VERSION);
        negotiate.domain = Some("CORP".into());
        negotiate.workstation = Some("WS01".into());
        negotiate.version = version;

        let mut challenge = ChallengeMessage::new(
            NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::TARGET_INFO | NegotiateFlags::VERSION,
            [9; 8],
        );
        challenge.target_name = Some("CORP".into());
        challenge.target_info = vec![
            AvPair::text(AvPair::NB_DOMAIN_NAME, "CORP"),
            AvPair {
                id: AvPair::TIMESTAMP,
                value: 132_000_000_000_000_000u64.to_le_bytes().to_vec(),
            },
        ];
        challenge.version = version;
        assert_eq!(challenge.timestamp(), Some(132_000_000_000_000_000));

        let mut auth = authenticate(
            &challenge,
            &NtlmCredentials::new("CORP", "Zoë", "pw"),
            "WS01",
            [7; 8],
            1,
        );
        assert_eq!(auth.lm_response, [0; 24]);
        let plain = auth.clone();
        auth.version = version;
        auth.mic = Some([5; 16]);

        for message in [
            NtlmMessage::Negotiate(negotiate),
            NtlmMessage::Negotiate(NegotiateMessage::new()),
            NtlmMessage::Challenge(challenge),
            NtlmMessage::Challenge(ChallengeMessage::new(NegotiateFlags::UNICODE, [0; 8])),
            NtlmMessage::Authenticate(auth),
            NtlmMessage::Authenticate(plain),
        ] {
            let bytes = message.encode().unwrap();
            assert_eq!(NtlmMessage::decode(&bytes).unwrap(), message);
            for scheme in [NtlmScheme::Ntlm, NtlmScheme::Negotiate] {
                let header = message.to_header(scheme).unwrap();
                assert_eq!(
                    NtlmMessage::from_header(&header).unwrap(),
                    (scheme, message.clone())
                );
            }
        }
    }

    #[test]
    fn decodes_short_messages_and_rejects_garbage() {
        // A 32-byte NEGOTIATE without version, and a 32-byte CHALLENGE.
        let mut negotiate = SIGNATURE.to_vec();
        negotiate.extend_from_slice(&1u32.to_le_bytes());
        negotiate.extend_from_slice(&0x0000_b207u32.to_le_bytes());
        negotiate.resize(32, 0);
        assert!(matches!(
            NtlmMessage::decode(&negotiate),
            Ok(NtlmMessage::Negotiate(_))
        ));

        let mut challenge = SIGNATURE.to_vec();
        challenge.extend_from_slice(&2u32.to_le_bytes());
        challenge.resize(32, 0);
        assert!(matches!(
            NtlmMessage::decode(&challenge),
            Ok(NtlmMessage::Challenge(_))
        ));

        assert_eq!(
            NtlmMessage::decode(b"NTLMSSX\0"),
            Err(AuthError::NtlmSignature)
        );
        let mut bad_type = SIGNATURE.to_vec();
        bad_type.extend_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            NtlmMessage::decode(&bad_type),
            Err(AuthError::NtlmMessageType(4))
        );
        let mut oob = challenge.clone();
        oob[12..20].copy_from_slice(&[4, 0, 4, 0, 0xff, 0xff, 0, 0]);
        assert!(matches!(
            NtlmMessage::decode(&oob),
            Err(AuthError::NtlmTruncated(_))
        ));
        assert!(matches!(
            NtlmMessage::from_header("Basic realm=x"),
            Err(AuthError::WrongScheme { .. })
        ));
        assert_eq!(NtlmMessage::from_header("NTLM a"), Err(AuthError::Base64));
    }

    #[test]
    fn picks_ntlm_out_of_a_challenge_list() {
        let token = NtlmMessage::Challenge(ChallengeMessage::new(NegotiateFlags::UNICODE, [3; 8]))
            .to_header(NtlmScheme::Negotiate)
            .unwrap();
        let header = format!("Basic realm=\"x\", NTLM, {token}");
        let (scheme, message) = NtlmMessage::from_header(&header).unwrap();
        assert_eq!(scheme, NtlmScheme::Negotiate);
        assert!(matches!(message, NtlmMessage::Challenge(c) if c.server_challenge == [3; 8]));
    }
}

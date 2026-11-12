//! SMB: the `NEGOTIATE` exchange, SMB 2/3 and SMB1.
//!
//! See [MS-SMB2 §2.2.3/§2.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5)
//! and [MS-CIFS §2.2.4.52](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/25c8c3c9-58fc-4bb8-aa8f-0272dede84c5).
//! A client opens an SMB connection with `NEGOTIATE`; the server answers
//! with the dialect it picked, its signing policy, GUID, capabilities and
//! the authentication mechanisms it accepts, all before any session is set
//! up. [`SmbProbe`] offers every SMB 2/3 dialect and reads that answer;
//! [`Smb1Probe`] offers only the SMB1 dialect `NT LM 0.12`, so an answer
//! that accepts it means SMB1 is enabled. Neither sets up a session.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{Action, End, ProbeSession, ServiceInfo, ServiceProbe, Target};

use crate::Error;
use crate::wire::{Reader, text};

const WHAT: &str = "smb negotiate";
const ID_SMB: &str = "smb";
const ID_SMB1: &str = "smb1";

/// Largest `NetBIOS` session message accepted.
const MAX_MESSAGE: usize = 64 * 1024;

const SMB2_MAGIC: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const SMB1_MAGIC: [u8; 4] = [0xff, b'S', b'M', b'B'];
const SMB2_HEADER_LEN: usize = 64;
const SMB1_HEADER_LEN: usize = 32;
const SMB1_COM_NEGOTIATE: u8 = 0x72;

/// `SecurityMode` bit: signing enabled (SMB 2/3).
pub const SMB2_SIGNING_ENABLED: u16 = 0x0001;
/// `SecurityMode` bit: signing required (SMB 2/3).
pub const SMB2_SIGNING_REQUIRED: u16 = 0x0002;
/// SMB1 `SecurityMode` bit: security signatures enabled.
pub const SMB1_SIGNATURES_ENABLED: u8 = 0x04;
/// SMB1 `SecurityMode` bit: security signatures required.
pub const SMB1_SIGNATURES_REQUIRED: u8 = 0x08;
/// SMB1 capability: extended security (SPNEGO) negotiation.
const SMB1_CAP_EXTENDED_SECURITY: u32 = 0x8000_0000;
/// SMB1 `Flags2` bit: strings are UTF-16LE.
const SMB1_FLAGS2_UNICODE: u16 = 0x8000;

/// The SMB 2/3 dialects [`SmbProbe`] offers, oldest first.
pub const SMB2_DIALECTS: [Dialect; 5] = [
    Dialect::SMB_2_0_2,
    Dialect::SMB_2_1,
    Dialect::SMB_3_0,
    Dialect::SMB_3_0_2,
    Dialect::SMB_3_1_1,
];

/// An SMB 2/3 dialect revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dialect(pub u16);

impl Dialect {
    /// SMB 2.0.2 (Windows Vista, Server 2008).
    pub const SMB_2_0_2: Self = Self(0x0202);
    /// SMB 2.1 (Windows 7, Server 2008 R2).
    pub const SMB_2_1: Self = Self(0x0210);
    /// SMB 3.0 (Windows 8, Server 2012): first with encryption.
    pub const SMB_3_0: Self = Self(0x0300);
    /// SMB 3.0.2 (Windows 8.1, Server 2012 R2).
    pub const SMB_3_0_2: Self = Self(0x0302);
    /// SMB 3.1.1 (Windows 10, Server 2016 and later).
    pub const SMB_3_1_1: Self = Self(0x0311);
    /// `SMB 2.???`: the wildcard answer to a multi-protocol SMB1 negotiate.
    pub const SMB_2_WILDCARD: Self = Self(0x02ff);

    /// The dialect's name, e.g. `3.1.1`, or `None` for an unknown value.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x0202 => "2.0.2",
            0x0210 => "2.1",
            0x0300 => "3.0",
            0x0302 => "3.0.2",
            0x0311 => "3.1.1",
            0x02ff => "2.???",
            _ => return None,
        })
    }

    /// True for SMB 3.x, which supports encryption.
    #[must_use]
    pub const fn supports_encryption(self) -> bool {
        self.0 >= 0x0300 && self.0 != 0x02ff
    }
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "{:#06x}", self.0),
        }
    }
}

/// Signing policy, from a `SecurityMode` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signing {
    /// The server signs only if the client insists.
    Disabled,
    /// Signing is supported but not required: messages can be tampered
    /// with or relayed (NTLM relay).
    Enabled,
    /// Every message must be signed.
    Required,
}

impl Signing {
    /// `disabled`, `enabled` or `required`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Required => "required",
        }
    }

    const fn from_flags(enabled: bool, required: bool) -> Self {
        if required {
            Self::Required
        } else if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// A parsed SMB 2/3 `NEGOTIATE` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Smb2Negotiate {
    /// `DialectRevision`: the dialect the server picked.
    pub dialect: u16,
    /// `SecurityMode`.
    pub security_mode: u16,
    /// `ServerGuid`.
    pub server_guid: [u8; 16],
    /// `Capabilities` (`SMB2_GLOBAL_CAP_*`).
    pub capabilities: u32,
    /// `MaxTransactSize`.
    pub max_transact_size: u32,
    /// `MaxReadSize`.
    pub max_read_size: u32,
    /// `MaxWriteSize`.
    pub max_write_size: u32,
    /// `SystemTime`, a Windows FILETIME.
    pub system_time: u64,
    /// `ServerStartTime`, a FILETIME; 0 on current Windows.
    pub server_start_time: u64,
    /// Authentication mechanisms named in the SPNEGO security buffer.
    pub mechanisms: Vec<&'static str>,
    /// Preauth integrity hash algorithm ids (3.1.1 context 1).
    pub preauth_hashes: Vec<u16>,
    /// Cipher ids the server picked (3.1.1 context 2).
    pub ciphers: Vec<u16>,
    /// Signing algorithm ids the server picked (3.1.1 context 8).
    pub signing_algorithms: Vec<u16>,
}

impl Smb2Negotiate {
    /// The dialect the server picked.
    #[must_use]
    pub const fn dialect(&self) -> Dialect {
        Dialect(self.dialect)
    }

    /// The signing policy.
    #[must_use]
    pub const fn signing(&self) -> Signing {
        Signing::from_flags(
            self.security_mode & SMB2_SIGNING_ENABLED != 0,
            self.security_mode & SMB2_SIGNING_REQUIRED != 0,
        )
    }

    /// `ServerGuid` in the usual `8-4-4-4-12` form.
    #[must_use]
    pub fn server_guid_string(&self) -> String {
        guid_string(&self.server_guid)
    }
}

/// A parsed SMB1 `SMB_COM_NEGOTIATE` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Smb1Negotiate {
    /// The index of the dialect the server picked among those offered;
    /// `0xffff` when it accepted none.
    pub dialect_index: u16,
    /// `SecurityMode`.
    pub security_mode: u8,
    /// `Capabilities` (`CAP_*`).
    pub capabilities: u32,
    /// `SystemTime`, a FILETIME.
    pub system_time: u64,
    /// `ServerGUID`, with extended security.
    pub server_guid: Option<[u8; 16]>,
    /// `DomainName`, without extended security: the server's domain or
    /// workgroup.
    pub domain: Option<String>,
    /// `ServerName`, without extended security.
    pub server_name: Option<String>,
    /// Authentication mechanisms in the SPNEGO blob, with extended security.
    pub mechanisms: Vec<&'static str>,
}

impl Smb1Negotiate {
    /// True when the server accepted an offered dialect.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.dialect_index != 0xffff
    }

    /// The signing policy.
    #[must_use]
    pub const fn signing(&self) -> Signing {
        Signing::from_flags(
            self.security_mode & SMB1_SIGNATURES_ENABLED != 0,
            self.security_mode & SMB1_SIGNATURES_REQUIRED != 0,
        )
    }
}

/// A `NEGOTIATE` response of either generation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Negotiate {
    /// SMB 2/3.
    Smb2(Smb2Negotiate),
    /// SMB1.
    Smb1(Smb1Negotiate),
    /// The server answered with an error status (an `NTSTATUS`), e.g.
    /// `0xC00000BB` (`STATUS_NOT_SUPPORTED`) when no dialect is common.
    Status {
        /// True for an SMB1 header.
        smb1: bool,
        /// The status.
        status: u32,
    },
}

fn guid_string(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

/// Wrap an SMB message in a `NetBIOS` session service header (RFC 1002
/// §4.3.1, as used over direct TCP on port 445).
fn netbios(message: &[u8]) -> Vec<u8> {
    let len = u32::try_from(message.len()).unwrap_or(0x00ff_ffff) & 0x00ff_ffff;
    let mut out = vec![0];
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(message);
    out
}

fn push_context(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(data);
}

/// The SMB 2/3 `NEGOTIATE` request [`SmbProbe`] sends, with its `NetBIOS`
/// header.
///
/// It offers every dialect from 2.0.2 to 3.1.1, signing enabled (not
/// required), and the 3.1.1 preauth-integrity (SHA-512), encryption
/// (AES-128/256 GCM/CCM) and signing (AES-GMAC, AES-CMAC, HMAC-SHA256)
/// contexts. The salt and client GUID are fixed: the probe never sets up
/// a session, so they protect nothing.
///
/// ```
/// let req = rune_probe_ms::smb::negotiate_request();
/// assert_eq!(&req[4..8], b"\xfeSMB");
/// assert_eq!(usize::from(req[3]) + 4, req.len());
/// ```
#[must_use]
pub fn negotiate_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(200);
    // SMB2 header.
    msg.extend_from_slice(&SMB2_MAGIC);
    msg.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    msg.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    msg.extend_from_slice(&0u32.to_le_bytes()); // Flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    msg.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    msg.extend_from_slice(&0xfeffu32.to_le_bytes()); // ProcessId
    msg.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    msg.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    msg.extend_from_slice(&[0; 16]); // Signature
    // NEGOTIATE request.
    let contexts_at = SMB2_HEADER_LEN + 36 + SMB2_DIALECTS.len() * 2;
    let contexts_at = contexts_at.next_multiple_of(8);
    msg.extend_from_slice(&36u16.to_le_bytes());
    msg.extend_from_slice(
        &u16::try_from(SMB2_DIALECTS.len())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    msg.extend_from_slice(&SMB2_SIGNING_ENABLED.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0x7fu32.to_le_bytes()); // Capabilities: all SMB 3 caps
    msg.extend_from_slice(b"rune-probe-ms\0\0\0"); // ClientGuid
    msg.extend_from_slice(&u32::try_from(contexts_at).unwrap_or(0).to_le_bytes());
    msg.extend_from_slice(&3u16.to_le_bytes()); // NegotiateContextCount
    msg.extend_from_slice(&0u16.to_le_bytes());
    for dialect in SMB2_DIALECTS {
        msg.extend_from_slice(&dialect.0.to_le_bytes());
    }
    // SMB2_PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 and a 32-byte salt.
    let mut preauth = vec![1, 0, 32, 0, 1, 0];
    preauth.extend_from_slice(&[0x5a; 32]);
    push_context(&mut msg, 1, &preauth);
    // SMB2_ENCRYPTION_CAPABILITIES: AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM.
    push_context(&mut msg, 2, &[4, 0, 2, 0, 1, 0, 4, 0, 3, 0]);
    // SMB2_SIGNING_CAPABILITIES: AES-GMAC, AES-CMAC, HMAC-SHA256.
    push_context(&mut msg, 8, &[3, 0, 2, 0, 1, 0, 0, 0]);
    netbios(&msg)
}

/// The SMB1 `SMB_COM_NEGOTIATE` request [`Smb1Probe`] sends, with its
/// `NetBIOS` header: the single dialect `NT LM 0.12`, Unicode and extended
/// security.
///
/// ```
/// let req = rune_probe_ms::smb::smb1_negotiate_request();
/// assert_eq!(&req[4..9], b"\xffSMB\x72");
/// assert!(req.ends_with(b"\x02NT LM 0.12\0"));
/// ```
#[must_use]
pub fn smb1_negotiate_request() -> Vec<u8> {
    let dialects = b"\x02NT LM 0.12\0";
    let mut msg = Vec::with_capacity(SMB1_HEADER_LEN + 3 + dialects.len());
    msg.extend_from_slice(&SMB1_MAGIC);
    msg.push(SMB1_COM_NEGOTIATE);
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.push(0x18); // Flags: case-insensitive, canonicalised paths
    msg.extend_from_slice(&0xc801u16.to_le_bytes()); // Flags2: Unicode, NT status, ext. security, long names
    msg.extend_from_slice(&[0; 12]); // PIDHigh, SecuritySignature, Reserved
    msg.extend_from_slice(&[0, 0]); // TID
    msg.extend_from_slice(&0xfeffu16.to_le_bytes()); // PIDLow
    msg.extend_from_slice(&[0, 0]); // UID
    msg.extend_from_slice(&[0, 0]); // MID
    msg.push(0); // WordCount
    msg.extend_from_slice(&u16::try_from(dialects.len()).unwrap_or(0).to_le_bytes());
    msg.extend_from_slice(dialects);
    netbios(&msg)
}

/// The SPNEGO mechanisms whose OIDs appear in a security blob.
fn mechanisms(blob: &[u8]) -> Vec<&'static str> {
    const OIDS: [(&[u8], &str); 4] = [
        // 1.2.840.48018.1.2.2 (MS Kerberos)
        (
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
            ],
            "kerberos",
        ),
        // 1.2.840.113554.1.2.2 (Kerberos 5)
        (
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
            ],
            "kerberos",
        ),
        // 1.3.6.1.4.1.311.2.2.30 (NEGOEX)
        (
            &[
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e,
            ],
            "negoex",
        ),
        // 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
        (
            &[
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
            ],
            "ntlmssp",
        ),
    ];
    let mut out = Vec::new();
    for (oid, name) in OIDS {
        if blob.windows(oid.len()).any(|w| w == oid) && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Split one `NetBIOS` session message off the front of `bytes`: its SMB
/// payload and the bytes it took.
///
/// # Errors
///
/// [`Error::Truncated`] until the whole message has arrived, and
/// [`Error::Malformed`] for a `NetBIOS` packet that is not a session message.
pub fn split_message(bytes: &[u8]) -> Result<(&[u8], usize), Error> {
    let mut r = Reader::new(bytes, WHAT);
    let kind = r.u8()?;
    if kind != 0 {
        return Err(Error::malformed(
            WHAT,
            format!("NetBIOS packet type {kind:#04x}"),
        ));
    }
    let [a, b, c] = r.array::<3>()?;
    let len = u32::from_be_bytes([0, a, b, c]) as usize;
    if len > MAX_MESSAGE {
        return Err(Error::malformed(WHAT, format!("message length {len}")));
    }
    Ok((r.take(len)?, 4 + len))
}

/// Parse a `NEGOTIATE` response, starting at the `NetBIOS` header.
///
/// ```
/// use rune_probe_ms::smb::{Negotiate, parse_negotiate};
///
/// // An SMB1 server refusing every offered dialect.
/// let mut msg = b"\xffSMB\x72".to_vec();
/// msg.extend_from_slice(&[0; 4]);         // STATUS_SUCCESS
/// msg.extend_from_slice(&[0x98, 0x01, 0xc8]);
/// msg.extend_from_slice(&[0; 20]);
/// msg.extend_from_slice(&[1, 0xff, 0xff, 0, 0]); // WordCount 1, DialectIndex 0xffff
/// let mut reply = vec![0, 0, 0, msg.len() as u8];
/// reply.extend_from_slice(&msg);
/// let Negotiate::Smb1(neg) = parse_negotiate(&reply)? else { unreachable!() };
/// assert!(!neg.accepted());
/// # Ok::<(), rune_probe_ms::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the whole message has arrived, and
/// [`Error::Malformed`] when it is not an SMB `NEGOTIATE` response.
pub fn parse_negotiate(bytes: &[u8]) -> Result<Negotiate, Error> {
    let (msg, _) = split_message(bytes)?;
    // The NetBIOS length says the message is complete: anything short
    // inside it is malformed.
    let complete = |e: Error| match e {
        Error::Truncated { what } => Error::malformed(what, "field overruns the message"),
        e @ Error::Malformed { .. } => e,
    };
    match msg.get(..4) {
        Some(m) if m == SMB2_MAGIC => parse_smb2(msg).map_err(complete),
        Some(m) if m == SMB1_MAGIC => parse_smb1(msg).map_err(complete),
        _ => Err(Error::malformed(WHAT, "no SMB signature")),
    }
}

fn parse_smb2(msg: &[u8]) -> Result<Negotiate, Error> {
    let mut h = Reader::new(msg, WHAT);
    h.take(4)?;
    if h.u16_le()? != 64 {
        return Err(Error::malformed(WHAT, "SMB2 header size"));
    }
    h.take(2)?;
    let status = h.u32_le()?;
    let command = h.u16_le()?;
    if command != 0 {
        return Err(Error::malformed(WHAT, format!("SMB2 command {command}")));
    }
    if status != 0 {
        return Ok(Negotiate::Status {
            smb1: false,
            status,
        });
    }
    let body = msg.get(SMB2_HEADER_LEN..).unwrap_or_default();
    let mut r = Reader::new(body, WHAT);
    if r.u16_le()? != 65 {
        return Err(Error::malformed(WHAT, "NEGOTIATE response size"));
    }
    let security_mode = r.u16_le()?;
    let dialect = r.u16_le()?;
    let context_count = r.u16_le()?;
    let server_guid = r.array::<16>()?;
    let capabilities = r.u32_le()?;
    let max_transact_size = r.u32_le()?;
    let max_read_size = r.u32_le()?;
    let max_write_size = r.u32_le()?;
    let system_time = r.u64_le()?;
    let server_start_time = r.u64_le()?;
    let blob_offset = usize::from(r.u16_le()?);
    let blob_len = usize::from(r.u16_le()?);
    let context_offset = r.u32_le()? as usize;
    let blob = msg
        .get(blob_offset..blob_offset + blob_len)
        .ok_or_else(|| Error::malformed(WHAT, "security buffer out of bounds"))?;
    let mut out = Smb2Negotiate {
        dialect,
        security_mode,
        server_guid,
        capabilities,
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time,
        server_start_time,
        mechanisms: mechanisms(blob),
        ..Smb2Negotiate::default()
    };
    if dialect == Dialect::SMB_3_1_1.0 && context_count > 0 {
        parse_contexts(msg, context_offset, context_count, &mut out)?;
    }
    Ok(Negotiate::Smb2(out))
}

fn parse_contexts(
    msg: &[u8],
    offset: usize,
    count: u16,
    out: &mut Smb2Negotiate,
) -> Result<(), Error> {
    let mut at = offset;
    for _ in 0..count.min(16) {
        at = at.next_multiple_of(8);
        let mut r = Reader::new(msg.get(at..).unwrap_or_default(), WHAT);
        let kind = r.u16_le()?;
        let len = usize::from(r.u16_le()?);
        r.take(4)?;
        let data = r.take(len)?;
        let mut d = Reader::new(data, WHAT);
        let list = |d: &mut Reader<'_>, skip: usize| -> Result<Vec<u16>, Error> {
            let n = d.u16_le()?;
            d.take(skip)?;
            (0..n.min(32)).map(|_| d.u16_le()).collect()
        };
        match kind {
            1 => out.preauth_hashes = list(&mut d, 2)?,
            2 => out.ciphers = list(&mut d, 0)?,
            8 => out.signing_algorithms = list(&mut d, 0)?,
            _ => {}
        }
        at += 8 + len;
    }
    Ok(())
}

fn utf16z(r: &mut Reader<'_>) -> Option<String> {
    let mut units = Vec::new();
    while let Ok(unit) = r.u16_le() {
        if unit == 0 {
            break;
        }
        units.push(unit);
        if units.len() >= 128 {
            break;
        }
    }
    let s = String::from_utf16_lossy(&units);
    (!s.is_empty()).then(|| text(s.as_bytes()))
}

fn parse_smb1(msg: &[u8]) -> Result<Negotiate, Error> {
    let mut h = Reader::new(msg, WHAT);
    h.take(4)?;
    let command = h.u8()?;
    if command != SMB1_COM_NEGOTIATE {
        return Err(Error::malformed(
            WHAT,
            format!("SMB1 command {command:#04x}"),
        ));
    }
    let status = h.u32_le()?;
    h.u8()?;
    let flags2 = h.u16_le()?;
    if status != 0 {
        return Ok(Negotiate::Status { smb1: true, status });
    }
    let mut r = Reader::new(msg.get(SMB1_HEADER_LEN..).unwrap_or_default(), WHAT);
    let words = usize::from(r.u8()?);
    let mut w = Reader::new(r.take(words * 2)?, WHAT);
    let dialect_index = w.u16_le()?;
    let mut out = Smb1Negotiate {
        dialect_index,
        ..Smb1Negotiate::default()
    };
    if words < 17 {
        // Only DialectIndex (no dialect accepted) or an LM-era reply.
        return Ok(Negotiate::Smb1(out));
    }
    out.security_mode = w.u8()?;
    w.take(2 + 2 + 4 + 4 + 4)?; // MaxMpxCount, MaxNumberVcs, MaxBufferSize, MaxRawSize, SessionKey
    out.capabilities = w.u32_le()?;
    out.system_time = w.u64_le()?;
    w.take(2)?; // ServerTimeZone
    let challenge_len = usize::from(w.u8()?);
    let byte_count = usize::from(r.u16_le()?);
    let rest = r.rest();
    let bytes = rest.get(..byte_count).unwrap_or(rest);
    let mut b = Reader::new(bytes, WHAT);
    if out.capabilities & SMB1_CAP_EXTENDED_SECURITY != 0 {
        out.server_guid = Some(b.array::<16>()?);
        out.mechanisms = mechanisms(b.rest());
    } else {
        b.take(challenge_len)?;
        if flags2 & SMB1_FLAGS2_UNICODE != 0 {
            out.domain = utf16z(&mut b);
            out.server_name = utf16z(&mut b);
        } else {
            out.domain = b.cstr().ok().map(text).filter(|s| !s.is_empty());
            out.server_name = b.cstr().ok().map(text).filter(|s| !s.is_empty());
        }
    }
    Ok(Negotiate::Smb1(out))
}

/// Seconds since the Unix epoch of a FILETIME, if it is after 1970.
const fn filetime_unix(filetime: u64) -> Option<u64> {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    (filetime / 10_000_000).checked_sub(EPOCH_DIFF)
}

/// Name of a cipher id from the encryption context.
const fn cipher_name(id: u16) -> &'static str {
    match id {
        1 => "AES-128-CCM",
        2 => "AES-128-GCM",
        3 => "AES-256-CCM",
        4 => "AES-256-GCM",
        _ => "unknown",
    }
}

/// Name of a signing algorithm id from the signing context.
const fn signing_algorithm_name(id: u16) -> &'static str {
    match id {
        0 => "HMAC-SHA256",
        1 => "AES-CMAC",
        2 => "AES-GMAC",
        _ => "unknown",
    }
}

fn signing_finding(
    target: &Target,
    signing: Signing,
    dialect: &str,
) -> rune_service_probe::rune_finding::Finding {
    target
        .finding(
            "smb.signing_not_required",
            "SMB signing is not required",
            Severity::Medium,
            Confidence::Certain,
        )
        .push_taxonomy(TaxonomyRef::cwe(345))
        .push_evidence(Evidence::new("signing", signing.as_str()))
        .push_evidence(Evidence::new("dialect", dialect))
        .with_remediation(Remediation::new(
            "Require SMB signing (Windows: \"Microsoft network server: Digitally sign communications (always)\"; Samba: `server signing = mandatory`) to stop NTLM relay and tampering.",
        ))
}

/// Read-only SMB 2/3 probe: one `NEGOTIATE`, no session.
///
/// Reports the dialect the server picked (`smb.dialect`, the highest it
/// shares with a modern client), the signing policy (`smb.signing`), the
/// server GUID, the server clock, the 3.1.1 cipher and signing algorithm
/// choices, and as capabilities the dialect (`dialect:3.1.1`), the
/// `SMB2_GLOBAL_CAP_*` flags (`cap:encryption`), the ciphers
/// (`cipher:AES-128-GCM`) and the authentication mechanisms in the
/// security buffer (`auth:kerberos`, `auth:ntlmssp`).
///
/// | Check id                     | When                                                             |
/// | ---------------------------- | ---------------------------------------------------------------- |
/// | `smb.signing_not_required`   | signing is enabled or disabled but not required: NTLM relay (CWE-345) |
/// | `smb.no_encryption_dialect`  | the best common dialect is SMB 2.x, which cannot encrypt (CWE-319) |
///
/// A server that answers SMB1 instead (SMB 2 unsupported) is reported as
/// for [`Smb1Probe`], with `smb.smb1_enabled`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SmbProbe;

impl SmbProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for SmbProbe {
    fn id(&self) -> &'static str {
        ID_SMB
    }

    fn default_ports(&self) -> &[u16] {
        &[445]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            id: ID_SMB,
            request: negotiate_request(),
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

/// Read-only SMB1 probe: an `SMB_COM_NEGOTIATE` offering only `NT LM 0.12`.
///
/// A server that accepts the dialect has SMB1 enabled, the protocol of
/// `EternalBlue` and `WannaCry` that Microsoft deprecated in 2014. The reply
/// also gives the SMB1 signing policy and, from servers without extended
/// security, the domain or workgroup (`smb.domain`) and server name
/// (`smb.server_name`). A server with SMB1 disabled refuses the dialect
/// (`smb.smb1 = not_accepted`), answers with an error status
/// (`smb.smb1 = refused`), or (current Windows) resets the connection,
/// which surfaces as [`rune_service_probe::Error::NoResponse`].
///
/// | Check id                   | When                                                     |
/// | -------------------------- | -------------------------------------------------------- |
/// | `smb.smb1_enabled`         | the server accepted `NT LM 0.12` (CWE-477)                |
/// | `smb.signing_not_required` | SMB1 is enabled without required signing (CWE-345)       |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Smb1Probe;

impl Smb1Probe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for Smb1Probe {
    fn id(&self) -> &'static str {
        ID_SMB1
    }

    fn default_ports(&self) -> &[u16] {
        &[445, 139]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            id: ID_SMB1,
            request: smb1_negotiate_request(),
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

struct Session {
    id: &'static str,
    request: Vec<u8>,
    target: Target,
    buf: Vec<u8>,
}

impl Session {
    fn describe_smb2(&self, neg: &Smb2Negotiate) -> ServiceInfo {
        let dialect = neg.dialect();
        let signing = neg.signing();
        let mut info = ServiceInfo::new(self.id)
            .with_detail("smb.dialect", dialect.to_string())
            .with_detail("smb.signing", signing.as_str())
            .with_detail("smb.server_guid", neg.server_guid_string())
            .with_detail("smb.max_read_size", neg.max_read_size.to_string())
            .push_capability(format!("dialect:{dialect}"));
        if let Some(now) = filetime_unix(neg.system_time) {
            info = info.with_detail("smb.system_time", now.to_string());
        }
        if let Some(boot) = filetime_unix(neg.server_start_time) {
            info = info.with_detail("smb.start_time", boot.to_string());
        }
        for (bit, name) in [
            (0x01, "dfs"),
            (0x02, "leasing"),
            (0x04, "large_mtu"),
            (0x08, "multi_channel"),
            (0x10, "persistent_handles"),
            (0x20, "directory_leasing"),
            (0x40, "encryption"),
            (0x80, "notifications"),
        ] {
            if neg.capabilities & bit != 0 {
                info = info.push_capability(format!("cap:{name}"));
            }
        }
        for &cipher in &neg.ciphers {
            info = info.push_capability(format!("cipher:{}", cipher_name(cipher)));
        }
        if let Some(&cipher) = neg.ciphers.first() {
            info = info.with_detail("smb.cipher", cipher_name(cipher));
        }
        if let Some(&alg) = neg.signing_algorithms.first() {
            info = info.with_detail("smb.signing_algorithm", signing_algorithm_name(alg));
        }
        for mech in &neg.mechanisms {
            info = info.push_capability(format!("auth:{mech}"));
        }
        if signing != Signing::Required {
            info = info.push_finding(signing_finding(&self.target, signing, &dialect.to_string()));
        }
        if !dialect.supports_encryption() {
            info = info.push_finding(
                self.target
                    .finding(
                        "smb.no_encryption_dialect",
                        "SMB server's best dialect cannot encrypt",
                        Severity::Low,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(319))
                    .push_evidence(Evidence::new("dialect", dialect.to_string()))
                    .with_remediation(Remediation::new(
                        "Upgrade the server to SMB 3.x and enable encryption for sensitive shares.",
                    )),
            );
        }
        info
    }

    fn describe_smb1(&self, neg: &Smb1Negotiate) -> ServiceInfo {
        let mut info = ServiceInfo::new(self.id);
        if !neg.accepted() {
            return info.with_detail("smb.smb1", "not_accepted");
        }
        let signing = neg.signing();
        info = info
            .with_detail("smb.smb1", "enabled")
            .with_detail("smb.dialect", "NT LM 0.12")
            .with_detail("smb.signing", signing.as_str())
            .push_capability("dialect:NT LM 0.12");
        if let Some(guid) = &neg.server_guid {
            info = info.with_detail("smb.server_guid", guid_string(guid));
        }
        if let Some(domain) = &neg.domain {
            info = info.with_detail("smb.domain", domain.clone());
        }
        if let Some(name) = &neg.server_name {
            info = info.with_detail("smb.server_name", name.clone());
        }
        if let Some(now) = filetime_unix(neg.system_time) {
            info = info.with_detail("smb.system_time", now.to_string());
        }
        for mech in &neg.mechanisms {
            info = info.push_capability(format!("auth:{mech}"));
        }
        info = info.push_finding(
            self.target
                .finding(
                    "smb.smb1_enabled",
                    "SMBv1 is enabled",
                    Severity::Medium,
                    Confidence::Certain,
                )
                .push_taxonomy(TaxonomyRef::cwe(477))
                .push_evidence(Evidence::new("dialect", "NT LM 0.12"))
                .with_remediation(Remediation::new(
                    "Disable SMBv1 (Windows: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`; Samba: `server min protocol = SMB2_10`).",
                )),
        );
        if signing != Signing::Required {
            info = info.push_finding(signing_finding(&self.target, signing, "NT LM 0.12"));
        }
        info
    }
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        Action::Send(std::mem::take(&mut self.request))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.buf.extend_from_slice(data);
        match parse_negotiate(&self.buf) {
            Err(e) if e.is_truncated() => Action::Receive,
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if self.buf.is_empty() {
            return Err(rune_service_probe::Error::no_response(self.id));
        }
        let neg = parse_negotiate(&self.buf).map_err(|e| e.into_probe_error(self.id))?;
        Ok(match neg {
            Negotiate::Smb2(neg) => {
                let info = self.describe_smb2(&neg);
                if self.id == ID_SMB1 {
                    // Answered SMB1 with SMB2: SMB1 is off.
                    info.with_detail("smb.smb1", "not_accepted")
                } else {
                    info
                }
            }
            Negotiate::Smb1(neg) => self.describe_smb1(&neg),
            Negotiate::Status { smb1, status } => {
                let info = ServiceInfo::new(self.id)
                    .with_detail("smb.negotiate_status", format!("{status:#010x}"));
                if smb1 && self.id == ID_SMB1 {
                    info.with_detail("smb.smb1", "refused")
                } else {
                    info
                }
            }
        })
    }
}

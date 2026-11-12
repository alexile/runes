//! Microsoft SQL Server: the TDS `PRELOGIN` exchange.
//!
//! See [MS-TDS §2.2.6.5 PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868).
//! The client opens with a `PRELOGIN` packet listing its version and
//! encryption preference; the server answers with its own version and
//! encryption setting before any login. [`MssqlProbe`] sends a client
//! `PRELOGIN` that asks for no encryption (`ENCRYPT_OFF`), so the answer
//! tells whether the server supports, or insists on, TLS.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, End, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::Error;
use crate::wire::Reader;

const WHAT: &str = "tds prelogin";

/// TDS packet type of a client `PRELOGIN`.
pub const PACKET_PRELOGIN: u8 = 0x12;
/// TDS packet type of a server response (tabular result).
pub const PACKET_RESPONSE: u8 = 0x04;
/// TDS packet status: end of message.
pub const STATUS_EOM: u8 = 0x01;

const TOKEN_VERSION: u8 = 0x00;
const TOKEN_ENCRYPTION: u8 = 0x01;
const TOKEN_INSTOPT: u8 = 0x02;
const TOKEN_THREADID: u8 = 0x03;
const TOKEN_MARS: u8 = 0x04;
const TOKEN_TERMINATOR: u8 = 0xff;

/// Largest response accepted, over all its TDS packets.
const MAX_RESPONSE: usize = 8 * 1024;

/// The encryption setting in a `PRELOGIN` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encryption {
    /// `ENCRYPT_OFF`: TLS is available but only the login packet is
    /// encrypted.
    Off,
    /// `ENCRYPT_ON`: the whole connection is encrypted.
    On,
    /// `ENCRYPT_NOT_SUP`: no TLS at all; the login, password included, is
    /// only obfuscated.
    NotSupported,
    /// `ENCRYPT_REQ`: the server requires encryption.
    Required,
    /// Any other value.
    Other(u8),
}

impl Encryption {
    /// Decode the option byte. The `ENCRYPT_CLIENT_CERT` flag (`0x80`) is
    /// ignored.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte & 0x7f {
            0 => Self::Off,
            1 => Self::On,
            2 => Self::NotSupported,
            3 => Self::Required,
            _ => Self::Other(byte),
        }
    }

    /// A short name: `off`, `on`, `not_supported`, `required`, `other`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::NotSupported => "not_supported",
            Self::Required => "required",
            Self::Other(_) => "other",
        }
    }

    /// What the setting means for [`ServiceInfo::tls`].
    #[must_use]
    pub const fn tls_support(self) -> TlsSupport {
        match self {
            Self::Off => TlsSupport::Optional,
            Self::On | Self::Required => TlsSupport::Required,
            Self::NotSupported => TlsSupport::NotOffered,
            Self::Other(_) => TlsSupport::Unknown,
        }
    }
}

/// The server version in a `PRELOGIN` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct Version {
    /// Major version, e.g. 16 for SQL Server 2022.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Build number.
    pub build: u16,
    /// Sub-build number.
    pub sub_build: u16,
}

impl Version {
    /// The product release, e.g. `2019`, or `None` for an unknown major
    /// version.
    ///
    #[must_use]
    pub const fn release(self) -> Option<&'static str> {
        Some(match (self.major, self.minor) {
            (17, _) => "2025",
            (16, _) => "2022",
            (15, _) => "2019",
            (14, _) => "2017",
            (13, _) => "2016",
            (12, _) => "2014",
            (11, _) => "2012",
            (10, 50) => "2008 R2",
            (10, _) => "2008",
            (9, _) => "2005",
            (8, _) => "2000",
            (7, _) => "7.0",
            _ => return None,
        })
    }

    /// True for releases out of Microsoft's extended support as of late
    /// 2026: SQL Server 2016 (13.x) and older.
    #[must_use]
    pub const fn is_out_of_support(self) -> bool {
        self.major <= 13
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)?;
        if self.sub_build != 0 {
            write!(f, ".{}", self.sub_build)?;
        }
        Ok(())
    }
}

/// A parsed server `PRELOGIN` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Prelogin {
    /// `VERSION`.
    pub version: Option<Version>,
    /// `ENCRYPTION`.
    pub encryption: Option<Encryption>,
    /// `INSTOPT`: 0 when the instance name matched.
    pub instance_ok: Option<bool>,
    /// `MARS`: multiple active result sets enabled.
    pub mars: Option<bool>,
    /// Option tokens present, in the server's order.
    pub tokens: Vec<u8>,
}

/// The client `PRELOGIN` packet [`MssqlProbe`] sends: version 0.0.0,
/// `ENCRYPT_OFF`, default instance, thread id 0, MARS off.
///
/// ```
/// let packet = rune_probe_sql::mssql::prelogin_request();
/// assert_eq!(&packet[..4], &[0x12, 0x01, 0x00, 47]);
/// ```
#[must_use]
pub fn prelogin_request() -> Vec<u8> {
    let options: [(u8, &[u8]); 5] = [
        (TOKEN_VERSION, &[0, 0, 0, 0, 0, 0]),
        (TOKEN_ENCRYPTION, &[0]),
        (TOKEN_INSTOPT, &[0]),
        (TOKEN_THREADID, &[0, 0, 0, 0]),
        (TOKEN_MARS, &[0]),
    ];
    let mut header = Vec::new();
    let mut data = Vec::new();
    let table_len = options.len() * 5 + 1;
    for (token, value) in options {
        let offset = u16::try_from(table_len + data.len()).unwrap_or(u16::MAX);
        let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
        header.push(token);
        header.extend_from_slice(&offset.to_be_bytes());
        header.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(value);
    }
    header.push(TOKEN_TERMINATOR);
    header.extend_from_slice(&data);
    let total = u16::try_from(header.len() + 8).unwrap_or(u16::MAX);
    let mut packet = vec![PACKET_PRELOGIN, STATUS_EOM];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]); // SPID, packet id, window
    packet.extend_from_slice(&header);
    packet
}

/// Join the payloads of the TDS packets at the start of `bytes`, up to
/// and including the one marked end-of-message.
///
/// # Errors
///
/// [`Error::Truncated`] until the end-of-message packet has arrived, and
/// [`Error::Malformed`] for a packet that is not a server response.
pub fn reassemble(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(bytes, WHAT);
    let mut payload = Vec::new();
    loop {
        let kind = r.u8()?;
        if kind != PACKET_RESPONSE {
            return Err(Error::malformed(WHAT, format!("packet type {kind:#04x}")));
        }
        let status = r.u8()?;
        let len = usize::from(r.u16_be()?);
        if len < 8 {
            return Err(Error::malformed(WHAT, format!("packet length {len}")));
        }
        r.take(4)?;
        payload.extend_from_slice(r.take(len - 8)?);
        if payload.len() > MAX_RESPONSE {
            return Err(Error::malformed(WHAT, "response too long"));
        }
        if status & STATUS_EOM != 0 {
            return Ok(payload);
        }
    }
}

/// Parse a server `PRELOGIN` response, starting at the TDS packet header.
///
/// ```
/// use rune_probe_sql::mssql::{Encryption, parse_response};
///
/// // SQL Server 2019 (15.0.2000), ENCRYPT_OFF.
/// let reply = [
///     0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00,
///     0x00, 0x00, 0x15, 0x00, 0x06,
///     0x01, 0x00, 0x1b, 0x00, 0x01,
///     0x02, 0x00, 0x1c, 0x00, 0x01,
///     0x03, 0x00, 0x1d, 0x00, 0x00,
///     0xff,
///     0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00,
///     0x00,
///     0x00,
/// ];
/// let prelogin = parse_response(&reply)?;
/// assert_eq!(prelogin.version.unwrap().to_string(), "15.0.2000");
/// assert_eq!(prelogin.encryption, Some(Encryption::Off));
/// # Ok::<(), rune_probe_sql::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the whole response has arrived, and
/// [`Error::Malformed`] when it is not a `PRELOGIN` response.
pub fn parse_response(bytes: &[u8]) -> Result<Prelogin, Error> {
    let payload = reassemble(bytes)?;
    let mut table = Reader::new(&payload, WHAT);
    let mut out = Prelogin::default();
    loop {
        let token = table
            .u8()
            .map_err(|_| Error::malformed(WHAT, "option table without terminator"))?;
        if token == TOKEN_TERMINATOR {
            break;
        }
        let (Ok(offset), Ok(len)) = (table.u16_be(), table.u16_be()) else {
            return Err(Error::malformed(WHAT, "truncated option table"));
        };
        let start = usize::from(offset);
        let value = payload
            .get(start..start + usize::from(len))
            .ok_or_else(|| Error::malformed(WHAT, format!("option {token:#04x} out of bounds")))?;
        if out.tokens.len() >= 32 {
            return Err(Error::malformed(WHAT, "too many options"));
        }
        out.tokens.push(token);
        match (token, value) {
            (TOKEN_VERSION, [major, minor, b0, b1, s0, s1, ..]) => {
                out.version = Some(Version {
                    major: *major,
                    minor: *minor,
                    build: u16::from_be_bytes([*b0, *b1]),
                    sub_build: u16::from_be_bytes([*s0, *s1]),
                });
            }
            (TOKEN_ENCRYPTION, [byte, ..]) => out.encryption = Some(Encryption::from_byte(*byte)),
            (TOKEN_INSTOPT, [byte, ..]) => out.instance_ok = Some(*byte == 0),
            (TOKEN_MARS, [byte, ..]) => out.mars = Some(*byte != 0),
            _ => {}
        }
    }
    if out.version.is_none() {
        return Err(Error::malformed(WHAT, "no VERSION option"));
    }
    Ok(out)
}

/// Read-only MSSQL probe: sends a `PRELOGIN` and reads the answer.
///
/// Reports the version (`15.0.2000`), the product release under
/// `mssql.release` (`2019`), and the encryption setting under
/// `mssql.encryption` and as [`ServiceInfo::tls`]. Never logs in, so
/// [`ServiceInfo::auth`] stays unknown.
///
/// | Check id                       | When                                                         |
/// | ------------------------------ | ------------------------------------------------------------ |
/// | `mssql.encryption_not_supported` | `ENCRYPT_NOT_SUP`: logins cross the network unencrypted (CWE-319) |
/// | `mssql.unsupported_version`    | SQL Server 2016 or older, out of extended support (CWE-1104) |
///
/// Azure SQL Database reports version 12 for every server; the
/// unsupported-version finding is therefore only tentative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MssqlProbe;

impl MssqlProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for MssqlProbe {
    fn id(&self) -> &'static str {
        "mssql"
    }

    fn default_ports(&self) -> &[u16] {
        &[1433]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(MssqlSession {
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

struct MssqlSession {
    target: Target,
    buf: Vec<u8>,
}

impl ProbeSession for MssqlSession {
    fn start(&mut self) -> Action {
        Action::Send(prelogin_request())
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.buf.extend_from_slice(data);
        match parse_response(&self.buf) {
            Err(e) if e.is_truncated() => Action::Receive,
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if self.buf.is_empty() {
            return Err(rune_service_probe::Error::no_response("mssql"));
        }
        let prelogin = parse_response(&self.buf).map_err(|e| e.into_probe_error("mssql"))?;
        let mut info = ServiceInfo::new("mssql").with_product("Microsoft SQL Server");
        if let Some(version) = prelogin.version {
            info = info.with_version(version.to_string());
            if let Some(release) = version.release() {
                info = info.with_detail("mssql.release", release);
            }
            if version.is_out_of_support() && version.major >= 7 {
                info = info.push_finding(
                    self.target
                        .finding(
                            "mssql.unsupported_version",
                            "SQL Server release is out of support",
                            Severity::Medium,
                            Confidence::Tentative,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(1104))
                        .push_evidence(Evidence::new("version", version.to_string()))
                        .with_remediation(Remediation::new(
                            "Upgrade to a supported SQL Server release.",
                        )),
                );
            }
        }
        if let Some(encryption) = prelogin.encryption {
            info = info
                .with_tls(encryption.tls_support())
                .with_detail("mssql.encryption", encryption.as_str());
            if encryption == Encryption::NotSupported {
                info = info.push_finding(
                    self.target
                        .finding(
                            "mssql.encryption_not_supported",
                            "SQL Server does not support encryption",
                            Severity::Medium,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(319))
                        .push_evidence(Evidence::new("prelogin_encryption", "ENCRYPT_NOT_SUP"))
                        .with_remediation(Remediation::new(
                            "Install a certificate for SQL Server and enable Force Encryption.",
                        )),
                );
            }
        }
        if let Some(mars) = prelogin.mars {
            info = info.with_detail("mssql.mars", mars.to_string());
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    /// A server PRELOGIN response with the given version and encryption.
    fn response(version: [u8; 6], encryption: u8) -> Vec<u8> {
        let mut payload = vec![
            0x00, 0x00, 0x15, 0x00, 0x06, //
            0x01, 0x00, 0x1b, 0x00, 0x01, //
            0x02, 0x00, 0x1c, 0x00, 0x01, //
            0x03, 0x00, 0x1d, 0x00, 0x00, //
            0xff,
        ];
        payload.extend_from_slice(&version);
        payload.push(encryption);
        payload.push(0);
        let mut packet = vec![PACKET_RESPONSE, STATUS_EOM];
        packet.extend_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0, 0, 1, 0]);
        packet.extend_from_slice(&payload);
        packet
    }

    fn run(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &MssqlProbe,
            &Target::new("sql.test", 1433),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    #[test]
    fn request_is_well_formed() {
        let req = prelogin_request();
        assert_eq!(req.len(), 47);
        assert_eq!(usize::from(u16::from_be_bytes([req[2], req[3]])), req.len());
        // VERSION at offset 26, length 6; ENCRYPTION at 32 = ENCRYPT_OFF.
        assert_eq!(&req[8..13], &[0x00, 0x00, 26, 0x00, 6]);
        assert_eq!(req[8 + 32], 0);
        assert_eq!(req[8 + 25], TOKEN_TERMINATOR);
    }

    #[test]
    fn sql_server_2022_required_encryption() {
        let reply = response([16, 0, 0x10, 0x87, 0, 0], 3);
        let sim = run(&[&reply[..5], &reply[5..]]);
        assert_eq!(sim.sent, [prelogin_request()]);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.version.as_deref(), Some("16.0.4231"));
        assert_eq!(info.details["mssql.release"], "2022");
        assert_eq!(info.details["mssql.encryption"], "required");
        assert_eq!(info.tls, TlsSupport::Required);
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn old_server_without_encryption() {
        let reply = response([10, 50, 0x06, 0x40, 0, 0], 2);
        let info = run(&[&reply]).result.unwrap();
        assert_eq!(info.details["mssql.release"], "2008 R2");
        assert_eq!(info.tls, TlsSupport::NotOffered);
        let ids: Vec<_> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "mssql.unsupported_version",
                "mssql.encryption_not_supported"
            ]
        );
    }

    #[test]
    fn encryption_off_is_optional() {
        let info = run(&[&response([15, 0, 0x07, 0xd0, 0, 0], 0)])
            .result
            .unwrap();
        assert_eq!(info.tls, TlsSupport::Optional);
        assert_eq!(info.version.as_deref(), Some("15.0.2000"));
        assert_eq!(Encryption::from_byte(0x81), Encryption::On);
    }

    #[test]
    fn multi_packet_response() {
        let full = response([14, 0, 0x03, 0xe8, 0, 1], 1);
        let payload = &full[8..];
        let (p1, p2) = (&payload[..10], &payload[10..]);
        let mut bytes = vec![
            PACKET_RESPONSE,
            0,
            0,
            u8::try_from(p1.len() + 8).unwrap(),
            0,
            0,
            1,
            0,
        ];
        bytes.extend_from_slice(p1);
        bytes.extend_from_slice(&[
            PACKET_RESPONSE,
            STATUS_EOM,
            0,
            u8::try_from(p2.len() + 8).unwrap(),
            0,
            0,
            2,
            0,
        ]);
        bytes.extend_from_slice(p2);
        let prelogin = parse_response(&bytes).unwrap();
        assert_eq!(prelogin.version.unwrap().to_string(), "14.0.1000.1");
        assert_eq!(prelogin.encryption, Some(Encryption::On));
    }

    #[test]
    fn rejects_other_protocols_and_bad_offsets() {
        assert!(run(&[b"HTTP/1.1 400 Bad Request\r\n"]).result.is_err());
        assert!(matches!(
            run(&[]).result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
        let mut reply = response([15, 0, 0, 0, 0, 0], 0);
        reply[8 + 2] = 0xf0; // VERSION offset past the payload
        assert!(matches!(
            parse_response(&reply),
            Err(Error::Malformed { .. })
        ));
        assert!(parse_response(&reply[..6]).unwrap_err().is_truncated());
    }
}

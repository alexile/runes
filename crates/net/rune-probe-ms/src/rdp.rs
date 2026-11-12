//! RDP: the X.224 connection request and its security-protocol
//! negotiation.
//!
//! See [MS-RDPBCGR §2.2.1.1/§2.2.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10).
//! The client's first packet, a TPKT-framed X.224 Connection Request,
//! carries `RDP_NEG_REQ` with the security protocols it supports; the
//! server's Connection Confirm names the one it picked (`RDP_NEG_RSP`) or
//! says why it refuses them all (`RDP_NEG_FAILURE`). Nothing is
//! authenticated yet: the probe reads the confirm and disconnects.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::Error;
use crate::wire::Reader;

const WHAT: &str = "rdp connection confirm";
const ID: &str = "rdp";

const TPKT_VERSION: u8 = 3;
const X224_CONNECTION_REQUEST: u8 = 0xe0;
const X224_CONNECTION_CONFIRM: u8 = 0xd0;
const TYPE_RDP_NEG_REQ: u8 = 1;
const TYPE_RDP_NEG_RSP: u8 = 2;
const TYPE_RDP_NEG_FAILURE: u8 = 3;

/// A set of RDP security protocols (`requestedProtocols`,
/// `selectedProtocol`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Protocols(pub u32);

impl Protocols {
    /// `PROTOCOL_RDP` (0): Standard RDP Security, RC4-based, no TLS.
    pub const RDP: Self = Self(0);
    /// `PROTOCOL_SSL`: TLS, with logon at the remote desktop.
    pub const SSL: Self = Self(0x01);
    /// `PROTOCOL_HYBRID`: `CredSSP` over TLS, i.e. Network Level
    /// Authentication.
    pub const HYBRID: Self = Self(0x02);
    /// `PROTOCOL_RDSTLS`.
    pub const RDSTLS: Self = Self(0x04);
    /// `PROTOCOL_HYBRID_EX`: `CredSSP` with the Early User Authorization
    /// Result PDU.
    pub const HYBRID_EX: Self = Self(0x08);
    /// `PROTOCOL_RDSAAD`: Azure AD authentication.
    pub const RDSAAD: Self = Self(0x10);

    /// True when every protocol in `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when the set uses `CredSSP` (NLA): `HYBRID` or `HYBRID_EX`.
    #[must_use]
    pub const fn is_nla(self) -> bool {
        self.0 & (Self::HYBRID.0 | Self::HYBRID_EX.0) != 0
    }

    /// The names of the protocols in the set, e.g. `["ssl", "hybrid"]`;
    /// `["rdp"]` for the empty set (Standard RDP Security).
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        if self.0 == 0 {
            return vec!["rdp"];
        }
        let mut out = Vec::new();
        for (bit, name) in [
            (Self::SSL, "ssl"),
            (Self::HYBRID, "hybrid"),
            (Self::RDSTLS, "rdstls"),
            (Self::HYBRID_EX, "hybrid_ex"),
            (Self::RDSAAD, "rdsaad"),
        ] {
            if self.contains(bit) {
                out.push(name);
            }
        }
        if self.0 & !0x1f != 0 {
            out.push("unknown");
        }
        out
    }
}

impl std::fmt::Display for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.names().join("|"))
    }
}

/// An `RDP_NEG_FAILURE` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureCode {
    /// `SSL_REQUIRED_BY_SERVER`: TLS is required, NLA is not.
    SslRequired,
    /// `SSL_NOT_ALLOWED_BY_SERVER`: only Standard RDP Security.
    SslNotAllowed,
    /// `SSL_CERT_NOT_ON_SERVER`.
    SslCertNotOnServer,
    /// `INCONSISTENT_FLAGS`.
    InconsistentFlags,
    /// `HYBRID_REQUIRED_BY_SERVER`: NLA is required.
    HybridRequired,
    /// `SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER`.
    SslWithUserAuthRequired,
    /// Any other code.
    Other(u32),
}

impl FailureCode {
    /// Decode the failure code.
    #[must_use]
    pub const fn from_u32(code: u32) -> Self {
        match code {
            1 => Self::SslRequired,
            2 => Self::SslNotAllowed,
            3 => Self::SslCertNotOnServer,
            4 => Self::InconsistentFlags,
            5 => Self::HybridRequired,
            6 => Self::SslWithUserAuthRequired,
            other => Self::Other(other),
        }
    }

    /// The code's name in MS-RDPBCGR, lowercase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SslRequired => "ssl_required_by_server",
            Self::SslNotAllowed => "ssl_not_allowed_by_server",
            Self::SslCertNotOnServer => "ssl_cert_not_on_server",
            Self::InconsistentFlags => "inconsistent_flags",
            Self::HybridRequired => "hybrid_required_by_server",
            Self::SslWithUserAuthRequired => "ssl_with_user_auth_required_by_server",
            Self::Other(_) => "other",
        }
    }
}

/// The negotiation outcome in a Connection Confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Negotiation {
    /// `RDP_NEG_RSP`: the server picked `protocol`.
    Selected {
        /// `selectedProtocol`.
        protocol: Protocols,
        /// The response flags (`EXTENDED_CLIENT_DATA_SUPPORTED`,
        /// `DYNVC_GFX_PROTOCOL_SUPPORTED`, `RESTRICTED_ADMIN_MODE_SUPPORTED`,
        /// `REDIRECTED_AUTHENTICATION_MODE_SUPPORTED`).
        flags: u8,
    },
    /// `RDP_NEG_FAILURE`: the server refuses every requested protocol.
    Failure(FailureCode),
    /// No negotiation data: a server older than Windows Server 2003 SP1
    /// that only speaks Standard RDP Security.
    Legacy,
}

/// The X.224 Connection Request [`RdpProbe`] sends for `requested`, with
/// its TPKT header and no routing cookie.
///
/// ```
/// use rune_probe_ms::rdp::{Protocols, connection_request};
///
/// assert_eq!(
///     connection_request(Protocols::RDP),
///     [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0],
/// );
/// ```
#[must_use]
pub fn connection_request(requested: Protocols) -> Vec<u8> {
    let mut out = vec![TPKT_VERSION, 0, 0, 19];
    // X.224: length indicator, CR, DST-REF, SRC-REF, class 0.
    out.extend_from_slice(&[14, X224_CONNECTION_REQUEST, 0, 0, 0, 0, 0]);
    // RDP_NEG_REQ.
    out.extend_from_slice(&[TYPE_RDP_NEG_REQ, 0, 8, 0]);
    out.extend_from_slice(&requested.0.to_le_bytes());
    out
}

/// Parse a Connection Confirm, starting at the TPKT header.
///
/// ```
/// use rune_probe_ms::rdp::{FailureCode, Negotiation, parse_confirm};
///
/// // HYBRID_REQUIRED_BY_SERVER: Network Level Authentication is enforced.
/// let reply = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 5, 0, 0, 0];
/// assert_eq!(parse_confirm(&reply)?, Negotiation::Failure(FailureCode::HybridRequired));
/// # Ok::<(), rune_probe_ms::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the whole TPKT has arrived, and
/// [`Error::Malformed`] when it is not an X.224 Connection Confirm.
pub fn parse_confirm(bytes: &[u8]) -> Result<Negotiation, Error> {
    let mut r = Reader::new(bytes, WHAT);
    let version = r.u8()?;
    if version != TPKT_VERSION {
        return Err(Error::malformed(WHAT, format!("TPKT version {version}")));
    }
    r.u8()?;
    let len = usize::from(r.u16_be()?);
    if len < 11 {
        return Err(Error::malformed(WHAT, format!("TPKT length {len}")));
    }
    let tpdu = r.take(len - 4)?;
    let mut t = Reader::new(tpdu, WHAT);
    let complete = |e: Error| match e {
        Error::Truncated { what } => Error::malformed(what, "field overruns the TPKT"),
        e @ Error::Malformed { .. } => e,
    };
    let li = usize::from(t.u8().map_err(complete)?);
    let code = t.u8().map_err(complete)?;
    if code & 0xf0 != X224_CONNECTION_CONFIRM {
        return Err(Error::malformed(WHAT, format!("X.224 code {code:#04x}")));
    }
    if li + 1 > tpdu.len() || li < 6 {
        return Err(Error::malformed(
            WHAT,
            format!("X.224 length indicator {li}"),
        ));
    }
    t.take(5).map_err(complete)?; // DST-REF, SRC-REF, class
    if li < 14 {
        return Ok(Negotiation::Legacy);
    }
    let kind = t.u8().map_err(complete)?;
    let flags = t.u8().map_err(complete)?;
    let neg_len = t.u16_le().map_err(complete)?;
    if neg_len != 8 {
        return Err(Error::malformed(
            WHAT,
            format!("negotiation length {neg_len}"),
        ));
    }
    let value = t.u32_le().map_err(complete)?;
    match kind {
        TYPE_RDP_NEG_RSP => Ok(Negotiation::Selected {
            protocol: Protocols(value),
            flags,
        }),
        TYPE_RDP_NEG_FAILURE => Ok(Negotiation::Failure(FailureCode::from_u32(value))),
        other => Err(Error::malformed(WHAT, format!("negotiation type {other}"))),
    }
}

/// Read-only RDP probe: one X.224 Connection Request, then disconnect.
///
/// By default it requests only Standard RDP Security
/// ([`Protocols::RDP`]), which answers the two questions that matter in
/// one connection: a server that accepts it allows the legacy RC4-based
/// security layer and does not enforce Network Level Authentication; a
/// server that requires TLS answers `SSL_REQUIRED_BY_SERVER`; one that
/// enforces NLA answers `HYBRID_REQUIRED_BY_SERVER`.
/// [`RdpProbe::requesting`] offers another set instead, e.g. to learn
/// which protocol a server prefers or to enumerate them one per
/// connection.
///
/// Reports `rdp.requested`, `rdp.selected_protocol` or `rdp.failure`, the
/// response flags as capabilities (`restricted_admin`, `redirected_auth`,
/// `gfx`, `extended_client_data`), [`ServiceInfo::tls`] and, when NLA is
/// enforced, [`AuthRequirement::Required`].
///
/// | Check id                | When                                                                 |
/// | ----------------------- | -------------------------------------------------------------------- |
/// | `rdp.nla_not_required`  | the server accepted a non-NLA protocol or asked for plain TLS (CWE-306) |
/// | `rdp.standard_security` | the server accepted Standard RDP Security (CWE-327)                  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RdpProbe {
    requested: Protocols,
}

impl Default for RdpProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl RdpProbe {
    /// The probe, requesting Standard RDP Security only.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requested: Protocols::RDP,
        }
    }

    /// The probe, requesting `protocols` instead.
    #[must_use]
    pub const fn requesting(protocols: Protocols) -> Self {
        Self {
            requested: protocols,
        }
    }

    /// The protocols the probe requests.
    #[must_use]
    pub const fn requested(&self) -> Protocols {
        self.requested
    }
}

impl ServiceProbe for RdpProbe {
    fn id(&self) -> &'static str {
        ID
    }

    fn default_ports(&self) -> &[u16] {
        &[3389]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            requested: self.requested,
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

struct Session {
    requested: Protocols,
    target: Target,
    buf: Vec<u8>,
}

impl Session {
    fn nla_finding(&self, evidence: String) -> rune_service_probe::rune_finding::Finding {
        self.target
            .finding(
                "rdp.nla_not_required",
                "RDP does not require Network Level Authentication",
                Severity::Medium,
                Confidence::Certain,
            )
            .push_taxonomy(TaxonomyRef::cwe(306))
            .push_evidence(Evidence::new("negotiation", evidence))
            .with_remediation(Remediation::new(
                "Require Network Level Authentication (\"Require user authentication for remote connections by using Network Level Authentication\").",
            ))
    }

    fn standard_security_finding(&self) -> rune_service_probe::rune_finding::Finding {
        self.target
            .finding(
                "rdp.standard_security",
                "RDP accepts Standard RDP Security",
                Severity::Medium,
                Confidence::Certain,
            )
            .push_taxonomy(TaxonomyRef::cwe(327))
            .push_evidence(Evidence::new("selected_protocol", "PROTOCOL_RDP"))
            .with_remediation(Remediation::new(
                "Set the RDP security layer to TLS (SecurityLayer = 2) and require NLA.",
            ))
    }
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        Action::Send(connection_request(self.requested))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.buf.extend_from_slice(data);
        match parse_confirm(&self.buf) {
            Err(e) if e.is_truncated() => Action::Receive,
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if self.buf.is_empty() {
            return Err(rune_service_probe::Error::no_response(ID));
        }
        let negotiation = parse_confirm(&self.buf).map_err(|e| e.into_probe_error(ID))?;
        let mut info =
            ServiceInfo::new(ID).with_detail("rdp.requested", self.requested.to_string());
        match negotiation {
            Negotiation::Selected { protocol, flags } => {
                info = info.with_detail("rdp.selected_protocol", protocol.to_string());
                for (bit, name) in [
                    (0x01, "extended_client_data"),
                    (0x02, "gfx"),
                    (0x08, "restricted_admin"),
                    (0x10, "redirected_auth"),
                ] {
                    if flags & bit != 0 {
                        info = info.push_capability(name);
                    }
                }
                if protocol == Protocols::RDP {
                    info = info
                        .push_finding(self.nla_finding("PROTOCOL_RDP selected".into()))
                        .push_finding(self.standard_security_finding());
                } else if !protocol.is_nla() {
                    info = info
                        .with_tls(TlsSupport::Required)
                        .push_finding(self.nla_finding(format!("{protocol} selected")));
                } else {
                    info = info.with_tls(TlsSupport::Required);
                }
            }
            Negotiation::Failure(code) => {
                info = info.with_detail("rdp.failure", code.as_str());
                match code {
                    FailureCode::HybridRequired => {
                        info = info
                            .with_tls(TlsSupport::Required)
                            .with_auth(AuthRequirement::Required)
                            .push_capability("nla");
                    }
                    FailureCode::SslRequired | FailureCode::SslWithUserAuthRequired => {
                        info = info
                            .with_tls(TlsSupport::Required)
                            .push_finding(self.nla_finding(code.as_str().to_owned()));
                    }
                    FailureCode::SslNotAllowed => {
                        info = info.with_tls(TlsSupport::NotOffered);
                    }
                    _ => {}
                }
            }
            Negotiation::Legacy => {
                info = info
                    .with_tls(TlsSupport::NotOffered)
                    .with_detail("rdp.selected_protocol", "rdp")
                    .with_detail("rdp.negotiation", "none")
                    .push_finding(self.nla_finding("no negotiation support".into()))
                    .push_finding(self.standard_security_finding());
            }
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    fn confirm(kind: u8, flags: u8, value: u32) -> Vec<u8> {
        let mut out = vec![
            3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, kind, flags, 8, 0,
        ];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    fn run(probe: RdpProbe, replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &probe,
            &Target::new("ts.test", 3389),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    fn ids(info: &ServiceInfo) -> Vec<&str> {
        info.findings.iter().map(|f| f.check_id.as_str()).collect()
    }

    #[test]
    fn nla_enforced() {
        let reply = confirm(TYPE_RDP_NEG_FAILURE, 0, 5);
        let sim = run(RdpProbe::new(), &[&reply[..3], &reply[3..]]);
        assert_eq!(sim.sent, [connection_request(Protocols::RDP)]);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.details["rdp.failure"], "hybrid_required_by_server");
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn standard_security_accepted() {
        let info = run(RdpProbe::new(), &[&confirm(TYPE_RDP_NEG_RSP, 0x1f, 0)])
            .result
            .unwrap();
        assert_eq!(
            ids(&info),
            ["rdp.nla_not_required", "rdp.standard_security"]
        );
        assert_eq!(info.details["rdp.selected_protocol"], "rdp");
        assert_eq!(
            info.capabilities,
            [
                "extended_client_data",
                "gfx",
                "restricted_admin",
                "redirected_auth"
            ]
        );
    }

    #[test]
    fn tls_without_nla() {
        let info = run(RdpProbe::new(), &[&confirm(TYPE_RDP_NEG_FAILURE, 0, 1)])
            .result
            .unwrap();
        assert_eq!(info.tls, TlsSupport::Required);
        assert_eq!(ids(&info), ["rdp.nla_not_required"]);
        let picked = RdpProbe::requesting(Protocols::SSL.union(Protocols::HYBRID));
        let info = run(picked, &[&confirm(TYPE_RDP_NEG_RSP, 0, 1)])
            .result
            .unwrap();
        assert_eq!(info.details["rdp.requested"], "ssl|hybrid");
        assert_eq!(ids(&info), ["rdp.nla_not_required"]);
        let info = run(picked, &[&confirm(TYPE_RDP_NEG_RSP, 0, 2)])
            .result
            .unwrap();
        assert_eq!(info.details["rdp.selected_protocol"], "hybrid");
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn legacy_server_without_negotiation() {
        let reply = [3, 0, 0, 11, 6, 0xd0, 0, 0, 0x12, 0x34, 0];
        let info = run(RdpProbe::new(), &[&reply]).result.unwrap();
        assert_eq!(info.tls, TlsSupport::NotOffered);
        assert_eq!(
            ids(&info),
            ["rdp.nla_not_required", "rdp.standard_security"]
        );
    }

    #[test]
    fn rejects_other_protocols() {
        assert!(
            run(RdpProbe::new(), &[b"SSH-2.0-OpenSSH_9.6\r\n"])
                .result
                .is_err()
        );
        assert!(matches!(
            run(RdpProbe::new(), &[]).result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
        assert!(
            parse_confirm(&[3, 0, 0, 19, 14])
                .unwrap_err()
                .is_truncated()
        );
        // TPKT complete, but the X.224 length indicator overruns it.
        assert!(
            !parse_confirm(&[3, 0, 0, 11, 40, 0xd0, 0, 0, 0, 0, 0])
                .unwrap_err()
                .is_truncated()
        );
        assert_eq!(Protocols(0x40).names(), ["unknown"]);
        assert_eq!(FailureCode::from_u32(9), FailureCode::Other(9));
    }
}

//! MySQL and MariaDB: the server's initial handshake packet.
//!
//! The server speaks first: on connect it sends a
//! [`Protocol::HandshakeV10`](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)
//! greeting with its version string, capability flags and default
//! authentication plugin, or an
//! [`ERR_Packet`](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html)
//! when it refuses the client (host not allowed, too many connections).
//! [`MysqlProbe`] only reads that packet: it sends nothing.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::Error;
use crate::wire::{Reader, text};

const WHAT: &str = "mysql handshake";

/// Largest greeting payload accepted. Real greetings are under 200 bytes;
/// anything far larger is another protocol whose first bytes happen to
/// decode as a big length.
const MAX_GREETING: usize = 16 * 1024;

/// `CLIENT_SSL`: the server can switch the connection to TLS.
pub const CLIENT_SSL: u32 = 1 << 11;
/// `CLIENT_SECURE_CONNECTION`: the 4.1 authentication scramble follows.
pub const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
/// `CLIENT_PLUGIN_AUTH`: the greeting names the authentication plugin.
pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;

/// Names of the capability flags, by bit.
const CAPABILITY_NAMES: [&str; 32] = [
    "CLIENT_LONG_PASSWORD",
    "CLIENT_FOUND_ROWS",
    "CLIENT_LONG_FLAG",
    "CLIENT_CONNECT_WITH_DB",
    "CLIENT_NO_SCHEMA",
    "CLIENT_COMPRESS",
    "CLIENT_ODBC",
    "CLIENT_LOCAL_FILES",
    "CLIENT_IGNORE_SPACE",
    "CLIENT_PROTOCOL_41",
    "CLIENT_INTERACTIVE",
    "CLIENT_SSL",
    "CLIENT_IGNORE_SIGPIPE",
    "CLIENT_TRANSACTIONS",
    "CLIENT_RESERVED",
    "CLIENT_SECURE_CONNECTION",
    "CLIENT_MULTI_STATEMENTS",
    "CLIENT_MULTI_RESULTS",
    "CLIENT_PS_MULTI_RESULTS",
    "CLIENT_PLUGIN_AUTH",
    "CLIENT_CONNECT_ATTRS",
    "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
    "CLIENT_SESSION_TRACK",
    "CLIENT_DEPRECATE_EOF",
    "CLIENT_OPTIONAL_RESULTSET_METADATA",
    "CLIENT_ZSTD_COMPRESSION_ALGORITHM",
    "CLIENT_QUERY_ATTRIBUTES",
    "MULTI_FACTOR_AUTHENTICATION",
    "CLIENT_CAPABILITY_EXTENSION",
    "CLIENT_SSL_VERIFY_SERVER_CERT",
    "CLIENT_REMEMBER_OPTIONS",
];

/// The names of the flags set in `capabilities`, lowest bit first.
///
/// ```
/// use rune_probe_sql::mysql::{CLIENT_SSL, capability_names};
///
/// assert_eq!(capability_names(CLIENT_SSL | 1), ["CLIENT_LONG_PASSWORD", "CLIENT_SSL"]);
/// ```
#[must_use]
pub fn capability_names(capabilities: u32) -> Vec<&'static str> {
    CAPABILITY_NAMES
        .iter()
        .enumerate()
        .filter(|&(bit, _)| capabilities & (1 << bit) != 0)
        .map(|(_, &name)| name)
        .collect()
}

/// A parsed initial handshake (protocol 10, or the ancient protocol 9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Handshake {
    /// Handshake protocol version: `10` (or `9` for MySQL 3.21 and older).
    pub protocol: u8,
    /// The server version string as sent, e.g. `8.0.36` or
    /// `5.5.5-10.11.6-MariaDB-0+deb12u1`, printable and bounded.
    pub server_version: String,
    /// The connection (thread) id.
    pub connection_id: u32,
    /// Capability flags (lower and upper halves combined). Zero for
    /// protocol 9.
    pub capabilities: u32,
    /// MariaDB's extended capability flags, when the server is MariaDB.
    pub mariadb_capabilities: Option<u32>,
    /// The default collation id, if sent.
    pub character_set: Option<u8>,
    /// Server status flags, if sent.
    pub status: Option<u16>,
    /// The default authentication plugin, e.g. `caching_sha2_password`.
    pub auth_plugin: Option<String>,
}

impl Handshake {
    /// True when the server advertises [`CLIENT_SSL`].
    #[must_use]
    pub const fn supports_tls(&self) -> bool {
        self.capabilities & CLIENT_SSL != 0
    }

    /// The product and version the version string identifies.
    ///
    /// ```
    /// use rune_probe_sql::mysql::split_version;
    ///
    /// let (product, version) = split_version("5.5.5-10.11.6-MariaDB-0+deb12u1");
    /// assert_eq!((product, version.as_deref()), ("MariaDB", Some("10.11.6")));
    /// ```
    #[must_use]
    pub fn product_and_version(&self) -> (&'static str, Option<String>) {
        split_version(&self.server_version)
    }
}

/// Identify the product and version in a MySQL-protocol version string.
///
/// MariaDB prefixes `5.5.5-` to stay compatible with old replication
/// clients; `TiDB` reports a MySQL version followed by its own. Percona
/// Server and other MySQL builds are reported as `MySQL`.
#[must_use]
pub fn split_version(raw: &str) -> (&'static str, Option<String>) {
    let numeric = |s: &str| {
        let v: &str = s.split(['-', ' ', '+']).next().unwrap_or_default();
        v.starts_with(|c: char| c.is_ascii_digit())
            .then(|| v.to_owned())
    };
    if raw.to_ascii_lowercase().contains("mariadb") {
        let rest = raw.strip_prefix("5.5.5-").unwrap_or(raw);
        return ("MariaDB", numeric(rest));
    }
    if let Some((_, tidb)) = raw.split_once("-TiDB-") {
        return ("TiDB", numeric(tidb.trim_start_matches('v')));
    }
    ("MySQL", numeric(raw))
}

/// An `ERR_Packet` sent instead of a greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrPacket {
    /// The error code, e.g. `1130` (host not allowed) or `1040` (too many
    /// connections).
    pub code: u16,
    /// The SQLSTATE, when the server sent one.
    pub sql_state: Option<String>,
    /// The error message, printable and bounded.
    pub message: String,
}

/// `ER_HOST_NOT_PRIVILEGED`: the client host may not connect.
pub const ER_HOST_NOT_PRIVILEGED: u16 = 1130;
/// `ER_HOST_IS_BLOCKED`: the client host is blocked after errors.
pub const ER_HOST_IS_BLOCKED: u16 = 1129;

/// What a MySQL server sends first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Greeting {
    /// A handshake: the server accepts the connection.
    Handshake(Handshake),
    /// An error: the server refuses the connection.
    Error(ErrPacket),
}

/// Parse the first packet a MySQL-protocol server sends.
///
/// `bytes` starts at the packet header (3-byte little-endian length,
/// 1-byte sequence id). Extra bytes after the packet are ignored.
///
/// ```
/// use rune_probe_sql::mysql::{Greeting, parse_greeting};
///
/// // An ERR_Packet: code 1130, no SQLSTATE.
/// let mut packet = vec![0x2a, 0, 0, 0, 0xff, 0x6a, 0x04];
/// packet.extend_from_slice(b"Host '192.0.2.7' is not allowed to connect");
/// packet[0] = (packet.len() - 4) as u8;
/// let Greeting::Error(err) = parse_greeting(&packet)? else { panic!() };
/// assert_eq!(err.code, 1130);
/// # Ok::<(), rune_probe_sql::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the whole packet has arrived, and
/// [`Error::Malformed`] when the bytes are not a MySQL greeting.
pub fn parse_greeting(bytes: &[u8]) -> Result<Greeting, Error> {
    let mut r = Reader::new(bytes, WHAT);
    let [l0, l1, l2, seq] = r.array()?;
    let len = usize::from(l0) | usize::from(l1) << 8 | usize::from(l2) << 16;
    if len == 0 || len > MAX_GREETING {
        return Err(Error::malformed(WHAT, format!("packet length {len}")));
    }
    if seq != 0 {
        return Err(Error::malformed(WHAT, format!("sequence id {seq}")));
    }
    // Reject other protocols on the first payload byte instead of waiting
    // for `len` bytes that will never come.
    match r.rest().first() {
        Some(9 | 10 | 0xff) | None => {}
        Some(other) => {
            return Err(Error::malformed(
                WHAT,
                format!("protocol byte {other:#04x}"),
            ));
        }
    }
    let payload = r.take(len)?;
    let mut r = Reader::new(payload, WHAT);
    let greeting = match r.u8()? {
        0xff => parse_err(r).map(Greeting::Error),
        protocol => parse_handshake(protocol, r).map(Greeting::Handshake),
    };
    greeting.map_err(Error::within_complete_message)
}

fn parse_err(mut r: Reader<'_>) -> Result<ErrPacket, Error> {
    let code = r.u16_le()?;
    let sql_state = if r.rest().first() == Some(&b'#') {
        let state = r.take(6)?;
        Some(text(state.get(1..).unwrap_or_default()))
    } else {
        None
    };
    Ok(ErrPacket {
        code,
        sql_state,
        message: text(r.rest()),
    })
}

fn parse_handshake(protocol: u8, mut r: Reader<'_>) -> Result<Handshake, Error> {
    let version = r.cstr()?;
    if version.is_empty() {
        return Err(Error::malformed(WHAT, "empty server version"));
    }
    let mut hs = Handshake {
        protocol,
        server_version: text(version),
        connection_id: r.u32_le()?,
        capabilities: 0,
        mariadb_capabilities: None,
        character_set: None,
        status: None,
        auth_plugin: None,
    };
    if protocol == 9 {
        return Ok(hs);
    }
    r.take(8)?; // auth-plugin-data-part-1
    r.take(1)?; // filler
    hs.capabilities = u32::from(r.u16_le()?);
    if r.is_empty() {
        // Pre-4.1 servers may stop here.
        return Ok(hs);
    }
    hs.character_set = Some(r.u8()?);
    hs.status = Some(r.u16_le()?);
    hs.capabilities |= u32::from(r.u16_le()?) << 16;
    let auth_len = r.u8()?;
    let reserved: [u8; 10] = r.array()?;
    // MariaDB clears CLIENT_LONG_PASSWORD ("CLIENT_MYSQL") and puts its
    // extended capabilities in the last four reserved bytes.
    if hs.capabilities & 1 == 0 && hs.server_version.to_ascii_lowercase().contains("mariadb") {
        let mut ext = [0; 4];
        ext.copy_from_slice(reserved.get(6..).unwrap_or(&[0; 4]));
        hs.mariadb_capabilities = Some(u32::from_le_bytes(ext));
    }
    if hs.capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let part2 = usize::from(auth_len).saturating_sub(8).max(13);
        // Some servers send a shorter scramble when no plugin follows.
        if r.take(part2).is_err() {
            return Ok(hs);
        }
    }
    if hs.capabilities & CLIENT_PLUGIN_AUTH != 0 && !r.is_empty() {
        // Some servers omit the terminating NUL.
        let rest = r.rest();
        let name = rest.split(|&b| b == 0).next().unwrap_or(rest);
        if !name.is_empty() {
            hs.auth_plugin = Some(text(name));
        }
    }
    Ok(hs)
}

/// Reads the MySQL or MariaDB greeting. Read-only: sends nothing.
///
/// Reports product, version and banner (the raw version string), the
/// capability flags, the default authentication plugin, whether TLS is
/// offered, and these findings:
///
/// | Check id                 | When                                                   |
/// | ------------------------ | ------------------------------------------------------ |
/// | `mysql.tls_not_offered`  | the greeting lacks `CLIENT_SSL` (CWE-319)              |
/// | `mysql.old_password_auth`| the default plugin is `mysql_old_password` (CWE-328)   |
///
/// The greeting does not say whether a given account needs a password, so
/// [`ServiceInfo::auth`] stays unknown, except that an `ERR_Packet`
/// refusing the client host reports [`AuthRequirement::Required`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MysqlProbe;

impl MysqlProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for MysqlProbe {
    fn id(&self) -> &'static str {
        "mysql"
    }

    fn default_ports(&self) -> &[u16] {
        &[3306]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(MysqlSession {
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

struct MysqlSession {
    target: Target,
    buf: Vec<u8>,
}

impl ProbeSession for MysqlSession {
    fn start(&mut self) -> Action {
        Action::Receive
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.buf.extend_from_slice(data);
        match parse_greeting(&self.buf) {
            Err(e) if e.is_truncated() => Action::Receive,
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if self.buf.is_empty() {
            return Err(rune_service_probe::Error::no_response("mysql"));
        }
        match parse_greeting(&self.buf).map_err(|e| e.into_probe_error("mysql"))? {
            Greeting::Handshake(hs) => Ok(report_handshake(&self.target, &hs)),
            Greeting::Error(err) => Ok(report_error(&err)),
        }
    }
}

fn report_handshake(target: &Target, hs: &Handshake) -> ServiceInfo {
    let (product, version) = hs.product_and_version();
    let mut info = ServiceInfo::new("mysql")
        .with_product(product)
        .with_banner(hs.server_version.clone())
        .with_detail("mysql.protocol", hs.protocol.to_string())
        .with_detail("mysql.capabilities", format!("{:#010x}", hs.capabilities));
    if let Some(version) = version {
        info = info.with_version(version);
    }
    info.capabilities = capability_names(hs.capabilities)
        .into_iter()
        .map(str::to_owned)
        .collect();
    if let Some(ext) = hs.mariadb_capabilities {
        info = info.with_detail("mysql.mariadb_capabilities", format!("{ext:#010x}"));
    }
    if let Some(charset) = hs.character_set {
        info = info.with_detail("mysql.character_set", charset.to_string());
    }
    if let Some(plugin) = &hs.auth_plugin {
        info = info.with_detail("mysql.auth_plugin", plugin.clone());
        if plugin == "mysql_old_password" {
            info = info.push_finding(
                target
                    .finding(
                        "mysql.old_password_auth",
                        "MySQL defaults to the pre-4.1 mysql_old_password authentication",
                        Severity::High,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(328))
                    .push_evidence(Evidence::new("auth_plugin", plugin.clone()))
                    .with_remediation(Remediation::new(
                        "Use caching_sha2_password (MySQL) or ed25519 (MariaDB) and rehash \
                         every account's password.",
                    )),
            );
        }
    }
    if hs.protocol == 10 && hs.capabilities != 0 {
        if hs.supports_tls() {
            info = info.with_tls(TlsSupport::Optional);
        } else {
            info = info.with_tls(TlsSupport::NotOffered).push_finding(
                target
                    .finding(
                        "mysql.tls_not_offered",
                        "MySQL does not offer TLS",
                        Severity::Medium,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(319))
                    .push_evidence(Evidence::new(
                        "capabilities",
                        format!("{:#010x}", hs.capabilities),
                    ))
                    .with_remediation(Remediation::new(
                        "Configure ssl_cert and ssl_key and set require_secure_transport=ON.",
                    )),
            );
        }
    }
    info
}

fn report_error(err: &ErrPacket) -> ServiceInfo {
    let mut info = ServiceInfo::new("mysql")
        .with_banner(err.message.clone())
        .with_detail("mysql.error_code", err.code.to_string())
        .with_detail("mysql.error_message", err.message.clone());
    if let Some(state) = &err.sql_state {
        info = info.with_detail("mysql.sql_state", state.clone());
    }
    if matches!(err.code, ER_HOST_NOT_PRIVILEGED | ER_HOST_IS_BLOCKED) {
        info = info.with_auth(AuthRequirement::Required);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    #[test]
    fn a_complete_packet_with_a_short_handshake_is_malformed_not_truncated() {
        // The header says five bytes and all five arrived: the handshake
        // inside is cut short, and no more bytes will fix that.
        let packet = [5, 0, 0, 0, 10, b'8', b'.', b'0', 0];
        let err = parse_greeting(&packet).unwrap_err();
        assert!(!err.is_truncated(), "{err}");
        assert_eq!(run(&[&packet]).end, End::Done);
    }

    /// Build a protocol-10 greeting packet.
    fn greeting(version: &str, caps: u32, plugin: &str) -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(version.as_bytes());
        p.push(0);
        p.extend_from_slice(&42u32.to_le_bytes());
        p.extend_from_slice(b"abcdefgh\0");
        p.extend_from_slice(&caps.to_le_bytes()[..2]);
        p.push(255);
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&caps.to_le_bytes()[2..]);
        p.push(21);
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0");
        p.extend_from_slice(plugin.as_bytes());
        p.push(0);
        let mut packet = u32::try_from(p.len()).unwrap().to_le_bytes()[..3].to_vec();
        packet.push(0);
        packet.extend_from_slice(&p);
        packet
    }

    const MYSQL8_CAPS: u32 = 0xdfff_ffff;

    fn run(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &MysqlProbe,
            &Target::new("db.test", 3306),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    #[test]
    fn mysql8_greeting() {
        let packet = greeting(
            "8.0.36-0ubuntu0.22.04.1",
            MYSQL8_CAPS,
            "caching_sha2_password",
        );
        let Greeting::Handshake(hs) = parse_greeting(&packet).unwrap() else {
            panic!("not a handshake")
        };
        assert_eq!(hs.protocol, 10);
        assert_eq!(hs.connection_id, 42);
        assert_eq!(hs.capabilities, MYSQL8_CAPS);
        assert_eq!(hs.character_set, Some(255));
        assert_eq!(hs.auth_plugin.as_deref(), Some("caching_sha2_password"));
        assert!(hs.supports_tls());
        assert_eq!(hs.product_and_version(), ("MySQL", Some("8.0.36".into())));
    }

    #[test]
    fn session_reassembles_split_greeting() {
        let packet = greeting("8.0.36", MYSQL8_CAPS, "caching_sha2_password");
        let sim = run(&[&packet[..7], &packet[7..]]);
        assert_eq!(sim.sent.len(), 0);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.product.as_deref(), Some("MySQL"));
        assert_eq!(info.version.as_deref(), Some("8.0.36"));
        assert_eq!(info.tls, TlsSupport::Optional);
        assert_eq!(info.details["mysql.auth_plugin"], "caching_sha2_password");
        assert!(info.capabilities.iter().any(|c| c == "CLIENT_SSL"));
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn mariadb_without_tls() {
        // MariaDB clears bit 0 and has no CLIENT_SSL here.
        let caps = 0x81ff_f7fe;
        let version = "5.5.5-10.11.6-MariaDB-0+deb12u1";
        let mut packet = greeting(version, caps, "mysql_native_password");
        // Extended capabilities sit in reserved[6..10], after header,
        // protocol, version, id, scramble, filler, caps, charset, status,
        // upper caps and the scramble length.
        let idx = 4 + 1 + version.len() + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 6;
        packet[idx..idx + 4].copy_from_slice(&0x1du32.to_le_bytes());
        let sim = run(&[&packet]);
        let info = sim.result.unwrap();
        assert_eq!(info.product.as_deref(), Some("MariaDB"));
        assert_eq!(info.version.as_deref(), Some("10.11.6"));
        assert_eq!(
            info.banner.as_deref(),
            Some("5.5.5-10.11.6-MariaDB-0+deb12u1")
        );
        assert_eq!(info.details["mysql.mariadb_capabilities"], "0x0000001d");
        assert_eq!(info.tls, TlsSupport::NotOffered);
        assert_eq!(info.findings.len(), 1);
        assert_eq!(info.findings[0].check_id, "mysql.tls_not_offered");
    }

    #[test]
    fn old_password_plugin_is_flagged() {
        let packet = greeting("5.0.95", MYSQL8_CAPS, "mysql_old_password");
        let info = run(&[&packet]).result.unwrap();
        assert!(
            info.findings
                .iter()
                .any(|f| f.check_id == "mysql.old_password_auth")
        );
    }

    #[test]
    fn host_not_allowed_err_packet() {
        let mut p = vec![0xff];
        p.extend_from_slice(&1130u16.to_le_bytes());
        p.extend_from_slice(b"Host '192.0.2.7' is not allowed to connect to this MySQL server");
        let mut packet = vec![u8::try_from(p.len()).unwrap(), 0, 0, 0];
        packet.extend_from_slice(&p);
        let info = run(&[&packet]).result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.details["mysql.error_code"], "1130");
        assert!(info.product.is_none());
    }

    #[test]
    fn err_packet_with_sql_state() {
        let mut p = vec![0xff, 0x10, 0x04, b'#'];
        p.extend_from_slice(b"08004Too many connections");
        let mut packet = vec![u8::try_from(p.len()).unwrap(), 0, 0, 0];
        packet.extend_from_slice(&p);
        let Greeting::Error(err) = parse_greeting(&packet).unwrap() else {
            panic!("not an error")
        };
        assert_eq!(err.code, 1040);
        assert_eq!(err.sql_state.as_deref(), Some("08004"));
        assert_eq!(err.message, "Too many connections");
    }

    #[test]
    fn protocol_9_greeting() {
        let mut p = vec![9];
        p.extend_from_slice(b"3.20.32a\0");
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(b"scramble\0");
        let mut packet = vec![u8::try_from(p.len()).unwrap(), 0, 0, 0];
        packet.extend_from_slice(&p);
        let info = run(&[&packet]).result.unwrap();
        assert_eq!(info.version.as_deref(), Some("3.20.32a"));
        assert_eq!(info.tls, TlsSupport::Unknown);
    }

    #[test]
    fn tidb_version() {
        assert_eq!(
            split_version("8.0.11-TiDB-v7.5.0"),
            ("TiDB", Some("7.5.0".into()))
        );
        assert_eq!(split_version("garbage"), ("MySQL", None));
    }

    #[test]
    fn other_protocols_fail_fast() {
        let sim = run(&[b"SSH-2.0-OpenSSH_9.6\r\n"]);
        assert_eq!(sim.end, End::Done);
        assert!(matches!(
            sim.result,
            Err(rune_service_probe::Error::Unrecognized { .. })
        ));
        let sim = run(&[b"HTTP/1.1 400 Bad Request\r\n"]);
        assert!(sim.result.is_err());
        assert!(matches!(
            run(&[]).result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
    }

    #[test]
    fn truncated_greeting_is_unrecognized() {
        let packet = greeting("8.0.36", MYSQL8_CAPS, "caching_sha2_password");
        let sim = run(&[&packet[..20]]);
        assert_eq!(sim.end, End::Closed);
        assert!(sim.result.is_err());
    }
}

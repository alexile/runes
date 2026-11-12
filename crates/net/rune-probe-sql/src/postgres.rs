//! PostgreSQL: the `SSLRequest` exchange, a version hint, and (intrusive)
//! the authentication method.
//!
//! See the [frontend/backend protocol](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-START-UP)
//! and its [message formats](https://www.postgresql.org/docs/current/protocol-message-formats.html).
//!
//! A PostgreSQL server reveals nothing before the client speaks, and its
//! version only after a successful login. [`PostgresProbe`] stays
//! read-only:
//!
//! 1. It sends an [`ssl_request`]. The one-byte answer says whether the
//!    server offers TLS (`S`) or not (`N`).
//! 2. After `N`, on the same connection, it sends a
//!    [`version_probe`]: a startup packet asking for protocol 9.0, which
//!    every server rejects before authentication with an `ErrorResponse`.
//!    The supported protocol range and the source file named in that error
//!    narrow the server version (see [`ErrorFields::version_hint`]).
//!
//! [`PostgresAuthProbe`] is [`Safety::Intrusive`]: it sends a real
//! `StartupMessage` (no password) and reports the authentication method
//! the server asks for, or that it let the user in without one.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, Safety, ServiceInfo, ServiceProbe, Target,
    TlsSupport,
};

use crate::Error;
use crate::wire::{Reader, text};

const WHAT: &str = "postgresql message";

/// Largest backend message accepted before the probe gives up.
const MAX_MESSAGE: usize = 16 * 1024;

/// The `SSLRequest` code, 1234.5679.
pub const SSL_REQUEST_CODE: u32 = 80_877_103;

/// The protocol the [`version_probe`] asks for: 9.0, which no server
/// supports.
pub const UNSUPPORTED_PROTOCOL: u32 = 9 << 16;

/// Protocol 3.0.
pub const PROTOCOL_3_0: u32 = 3 << 16;

/// The 8-byte `SSLRequest` packet.
///
/// ```
/// assert_eq!(rune_probe_sql::postgres::ssl_request(), [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
/// ```
#[must_use]
pub fn ssl_request() -> [u8; 8] {
    packet8(SSL_REQUEST_CODE)
}

/// A startup packet for protocol 9.0 with no parameters. The server
/// answers with an `ErrorResponse` ("unsupported frontend protocol")
/// before looking at users, databases or authentication.
#[must_use]
pub fn version_probe() -> [u8; 8] {
    packet8(UNSUPPORTED_PROTOCOL)
}

fn packet8(code: u32) -> [u8; 8] {
    let mut out = [0; 8];
    out[..4].copy_from_slice(&8u32.to_be_bytes());
    out[4..].copy_from_slice(&code.to_be_bytes());
    out
}

/// A protocol 3.0 `StartupMessage` for `user` and `database`.
///
/// ```
/// let msg = rune_probe_sql::postgres::startup_message("postgres", None);
/// assert_eq!(&msg[..8], &[0, 0, 0, 23, 0, 3, 0, 0]);
/// assert!(msg.ends_with(b"user\0postgres\0\0"));
/// ```
#[must_use]
pub fn startup_message(user: &str, database: Option<&str>) -> Vec<u8> {
    let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
    let mut param = |name: &str, value: &str| {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend(value.bytes().filter(|&b| b != 0));
        body.push(0);
    };
    param("user", user);
    if let Some(database) = database {
        param("database", database);
    }
    body.push(0);
    let len = u32::try_from(body.len() + 4).unwrap_or(u32::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// The `Terminate` message.
pub const TERMINATE: [u8; 5] = [b'X', 0, 0, 0, 4];

/// The fields of an `ErrorResponse` or `NoticeResponse`, printable and
/// bounded. Unknown field codes are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorFields {
    /// `S`: severity, possibly localized.
    pub severity: Option<String>,
    /// `V`: severity, never localized (9.6 and later).
    pub severity_nonlocalized: Option<String>,
    /// `C`: the SQLSTATE code, e.g. `0A000`.
    pub code: Option<String>,
    /// `M`: the message.
    pub message: Option<String>,
    /// `F`: the source file that raised the error.
    pub file: Option<String>,
    /// `L`: the source line.
    pub line: Option<String>,
    /// `R`: the source routine.
    pub routine: Option<String>,
}

impl ErrorFields {
    /// The protocol range in an "unsupported frontend protocol X: server
    /// supports A to B" message: `(A, B)` as `(major, minor)` pairs. The
    /// numbers are read positionally, so localized messages work too.
    #[must_use]
    pub fn supported_protocols(&self) -> Option<((u16, u16), (u16, u16))> {
        let message = self.message.as_deref()?;
        let versions: Vec<(u16, u16)> = message
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .filter_map(|tok| {
                let (major, minor) = tok.trim_matches('.').split_once('.')?;
                Some((major.parse().ok()?, minor.parse().ok()?))
            })
            .collect();
        match versions.as_slice() {
            [.., _requested, earliest, latest] => Some((*earliest, *latest)),
            _ => None,
        }
    }

    /// A coarse server version range from the answer to
    /// [`version_probe`], e.g. `14-16` or `>=18`.
    ///
    /// Servers before 14 accept protocols from 1.0 or 2.0; 18 added
    /// protocol 3.2; 17 moved startup handling from `postmaster.c` to
    /// `backend_startup.c`. A hint, not a fingerprint: forks and poolers
    /// can answer differently.
    ///
    /// ```
    /// use rune_probe_sql::postgres::ErrorFields;
    ///
    /// let mut e = ErrorFields::default();
    /// e.message = Some("unsupported frontend protocol 9.0: server supports 3.0 to 3.2".into());
    /// assert_eq!(e.version_hint().as_deref(), Some(">=18"));
    /// ```
    #[must_use]
    pub fn version_hint(&self) -> Option<String> {
        let file = self.file.as_deref();
        let hint = match (self.supported_protocols(), file) {
            (Some((earliest, _)), _) if earliest.0 < 3 => "<=13",
            (Some((_, latest)), _) if latest >= (3, 2) => ">=18",
            (Some(_), Some("backend_startup.c")) => "17",
            (Some(_), Some("postmaster.c")) => "14-16",
            (Some(_), _) => "14-17",
            (None, Some("backend_startup.c")) => ">=17",
            (None, Some("postmaster.c")) => "<=16",
            (None, _) => return None,
        };
        Some(hint.to_owned())
    }

    /// True when the server or source fields mark this as PostgreSQL
    /// itself rather than a pooler or another implementation.
    #[must_use]
    pub const fn has_source_location(&self) -> bool {
        self.file.is_some() && self.routine.is_some()
    }
}

/// A backend message the probes understand.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// `R`: an authentication request. `code` 0 is `AuthenticationOk`.
    Authentication {
        /// The request code (0 ok, 3 cleartext, 5 MD5, 10 SASL, ...).
        code: u32,
        /// SASL mechanism names, for code 10.
        mechanisms: Vec<String>,
    },
    /// `E`: an error.
    Error(ErrorFields),
    /// `N`: a notice.
    Notice(ErrorFields),
    /// `S`: a run-time parameter, e.g. `server_version`.
    ParameterStatus {
        /// Parameter name.
        name: String,
        /// Parameter value.
        value: String,
    },
    /// `Z`: ready for a query.
    ReadyForQuery,
    /// Any other message, by type byte.
    Other(u8),
}

/// The name of an authentication request code.
///
/// ```
/// assert_eq!(rune_probe_sql::postgres::auth_method_name(10), "sasl");
/// ```
#[must_use]
pub const fn auth_method_name(code: u32) -> &'static str {
    match code {
        0 => "ok",
        2 => "kerberos_v5",
        3 => "cleartext_password",
        5 => "md5",
        6 => "scm_credential",
        7 => "gss",
        8 => "gss_continue",
        9 => "sspi",
        10 => "sasl",
        11 => "sasl_continue",
        12 => "sasl_final",
        _ => "unknown",
    }
}

/// Parse one backend message from the start of `bytes`, returning it and
/// the number of bytes it took.
///
/// ```
/// use rune_probe_sql::postgres::{Message, parse_message};
///
/// let (msg, used) = parse_message(&[b'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4])?;
/// assert_eq!(msg, Message::Authentication { code: 5, mechanisms: vec![] });
/// assert_eq!(used, 13);
/// # Ok::<(), rune_probe_sql::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the whole message has arrived, and
/// [`Error::Malformed`] for a length no backend message has.
pub fn parse_message(bytes: &[u8]) -> Result<(Message, usize), Error> {
    let mut r = Reader::new(bytes, WHAT);
    let tag = r.u8()?;
    if !tag.is_ascii_alphabetic() {
        return Err(Error::malformed(WHAT, format!("type byte {tag:#04x}")));
    }
    let len = usize::try_from(r.u32_be()?).unwrap_or(usize::MAX);
    if !(4..=MAX_MESSAGE).contains(&len) {
        return Err(Error::malformed(WHAT, format!("length {len}")));
    }
    let body = r.take(len - 4)?;
    let mut b = Reader::new(body, WHAT);
    let msg = match tag {
        b'R' => {
            let code = b.u32_be()?;
            let mut mechanisms = Vec::new();
            if code == 10 {
                while let Ok(name) = b.cstr() {
                    if name.is_empty() {
                        break;
                    }
                    mechanisms.push(text(name));
                }
            }
            Message::Authentication { code, mechanisms }
        }
        b'E' => Message::Error(parse_fields(b)),
        b'N' => Message::Notice(parse_fields(b)),
        b'S' => Message::ParameterStatus {
            name: text(b.cstr()?),
            value: text(b.cstr()?),
        },
        b'Z' => Message::ReadyForQuery,
        other => Message::Other(other),
    };
    Ok((msg, len + 1))
}

fn parse_fields(mut r: Reader<'_>) -> ErrorFields {
    let mut f = ErrorFields::default();
    while let Ok(code) = r.u8() {
        if code == 0 {
            break;
        }
        let Ok(value) = r.cstr() else { break };
        let value = Some(text(value));
        match code {
            b'S' => f.severity = value,
            b'V' => f.severity_nonlocalized = value,
            b'C' => f.code = value,
            b'M' => f.message = value,
            b'F' => f.file = value,
            b'L' => f.line = value,
            b'R' => f.routine = value,
            _ => {}
        }
    }
    f
}

fn error_details(mut info: ServiceInfo, e: &ErrorFields) -> ServiceInfo {
    let fields = [
        ("postgresql.error_code", &e.code),
        ("postgresql.error_message", &e.message),
        ("postgresql.error_file", &e.file),
        ("postgresql.error_line", &e.line),
        ("postgresql.error_routine", &e.routine),
    ];
    for (key, value) in fields {
        if let Some(value) = value {
            info = info.with_detail(key, value.clone());
        }
    }
    info
}

/// Read-only PostgreSQL probe: TLS support and a version hint.
///
/// Reports [`ServiceInfo::tls`] from the `SSLRequest` answer, and after an
/// `N` the details `postgresql.version_hint` and
/// `postgresql.supported_protocols` (with the raw error fields under
/// `postgresql.error_*`). With [`with_ssl_request(false)`](Self::with_ssl_request)
/// it skips the `SSLRequest` and only collects the version hint; a
/// server that answers `S` cannot be asked for the hint on the same
/// connection.
///
/// `S` is reported as [`TlsSupport::Optional`]: whether plaintext logins
/// are refused is decided per `pg_hba.conf` rule after the startup
/// message, which only [`PostgresAuthProbe`] sends.
///
/// | Check id                     | When                                      |
/// | ---------------------------- | ----------------------------------------- |
/// | `postgresql.tls_not_offered` | the server answers `N` (CWE-319)          |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PostgresProbe {
    ssl_request: bool,
}

impl Default for PostgresProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresProbe {
    /// A probe that sends an `SSLRequest`, then the version probe.
    #[must_use]
    pub const fn new() -> Self {
        Self { ssl_request: true }
    }

    /// Whether to start with an `SSLRequest` (on by default).
    #[must_use]
    pub const fn with_ssl_request(mut self, enabled: bool) -> Self {
        self.ssl_request = enabled;
        self
    }
}

impl ServiceProbe for PostgresProbe {
    fn id(&self) -> &'static str {
        "postgresql"
    }

    fn default_ports(&self) -> &[u16] {
        &[5432]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(ReadOnlySession {
            target: target.clone(),
            ssl_request: self.ssl_request,
            state: State::AwaitSsl,
            ssl: None,
            buf: Vec::new(),
            received: false,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitSsl,
    AwaitError,
}

struct ReadOnlySession {
    target: Target,
    ssl_request: bool,
    state: State,
    ssl: Option<u8>,
    buf: Vec<u8>,
    received: bool,
}

impl ProbeSession for ReadOnlySession {
    fn start(&mut self) -> Action {
        if self.ssl_request {
            Action::Send(ssl_request().to_vec())
        } else {
            self.state = State::AwaitError;
            Action::Send(version_probe().to_vec())
        }
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        if self.state == State::AwaitSsl {
            // The answer is exactly one byte, after which the server waits;
            // anything longer (`SSH-2.0-...`) is another protocol.
            match *self.buf.as_slice() {
                [answer @ (b'S' | b'N')] => {
                    self.ssl = Some(answer);
                    self.buf.clear();
                    if answer == b'S' {
                        return Action::Done;
                    }
                    self.state = State::AwaitError;
                    return Action::Send(version_probe().to_vec());
                }
                // Very old servers answer an error instead.
                [b'E', ..] => self.state = State::AwaitError,
                _ => return Action::Done,
            }
        }
        match parse_message(&self.buf) {
            Err(e) if e.is_truncated() => Action::Receive,
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if !self.received {
            return Err(rune_service_probe::Error::no_response("postgresql"));
        }
        let mut info = ServiceInfo::new("postgresql");
        match self.ssl {
            Some(b'S') => info = info.with_tls(TlsSupport::Optional),
            Some(_) => {
                info = info.with_tls(TlsSupport::NotOffered).push_finding(
                    self.target
                        .finding(
                            "postgresql.tls_not_offered",
                            "PostgreSQL does not offer TLS",
                            Severity::Medium,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(319))
                        .push_evidence(Evidence::new("ssl_request", "N"))
                        .with_remediation(Remediation::new(
                            "Set ssl = on with a certificate, and use hostssl rules in \
                             pg_hba.conf for remote clients.",
                        )),
                );
            }
            None => {}
        }
        if self.buf.is_empty() {
            return match self.ssl {
                Some(_) => Ok(info.with_product("PostgreSQL")),
                None => Err(rune_service_probe::Error::unrecognized(
                    "postgresql",
                    "no SSLRequest answer",
                )),
            };
        }
        let (msg, _) = match parse_message(&self.buf) {
            Ok(parsed) => parsed,
            // `N` already identified the server; a broken follow-up does
            // not undo that.
            Err(_) if self.ssl.is_some() => return Ok(info.with_product("PostgreSQL")),
            Err(e) => return Err(e.into_probe_error("postgresql")),
        };
        let Message::Error(fields) = msg else {
            return Err(rune_service_probe::Error::unrecognized(
                "postgresql",
                "expected an ErrorResponse",
            ));
        };
        if self.ssl.is_some() || fields.has_source_location() {
            info = info.with_product("PostgreSQL");
        }
        if let Some(message) = &fields.message {
            info = info.with_banner(message.clone());
        }
        if let Some((earliest, latest)) = fields.supported_protocols() {
            info = info.with_detail(
                "postgresql.supported_protocols",
                format!("{}.{}-{}.{}", earliest.0, earliest.1, latest.0, latest.1),
            );
        }
        if let Some(hint) = fields.version_hint() {
            info = info.with_detail("postgresql.version_hint", hint);
        }
        Ok(error_details(info, &fields))
    }
}

/// Intrusive PostgreSQL probe: which authentication method the server asks
/// a user for.
///
/// Sends a `StartupMessage` for [`user`](Self::with_user) (default
/// `postgres`) and never a password. If the server answers
/// `AuthenticationOk` it has logged the user in (a `trust` rule): the
/// probe reads the parameters the server reports, including the exact
/// `server_version`, sends `Terminate` and stops. Declared
/// [`Safety::Intrusive`] because a successful startup is a login and shows
/// up in server logs as one.
///
/// | Check id                         | When                                                 |
/// | -------------------------------- | ---------------------------------------------------- |
/// | `postgresql.unauthenticated`     | `AuthenticationOk` without credentials (CWE-306)     |
/// | `postgresql.cleartext_password`  | the server asks for a cleartext password (CWE-319)   |
/// | `postgresql.md5_auth`            | the server asks for an MD5 password hash (CWE-328)   |
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PostgresAuthProbe {
    user: String,
    database: Option<String>,
}

impl Default for PostgresAuthProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresAuthProbe {
    /// A probe for the `postgres` user and its default database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            user: "postgres".to_owned(),
            database: None,
        }
    }

    /// The user name to start up as.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// The database to ask for (the server defaults it to the user name).
    #[must_use]
    pub fn with_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }
}

impl ServiceProbe for PostgresAuthProbe {
    fn id(&self) -> &'static str {
        "postgresql-auth"
    }

    fn safety(&self) -> Safety {
        Safety::Intrusive
    }

    fn default_ports(&self) -> &[u16] {
        &[5432]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(AuthSession {
            target: target.clone(),
            startup: startup_message(&self.user, self.database.as_deref()),
            user: self.user.clone(),
            buf: Vec::new(),
            received: false,
            terminated: false,
            auth: None,
            params: Vec::new(),
            error: None,
            malformed: None,
        })
    }
}

struct AuthSession {
    target: Target,
    startup: Vec<u8>,
    user: String,
    buf: Vec<u8>,
    received: bool,
    terminated: bool,
    auth: Option<(u32, Vec<String>)>,
    params: Vec<(String, String)>,
    error: Option<ErrorFields>,
    malformed: Option<Error>,
}

impl ProbeSession for AuthSession {
    fn start(&mut self) -> Action {
        Action::Send(std::mem::take(&mut self.startup))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        if self.terminated {
            return Action::Done;
        }
        self.buf.extend_from_slice(data);
        loop {
            let (msg, used) = match parse_message(&self.buf) {
                Ok(parsed) => parsed,
                Err(e) if e.is_truncated() => return Action::Receive,
                Err(e) => {
                    self.malformed = Some(e);
                    return Action::Done;
                }
            };
            self.buf.drain(..used.min(self.buf.len()));
            match msg {
                Message::Authentication { code: 0, .. } => self.auth = Some((0, Vec::new())),
                Message::Authentication { code, mechanisms } => {
                    self.auth = Some((code, mechanisms));
                    return Action::Done;
                }
                Message::ParameterStatus { name, value } => {
                    if self.params.len() < 64 {
                        self.params.push((name, value));
                    }
                }
                Message::Error(fields) => {
                    self.error = Some(fields);
                    return Action::Done;
                }
                Message::ReadyForQuery => {
                    self.terminated = true;
                    return Action::Send(TERMINATE.to_vec());
                }
                Message::Notice(_) | Message::Other(_) => {}
            }
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        const ID: &str = "postgresql-auth";
        if !self.received {
            return Err(rune_service_probe::Error::no_response(ID));
        }
        if self.auth.is_none() && self.error.is_none() {
            let reason = self
                .malformed
                .take()
                .map_or_else(|| "no authentication reply".to_owned(), |e| e.to_string());
            return Err(rune_service_probe::Error::unrecognized(ID, reason));
        }
        let mut info = ServiceInfo::new(ID).with_product("PostgreSQL");
        for (name, value) in &self.params {
            if name == "server_version" {
                let version = value.split_whitespace().next().unwrap_or(value);
                info = info.with_version(version).with_banner(value.clone());
            }
            info = info.with_detail(format!("postgresql.param.{name}"), value.clone());
        }
        let finding = |id: &str, title: &str, severity, confidence, cwe| {
            self.target
                .finding(id, title, severity, confidence)
                .push_taxonomy(TaxonomyRef::cwe(cwe))
                .push_evidence(Evidence::new("user", self.user.clone()))
        };
        if let Some((code, mechanisms)) = &self.auth {
            info = info.with_detail("postgresql.auth_method", auth_method_name(*code));
            info.capabilities.extend(mechanisms.iter().cloned());
            match code {
                0 => {
                    info = info.with_auth(AuthRequirement::NotRequired).push_finding(
                        finding(
                            "postgresql.unauthenticated",
                            "PostgreSQL logs users in without authentication",
                            Severity::Critical,
                            Confidence::Certain,
                            306,
                        )
                        .with_remediation(Remediation::new(
                            "Replace trust rules in pg_hba.conf with scram-sha-256 or cert \
                             authentication, and firewall the port.",
                        )),
                    );
                }
                3 => {
                    info = info
                        .with_auth(AuthRequirement::Required)
                        .push_finding(finding(
                            "postgresql.cleartext_password",
                            "PostgreSQL asks for the password in clear text",
                            Severity::Medium,
                            Confidence::Firm,
                            319,
                        ));
                }
                5 => {
                    info = info
                        .with_auth(AuthRequirement::Required)
                        .push_finding(finding(
                            "postgresql.md5_auth",
                            "PostgreSQL uses MD5 password authentication",
                            Severity::Low,
                            Confidence::Certain,
                            328,
                        ));
                }
                _ => info = info.with_auth(AuthRequirement::Required),
            }
        }
        if let Some(fields) = &self.error {
            if let Some(message) = &fields.message {
                info = info.with_banner(message.clone());
            }
            // 28000 invalid_authorization_specification (pg_hba rejection),
            // 28P01 invalid_password.
            if matches!(fields.code.as_deref(), Some("28000" | "28P01")) {
                info = info.with_auth(AuthRequirement::Required);
            }
            info = error_details(info, fields);
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    fn error_response(fields: &[(u8, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (code, value) in fields {
            body.push(*code);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut out = vec![b'E'];
        out.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn pg16_error() -> Vec<u8> {
        error_response(&[
            (b'S', "FATAL"),
            (b'V', "FATAL"),
            (b'C', "0A000"),
            (
                b'M',
                "unsupported frontend protocol 9.0: server supports 3.0 to 3.0",
            ),
            (b'F', "postmaster.c"),
            (b'L', "2165"),
            (b'R', "ProcessStartupPacket"),
        ])
    }

    fn target() -> Target {
        Target::new("pg.test", 5432)
    }

    #[test]
    fn plaintext_server_gets_version_hint() {
        let error = pg16_error();
        let (a, b) = (&error[..10], &error[10..]);
        let sim = simulate(
            &PostgresProbe::new(),
            &target(),
            &[b"N", a, b],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(sim.sent, [ssl_request().to_vec(), version_probe().to_vec()]);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.product.as_deref(), Some("PostgreSQL"));
        assert_eq!(info.tls, TlsSupport::NotOffered);
        assert_eq!(info.details["postgresql.version_hint"], "14-16");
        assert_eq!(info.details["postgresql.supported_protocols"], "3.0-3.0");
        assert_eq!(
            info.details["postgresql.error_routine"],
            "ProcessStartupPacket"
        );
        assert_eq!(info.findings[0].check_id, "postgresql.tls_not_offered");
        assert_eq!(info.auth, AuthRequirement::Unknown);
    }

    #[test]
    fn tls_server_stops_after_s() {
        let sim = simulate(
            &PostgresProbe::new(),
            &target(),
            &[b"S"],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(sim.sent.len(), 1);
        let info = sim.result.unwrap();
        assert_eq!(info.tls, TlsSupport::Optional);
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn version_hints() {
        let hint = |msg: &str, file: Option<&str>| {
            ErrorFields {
                message: Some(msg.into()),
                file: file.map(Into::into),
                ..ErrorFields::default()
            }
            .version_hint()
        };
        let m = |a: &str, b: &str| {
            format!("unsupported frontend protocol 9.0: server supports {a} to {b}")
        };
        assert_eq!(
            hint(&m("1.0", "3.0"), Some("postmaster.c")).as_deref(),
            Some("<=13")
        );
        assert_eq!(hint(&m("2.0", "3.0"), None).as_deref(), Some("<=13"));
        assert_eq!(
            hint(&m("3.0", "3.0"), Some("backend_startup.c")).as_deref(),
            Some("17")
        );
        assert_eq!(
            hint(&m("3.0", "3.2"), Some("backend_startup.c")).as_deref(),
            Some(">=18")
        );
        assert_eq!(hint(&m("3.0", "3.0"), None).as_deref(), Some("14-17"));
        // Localized message: numbers are read positionally.
        assert_eq!(
            hint(
                "nicht unterstütztes Frontend-Protokoll 9.0: Server unterstützt 3.0 bis 3.0",
                Some("postmaster.c")
            )
            .as_deref(),
            Some("14-16")
        );
        assert_eq!(hint("something else", None), None);
    }

    #[test]
    fn version_hint_only_mode() {
        let probe = PostgresProbe::new().with_ssl_request(false);
        let sim = simulate(&probe, &target(), &[&pg16_error()], &Options::default()).unwrap();
        assert_eq!(sim.sent, [version_probe().to_vec()]);
        let info = sim.result.unwrap();
        assert_eq!(info.tls, TlsSupport::Unknown);
        assert_eq!(info.product.as_deref(), Some("PostgreSQL"));
    }

    #[test]
    fn non_postgres_is_unrecognized() {
        for reply in [&b"SSH-2.0-OpenSSH_9.6\r\n"[..], b"\x15\x03\x01\x00\x02"] {
            let sim = simulate(
                &PostgresProbe::new(),
                &target(),
                &[reply],
                &Options::default(),
            )
            .unwrap();
            assert!(
                matches!(
                    sim.result,
                    Err(rune_service_probe::Error::Unrecognized { .. })
                ),
                "{reply:?}"
            );
        }
        let sim = simulate(&PostgresProbe::new(), &target(), &[], &Options::default()).unwrap();
        assert!(matches!(
            sim.result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
    }

    #[test]
    fn auth_probe_is_intrusive() {
        let err = simulate(
            &PostgresAuthProbe::new(),
            &target(),
            &[],
            &Options::default(),
        );
        assert!(matches!(
            err,
            Err(rune_service_probe::Error::IntrusiveNotAllowed { .. })
        ));
    }

    fn run_auth(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &PostgresAuthProbe::new(),
            &target(),
            replies,
            &Options::default().with_allow_intrusive(true),
        )
        .unwrap()
    }

    #[test]
    fn trust_auth_is_unauthenticated() {
        let mut reply = msg(b'R', &0u32.to_be_bytes());
        reply.extend(msg(
            b'S',
            b"server_version\x0016.2 (Debian 16.2-1.pgdg120+2)\0",
        ));
        reply.extend(msg(b'S', b"server_encoding\0UTF8\0"));
        reply.extend(msg(b'K', &[0; 8]));
        reply.extend(msg(b'Z', b"I"));
        let sim = run_auth(&[&reply]);
        assert_eq!(sim.sent.len(), 2);
        assert!(sim.sent[0].ends_with(b"user\0postgres\0\0"));
        assert_eq!(sim.sent[1], TERMINATE);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.version.as_deref(), Some("16.2"));
        assert_eq!(info.details["postgresql.param.server_encoding"], "UTF8");
        assert_eq!(info.findings[0].check_id, "postgresql.unauthenticated");
        assert_eq!(info.findings[0].taxonomy[0].cwe_number(), Some(306));
    }

    #[test]
    fn scram_requires_auth() {
        let mut body = 10u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        let sim = run_auth(&[&msg(b'R', &body)]);
        assert_eq!(sim.sent.len(), 1);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.details["postgresql.auth_method"], "sasl");
        assert_eq!(info.capabilities, ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]);
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn md5_and_cleartext_are_flagged() {
        let mut md5 = 5u32.to_be_bytes().to_vec();
        md5.extend_from_slice(&[1, 2, 3, 4]);
        let info = run_auth(&[&msg(b'R', &md5)]).result.unwrap();
        assert_eq!(info.findings[0].check_id, "postgresql.md5_auth");
        let info = run_auth(&[&msg(b'R', &3u32.to_be_bytes())]).result.unwrap();
        assert_eq!(info.findings[0].check_id, "postgresql.cleartext_password");
    }

    #[test]
    fn hba_rejection_requires_auth() {
        let reply = error_response(&[
            (b'S', "FATAL"),
            (b'C', "28000"),
            (
                b'M',
                "no pg_hba.conf entry for host \"192.0.2.7\", user \"postgres\", database \"postgres\", no encryption",
            ),
        ]);
        let info = run_auth(&[&reply]).result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.details["postgresql.error_code"], "28000");
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(matches!(
            parse_message(&[b'E', 0, 0, 0, 1]),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            parse_message(&[b'E', 0xff, 0, 0, 0]),
            Err(Error::Malformed { .. })
        ));
        assert!(parse_message(&[b'R', 0, 0]).unwrap_err().is_truncated());
    }
}

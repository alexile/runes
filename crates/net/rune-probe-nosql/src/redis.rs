//! Redis (and Valkey, Dragonfly): `INFO server`, falling back to `PING`.
//!
//! Replies are [RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/).
//! An unauthenticated client that gets an `INFO` bulk reply or `+PONG`
//! can run commands: the classic open-Redis exposure. `-NOAUTH` means a
//! password (or ACL user) is required; `-DENIED` is protected mode, which
//! refuses remote clients when no password is set.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target,
};

use crate::Error;
use crate::wire::text;

const WHAT: &str = "resp reply";

/// Longest status or error line accepted.
const MAX_LINE: usize = 4096;
/// Largest bulk string accepted (`INFO server` is about 1.5 KiB).
const MAX_BULK: usize = 256 * 1024;

/// `INFO server` as a RESP array.
pub const INFO_SERVER: &[u8] = b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n";
/// `PING` as a RESP array.
pub const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

/// A RESP reply, as far as the probe needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// `+...`: a simple string, e.g. `PONG`.
    Simple(String),
    /// `-...`: an error, e.g. `NOAUTH Authentication required.`.
    Error(String),
    /// `:...`: an integer.
    Integer(i64),
    /// `$...`: a bulk string; `None` for the null bulk string.
    Bulk(Option<Vec<u8>>),
    /// `*...`: an array, of which only the length is kept.
    Array(i64),
}

/// Parse one RESP reply from the start of `buf`, returning it and the
/// bytes it took. Array elements are not parsed.
///
/// ```
/// use rune_probe_nosql::redis::{Reply, parse_reply};
///
/// assert_eq!(parse_reply(b"+PONG\r\n")?, (Reply::Simple("PONG".into()), 7));
/// assert_eq!(parse_reply(b"$3\r\nabc\r\n")?.0, Reply::Bulk(Some(b"abc".to_vec())));
/// # Ok::<(), rune_probe_nosql::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Truncated`] until the reply is complete, and
/// [`Error::Malformed`] when the bytes are not RESP.
pub fn parse_reply(buf: &[u8]) -> Result<(Reply, usize), Error> {
    let Some(&kind) = buf.first() else {
        return Err(Error::Truncated { what: WHAT });
    };
    if !matches!(kind, b'+' | b'-' | b':' | b'$' | b'*') {
        return Err(Error::malformed(WHAT, format!("type byte {kind:#04x}")));
    }
    let rest = buf.get(1..).unwrap_or_default();
    let Some(end) = rest.windows(2).position(|w| w == b"\r\n") else {
        if rest.len() > MAX_LINE {
            return Err(Error::malformed(WHAT, "line too long"));
        }
        return Err(Error::Truncated { what: WHAT });
    };
    if end > MAX_LINE {
        return Err(Error::malformed(WHAT, "line too long"));
    }
    let line = rest.get(..end).unwrap_or_default();
    let used = 1 + end + 2;
    let int = || {
        std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| Error::malformed(WHAT, "bad integer"))
    };
    let reply = match kind {
        b'+' => Reply::Simple(text(line)),
        b'-' => Reply::Error(text(line)),
        b':' => Reply::Integer(int()?),
        b'*' => Reply::Array(int()?),
        _ => {
            let len = int()?;
            if len < 0 {
                return Ok((Reply::Bulk(None), used));
            }
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > MAX_BULK {
                return Err(Error::malformed(WHAT, format!("bulk length {len}")));
            }
            let body = buf
                .get(used..used + len)
                .ok_or(Error::Truncated { what: WHAT })?;
            match buf.get(used + len..used + len + 2) {
                Some(b"\r\n") => {}
                Some(_) => return Err(Error::malformed(WHAT, "bulk without CRLF")),
                None => return Err(Error::Truncated { what: WHAT }),
            }
            return Ok((Reply::Bulk(Some(body.to_vec())), used + len + 2));
        }
    };
    Ok((reply, used))
}

/// The `key:value` fields of an `INFO` reply, in order, without section
/// headers.
///
/// ```
/// let fields = rune_probe_nosql::redis::parse_info("# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n");
/// assert_eq!(fields, [("redis_version".into(), "7.2.4".into()), ("os".into(), "Linux".into())]);
/// ```
#[must_use]
pub fn parse_info(info: &str) -> Vec<(String, String)> {
    info.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// What an error reply says about access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// `NOAUTH`, `WRONGPASS` or the pre-2.6 "operation not permitted":
    /// credentials are required.
    AuthRequired,
    /// `DENIED`: protected mode refuses remote clients.
    ProtectedMode,
    /// `NOPERM`: the client is the (unauthenticated) default user, which
    /// the ACL does not allow this command.
    NoPermission,
    /// The command is unknown (renamed or disabled).
    UnknownCommand,
    /// Anything else.
    Other,
}

/// Classify an error reply's text.
///
/// ```
/// use rune_probe_nosql::redis::{ErrorKind, classify_error};
///
/// assert_eq!(classify_error("NOAUTH Authentication required."), ErrorKind::AuthRequired);
/// assert_eq!(classify_error("ERR unknown command 'INFO'"), ErrorKind::UnknownCommand);
/// ```
#[must_use]
pub fn classify_error(message: &str) -> ErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.starts_with("noauth")
        || lower.starts_with("wrongpass")
        || lower.contains("authentication required")
        || lower.contains("operation not permitted")
    {
        ErrorKind::AuthRequired
    } else if lower.starts_with("denied") {
        ErrorKind::ProtectedMode
    } else if lower.starts_with("noperm") {
        ErrorKind::NoPermission
    } else if lower.contains("unknown command") {
        ErrorKind::UnknownCommand
    } else {
        ErrorKind::Other
    }
}

/// Read-only Redis probe: `INFO server`, then `PING` if `INFO` is refused
/// for a reason other than authentication.
///
/// Reports product (`Redis`, `Valkey` or `Dragonfly`), version, mode, OS
/// and [`ServiceInfo::auth`], with these findings:
///
/// | Check id                  | When                                                         |
/// | ------------------------- | ------------------------------------------------------------ |
/// | `redis.unauthenticated`   | `INFO` or `PING` answered without credentials (CWE-306); High instead of Critical when the default user's ACL restricts commands |
///
/// `-DENIED` (protected mode) is reported as `redis.protected_mode = yes`
/// with authentication unknown: the server is not reachable remotely, but
/// it has no password either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RedisProbe;

impl RedisProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for RedisProbe {
    fn id(&self) -> &'static str {
        "redis"
    }

    fn default_ports(&self) -> &[u16] {
        &[6379]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(RedisSession {
            target: target.clone(),
            buf: Vec::new(),
            received: false,
            pinged: false,
            info: None,
            pong: false,
            errors: Vec::new(),
            malformed: None,
        })
    }
}

struct RedisSession {
    target: Target,
    buf: Vec<u8>,
    received: bool,
    pinged: bool,
    info: Option<Vec<(String, String)>>,
    pong: bool,
    errors: Vec<String>,
    malformed: Option<Error>,
}

impl ProbeSession for RedisSession {
    fn start(&mut self) -> Action {
        Action::Send(INFO_SERVER.to_vec())
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        let reply = match parse_reply(&self.buf) {
            Ok((reply, _)) => reply,
            Err(e) if e.is_truncated() => return Action::Receive,
            Err(e) => {
                self.malformed = Some(e);
                return Action::Done;
            }
        };
        self.buf.clear();
        match reply {
            Reply::Bulk(Some(body)) if !self.pinged => {
                self.info = Some(parse_info(&String::from_utf8_lossy(&body)));
                Action::Done
            }
            Reply::Simple(s) if self.pinged && s.eq_ignore_ascii_case("PONG") => {
                self.pong = true;
                Action::Done
            }
            Reply::Error(message) => {
                let kind = classify_error(&message);
                self.errors.push(message);
                let retry = matches!(
                    kind,
                    ErrorKind::NoPermission | ErrorKind::UnknownCommand | ErrorKind::Other
                );
                if retry && !self.pinged {
                    self.pinged = true;
                    Action::Send(PING.to_vec())
                } else {
                    Action::Done
                }
            }
            _ => Action::Done,
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if !self.received {
            return Err(rune_service_probe::Error::no_response("redis"));
        }
        if self.info.is_none() && !self.pong && self.errors.is_empty() {
            let reason = self
                .malformed
                .take()
                .map_or_else(|| "no RESP reply".to_owned(), |e| e.to_string());
            return Err(rune_service_probe::Error::unrecognized("redis", reason));
        }
        let mut info = ServiceInfo::new("redis").with_product("Redis");
        if let Some(fields) = &self.info {
            info = with_info_fields(info, fields);
        }
        let kinds: Vec<ErrorKind> = self.errors.iter().map(|e| classify_error(e)).collect();
        if let Some(first) = self.errors.first() {
            info = info.with_banner(format!("-{first}"));
        }
        let restricted = kinds.contains(&ErrorKind::NoPermission);
        let open = self.info.is_some() || self.pong || restricted;
        if open {
            let (severity, title) = if restricted {
                (
                    Severity::High,
                    "Redis accepts unauthenticated clients as a restricted default user",
                )
            } else {
                (Severity::Critical, "Redis answers without authentication")
            };
            let evidence = if self.info.is_some() {
                "INFO server returned server details"
            } else if self.pong {
                "PING returned +PONG"
            } else {
                "-NOPERM for the unauthenticated default user"
            };
            if restricted {
                info = info.with_detail("redis.acl_restricted", "yes");
            }
            info = info.with_auth(AuthRequirement::NotRequired).push_finding(
                self.target
                    .finding(
                        "redis.unauthenticated",
                        title,
                        severity,
                        Confidence::Certain,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(306))
                    .push_evidence(Evidence::new("reply", evidence))
                    .with_remediation(Remediation::new(
                        "Require authentication (requirepass or ACL users with nopass removed \
                         from the default user), bind Redis to a private interface and \
                         firewall the port.",
                    )),
            );
        } else if kinds.contains(&ErrorKind::AuthRequired) {
            info = info.with_auth(AuthRequirement::Required);
        } else if kinds.contains(&ErrorKind::ProtectedMode) {
            info = info.with_detail("redis.protected_mode", "yes");
        }
        Ok(info)
    }
}

fn with_info_fields(mut info: ServiceInfo, fields: &[(String, String)]) -> ServiceInfo {
    let get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| text(v.as_bytes()))
    };
    if let Some(v) = get("valkey_version") {
        info = info.with_product("Valkey").with_version(v);
    } else if let Some(v) = get("dragonfly_version") {
        info = info.with_product("Dragonfly").with_version(v);
    } else if let Some(v) = get("redis_version") {
        info = info.with_version(v);
    }
    for (key, detail) in [
        ("redis_version", "redis.redis_version"),
        ("redis_mode", "redis.mode"),
        ("os", "redis.os"),
        ("arch_bits", "redis.arch_bits"),
        ("tcp_port", "redis.tcp_port"),
        ("uptime_in_days", "redis.uptime_in_days"),
    ] {
        if let Some(v) = get(key) {
            info = info.with_detail(detail, v);
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    fn run(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &RedisProbe,
            &Target::new("cache.test", 6379),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    fn bulk(body: &str) -> Vec<u8> {
        format!("${}\r\n{body}\r\n", body.len()).into_bytes()
    }

    const INFO: &str = "# Server\r\nredis_version:7.2.4\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\nos:Linux 6.1.0-18-amd64 x86_64\r\narch_bits:64\r\ntcp_port:6379\r\nuptime_in_days:12\r\n";

    #[test]
    fn open_redis_info() {
        let reply = bulk(INFO);
        let sim = run(&[&reply[..20], &reply[20..]]);
        assert_eq!(sim.sent, [INFO_SERVER.to_vec()]);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.product.as_deref(), Some("Redis"));
        assert_eq!(info.version.as_deref(), Some("7.2.4"));
        assert_eq!(info.details["redis.mode"], "standalone");
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        let finding = &info.findings[0];
        assert_eq!(finding.check_id, "redis.unauthenticated");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.taxonomy[0].cwe_number(), Some(306));
    }

    #[test]
    fn noauth_requires_auth() {
        let sim = run(&[b"-NOAUTH Authentication required.\r\n"]);
        assert_eq!(sim.sent.len(), 1);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn renamed_info_falls_back_to_ping() {
        let sim = run(&[
            b"-ERR unknown command 'INFO', with args beginning with: 'server' \r\n",
            b"+PONG\r\n",
        ]);
        assert_eq!(sim.sent, [INFO_SERVER.to_vec(), PING.to_vec()]);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn acl_restricted_default_user() {
        let sim = run(&[
            b"-NOPERM User default has no permissions to run the 'info' command\r\n",
            b"+PONG\r\n",
        ]);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.details["redis.acl_restricted"], "yes");
        assert_eq!(info.findings[0].severity, Severity::High);
    }

    #[test]
    fn protected_mode() {
        let sim = run(&[b"-DENIED Redis is running in protected mode because protected mode is enabled and no password is set for the default user.\r\n"]);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Unknown);
        assert_eq!(info.details["redis.protected_mode"], "yes");
    }

    #[test]
    fn valkey_is_identified() {
        let reply = bulk(
            "# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:8.0.1\r\n",
        );
        let info = run(&[&reply]).result.unwrap();
        assert_eq!(info.product.as_deref(), Some("Valkey"));
        assert_eq!(info.version.as_deref(), Some("8.0.1"));
    }

    #[test]
    fn not_redis() {
        let sim = run(&[b"HTTP/1.1 400 Bad Request\r\n\r\n"]);
        assert!(matches!(
            sim.result,
            Err(rune_service_probe::Error::Unrecognized { .. })
        ));
        assert!(matches!(
            run(&[]).result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
    }

    #[test]
    fn resp_edge_cases() {
        assert_eq!(parse_reply(b"$-1\r\n").unwrap().0, Reply::Bulk(None));
        assert_eq!(parse_reply(b":42\r\n").unwrap().0, Reply::Integer(42));
        assert_eq!(parse_reply(b"*3\r\n").unwrap().0, Reply::Array(3));
        assert!(parse_reply(b"$5\r\nab").unwrap_err().is_truncated());
        assert!(parse_reply(b"$999999999\r\n").is_err());
        assert!(matches!(
            parse_reply(b"$2\r\nabcd"),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            parse_reply(b":x\r\n"),
            Err(Error::Malformed { .. })
        ));
    }
}

//! MongoDB: `isMaster`, `buildInfo` and an access check.
//!
//! See the [wire protocol](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/).
//! The probe opens with a legacy `OP_QUERY` `isMaster`, which every server
//! version answers, then switches to `OP_MSG` when the server supports it
//! (wire version 6, MongoDB 3.6, and later). `isMaster` and `buildInfo`
//! never need authentication. Whether the server enforces access control
//! shows in the answer to `listDatabases` with `nameOnly`: an
//! `Unauthorized` (13) error, or a list. The probe keeps only the number
//! of databases, never their names.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target,
};

use crate::Error;
use crate::bson::{Bson, Document};
use crate::wire::Reader;

const WHAT: &str = "mongodb message";

/// Largest reply accepted.
const MAX_MESSAGE: usize = 1024 * 1024;

/// `OP_REPLY`.
pub const OP_REPLY: u32 = 1;
/// `OP_QUERY` (legacy; only for the handshake on current servers).
pub const OP_QUERY: u32 = 2004;
/// `OP_MSG`.
pub const OP_MSG: u32 = 2013;

/// The `Unauthorized` error code.
pub const UNAUTHORIZED: i64 = 13;

fn header(len: usize, request_id: u32, op: u32) -> Vec<u8> {
    let mut out = u32::try_from(len)
        .unwrap_or(u32::MAX)
        .to_le_bytes()
        .to_vec();
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&op.to_le_bytes());
    out
}

/// An `OP_QUERY` running `command` against `admin.$cmd`.
///
/// ```
/// use rune_probe_nosql::bson::{Bson, Document};
/// use rune_probe_nosql::mongodb::{OP_QUERY, op_query};
///
/// let msg = op_query(1, &Document::encode(&[("isMaster", Bson::Int32(1))]));
/// assert_eq!(u32::from_le_bytes(msg[12..16].try_into().unwrap()), OP_QUERY);
/// assert_eq!(u32::from_le_bytes(msg[..4].try_into().unwrap()) as usize, msg.len());
/// ```
#[must_use]
pub fn op_query(request_id: u32, command: &[u8]) -> Vec<u8> {
    let mut body = 0u32.to_le_bytes().to_vec(); // flags
    body.extend_from_slice(b"admin.$cmd\0");
    body.extend_from_slice(&0i32.to_le_bytes()); // numberToSkip
    body.extend_from_slice(&(-1i32).to_le_bytes()); // numberToReturn
    body.extend_from_slice(command);
    let mut out = header(16 + body.len(), request_id, OP_QUERY);
    out.extend_from_slice(&body);
    out
}

/// An `OP_MSG` with one body section, `command` (which must name `$db`).
#[must_use]
pub fn op_msg(request_id: u32, command: &[u8]) -> Vec<u8> {
    let mut body = 0u32.to_le_bytes().to_vec(); // flagBits
    body.push(0); // section kind 0: body
    body.extend_from_slice(command);
    let mut out = header(16 + body.len(), request_id, OP_MSG);
    out.extend_from_slice(&body);
    out
}

/// Parse one `OP_REPLY` or `OP_MSG` from the start of `bytes` and return
/// its (first) document and the bytes it took.
///
/// # Errors
///
/// [`Error::Truncated`] until the whole message has arrived, and
/// [`Error::Malformed`] for anything that is not such a reply.
pub fn parse_reply(bytes: &[u8]) -> Result<(Document, usize), Error> {
    let mut r = Reader::new(bytes, WHAT);
    let len = usize::try_from(r.u32_le()?).unwrap_or(usize::MAX);
    if !(16..=MAX_MESSAGE).contains(&len) {
        return Err(Error::malformed(WHAT, format!("length {len}")));
    }
    // Fail fast on another protocol: check the opcode before waiting for
    // `len` bytes.
    if let Some(op) = bytes.get(12..16) {
        let op = u32::from_le_bytes([op[0], op[1], op[2], op[3]]);
        if op != OP_REPLY && op != OP_MSG {
            return Err(Error::malformed(WHAT, format!("opcode {op}")));
        }
    }
    let message = r.take(len - 4)?;
    let mut m = Reader::new(message, WHAT);
    m.take(8)?; // requestID, responseTo
    let op = m.u32_le()?;
    let in_message = |e: Error| match e {
        Error::Truncated { .. } => Error::malformed(WHAT, "document overruns the message"),
        other => other,
    };
    if op == OP_REPLY {
        m.take(20).map_err(in_message)?; // flags, cursorID, startingFrom, numberReturned
    } else {
        m.take(4).map_err(in_message)?; // flagBits
        if m.u8().map_err(in_message)? != 0 {
            return Err(Error::malformed(WHAT, "first section is not a body"));
        }
    }
    let (doc, _) = Document::parse(m.rest()).map_err(in_message)?;
    Ok((doc, len))
}

/// Read-only MongoDB probe.
///
/// Reports version (from `buildInfo`), product (`MongoDB`, or `MongoDB
/// Enterprise`), replica-set role and name, wire versions, and whether
/// access control is enforced. Findings:
///
/// | Check id                  | When                                                    |
/// | ------------------------- | ------------------------------------------------------- |
/// | `mongodb.unauthenticated` | `listDatabases` succeeds without credentials (CWE-306)  |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MongodbProbe;

impl MongodbProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for MongodbProbe {
    fn id(&self) -> &'static str {
        "mongodb"
    }

    fn default_ports(&self) -> &[u16] {
        &[27017, 27018, 27019]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(MongoSession {
            target: target.clone(),
            buf: Vec::new(),
            received: false,
            step: Step::Hello,
            op_msg: false,
            hello: None,
            build_info: None,
            list: None,
            malformed: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Hello,
    BuildInfo,
    ListDatabases,
}

struct MongoSession {
    target: Target,
    buf: Vec<u8>,
    received: bool,
    step: Step,
    op_msg: bool,
    hello: Option<Document>,
    build_info: Option<Document>,
    list: Option<Document>,
    malformed: Option<Error>,
}

impl MongoSession {
    fn command(&self, request_id: u32, elements: &[(&str, Bson)]) -> Vec<u8> {
        if self.op_msg {
            let mut elements = elements.to_vec();
            elements.push(("$db", Bson::String("admin".into())));
            op_msg(request_id, &Document::encode(&elements))
        } else {
            op_query(request_id, &Document::encode(elements))
        }
    }
}

impl ProbeSession for MongoSession {
    fn start(&mut self) -> Action {
        Action::Send(op_query(
            1,
            &Document::encode(&[("isMaster", Bson::Int32(1))]),
        ))
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        let doc = match parse_reply(&self.buf) {
            Ok((doc, _)) => doc,
            Err(e) if e.is_truncated() => return Action::Receive,
            Err(e) => {
                self.malformed = Some(e);
                return Action::Done;
            }
        };
        self.buf.clear();
        match self.step {
            Step::Hello => {
                self.op_msg = doc
                    .get("maxWireVersion")
                    .and_then(Bson::as_i64)
                    .is_some_and(|v| v >= 6);
                self.hello = Some(doc);
                self.step = Step::BuildInfo;
                Action::Send(self.command(2, &[("buildInfo", Bson::Int32(1))]))
            }
            Step::BuildInfo => {
                self.build_info = Some(doc);
                self.step = Step::ListDatabases;
                Action::Send(self.command(
                    3,
                    &[
                        ("listDatabases", Bson::Int32(1)),
                        ("nameOnly", Bson::Bool(true)),
                    ],
                ))
            }
            Step::ListDatabases => {
                self.list = Some(doc);
                Action::Done
            }
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if !self.received {
            return Err(rune_service_probe::Error::no_response("mongodb"));
        }
        let Some(hello) = &self.hello else {
            let reason = self
                .malformed
                .take()
                .map_or_else(|| "no isMaster reply".to_owned(), |e| e.to_string());
            return Err(rune_service_probe::Error::unrecognized("mongodb", reason));
        };
        let mut info = ServiceInfo::new("mongodb").with_product("MongoDB");
        info = hello_details(info, hello);
        if let Some(build) = &self.build_info {
            info = build_details(info, build);
        }
        if let Some(list) = &self.list {
            let ok = list.get("ok").and_then(Bson::as_bool) == Some(true);
            let code = list.get("code").and_then(Bson::as_i64);
            let errmsg = list
                .get("errmsg")
                .and_then(Bson::as_str)
                .unwrap_or_default();
            if ok {
                let count = list
                    .get("databases")
                    .and_then(Bson::as_array)
                    .map_or(0, <[Bson]>::len);
                info = info
                    .with_auth(AuthRequirement::NotRequired)
                    .with_detail("mongodb.database_count", count.to_string())
                    .push_finding(
                        self.target
                            .finding(
                                "mongodb.unauthenticated",
                                "MongoDB serves requests without authentication",
                                Severity::Critical,
                                Confidence::Certain,
                            )
                            .push_taxonomy(TaxonomyRef::cwe(306))
                            .push_evidence(Evidence::new(
                                "listDatabases",
                                format!("ok without credentials ({count} databases)"),
                            ))
                            .with_remediation(Remediation::new(
                                "Enable access control (security.authorization: enabled), \
                                 create administrative users, bind MongoDB to a private \
                                 interface and firewall the port.",
                            )),
                    );
            } else if code == Some(UNAUTHORIZED) || errmsg.to_ascii_lowercase().contains("auth") {
                info = info.with_auth(AuthRequirement::Required);
            }
            if !ok && !errmsg.is_empty() {
                info = info.with_detail("mongodb.list_databases_error", errmsg);
            }
        }
        Ok(info)
    }
}

fn hello_details(mut info: ServiceInfo, hello: &Document) -> ServiceInfo {
    let flag = |key: &str| hello.get(key).and_then(Bson::as_bool) == Some(true);
    let set_name = hello.get("setName").and_then(Bson::as_str);
    let role = if hello.get("msg").and_then(Bson::as_str) == Some("isdbgrid") {
        "mongos"
    } else if flag("arbiterOnly") {
        "arbiter"
    } else if flag("secondary") {
        "secondary"
    } else if set_name.is_some() && (flag("ismaster") || flag("isWritablePrimary")) {
        "primary"
    } else if flag("ismaster") || flag("isWritablePrimary") {
        "standalone"
    } else {
        "unknown"
    };
    info = info.with_detail("mongodb.role", role);
    if let Some(name) = set_name {
        info = info.with_detail("mongodb.set_name", name);
    }
    for (key, detail) in [
        ("maxWireVersion", "mongodb.max_wire_version"),
        ("minWireVersion", "mongodb.min_wire_version"),
    ] {
        if let Some(v) = hello.get(key).and_then(Bson::as_i64) {
            info = info.with_detail(detail, v.to_string());
        }
    }
    info
}

fn build_details(mut info: ServiceInfo, build: &Document) -> ServiceInfo {
    if let Some(version) = build.get("version").and_then(Bson::as_str) {
        info = info.with_version(version);
    }
    if let Some(git) = build.get("gitVersion").and_then(Bson::as_str) {
        info = info.with_detail("mongodb.git_version", git);
    }
    let modules: Vec<&str> = build
        .get("modules")
        .and_then(Bson::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Bson::as_str)
        .collect();
    if modules.contains(&"enterprise") {
        info = info.with_product("MongoDB Enterprise");
    }
    if !modules.is_empty() {
        info = info.with_detail("mongodb.modules", modules.join(","));
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    fn op_msg_reply(doc: &[(&str, Bson)]) -> Vec<u8> {
        let mut body = 0u32.to_le_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(&Document::encode(doc));
        let mut out = header(16 + body.len(), 99, OP_MSG);
        out.extend_from_slice(&body);
        out
    }

    fn op_reply(doc: &[(&str, Bson)]) -> Vec<u8> {
        let mut body = vec![0; 20];
        body[16] = 1; // numberReturned
        body.extend_from_slice(&Document::encode(doc));
        let mut out = header(16 + body.len(), 99, OP_REPLY);
        out.extend_from_slice(&body);
        out
    }

    fn hello(wire: i32) -> Vec<u8> {
        op_reply(&[
            ("ismaster", Bson::Bool(true)),
            ("maxBsonObjectSize", Bson::Int32(16_777_216)),
            ("maxWireVersion", Bson::Int32(wire)),
            ("minWireVersion", Bson::Int32(0)),
            ("ok", Bson::Double(1.0)),
        ])
    }

    fn build_info(version: &str) -> Vec<u8> {
        op_msg_reply(&[
            ("version", Bson::String(version.into())),
            ("gitVersion", Bson::String("2a4a8d2e".into())),
            ("ok", Bson::Double(1.0)),
        ])
    }

    fn run(replies: &[&[u8]]) -> rune_service_probe::Simulation {
        simulate(
            &MongodbProbe,
            &Target::new("mongo.test", 27017),
            replies,
            &Options::default(),
        )
        .unwrap()
    }

    #[test]
    fn open_mongodb() {
        // Build a real `databases` array by hand: [{name: "admin"}, {name: "app"}].
        let db = |name: &str| Document::encode(&[("name", Bson::String(name.into()))]);
        let mut arr = vec![0, 0, 0, 0, 0x03, b'0', 0];
        arr.extend_from_slice(&db("admin"));
        arr.extend_from_slice(&[0x03, b'1', 0]);
        arr.extend_from_slice(&db("app"));
        arr.push(0);
        let n = u32::try_from(arr.len()).unwrap();
        arr[..4].copy_from_slice(&n.to_le_bytes());
        let mut doc = vec![0, 0, 0, 0, 0x04];
        doc.extend_from_slice(b"databases\0");
        doc.extend_from_slice(&arr);
        doc.extend_from_slice(&[0x01, b'o', b'k', 0]);
        doc.extend_from_slice(&1.0f64.to_le_bytes());
        doc.push(0);
        let n = u32::try_from(doc.len()).unwrap();
        doc[..4].copy_from_slice(&n.to_le_bytes());
        let mut body = vec![0, 0, 0, 0, 0];
        body.extend_from_slice(&doc);
        let mut list_reply = header(16 + body.len(), 3, OP_MSG);
        list_reply.extend_from_slice(&body);

        let h = hello(21);
        let sim = run(&[&h[..10], &h[10..], &build_info("7.0.12"), &list_reply]);
        assert_eq!(sim.sent.len(), 3);
        let op = |m: &[u8]| u32::from_le_bytes([m[12], m[13], m[14], m[15]]);
        assert_eq!(op(&sim.sent[0]), OP_QUERY);
        assert_eq!(op(&sim.sent[1]), OP_MSG);
        assert!(sim.sent[2].windows(9).any(|w| w == b"nameOnly\0"));
        let info = sim.result.unwrap();
        assert_eq!(info.version.as_deref(), Some("7.0.12"));
        assert_eq!(info.details["mongodb.role"], "standalone");
        assert_eq!(info.details["mongodb.database_count"], "2");
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.findings[0].check_id, "mongodb.unauthenticated");
        assert_eq!(info.findings[0].taxonomy[0].cwe_number(), Some(306));
    }

    #[test]
    fn auth_enabled() {
        let list = op_msg_reply(&[
            ("ok", Bson::Double(0.0)),
            (
                "errmsg",
                Bson::String("command listDatabases requires authentication".into()),
            ),
            ("code", Bson::Int32(13)),
            ("codeName", Bson::String("Unauthorized".into())),
        ]);
        let sim = run(&[&hello(17), &build_info("6.0.5"), &list]);
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.version.as_deref(), Some("6.0.5"));
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn legacy_server_uses_op_query_throughout() {
        let build = op_reply(&[
            ("version", Bson::String("3.2.22".into())),
            ("ok", Bson::Double(1.0)),
        ]);
        let sim = run(&[&hello(4), &build]);
        let op = |m: &[u8]| u32::from_le_bytes([m[12], m[13], m[14], m[15]]);
        assert!(sim.sent.iter().all(|m| op(m) == OP_QUERY));
        let info = sim.result.unwrap();
        assert_eq!(info.version.as_deref(), Some("3.2.22"));
        assert_eq!(info.auth, AuthRequirement::Unknown);
    }

    #[test]
    fn replica_set_and_mongos_roles() {
        let rs = op_reply(&[
            ("ismaster", Bson::Bool(false)),
            ("secondary", Bson::Bool(true)),
            ("setName", Bson::String("rs0".into())),
            ("maxWireVersion", Bson::Int32(17)),
        ]);
        let info = run(&[&rs]).result.unwrap();
        assert_eq!(info.details["mongodb.role"], "secondary");
        assert_eq!(info.details["mongodb.set_name"], "rs0");
        let mongos = op_reply(&[
            ("ismaster", Bson::Bool(true)),
            ("msg", Bson::String("isdbgrid".into())),
        ]);
        assert_eq!(
            run(&[&mongos]).result.unwrap().details["mongodb.role"],
            "mongos"
        );
    }

    #[test]
    fn not_mongodb() {
        assert!(matches!(
            run(&[
                b"HTTP/1.0 200 OK\r\n\r\nIt looks like you are trying to access MongoDB over HTTP"
            ])
            .result,
            Err(rune_service_probe::Error::Unrecognized { .. })
        ));
        assert!(matches!(
            run(&[]).result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
        // A huge length is rejected at once.
        assert!(matches!(
            parse_reply(&[0xff; 16]),
            Err(Error::Malformed { .. })
        ));
    }
}

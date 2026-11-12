//! `LDAPMessage` encoding and decoding, for the operations the probes use.
//!
//! See [RFC 4511 §4](https://www.rfc-editor.org/rfc/rfc4511#section-4).
//! Requests (bind, unbind, search) and the replies to them decode and
//! encode symmetrically, so the same types serve a client probe and a mock
//! or callback listener. Operations outside that subset decode as
//! [`Op::Other`] with their raw content.

use crate::Error;
use crate::ber::{self, BOOLEAN, ENUMERATED, INTEGER, OCTET_STRING, Reader, SEQUENCE, SET};

const WHAT: &str = "LDAPMessage";

/// Most attributes accepted in one entry.
const MAX_ATTRIBUTES: usize = 512;
/// Most values accepted for one attribute, or references in one reply.
const MAX_VALUES: usize = 1024;

const TAG_BIND_REQUEST: u8 = 0x60;
const TAG_BIND_RESPONSE: u8 = 0x61;
const TAG_UNBIND_REQUEST: u8 = 0x42;
const TAG_SEARCH_REQUEST: u8 = 0x63;
const TAG_SEARCH_ENTRY: u8 = 0x64;
const TAG_SEARCH_DONE: u8 = 0x65;
const TAG_SEARCH_REFERENCE: u8 = 0x73;
const TAG_EXTENDED_RESPONSE: u8 = 0x78;
/// `AuthenticationChoice` `simple [0] OCTET STRING`.
const TAG_AUTH_SIMPLE: u8 = 0x80;
/// `AuthenticationChoice` `sasl [3] SaslCredentials`.
const TAG_AUTH_SASL: u8 = 0xa3;
/// `Filter` `present [7] AttributeDescription`.
const TAG_FILTER_PRESENT: u8 = 0x87;
/// `ExtendedResponse` `responseName [10]`.
const TAG_RESPONSE_NAME: u8 = 0x8a;
/// `ExtendedResponse` `responseValue [11]`.
const TAG_RESPONSE_VALUE: u8 = 0x8b;

/// An LDAP result code ([RFC 4511 Appendix A](https://www.rfc-editor.org/rfc/rfc4511#appendix-A)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResultCode(pub i64);

impl ResultCode {
    /// `success`.
    pub const SUCCESS: Self = Self(0);
    /// `operationsError`: Active Directory's answer to an unauthenticated
    /// search when anonymous access is off.
    pub const OPERATIONS_ERROR: Self = Self(1);
    /// `protocolError`.
    pub const PROTOCOL_ERROR: Self = Self(2);
    /// `sizeLimitExceeded`: entries were returned, more exist.
    pub const SIZE_LIMIT_EXCEEDED: Self = Self(4);
    /// `authMethodNotSupported`.
    pub const AUTH_METHOD_NOT_SUPPORTED: Self = Self(7);
    /// `strongerAuthRequired`.
    pub const STRONGER_AUTH_REQUIRED: Self = Self(8);
    /// `confidentialityRequired`: the operation needs TLS.
    pub const CONFIDENTIALITY_REQUIRED: Self = Self(13);
    /// `noSuchObject`.
    pub const NO_SUCH_OBJECT: Self = Self(32);
    /// `inappropriateAuthentication`: e.g. anonymous bind refused.
    pub const INAPPROPRIATE_AUTHENTICATION: Self = Self(48);
    /// `invalidCredentials`.
    pub const INVALID_CREDENTIALS: Self = Self(49);
    /// `insufficientAccessRights`.
    pub const INSUFFICIENT_ACCESS_RIGHTS: Self = Self(50);
    /// `unwillingToPerform`.
    pub const UNWILLING_TO_PERFORM: Self = Self(53);

    /// The code's name in RFC 4511, e.g. `operationsError`, or `None` for
    /// codes outside the common set.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "success",
            1 => "operationsError",
            2 => "protocolError",
            3 => "timeLimitExceeded",
            4 => "sizeLimitExceeded",
            7 => "authMethodNotSupported",
            8 => "strongerAuthRequired",
            10 => "referral",
            11 => "adminLimitExceeded",
            13 => "confidentialityRequired",
            14 => "saslBindInProgress",
            32 => "noSuchObject",
            34 => "invalidDNSyntax",
            48 => "inappropriateAuthentication",
            49 => "invalidCredentials",
            50 => "insufficientAccessRights",
            51 => "busy",
            52 => "unavailable",
            53 => "unwillingToPerform",
            80 => "other",
            _ => return None,
        })
    }
}

impl std::fmt::Display for ResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({})", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

/// An `LDAPResult`: the outcome of an operation. Referrals are not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapResult {
    /// The result code.
    pub code: ResultCode,
    /// `matchedDN`.
    pub matched_dn: String,
    /// `diagnosticMessage`: free text, often revealing (AD prints its
    /// internal error and build here).
    pub diagnostic: String,
}

impl LdapResult {
    /// A result with this code and empty strings.
    #[must_use]
    pub const fn new(code: ResultCode) -> Self {
        Self {
            code,
            matched_dn: String::new(),
            diagnostic: String::new(),
        }
    }

    /// Set [`LdapResult::diagnostic`].
    #[must_use]
    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostic = diagnostic.into();
        self
    }
}

/// One attribute of an entry, with its raw values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attribute {
    /// The attribute description, as the server spelt it.
    pub name: String,
    /// The values, as sent.
    pub values: Vec<Vec<u8>>,
}

impl Attribute {
    /// An attribute with text values.
    pub fn new<I, V>(name: impl Into<String>, values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: AsRef<[u8]>,
    {
        Self {
            name: name.into(),
            values: values.into_iter().map(|v| v.as_ref().to_vec()).collect(),
        }
    }
}

/// A `SearchResultEntry`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SearchEntry {
    /// The entry's DN; empty for the rootDSE.
    pub dn: String,
    /// The attributes returned, in the server's order.
    pub attributes: Vec<Attribute>,
}

impl SearchEntry {
    /// An entry at `dn`.
    #[must_use]
    pub fn new(dn: impl Into<String>, attributes: Vec<Attribute>) -> Self {
        Self {
            dn: dn.into(),
            attributes,
        }
    }

    /// The values of `name` (case-insensitive), or an empty slice.
    #[must_use]
    pub fn values(&self, name: &str) -> &[Vec<u8>] {
        self.attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
            .map_or(&[], |a| a.values.as_slice())
    }
}

/// Search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// `baseObject`: the base entry only (how the rootDSE is read).
    Base,
    /// `singleLevel`: the base's immediate children.
    OneLevel,
    /// `wholeSubtree`.
    Subtree,
    /// Any other value.
    Other(i64),
}

impl Scope {
    const fn code(self) -> i64 {
        match self {
            Self::Base => 0,
            Self::OneLevel => 1,
            Self::Subtree => 2,
            Self::Other(code) => code,
        }
    }

    const fn from_code(code: i64) -> Self {
        match code {
            0 => Self::Base,
            1 => Self::OneLevel,
            2 => Self::Subtree,
            other => Self::Other(other),
        }
    }
}

/// A `SearchRequest`. The filter is kept as its BER encoding;
/// [`SearchRequest::new`] uses `(objectClass=*)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SearchRequest {
    /// `baseObject`: empty for the rootDSE.
    pub base: String,
    /// `scope`.
    pub scope: Scope,
    /// `derefAliases` (0, never, by default).
    pub deref_aliases: i64,
    /// `sizeLimit`; 0 means no client limit.
    pub size_limit: i64,
    /// `timeLimit` in seconds; 0 means no client limit.
    pub time_limit: i64,
    /// `typesOnly`.
    pub types_only: bool,
    /// The BER-encoded `Filter`.
    pub filter: Vec<u8>,
    /// Attributes to return. `1.1` asks for none.
    pub attributes: Vec<String>,
}

impl SearchRequest {
    /// A search of `base` with filter `(objectClass=*)`, no limits and
    /// all user attributes.
    pub fn new(base: impl Into<String>, scope: Scope) -> Self {
        Self {
            base: base.into(),
            scope,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: present_filter("objectClass"),
            attributes: Vec::new(),
        }
    }

    /// Set [`SearchRequest::size_limit`].
    #[must_use]
    pub const fn with_size_limit(mut self, limit: i64) -> Self {
        self.size_limit = limit;
        self
    }

    /// Set [`SearchRequest::time_limit`].
    #[must_use]
    pub const fn with_time_limit(mut self, seconds: i64) -> Self {
        self.time_limit = seconds;
        self
    }

    /// Set [`SearchRequest::attributes`].
    #[must_use]
    pub fn with_attributes<I, S>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.attributes = attributes.into_iter().map(Into::into).collect();
        self
    }
}

/// The BER encoding of the filter `(<attribute>=*)`.
#[must_use]
pub fn present_filter(attribute: &str) -> Vec<u8> {
    ber::tlv(TAG_FILTER_PRESENT, attribute.as_bytes())
}

/// How a `BindRequest` authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindAuth {
    /// Simple authentication with this password. An empty name and an
    /// empty password is an anonymous bind (RFC 4513 §5.1.1).
    Simple(Vec<u8>),
    /// SASL with this mechanism; credentials are not kept.
    Sasl(String),
}

/// A `BindRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BindRequest {
    /// Protocol version, 3.
    pub version: i64,
    /// The DN to bind as; empty for anonymous.
    pub name: String,
    /// The authentication choice.
    pub auth: BindAuth,
}

impl BindRequest {
    /// An anonymous simple bind: `LDAPv3`, empty name, empty password.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            version: 3,
            name: String::new(),
            auth: BindAuth::Simple(Vec::new()),
        }
    }

    /// True for an anonymous simple bind.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.name.is_empty() && matches!(&self.auth, BindAuth::Simple(p) if p.is_empty())
    }
}

/// The protocol operation of an [`Message`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// `BindRequest`.
    BindRequest(BindRequest),
    /// `BindResponse` (SASL server credentials are not kept).
    BindResponse(LdapResult),
    /// `UnbindRequest`.
    UnbindRequest,
    /// `SearchRequest`.
    SearchRequest(SearchRequest),
    /// `SearchResultEntry`.
    SearchResultEntry(SearchEntry),
    /// `SearchResultDone`.
    SearchResultDone(LdapResult),
    /// `SearchResultReference`: continuation URIs.
    SearchResultReference(Vec<String>),
    /// `ExtendedResponse`. With message id 0 and name
    /// `1.3.6.1.4.1.1466.20036` it is a notice of disconnection.
    ExtendedResponse {
        /// The result.
        result: LdapResult,
        /// `responseName`, an OID.
        name: Option<String>,
        /// `responseValue`.
        value: Option<Vec<u8>>,
    },
    /// Any other operation: its tag and raw content.
    Other {
        /// The `[APPLICATION n]` tag byte.
        tag: u8,
        /// The element content.
        content: Vec<u8>,
    },
}

/// One `LDAPMessage`. Controls are skipped when decoding and not encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Message {
    /// `messageID`. 0 is reserved for unsolicited notifications.
    pub id: i64,
    /// The operation.
    pub op: Op,
}

impl Message {
    /// A message with this id and operation.
    #[must_use]
    pub const fn new(id: i64, op: Op) -> Self {
        Self { id, op }
    }

    /// Encode the message.
    ///
    /// ```
    /// use rune_probe_ldap::{BindRequest, Message, Op};
    ///
    /// let bind = Message::new(1, Op::BindRequest(BindRequest::anonymous())).encode();
    /// assert_eq!(bind, [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
    /// assert_eq!(Message::decode(&bind)?.op, Op::BindRequest(BindRequest::anonymous()));
    /// # Ok::<(), rune_probe_ldap::Error>(())
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = ber::integer(INTEGER, self.id);
        body.extend(encode_op(&self.op));
        ber::tlv(SEQUENCE, &body)
    }

    /// Decode exactly one complete message.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `bytes` ends early and [`Error::Malformed`]
    /// if it is not an `LDAPMessage` or has bytes after it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (message, used) = parse_message(bytes)?;
        if used != bytes.len() {
            return Err(Error::malformed(WHAT, "trailing bytes"));
        }
        Ok(message)
    }
}

/// Parse the message at the start of a byte stream, returning it and the
/// number of bytes it took. Use this on TCP reads, which may hold part of
/// a message or several.
///
/// # Errors
///
/// [`Error::Truncated`] until the whole message has arrived, and
/// [`Error::Malformed`] when the bytes are not an `LDAPMessage`.
pub fn parse_message(buf: &[u8]) -> Result<(Message, usize), Error> {
    let (tag, header, len) = ber::header(buf, WHAT)?;
    if tag != SEQUENCE {
        return Err(Error::malformed(WHAT, format!("tag {tag:#04x}")));
    }
    let total = header + len;
    let content = buf
        .get(header..total)
        .ok_or(Error::Truncated { what: WHAT })?;
    let message = decode_body(content).map_err(|e| match e {
        // The outer length said the message is complete: a short element
        // inside it is malformed, not truncated.
        Error::Truncated { what } => Error::malformed(what, "element overruns its message"),
        e @ Error::Malformed { .. } => e,
    })?;
    Ok((message, total))
}

fn decode_body(content: &[u8]) -> Result<Message, Error> {
    let mut r = Reader::new(content, WHAT);
    let id = r.integer(INTEGER)?;
    let (tag, op) = r.tlv()?;
    let op = decode_op(tag, op)?;
    // Controls [0] and anything after are ignored.
    Ok(Message { id, op })
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn decode_op(tag: u8, content: &[u8]) -> Result<Op, Error> {
    let mut r = Reader::new(content, WHAT);
    Ok(match tag {
        TAG_BIND_REQUEST => {
            let version = r.integer(INTEGER)?;
            let name = text(r.expect(OCTET_STRING)?);
            let (auth_tag, auth) = r.tlv()?;
            let auth = match auth_tag {
                TAG_AUTH_SIMPLE => BindAuth::Simple(auth.to_vec()),
                TAG_AUTH_SASL => {
                    let mut sasl = Reader::new(auth, WHAT);
                    BindAuth::Sasl(text(sasl.expect(OCTET_STRING)?))
                }
                other => {
                    return Err(Error::malformed(
                        WHAT,
                        format!("authentication choice {other:#04x}"),
                    ));
                }
            };
            Op::BindRequest(BindRequest {
                version,
                name,
                auth,
            })
        }
        TAG_BIND_RESPONSE => Op::BindResponse(decode_result(&mut r)?),
        TAG_UNBIND_REQUEST => Op::UnbindRequest,
        TAG_SEARCH_REQUEST => {
            let base = text(r.expect(OCTET_STRING)?);
            let scope = Scope::from_code(r.integer(ENUMERATED)?);
            let deref_aliases = r.integer(ENUMERATED)?;
            let size_limit = r.integer(INTEGER)?;
            let time_limit = r.integer(INTEGER)?;
            let types_only = r.expect(BOOLEAN)?.iter().any(|&b| b != 0);
            let filter_start = content.len() - r.remaining();
            r.tlv()?;
            let filter_end = content.len() - r.remaining();
            let filter = content
                .get(filter_start..filter_end)
                .unwrap_or_default()
                .to_vec();
            let mut attrs = Reader::new(r.expect(SEQUENCE)?, WHAT);
            let mut attributes = Vec::new();
            while !attrs.is_empty() {
                if attributes.len() >= MAX_VALUES {
                    return Err(Error::malformed(WHAT, "too many attributes"));
                }
                attributes.push(text(attrs.expect(OCTET_STRING)?));
            }
            Op::SearchRequest(SearchRequest {
                base,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            })
        }
        TAG_SEARCH_ENTRY => {
            let dn = text(r.expect(OCTET_STRING)?);
            let mut list = Reader::new(r.expect(SEQUENCE)?, WHAT);
            let mut attributes = Vec::new();
            while !list.is_empty() {
                if attributes.len() >= MAX_ATTRIBUTES {
                    return Err(Error::malformed(WHAT, "too many attributes"));
                }
                let mut attr = Reader::new(list.expect(SEQUENCE)?, WHAT);
                let name = text(attr.expect(OCTET_STRING)?);
                let mut vals = Reader::new(attr.expect(SET)?, WHAT);
                let mut values = Vec::new();
                while !vals.is_empty() {
                    if values.len() >= MAX_VALUES {
                        return Err(Error::malformed(WHAT, "too many values"));
                    }
                    values.push(vals.expect(OCTET_STRING)?.to_vec());
                }
                attributes.push(Attribute { name, values });
            }
            Op::SearchResultEntry(SearchEntry { dn, attributes })
        }
        TAG_SEARCH_DONE => Op::SearchResultDone(decode_result(&mut r)?),
        TAG_SEARCH_REFERENCE => {
            let mut uris = Vec::new();
            while !r.is_empty() {
                if uris.len() >= MAX_VALUES {
                    return Err(Error::malformed(WHAT, "too many references"));
                }
                uris.push(text(r.expect(OCTET_STRING)?));
            }
            Op::SearchResultReference(uris)
        }
        TAG_EXTENDED_RESPONSE => {
            let result = decode_result(&mut r)?;
            let (mut name, mut value) = (None, None);
            while !r.is_empty() {
                let (tag, content) = r.tlv()?;
                match tag {
                    TAG_RESPONSE_NAME => name = Some(text(content)),
                    TAG_RESPONSE_VALUE => value = Some(content.to_vec()),
                    _ => {}
                }
            }
            Op::ExtendedResponse {
                result,
                name,
                value,
            }
        }
        tag => Op::Other {
            tag,
            content: content.to_vec(),
        },
    })
}

fn decode_result(r: &mut Reader<'_>) -> Result<LdapResult, Error> {
    let code = ResultCode(r.integer(ENUMERATED)?);
    let matched_dn = text(r.expect(OCTET_STRING)?);
    let diagnostic = text(r.expect(OCTET_STRING)?);
    // A referral [3] and operation-specific fields may follow; callers
    // read what they need and ignore the rest.
    Ok(LdapResult {
        code,
        matched_dn,
        diagnostic,
    })
}

fn encode_result(result: &LdapResult) -> Vec<u8> {
    let mut out = ber::integer(ENUMERATED, result.code.0);
    out.extend(ber::tlv(OCTET_STRING, result.matched_dn.as_bytes()));
    out.extend(ber::tlv(OCTET_STRING, result.diagnostic.as_bytes()));
    out
}

fn encode_op(op: &Op) -> Vec<u8> {
    match op {
        Op::BindRequest(bind) => {
            let mut out = ber::integer(INTEGER, bind.version);
            out.extend(ber::tlv(OCTET_STRING, bind.name.as_bytes()));
            match &bind.auth {
                BindAuth::Simple(password) => out.extend(ber::tlv(TAG_AUTH_SIMPLE, password)),
                BindAuth::Sasl(mechanism) => out.extend(ber::tlv(
                    TAG_AUTH_SASL,
                    &ber::tlv(OCTET_STRING, mechanism.as_bytes()),
                )),
            }
            ber::tlv(TAG_BIND_REQUEST, &out)
        }
        Op::BindResponse(result) => ber::tlv(TAG_BIND_RESPONSE, &encode_result(result)),
        Op::UnbindRequest => ber::tlv(TAG_UNBIND_REQUEST, &[]),
        Op::SearchRequest(search) => {
            let mut out = ber::tlv(OCTET_STRING, search.base.as_bytes());
            out.extend(ber::integer(ENUMERATED, search.scope.code()));
            out.extend(ber::integer(ENUMERATED, search.deref_aliases));
            out.extend(ber::integer(INTEGER, search.size_limit));
            out.extend(ber::integer(INTEGER, search.time_limit));
            out.extend(ber::tlv(
                BOOLEAN,
                &[if search.types_only { 0xff } else { 0 }],
            ));
            out.extend_from_slice(&search.filter);
            let attrs: Vec<u8> = search
                .attributes
                .iter()
                .flat_map(|a| ber::tlv(OCTET_STRING, a.as_bytes()))
                .collect();
            out.extend(ber::tlv(SEQUENCE, &attrs));
            ber::tlv(TAG_SEARCH_REQUEST, &out)
        }
        Op::SearchResultEntry(entry) => {
            let mut out = ber::tlv(OCTET_STRING, entry.dn.as_bytes());
            let mut list = Vec::new();
            for attr in &entry.attributes {
                let mut a = ber::tlv(OCTET_STRING, attr.name.as_bytes());
                let vals: Vec<u8> = attr
                    .values
                    .iter()
                    .flat_map(|v| ber::tlv(OCTET_STRING, v))
                    .collect();
                a.extend(ber::tlv(SET, &vals));
                list.extend(ber::tlv(SEQUENCE, &a));
            }
            out.extend(ber::tlv(SEQUENCE, &list));
            ber::tlv(TAG_SEARCH_ENTRY, &out)
        }
        Op::SearchResultDone(result) => ber::tlv(TAG_SEARCH_DONE, &encode_result(result)),
        Op::SearchResultReference(uris) => {
            let out: Vec<u8> = uris
                .iter()
                .flat_map(|u| ber::tlv(OCTET_STRING, u.as_bytes()))
                .collect();
            ber::tlv(TAG_SEARCH_REFERENCE, &out)
        }
        Op::ExtendedResponse {
            result,
            name,
            value,
        } => {
            let mut out = encode_result(result);
            if let Some(name) = name {
                out.extend(ber::tlv(TAG_RESPONSE_NAME, name.as_bytes()));
            }
            if let Some(value) = value {
                out.extend(ber::tlv(TAG_RESPONSE_VALUE, value));
            }
            ber::tlv(TAG_EXTENDED_RESPONSE, &out)
        }
        Op::Other { tag, content } => ber::tlv(*tag, content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_dse_search_matches_reference_encoding() {
        // ldapsearch -x -s base -b "" "(objectClass=*)" namingContexts
        let req = SearchRequest::new("", Scope::Base).with_attributes(["namingContexts"]);
        let bytes = Message::new(1, Op::SearchRequest(req.clone())).encode();
        let expected = [
            0x30, 0x35, 0x02, 0x01, 0x01, 0x63, 0x30, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01,
            0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, b'o', b'b',
            b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's', 0x30, 0x10, 0x04, 0x0e, b'n',
            b'a', b'm', b'i', b'n', b'g', b'C', b'o', b'n', b't', b'e', b'x', b't', b's',
        ];
        assert_eq!(bytes, expected);
        assert_eq!(Message::decode(&bytes).unwrap().op, Op::SearchRequest(req));
    }

    #[test]
    fn unbind_and_notice_of_disconnection() {
        let unbind = Message::new(3, Op::UnbindRequest).encode();
        assert_eq!(unbind, [0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00]);
        let notice = Message::new(
            0,
            Op::ExtendedResponse {
                result: LdapResult::new(ResultCode::PROTOCOL_ERROR),
                name: Some("1.3.6.1.4.1.1466.20036".into()),
                value: None,
            },
        );
        assert_eq!(Message::decode(&notice.encode()).unwrap(), notice);
    }

    #[test]
    fn stream_parsing_and_errors() {
        let done = Message::new(
            1,
            Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS)),
        );
        let mut stream = done.encode();
        stream.extend(Message::new(2, Op::UnbindRequest).encode());
        let (first, used) = parse_message(&stream).unwrap();
        assert_eq!(first, done);
        assert_eq!(parse_message(&stream[used..]).unwrap().0.id, 2);
        assert!(
            parse_message(&stream[..used - 1])
                .unwrap_err()
                .is_truncated()
        );
        assert!(Message::decode(&stream).is_err());
        assert!(parse_message(b"HTTP/1.1 400").is_err_and(|e| !e.is_truncated()));
        // A complete outer SEQUENCE whose inner element overruns it.
        assert!(parse_message(&[0x30, 0x03, 0x02, 0x05, 0x01]).is_err_and(|e| !e.is_truncated()));
        assert_eq!(ResultCode(50).to_string(), "insufficientAccessRights (50)");
        assert_eq!(ResultCode(999).to_string(), "999");
    }
}

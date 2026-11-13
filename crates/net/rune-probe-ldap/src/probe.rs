//! The probes: a read-only root DSE read and an opt-in anonymous-access
//! check.

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, Safety, ServiceInfo, ServiceProbe, Target,
    TlsSupport,
};

use crate::Error;
use crate::message::{
    BindRequest, LdapResult, Message, Op, ResultCode, Scope, SearchEntry, SearchRequest,
    parse_message,
};
use crate::rootdse::{
    OID_PASSWORD_MODIFY, OID_WHOAMI, RootDse, functional_level_name, root_dse_search,
};

/// Message id of the root DSE search.
const ID_ROOT_DSE: i64 = 1;
/// Message id of the anonymous bind.
const ID_BIND: i64 = 2;
/// Message id of the anonymous naming-context search.
const ID_SEARCH: i64 = 3;
/// Message id of the unbind.
const ID_UNBIND: i64 = 4;

/// Longest diagnostic message copied into the report.
const MAX_DIAGNOSTIC: usize = 256;

/// Read-only LDAP probe: reads the root DSE without binding.
///
/// Every `LDAPv3` server publishes its root DSE to anonymous clients
/// (RFC 4512 §5.1), so this sends one base-scope search of `""` and
/// nothing else. It reports the product (`Microsoft Active Directory`,
/// `OpenLDAP`, `vendorName`/`vendorVersion`), naming contexts, LDAP
/// versions, SASL mechanisms and extended operations as capabilities
/// (`sasl:GSSAPI`, `starttls`), Active Directory functional levels and DNS
/// host name under `ldap.*` details, and `StartTLS` support as
/// [`ServiceInfo::tls`]. It never binds, so [`ServiceInfo::auth`] stays
/// unknown; [`LdapAnonymousProbe`] answers that.
///
/// | Check id               | When                                                                |
/// | ---------------------- | ------------------------------------------------------------------- |
/// | `ldap.tls_not_offered` | plain LDAP without `StartTLS`: binds cross the network in clear (CWE-319) |
/// | `ldap.ldapv2_enabled`  | `supportedLDAPVersion` includes 2, an obsolete protocol (CWE-477)    |
///
/// For LDAPS (636, 3269) wrap the stream in TLS yourself and run
/// [`LdapProbe::over_tls`] with `Runner::probe_stream`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapProbe {
    over_tls: bool,
}

impl LdapProbe {
    /// The probe for plain LDAP (389, 3268).
    #[must_use]
    pub const fn new() -> Self {
        Self { over_tls: false }
    }

    /// The probe for a stream already inside TLS (LDAPS on 636, 3269):
    /// reports [`TlsSupport::Implicit`] and no TLS finding.
    #[must_use]
    pub const fn over_tls() -> Self {
        Self { over_tls: true }
    }
}

impl ServiceProbe for LdapProbe {
    fn id(&self) -> &'static str {
        "ldap"
    }

    fn default_ports(&self) -> &[u16] {
        if self.over_tls {
            &[636, 3269]
        } else {
            &[389, 3268]
        }
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session::new(target, Mode::RootDse, self.over_tls))
    }
}

/// Intrusive LDAP probe: an anonymous bind and a one-entry search of the
/// default naming context.
///
/// After reading the root DSE as [`LdapProbe`] does (and reporting the
/// same), it sends an anonymous simple bind (empty name and password,
/// RFC 4513 §5.1.1) and, if the server accepts it, a one-level search of
/// the default naming context for at most one entry with no attributes
/// (`1.1`), then unbinds. It reads no directory data beyond whether an
/// entry is visible, but it does authenticate, so it is
/// [`Safety::Intrusive`] and runners refuse it unless intrusive probes are
/// allowed. Its id is `ldap-anonymous`; findings use the `ldap.` prefix.
///
/// | Check id              | When                                                                  |
/// | --------------------- | --------------------------------------------------------------------- |
/// | `ldap.anonymous_read` | the anonymous search returned a directory entry (CWE-306)              |
/// | `ldap.anonymous_bind` | the anonymous bind succeeded but no entry was visible (CWE-1390)       |
///
/// [`ServiceInfo::auth`] is [`AuthRequirement::NotRequired`] when an entry
/// was visible, and [`AuthRequirement::Required`] when the bind or the
/// search was refused. The outcome is also in `ldap.anonymous_bind`
/// (`accepted`, `refused`) and `ldap.anonymous_search` (`entries`,
/// `empty`, `refused`) details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LdapAnonymousProbe {
    over_tls: bool,
}

impl LdapAnonymousProbe {
    /// The probe for plain LDAP.
    #[must_use]
    pub const fn new() -> Self {
        Self { over_tls: false }
    }

    /// The probe for a stream already inside TLS (LDAPS).
    #[must_use]
    pub const fn over_tls() -> Self {
        Self { over_tls: true }
    }
}

impl ServiceProbe for LdapAnonymousProbe {
    fn id(&self) -> &'static str {
        "ldap-anonymous"
    }

    fn safety(&self) -> Safety {
        Safety::Intrusive
    }

    fn default_ports(&self) -> &[u16] {
        if self.over_tls {
            &[636, 3269]
        } else {
            &[389, 3268]
        }
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session::new(target, Mode::Anonymous, self.over_tls))
    }
}

/// The request that opens every session: the root DSE search.
///
/// ```
/// use rune_probe_ldap::{Message, Op, root_dse_request};
///
/// let msg = Message::decode(&root_dse_request())?;
/// let Op::SearchRequest(search) = msg.op else { unreachable!() };
/// assert_eq!(search.base, "");
/// assert!(search.attributes.iter().any(|a| a == "namingContexts"));
/// # Ok::<(), rune_probe_ldap::Error>(())
/// ```
#[must_use]
pub fn root_dse_request() -> Vec<u8> {
    Message::new(ID_ROOT_DSE, Op::SearchRequest(root_dse_search())).encode()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    RootDse,
    Anonymous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    RootDse,
    Bind,
    Search,
    Unbinding,
}

struct Session {
    target: Target,
    mode: Mode,
    over_tls: bool,
    phase: Phase,
    buf: Vec<u8>,
    received: bool,
    root: Option<SearchEntry>,
    root_done: Option<LdapResult>,
    bind: Option<LdapResult>,
    search_base: Option<String>,
    search_entries: usize,
    search_done: Option<LdapResult>,
    notice: Option<LdapResult>,
    malformed: Option<Error>,
}

impl Session {
    fn new(target: &Target, mode: Mode, over_tls: bool) -> Self {
        Self {
            target: target.clone(),
            mode,
            over_tls,
            phase: Phase::RootDse,
            buf: Vec::new(),
            received: false,
            root: None,
            root_done: None,
            bind: None,
            search_base: None,
            search_entries: 0,
            search_done: None,
            notice: None,
            malformed: None,
        }
    }

    const fn id(&self) -> &'static str {
        match self.mode {
            Mode::RootDse => "ldap",
            Mode::Anonymous => "ldap-anonymous",
        }
    }

    fn unbind(&mut self) -> Action {
        self.phase = Phase::Unbinding;
        Action::Send(Message::new(ID_UNBIND, Op::UnbindRequest).encode())
    }

    /// Handle one message; `Some` ends the read loop with that action.
    fn on_message(&mut self, msg: Message) -> Option<Action> {
        if msg.id == 0 {
            // Unsolicited notification, e.g. notice of disconnection.
            if let Op::ExtendedResponse { result, .. } = msg.op {
                self.notice = Some(result);
            }
            return Some(Action::Done);
        }
        match (self.phase, msg.id, msg.op) {
            (Phase::RootDse, ID_ROOT_DSE, Op::SearchResultEntry(entry)) => {
                if self.root.is_none() {
                    self.root = Some(entry);
                }
                None
            }
            (Phase::RootDse, ID_ROOT_DSE, Op::SearchResultDone(result)) => {
                let ok = result.code == ResultCode::SUCCESS;
                self.root_done = Some(result);
                if self.mode == Mode::RootDse || !ok {
                    return Some(Action::Done);
                }
                self.phase = Phase::Bind;
                Some(Action::Send(
                    Message::new(ID_BIND, Op::BindRequest(BindRequest::anonymous())).encode(),
                ))
            }
            (Phase::Bind, ID_BIND, Op::BindResponse(result)) => {
                let ok = result.code == ResultCode::SUCCESS;
                self.bind = Some(result);
                let base = self
                    .root
                    .clone()
                    .and_then(|e| RootDse::new(e).search_base());
                match base {
                    Some(base) if ok => {
                        let search = SearchRequest::new(base.clone(), Scope::OneLevel)
                            .with_size_limit(1)
                            .with_time_limit(10)
                            .with_attributes(["1.1"]);
                        self.search_base = Some(base);
                        self.phase = Phase::Search;
                        Some(Action::Send(
                            Message::new(ID_SEARCH, Op::SearchRequest(search)).encode(),
                        ))
                    }
                    _ => Some(self.unbind()),
                }
            }
            (Phase::Search, ID_SEARCH, Op::SearchResultEntry(_)) => {
                self.search_entries = self.search_entries.saturating_add(1);
                None
            }
            (Phase::Search, ID_SEARCH, Op::SearchResultDone(result)) => {
                self.search_done = Some(result);
                Some(self.unbind())
            }
            _ => None,
        }
    }

    fn finding_tls(&self) -> rune_service_probe::rune_finding::Finding {
        self.target
            .finding(
                "ldap.tls_not_offered",
                "LDAP server does not offer StartTLS",
                Severity::Medium,
                Confidence::Firm,
            )
            .push_taxonomy(TaxonomyRef::cwe(319))
            .push_evidence(Evidence::new(
                "supportedExtension",
                "no 1.3.6.1.4.1.1466.20037 (StartTLS)",
            ))
            .with_remediation(Remediation::new(
                "Install a server certificate and enable StartTLS and LDAPS; require TLS (or signing and sealing) for binds.",
            ))
    }

    fn describe_root(&self, mut info: ServiceInfo, dse: &RootDse) -> ServiceInfo {
        if let Some((product, version)) = dse.product() {
            info = info.with_product(product);
            if let Some(version) = version {
                info = info.with_version(version);
            }
        }
        let versions = dse.ldap_versions();
        for version in &versions {
            info = info.push_capability(format!("ldapv{version}"));
        }
        if dse.supports_starttls() {
            info = info.push_capability("starttls");
        }
        let extensions = dse.values("supportedExtension");
        for (oid, name) in [
            (OID_WHOAMI, "whoami"),
            (OID_PASSWORD_MODIFY, "password_modify"),
        ] {
            if extensions.iter().any(|e| e == oid) {
                info = info.push_capability(name);
            }
        }
        for mechanism in dse.sasl_mechanisms() {
            info = info.push_capability(format!("sasl:{mechanism}"));
        }
        let contexts = dse.naming_contexts();
        if !contexts.is_empty() {
            info = info.with_detail("ldap.naming_contexts", contexts.join("; "));
        }
        if let Some(nc) = dse.default_naming_context() {
            info = info.with_detail("ldap.default_naming_context", nc);
        }
        if !versions.is_empty() {
            info = info.with_detail("ldap.versions", versions.join(","));
        }
        for (attr, key) in [
            ("dnsHostName", "ldap.dns_host_name"),
            ("serverName", "ldap.server_name"),
            ("ldapServiceName", "ldap.service_name"),
            ("isGlobalCatalogReady", "ldap.global_catalog"),
            ("vendorName", "ldap.vendor_name"),
            ("vendorVersion", "ldap.vendor_version"),
        ] {
            if let Some(value) = dse.first(attr) {
                info = info.with_detail(key, value);
            }
        }
        for (attr, key) in [
            ("domainFunctionality", "ldap.domain_functionality"),
            ("forestFunctionality", "ldap.forest_functionality"),
            ("domainControllerFunctionality", "ldap.dc_functionality"),
        ] {
            if let Some(value) = dse.first(attr) {
                let named = value
                    .parse::<u32>()
                    .ok()
                    .and_then(functional_level_name)
                    .map_or_else(|| value.clone(), |name| format!("{value} ({name})"));
                info = info.with_detail(key, named);
            }
        }
        if versions.iter().any(|v| v == "2") {
            info = info.push_finding(
                self.target
                    .finding(
                        "ldap.ldapv2_enabled",
                        "LDAP server accepts the obsolete LDAPv2 protocol",
                        Severity::Low,
                        Confidence::Firm,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(477))
                    .push_evidence(Evidence::new("supportedLDAPVersion", versions.join(",")))
                    .with_remediation(Remediation::new(
                        "Disable LDAPv2 (RFC 3494 made it historic); OpenLDAP: remove `allow bind_v2`.",
                    )),
            );
        }
        info
    }

    fn describe_anonymous(&self, mut info: ServiceInfo) -> ServiceInfo {
        let Some(bind) = &self.bind else {
            return info;
        };
        if bind.code != ResultCode::SUCCESS {
            return info
                .with_auth(AuthRequirement::Required)
                .with_detail("ldap.anonymous_bind", "refused")
                .with_detail("ldap.anonymous_bind_result", bind.code.to_string());
        }
        info = info.with_detail("ldap.anonymous_bind", "accepted");
        let base = rune_service_probe::banner::printable(
            self.search_base.as_deref().unwrap_or_default().as_bytes(),
            MAX_DIAGNOSTIC,
        );
        let search_ok = self.search_done.as_ref().is_some_and(|r| {
            r.code == ResultCode::SUCCESS || r.code == ResultCode::SIZE_LIMIT_EXCEEDED
        });
        if self.search_entries > 0 {
            return info
                .with_auth(AuthRequirement::NotRequired)
                .with_detail("ldap.anonymous_search", "entries")
                .push_finding(
                    self.target
                        .finding(
                            "ldap.anonymous_read",
                            "LDAP directory is readable without authentication",
                            Severity::High,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(306))
                        .push_evidence(Evidence::new("anonymous_search_base", base))
                        .with_remediation(Remediation::new(
                            "Deny anonymous reads below the root DSE (OpenLDAP: `disallow bind_anon` or ACLs; AD: clear dsHeuristics anonymous access).",
                        )),
                );
        }
        if let Some(done) = &self.search_done {
            info = info.with_detail(
                "ldap.anonymous_search",
                if search_ok { "empty" } else { "refused" },
            );
            if !search_ok {
                info = info
                    .with_auth(AuthRequirement::Required)
                    .with_detail("ldap.anonymous_search_result", done.code.to_string());
            }
        }
        info.push_finding(
            self.target
                .finding(
                    "ldap.anonymous_bind",
                    "LDAP server accepts anonymous binds",
                    Severity::Low,
                    Confidence::Certain,
                )
                .push_taxonomy(TaxonomyRef::cwe(1390))
                .push_evidence(Evidence::new("bind", "simple, empty name and password"))
                .with_remediation(Remediation::new(
                    "Refuse anonymous binds unless an application needs them.",
                )),
        )
    }
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        Action::Send(root_dse_request())
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        if self.phase == Phase::Unbinding {
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
            if let Some(action) = self.on_message(msg) {
                return action;
            }
            if self.buf.is_empty() {
                return Action::Receive;
            }
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        let id = self.id();
        if !self.received {
            return Err(rune_service_probe::Error::no_response(id));
        }
        if self.root.is_none() && self.root_done.is_none() && self.notice.is_none() {
            let reason = self.malformed.take().map_or_else(
                || "no reply to the root DSE search".to_owned(),
                |e| e.to_string(),
            );
            return Err(rune_service_probe::Error::unrecognized(id, reason));
        }
        let mut info = ServiceInfo::new(id);
        if self.over_tls {
            info = info.with_tls(TlsSupport::Implicit);
        }
        let failure = self
            .root_done
            .as_ref()
            .or(self.notice.as_ref())
            .filter(|r| r.code != ResultCode::SUCCESS);
        if let Some(result) = failure {
            info = info.with_detail("ldap.root_dse_result", result.code.to_string());
            if !result.diagnostic.is_empty() {
                info = info.with_detail(
                    "ldap.diagnostic",
                    rune_service_probe::banner::printable(
                        result.diagnostic.as_bytes(),
                        MAX_DIAGNOSTIC,
                    ),
                );
            }
            if result.code == ResultCode::CONFIDENTIALITY_REQUIRED && !self.over_tls {
                info = info.with_tls(TlsSupport::Required);
            }
        }
        if let Some(entry) = self.root.clone() {
            let dse = RootDse::new(entry);
            info = self.describe_root(info, &dse);
            if !self.over_tls {
                if dse.supports_starttls() {
                    info = info.with_tls(TlsSupport::Optional);
                } else {
                    info = info
                        .with_tls(TlsSupport::NotOffered)
                        .push_finding(self.finding_tls());
                }
            }
        }
        if self.mode == Mode::Anonymous {
            info = self.describe_anonymous(info);
        }
        Ok(info)
    }
}

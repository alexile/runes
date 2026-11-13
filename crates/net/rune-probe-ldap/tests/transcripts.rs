//! The probes against scripted server transcripts, in memory.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use rune_probe_ldap::{
    Attribute, BindRequest, LdapAnonymousProbe, LdapProbe, LdapResult, Message, Op, ResultCode,
    Scope, SearchEntry, root_dse_request,
};
use rune_service_probe::rune_finding::Severity;
use rune_service_probe::{AuthRequirement, End, Error, Options, Target, TlsSupport, simulate};

fn target() -> Target {
    Target::new("dc01.corp.example", 389)
}

fn options() -> Options {
    Options::default().with_allow_intrusive(true)
}

fn done(id: i64, code: ResultCode) -> Vec<u8> {
    Message::new(id, Op::SearchResultDone(LdapResult::new(code))).encode()
}

fn entry(id: i64, dn: &str, attributes: Vec<Attribute>) -> Vec<u8> {
    Message::new(id, Op::SearchResultEntry(SearchEntry::new(dn, attributes))).encode()
}

/// The root DSE of a Windows Server 2019 domain controller (functional
/// level 7), trimmed to the attributes the probe reads.
fn ad_root_dse(starttls: bool) -> Vec<u8> {
    let mut extensions = vec!["1.3.6.1.4.1.4203.1.11.3", "1.2.840.113556.1.4.1781"];
    if starttls {
        extensions.insert(0, "1.3.6.1.4.1.1466.20037");
    }
    let mut out = entry(
        1,
        "",
        vec![
            Attribute::new("domainFunctionality", ["7"]),
            Attribute::new("forestFunctionality", ["7"]),
            Attribute::new("domainControllerFunctionality", ["7"]),
            Attribute::new("rootDomainNamingContext", ["DC=corp,DC=example"]),
            Attribute::new("ldapServiceName", ["corp.example:dc01$@CORP.EXAMPLE"]),
            Attribute::new("isGlobalCatalogReady", ["TRUE"]),
            Attribute::new(
                "supportedSASLMechanisms",
                ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            ),
            Attribute::new("supportedLDAPVersion", ["3", "2"]),
            Attribute::new("supportedExtension", extensions),
            Attribute::new(
                "supportedCapabilities",
                [
                    "1.2.840.113556.1.4.800",
                    "1.2.840.113556.1.4.1670",
                    "1.2.840.113556.1.4.1791",
                ],
            ),
            Attribute::new(
                "namingContexts",
                [
                    "DC=corp,DC=example",
                    "CN=Configuration,DC=corp,DC=example",
                    "CN=Schema,CN=Configuration,DC=corp,DC=example",
                ],
            ),
            Attribute::new("defaultNamingContext", ["DC=corp,DC=example"]),
            Attribute::new(
                "serverName",
                [
                    "CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example",
                ],
            ),
            Attribute::new("dnsHostName", ["dc01.corp.example"]),
        ],
    );
    out.extend(done(1, ResultCode::SUCCESS));
    out
}

fn openldap_root_dse() -> Vec<u8> {
    let mut out = entry(
        1,
        "",
        vec![
            Attribute::new("objectClass", ["top", "OpenLDAProotDSE"]),
            Attribute::new("namingContexts", ["dc=example,dc=org"]),
            Attribute::new("supportedLDAPVersion", ["3"]),
            Attribute::new(
                "supportedExtension",
                ["1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3"],
            ),
            Attribute::new("subschemaSubentry", ["cn=Subschema"]),
        ],
    );
    out.extend(done(1, ResultCode::SUCCESS));
    out
}

fn ids(info: &rune_service_probe::ServiceInfo) -> Vec<&str> {
    info.findings.iter().map(|f| f.check_id.as_str()).collect()
}

#[test]
fn active_directory_root_dse() {
    let reply = ad_root_dse(true);
    // Delivered in three reads, split mid-element.
    let sim = simulate(
        &LdapProbe::new(),
        &target(),
        &[&reply[..7], &reply[7..200], &reply[200..]],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, [root_dse_request()]);
    assert_eq!(sim.end, End::Done);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "ldap");
    assert_eq!(info.product.as_deref(), Some("Microsoft Active Directory"));
    assert_eq!(info.tls, TlsSupport::Optional);
    assert_eq!(info.auth, AuthRequirement::Unknown);
    assert_eq!(
        info.details["ldap.dc_functionality"],
        "7 (Windows Server 2016)"
    );
    assert_eq!(info.details["ldap.dns_host_name"], "dc01.corp.example");
    assert_eq!(
        info.details["ldap.default_naming_context"],
        "DC=corp,DC=example"
    );
    assert_eq!(info.details["ldap.versions"], "3,2");
    assert_eq!(info.details["ldap.global_catalog"], "TRUE");
    for cap in ["ldapv3", "starttls", "whoami", "sasl:GSS-SPNEGO"] {
        assert!(info.capabilities.iter().any(|c| c == cap), "{cap}");
    }
    // AD still advertises LDAPv2.
    assert_eq!(ids(&info), ["ldap.ldapv2_enabled"]);
    assert_eq!(info.findings[0].severity, Severity::Low);
}

#[test]
fn active_directory_without_certificate() {
    let info = simulate(
        &LdapProbe::new(),
        &target(),
        &[&ad_root_dse(false)],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.tls, TlsSupport::NotOffered);
    assert_eq!(ids(&info), ["ldap.ldapv2_enabled", "ldap.tls_not_offered"]);
}

#[test]
fn ldaps_reports_implicit_tls() {
    let info = simulate(
        &LdapProbe::over_tls(),
        &target(),
        &[&ad_root_dse(false)],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.tls, TlsSupport::Implicit);
    assert_eq!(ids(&info), ["ldap.ldapv2_enabled"]);
}

#[test]
fn openldap_without_starttls() {
    let info = simulate(
        &LdapProbe::new(),
        &target(),
        &[&openldap_root_dse()],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.product.as_deref(), Some("OpenLDAP"));
    assert_eq!(info.capabilities, ["ldapv3", "whoami", "password_modify"]);
    assert_eq!(ids(&info), ["ldap.tls_not_offered"]);
}

#[test]
fn confidentiality_required() {
    let reply = Message::new(
        1,
        Op::SearchResultDone(
            LdapResult::new(ResultCode::CONFIDENTIALITY_REQUIRED)
                .with_diagnostic("TLS confidentiality required"),
        ),
    )
    .encode();
    let info = simulate(&LdapProbe::new(), &target(), &[&reply], &Options::default())
        .unwrap()
        .result
        .unwrap();
    assert_eq!(info.tls, TlsSupport::Required);
    assert_eq!(
        info.details["ldap.root_dse_result"],
        "confidentialityRequired (13)"
    );
    assert_eq!(
        info.details["ldap.diagnostic"],
        "TLS confidentiality required"
    );
    assert_eq!(info.findings.len(), 0);
}

#[test]
fn notice_of_disconnection_is_ldap() {
    let notice = Message::new(
        0,
        Op::ExtendedResponse {
            result: LdapResult::new(ResultCode::PROTOCOL_ERROR),
            name: Some("1.3.6.1.4.1.1466.20036".into()),
            value: None,
        },
    )
    .encode();
    let info = simulate(
        &LdapProbe::new(),
        &target(),
        &[&notice],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.details["ldap.root_dse_result"], "protocolError (2)");
}

#[test]
fn other_protocols_and_silence() {
    let http = simulate(
        &LdapProbe::new(),
        &target(),
        &[b"HTTP/1.1 400 Bad Request\r\n\r\n"],
        &Options::default(),
    )
    .unwrap();
    assert!(matches!(http.result, Err(Error::Unrecognized { .. })));
    let silent = simulate(&LdapProbe::new(), &target(), &[], &Options::default()).unwrap();
    assert!(matches!(silent.result, Err(Error::NoResponse { .. })));
    // A partial message then a close: LDAP-shaped but unrecognised.
    let partial = &ad_root_dse(true)[..40];
    let cut = simulate(
        &LdapProbe::new(),
        &target(),
        &[partial],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(cut.end, End::Closed);
    assert!(matches!(cut.result, Err(Error::Unrecognized { .. })));
}

#[test]
fn anonymous_probe_is_refused_by_default() {
    let err = simulate(
        &LdapAnonymousProbe::new(),
        &target(),
        &[],
        &Options::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::IntrusiveNotAllowed { .. }));
}

#[test]
fn anonymous_read_on_openldap() {
    let bind_ok = Message::new(2, Op::BindResponse(LdapResult::new(ResultCode::SUCCESS))).encode();
    let mut search = entry(3, "ou=people,dc=example,dc=org", Vec::new());
    search.extend(done(3, ResultCode::SIZE_LIMIT_EXCEEDED));
    let sim = simulate(
        &LdapAnonymousProbe::new(),
        &target(),
        &[&openldap_root_dse(), &bind_ok, &search],
        &options(),
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 4);
    assert_eq!(
        Message::decode(&sim.sent[1]).unwrap().op,
        Op::BindRequest(BindRequest::anonymous())
    );
    let Op::SearchRequest(req) = Message::decode(&sim.sent[2]).unwrap().op else {
        panic!("not a search");
    };
    assert_eq!(req.base, "dc=example,dc=org");
    assert_eq!(req.scope, Scope::OneLevel);
    assert_eq!(req.size_limit, 1);
    assert_eq!(req.attributes, ["1.1"]);
    assert_eq!(Message::decode(&sim.sent[3]).unwrap().op, Op::UnbindRequest);
    assert_eq!(sim.end, End::Closed);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "ldap-anonymous");
    assert_eq!(info.auth, AuthRequirement::NotRequired);
    assert_eq!(info.details["ldap.anonymous_search"], "entries");
    assert_eq!(ids(&info), ["ldap.tls_not_offered", "ldap.anonymous_read"]);
    assert_eq!(info.findings[1].severity, Severity::High);
}

#[test]
fn anonymous_bind_accepted_but_ad_refuses_search() {
    let bind_ok = Message::new(2, Op::BindResponse(LdapResult::new(ResultCode::SUCCESS))).encode();
    let refused = Message::new(
        3,
        Op::SearchResultDone(LdapResult::new(ResultCode::OPERATIONS_ERROR).with_diagnostic(
            "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563",
        )),
    )
    .encode();
    let info = simulate(
        &LdapAnonymousProbe::new(),
        &target(),
        &[&ad_root_dse(true), &bind_ok, &refused],
        &options(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.auth, AuthRequirement::Required);
    assert_eq!(info.details["ldap.anonymous_bind"], "accepted");
    assert_eq!(info.details["ldap.anonymous_search"], "refused");
    assert_eq!(
        info.details["ldap.anonymous_search_result"],
        "operationsError (1)"
    );
    assert_eq!(ids(&info), ["ldap.ldapv2_enabled", "ldap.anonymous_bind"]);
}

#[test]
fn anonymous_bind_refused() {
    let refused = Message::new(
        2,
        Op::BindResponse(LdapResult::new(ResultCode::INAPPROPRIATE_AUTHENTICATION)),
    )
    .encode();
    let sim = simulate(
        &LdapAnonymousProbe::new(),
        &target(),
        &[&openldap_root_dse(), &refused],
        &options(),
    )
    .unwrap();
    // Root DSE search, bind, unbind: no directory search.
    assert_eq!(sim.sent.len(), 3);
    let info = sim.result.unwrap();
    assert_eq!(info.auth, AuthRequirement::Required);
    assert_eq!(info.details["ldap.anonymous_bind"], "refused");
    assert_eq!(ids(&info), ["ldap.tls_not_offered"]);
}

#[test]
fn anonymous_probe_stops_when_root_dse_fails() {
    let sim = simulate(
        &LdapAnonymousProbe::new(),
        &target(),
        &[&done(1, ResultCode::CONFIDENTIALITY_REQUIRED)],
        &options(),
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 1);
    assert_eq!(sim.result.unwrap().tls, TlsSupport::Required);
}

#[test]
fn decodes_wire_bytes() {
    // BindResponse success, message id 1, as slapd sends it.
    let bytes = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    ];
    let msg = Message::decode(&bytes).unwrap();
    assert_eq!(msg.id, 1);
    assert_eq!(
        msg.op,
        Op::BindResponse(LdapResult::new(ResultCode::SUCCESS))
    );
    // The same with a long-form length and a trailing control, as AD sends.
    let bytes = [
        0x30, 0x84, 0x00, 0x00, 0x00, 0x10, 0x02, 0x01, 0x01, 0x61, 0x84, 0x00, 0x00, 0x00, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    ];
    assert_eq!(Message::decode(&bytes).unwrap().op, msg.op);
}

#[test]
fn anonymous_search_uses_the_naming_context_verbatim() {
    // A DN with UTF-8 and an escaped comma must go back to the server as
    // the server sent it, not in the escaped form used for display.
    let long = format!("ou={},dc=example,dc=org", "x".repeat(300));
    for dn in ["ou=Smith\\, J,dc=exämple,dc=org", long.as_str()] {
        let mut root = entry(
            1,
            "",
            vec![
                Attribute::new("namingContexts", [dn]),
                Attribute::new("supportedLDAPVersion", ["3"]),
            ],
        );
        root.extend(done(1, ResultCode::SUCCESS));
        let bind_ok =
            Message::new(2, Op::BindResponse(LdapResult::new(ResultCode::SUCCESS))).encode();
        let sim = simulate(
            &LdapAnonymousProbe::new(),
            &target(),
            &[&root, &bind_ok],
            &options(),
        )
        .unwrap();
        let Op::SearchRequest(req) = Message::decode(&sim.sent[2]).unwrap().op else {
            panic!("not a search");
        };
        assert_eq!(req.base, dn);
    }
}

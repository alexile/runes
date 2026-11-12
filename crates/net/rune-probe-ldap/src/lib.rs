//! Read-only LDAP probing, built on [`rune_service_probe`]: the root DSE
//! read and an opt-in anonymous-access check.
//!
//! | Probe                                   | Id               | Ports     | Sends                                             | Learns                                                              |
//! | --------------------------------------- | ---------------- | --------- | ------------------------------------------------- | ------------------------------------------------------------------- |
//! | [`LdapProbe`]                           | `ldap`           | 389, 3268 | one root DSE search, no bind                      | product, naming contexts, versions, SASL mechanisms, `StartTLS`, AD levels |
//! | [`LdapAnonymousProbe`] (**intrusive**)  | `ldap-anonymous` | 389, 3268 | the root DSE search, an anonymous bind, a one-entry search, unbind | whether anonymous binds are accepted and the directory is readable |
//!
//! Both are sans-I/O [`ServiceProbe`]s: run them in memory with
//! [`simulate`](rune_service_probe::simulate), over tokio with
//! `rune_service_probe::Runner` (its `tokio` feature), over a TLS stream
//! for LDAPS with `Runner::probe_stream` and [`LdapProbe::over_tls`], or in
//! any I/O loop around a [`Driver`](rune_service_probe::Driver).
//! [`LdapAnonymousProbe`] binds, so it is
//! [`Safety::Intrusive`](rune_service_probe::Safety) and refused unless the
//! caller allows intrusive probes.
//!
//! The LDAP message codec ([`Message`], [`parse_message`]) is public and
//! symmetric: it decodes and encodes binds, searches and their replies,
//! for captures, mock servers and callback listeners
//! ([RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)). The root DSE is
//! described by [RFC 4512 §5.1](https://www.rfc-editor.org/rfc/rfc4512#section-5.1).
//!
//! Findings use check ids `ldap.<issue>` and carry a CWE:
//! `ldap.tls_not_offered` (319), `ldap.ldapv2_enabled` (477),
//! `ldap.anonymous_read` (306) and `ldap.anonymous_bind` (1390).
//!
//! # Example
//!
//! ```
//! use rune_probe_ldap::{Attribute, LdapProbe, LdapResult, Message, Op, ResultCode, SearchEntry, root_dse_request};
//! use rune_service_probe::{Options, Target, TlsSupport, simulate};
//!
//! // An `OpenLDAP` root DSE, as the server sends it.
//! let entry = SearchEntry::new("", vec![
//!     Attribute::new("objectClass", ["top", "OpenLDAProotDSE"]),
//!     Attribute::new("namingContexts", ["dc=example,dc=org"]),
//!     Attribute::new("supportedLDAPVersion", ["3"]),
//!     Attribute::new("supportedSASLMechanisms", ["SCRAM-SHA-256", "GSSAPI"]),
//!     Attribute::new("supportedExtension", ["1.3.6.1.4.1.1466.20037"]),
//! ]);
//! let mut reply = Message::new(1, Op::SearchResultEntry(entry)).encode();
//! reply.extend(Message::new(1, Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS))).encode());
//!
//! let target = Target::new("ldap.example.org", 389);
//! let sim = simulate(&LdapProbe::new(), &target, &[&reply], &Options::default())?;
//! assert_eq!(sim.sent, [root_dse_request()]); // one search, no bind
//! let info = sim.result?;
//! assert_eq!(info.product.as_deref(), Some("OpenLDAP"));
//! assert_eq!(info.tls, TlsSupport::Optional); // `StartTLS` offered
//! assert_eq!(info.details["ldap.default_naming_context"], "dc=example,dc=org");
//! assert!(info.capabilities.iter().any(|c| c == "sasl:GSSAPI"));
//! assert!(info.findings.is_empty());
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ber;
mod error;
mod message;
mod probe;
mod rootdse;

pub use error::Error;
pub use message::{
    Attribute, BindAuth, BindRequest, LdapResult, Message, Op, ResultCode, Scope, SearchEntry,
    SearchRequest, parse_message, present_filter,
};
pub use probe::{LdapAnonymousProbe, LdapProbe, root_dse_request};
pub use rootdse::{
    OID_CAP_ACTIVE_DIRECTORY, OID_CAP_AD_LDS, OID_PASSWORD_MODIFY, OID_STARTTLS, OID_WHOAMI,
    ROOT_DSE_ATTRIBUTES, RootDse, functional_level_name, root_dse_search,
};

use rune_service_probe::{ProbeSet, ServiceProbe};

/// The read-only probes of this crate, as a [`ProbeSet`]: [`LdapProbe`]
/// for plain LDAP. The intrusive [`LdapAnonymousProbe`] is not included.
#[must_use]
pub fn probe_set() -> ProbeSet {
    let mut set = ProbeSet::new();
    set.push(LdapProbe::new());
    set
}

/// Every probe of this crate, read-only and intrusive, boxed.
#[must_use]
pub fn all_probes() -> Vec<Box<dyn ServiceProbe>> {
    vec![
        Box::new(LdapProbe::new()),
        Box::new(LdapAnonymousProbe::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::Safety;

    #[test]
    fn probe_set_is_read_only() {
        let set = probe_set();
        assert!(set.iter().all(|p| p.safety() == Safety::ReadOnly));
        assert_eq!(set.for_port(389).count(), 1);
        assert_eq!(
            all_probes()
                .iter()
                .filter(|p| p.safety() == Safety::Intrusive)
                .count(),
            1
        );
        assert_eq!(LdapProbe::over_tls().default_ports(), [636, 3269]);
    }
}

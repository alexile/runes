//! Typed parsers and weakness checks for email and DNS security records.
//!
//! `rune-dns-records` turns the text and RDATA of security-relevant DNS
//! records into typed values, and flags common weaknesses as [`Issue`]s
//! that map to [`rune_finding::Finding`]s. It does no I/O: hand it the
//! records you fetched (with `rune-dns-wire` or any resolver).
//!
//! | Module | Record | Specification |
//! | --- | --- | --- |
//! | [`spf`] | SPF `TXT`, with the `include`/`redirect` lookup limit | [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) |
//! | [`dkim`] | DKIM key `TXT` at `<selector>._domainkey` | [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376), [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301), [RFC 8463](https://www.rfc-editor.org/rfc/rfc8463) |
//! | [`dmarc`] | DMARC `TXT` at `_dmarc` | [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489), [RFC 9091](https://www.rfc-editor.org/rfc/rfc9091) |
//! | [`mta_sts`] | MTA-STS `TXT` and policy file | [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) |
//! | [`tls_rpt`] | TLS-RPT `TXT` at `_smtp._tls` | [RFC 8460](https://www.rfc-editor.org/rfc/rfc8460) |
//! | [`bimi`] | BIMI `TXT` at `default._bimi` | [draft-brand-indicators-for-message-identification](https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/) |
//! | [`caa`] | `CAA` properties and issuance decisions | [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) |
//! | [`tlsa`] | DANE `TLSA` | [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) |
//! | [`dnssec`] | `DS`, `DNSKEY`, `RRSIG` basics | [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034), [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624) |
//!
//! Every parser is total: any input gives a value or an [`Error`], never a
//! panic. Parsers that select a record among a name's `TXT` records
//! (`find`) report several matching records as
//! [`Error::MultipleRecords`], as the specifications require.
//!
//! # Example
//!
//! ```
//! use rune_dns_records::{IssueKind, RecordKind, dmarc::Dmarc, issues_for, spf::Spf};
//!
//! // TXT records at example.com and _dmarc.example.com.
//! let apex = ["google-site-verification=abc", "v=spf1 include:_spf.example.net +all"];
//! let dmarc = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"];
//!
//! let mut issues = issues_for(Spf::find(apex), RecordKind::Spf, Spf::issues);
//! issues.extend(issues_for(Dmarc::find(dmarc), RecordKind::Dmarc, Dmarc::issues));
//!
//! let kinds: Vec<_> = issues.iter().map(|i| i.kind).collect();
//! assert_eq!(kinds, [IssueKind::SpfPermissiveAll, IssueKind::DmarcPolicyNone]);
//!
//! let finding = issues[0].to_finding::<()>("example.com");
//! assert_eq!(finding.check_id, "dns.spf_permissive_all");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bimi;
pub mod caa;
pub mod dkim;
pub mod dmarc;
pub mod dnssec;
mod error;
mod issue;
pub mod mta_sts;
pub mod spf;
mod tags;
pub mod tls_rpt;
pub mod tlsa;

pub use error::{Error, RecordKind};
pub use issue::{DNS_PORT, Issue, IssueKind};

/// Joins the `<character-string>`s of one `TXT` record, as SPF, DKIM and
/// DMARC require (RFC 7208 §3.3): concatenated without separators, invalid
/// UTF-8 replaced.
///
/// ```
/// let strings = vec![b"v=spf1 ip4:192.0.2.1 ".to_vec(), b"-all".to_vec()];
/// assert_eq!(rune_dns_records::txt_to_string(&strings), "v=spf1 ip4:192.0.2.1 -all");
/// ```
#[must_use]
pub fn txt_to_string(strings: &[Vec<u8>]) -> String {
    String::from_utf8_lossy(&strings.concat()).into_owned()
}

/// The issues for the outcome of a `find`: the "missing" issue for
/// `Ok(None)` (see [`Issue::missing`]), the "invalid" issue for an error,
/// and `check(record)` for a record.
#[must_use]
pub fn issues_for<T>(
    found: Result<Option<T>, Error>,
    record: RecordKind,
    check: impl FnOnce(&T) -> Vec<Issue>,
) -> Vec<Issue> {
    match found {
        Ok(Some(value)) => check(&value),
        Ok(None) => Issue::missing(record).into_iter().collect(),
        Err(error) => vec![Issue::invalid(&error)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_for_maps_every_outcome() {
        let missing = issues_for(spf::Spf::find(["x"]), RecordKind::Spf, spf::Spf::issues);
        assert_eq!(missing[0].kind, IssueKind::SpfMissing);
        let multiple = issues_for(
            spf::Spf::find(["v=spf1 -all", "v=spf1 ~all"]),
            RecordKind::Spf,
            spf::Spf::issues,
        );
        assert_eq!(multiple[0].kind, IssueKind::SpfMultipleRecords);
        let invalid = issues_for(
            dmarc::Dmarc::find(["v=DMARC1; p=maybe"]),
            RecordKind::Dmarc,
            dmarc::Dmarc::issues,
        );
        assert_eq!(invalid[0].kind, IssueKind::DmarcInvalid);
        let fine = issues_for(
            spf::Spf::find(["v=spf1 -all"]),
            RecordKind::Spf,
            spf::Spf::issues,
        );
        assert_eq!(fine.len(), 0);
    }

    #[test]
    fn txt_joins_strings() {
        assert_eq!(txt_to_string(&[]), "");
        assert_eq!(txt_to_string(&[vec![0xff]]), "\u{fffd}");
    }
}

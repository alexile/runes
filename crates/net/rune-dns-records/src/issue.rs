//! Weaknesses found in records, and their mapping to `rune_finding`.

use core::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::error::{Error, RecordKind};

/// The DNS port, used for [`Location::Network`] findings.
pub const DNS_PORT: u16 = 53;

macro_rules! issue_kinds {
    ($(
        $(#[$meta:meta])*
        $variant:ident => ($record:ident, $id:literal, $severity:ident, $cwes:expr, $remediation:literal),
    )*) => {
        /// The class of a weakness. Each kind belongs to one [`RecordKind`]
        /// and has a stable check id, `dns.<kind>`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum IssueKind {
            $( $(#[$meta])* $variant, )*
        }

        impl IssueKind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// The snake-case name, e.g. `spf_permissive_all`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $id,)* }
            }

            /// The record kind this issue concerns.
            #[must_use]
            pub const fn record(self) -> RecordKind {
                match self { $(Self::$variant => RecordKind::$record,)* }
            }

            /// The severity an issue of this kind usually has. Some checks
            /// raise or lower it with context (a 512-bit key is worse than
            /// a 1024-bit one); [`Issue::severity`] holds the actual value.
            #[must_use]
            pub const fn default_severity(self) -> Severity {
                match self { $(Self::$variant => Severity::$severity,)* }
            }

            /// CWE numbers the issue is classified under.
            #[must_use]
            pub const fn cwes(self) -> &'static [u32] {
                match self { $(Self::$variant => $cwes,)* }
            }

            /// What to do about it.
            #[must_use]
            pub const fn remediation(self) -> &'static str {
                match self { $(Self::$variant => $remediation,)* }
            }
        }
    };
}

const CONFIG: &[u32] = &[16];
const SPOOF: &[u32] = &[16, 290];
const WEAK_KEY: &[u32] = &[16, 326];
const WEAK_ALG: &[u32] = &[16, 327];
const EXPIRY: &[u32] = &[16, 324];

issue_kinds! {
    /// No SPF record is published.
    SpfMissing => (Spf, "spf_missing", Low, SPOOF,
        "Publish an SPF TXT record ending in -all or ~all."),
    /// The SPF record does not parse; receivers treat it as a permanent
    /// error and ignore it.
    SpfInvalid => (Spf, "spf_invalid", Medium, SPOOF,
        "Fix the SPF record syntax; receivers treat an invalid record as a permerror."),
    /// More than one SPF record is published (RFC 7208 §4.5 permerror).
    SpfMultipleRecords => (Spf, "spf_multiple_records", Medium, SPOOF,
        "Merge the SPF records into a single v=spf1 TXT record."),
    /// `+all` (or a bare `all`): every host on the Internet passes.
    SpfPermissiveAll => (Spf, "spf_permissive_all", Medium, SPOOF,
        "Replace +all with -all (fail) or ~all (softfail)."),
    /// `?all`: unlisted hosts get a neutral result, which protects nothing.
    SpfNeutralAll => (Spf, "spf_neutral_all", Low, SPOOF,
        "Replace ?all with -all (fail) or ~all (softfail)."),
    /// Neither `all` nor `redirect=`: unlisted hosts get a neutral result.
    SpfNoAll => (Spf, "spf_no_all", Low, SPOOF,
        "End the SPF record with -all or ~all."),
    /// Evaluation needs more than 10 DNS lookups (RFC 7208 §4.6.4); the
    /// result is a permerror.
    SpfTooManyLookups => (Spf, "spf_too_many_lookups", Medium, SPOOF,
        "Reduce include/a/mx/ptr/exists/redirect terms to at most 10 lookups, e.g. by replacing includes with ip4/ip6 ranges."),
    /// More than 2 lookups return nothing (RFC 7208 §4.6.4); the result is a
    /// permerror at receivers that enforce the void lookup limit.
    SpfTooManyVoidLookups => (Spf, "spf_too_many_void_lookups", Low, SPOOF,
        "Remove include and mechanism targets that do not resolve."),
    /// An `include:` or `redirect=` target publishes no SPF record (permerror).
    SpfIncludeMissing => (Spf, "spf_include_missing", Medium, SPOOF,
        "Remove the include or redirect, or publish an SPF record at its target."),
    /// `include:` or `redirect=` targets form a loop.
    SpfIncludeLoop => (Spf, "spf_include_loop", Medium, SPOOF,
        "Break the include/redirect loop."),
    /// The deprecated `ptr` mechanism (RFC 7208 §5.5).
    SpfPtrMechanism => (Spf, "spf_ptr_mechanism", Low, CONFIG,
        "Replace ptr with ip4/ip6 ranges or a mechanisms; ptr is slow, unreliable and deprecated."),
    /// An `ip4`/`ip6` range so broad it authorizes much of the Internet.
    SpfBroadIpRange => (Spf, "spf_broad_ip_range", Medium, SPOOF,
        "Narrow the ip4/ip6 range to the addresses that actually send mail."),
    /// Terms after `all` are never evaluated.
    SpfTermsAfterAll => (Spf, "spf_terms_after_all", Informational, CONFIG,
        "Move every mechanism before the all mechanism, or remove it."),
    /// `redirect=` next to `all` is ignored (RFC 7208 §6.1).
    SpfRedirectIgnored => (Spf, "spf_redirect_ignored", Informational, CONFIG,
        "Remove either the all mechanism or the redirect modifier."),

    /// The DKIM key record for a selector is missing.
    DkimMissing => (Dkim, "dkim_missing", Low, SPOOF,
        "Publish the DKIM public key at <selector>._domainkey.<domain>."),
    /// The DKIM key record does not parse.
    DkimInvalid => (Dkim, "dkim_invalid", Medium, SPOOF,
        "Fix the DKIM key record syntax and key encoding."),
    /// The key is revoked (`p=` is empty).
    DkimRevoked => (Dkim, "dkim_revoked", Informational, CONFIG,
        "Remove the selector from signing configuration, or retire the record."),
    /// The domain is testing DKIM (`t=y`); receivers may ignore failures.
    DkimTestMode => (Dkim, "dkim_test_mode", Low, SPOOF,
        "Remove t=y once DKIM signing is verified."),
    /// An RSA key shorter than 2048 bits (RFC 8301 §3.2 forbids under 1024).
    DkimWeakKey => (Dkim, "dkim_weak_key", Low, WEAK_KEY,
        "Rotate to a 2048-bit RSA or an Ed25519 key."),
    /// The key only allows SHA-1 signatures (`h=sha1`), which RFC 8301
    /// forbids.
    DkimSha1Only => (Dkim, "dkim_sha1_only", Medium, WEAK_ALG,
        "Sign with rsa-sha256 and drop h=sha1 (or the h= tag)."),
    /// The key type is not one receivers understand.
    DkimUnknownKeyType => (Dkim, "dkim_unknown_key_type", Medium, CONFIG,
        "Use k=rsa or k=ed25519."),

    /// No DMARC record is published.
    DmarcMissing => (Dmarc, "dmarc_missing", Medium, SPOOF,
        "Publish a _dmarc TXT record with a p=quarantine or p=reject policy."),
    /// The DMARC record does not parse.
    DmarcInvalid => (Dmarc, "dmarc_invalid", Medium, SPOOF,
        "Fix the DMARC record syntax; receivers ignore an invalid record."),
    /// More than one DMARC record is published (RFC 7489 §6.6.3).
    DmarcMultipleRecords => (Dmarc, "dmarc_multiple_records", Medium, SPOOF,
        "Publish exactly one v=DMARC1 record at _dmarc."),
    /// `p=none`: failing mail is delivered as normal.
    DmarcPolicyNone => (Dmarc, "dmarc_policy_none", Low, SPOOF,
        "Move from p=none to p=quarantine or p=reject once reporting is reviewed."),
    /// `sp=none` (or `np=none`) weakens an enforcing domain policy for
    /// subdomains.
    DmarcSubdomainPolicyNone => (Dmarc, "dmarc_subdomain_policy_none", Low, SPOOF,
        "Set sp= (and np=) to quarantine or reject, or remove them to inherit p=."),
    /// `pct` below 100: the policy applies to only part of the mail.
    DmarcPartialPct => (Dmarc, "dmarc_partial_pct", Low, SPOOF,
        "Raise pct to 100 (or remove it)."),
    /// No `rua=`: the domain gets no aggregate reports.
    DmarcNoReporting => (Dmarc, "dmarc_no_reporting", Informational, CONFIG,
        "Add rua=mailto:<address> to receive aggregate reports."),

    /// No MTA-STS record is published; SMTP TLS can be downgraded.
    MtaStsMissing => (MtaSts, "mta_sts_missing", Low, CONFIG,
        "Publish _mta-sts TXT and an HTTPS policy at mta-sts.<domain>/.well-known/mta-sts.txt."),
    /// The MTA-STS `TXT` record does not parse.
    MtaStsInvalid => (MtaSts, "mta_sts_invalid", Low, CONFIG,
        "Fix the _mta-sts record: v=STSv1; id=<1-32 alphanumerics>."),
    /// The MTA-STS policy file does not parse.
    MtaStsPolicyInvalid => (MtaStsPolicy, "mta_sts_policy_invalid", Low, CONFIG,
        "Fix the policy file: version, mode, max_age and mx lines."),
    /// `mode: testing`: failures are reported but not enforced.
    MtaStsTestingMode => (MtaStsPolicy, "mta_sts_testing_mode", Low, CONFIG,
        "Switch to mode: enforce once TLS reports are clean."),
    /// `mode: none`: the policy is withdrawn.
    MtaStsModeNone => (MtaStsPolicy, "mta_sts_mode_none", Low, CONFIG,
        "Publish mode: enforce, or remove MTA-STS deliberately."),
    /// `max_age` shorter than a day; RFC 8461 recommends weeks.
    MtaStsShortMaxAge => (MtaStsPolicy, "mta_sts_short_max_age", Low, CONFIG,
        "Raise max_age to at least 604800 (one week); 31557600 is the maximum."),
    /// No TLS-RPT record: MTA-STS and DANE failures go unreported.
    TlsRptMissing => (TlsRpt, "tls_rpt_missing", Informational, CONFIG,
        "Publish _smtp._tls TXT: v=TLSRPTv1; rua=mailto:<address>."),
    /// The TLS-RPT record does not parse.
    TlsRptInvalid => (TlsRpt, "tls_rpt_invalid", Low, CONFIG,
        "Fix the TLS-RPT record: v=TLSRPTv1; rua=<mailto: or https: URIs>."),

    /// The BIMI record does not parse.
    BimiInvalid => (Bimi, "bimi_invalid", Low, CONFIG,
        "Fix the BIMI record: v=BIMI1; l=<https SVG URL>; a=<https PEM URL>."),
    /// A BIMI `l=` or `a=` URI is not `https:`; receivers ignore it.
    BimiInsecureUri => (Bimi, "bimi_insecure_uri", Low, CONFIG,
        "Serve the BIMI logo and certificate over https."),
    /// No `a=` evidence document; most mailbox providers require one.
    BimiNoAuthority => (Bimi, "bimi_no_authority", Informational, CONFIG,
        "Add a=<https URL of a VMC or CMC certificate>."),

    /// No CAA records: any public CA may issue for the domain.
    CaaMissing => (Caa, "caa_missing", Low, CONFIG,
        "Publish CAA issue (and issuewild) records naming the CAs you use."),
    /// A CAA record does not parse; CAs treat it as forbidding issuance.
    CaaInvalid => (Caa, "caa_invalid", Low, CONFIG,
        "Fix the CAA record value syntax."),
    /// A critical CAA property no CA understands: all issuance is blocked.
    CaaUnknownCritical => (Caa, "caa_unknown_critical", Medium, CONFIG,
        "Clear the critical flag or fix the property tag."),
    /// No `iodef` property: CAs cannot report refused requests.
    CaaNoIodef => (Caa, "caa_no_iodef", Informational, CONFIG,
        "Add an iodef property, e.g. 0 iodef \"mailto:security@<domain>\"."),

    /// A TLSA record does not fit its parameters (wrong digest length).
    TlsaInvalid => (Tlsa, "tlsa_invalid", Medium, CONFIG,
        "Regenerate the TLSA record; its data does not match its matching type."),
    /// A TLSA record uses a usage, selector or matching type no client
    /// supports, so it can never match.
    TlsaUnusable => (Tlsa, "tlsa_unusable", Medium, CONFIG,
        "Use a standard usage (2 or 3), selector (0 or 1) and matching type (1 or 2)."),

    /// The zone is not signed (no DS or DNSKEY records).
    DnssecMissing => (Dnssec, "dnssec_missing", Low, CONFIG,
        "Sign the zone and publish its DS record at the parent."),
    /// A DS, DNSKEY or RRSIG uses an algorithm that must not be used
    /// (RFC 8624).
    DnssecDeprecatedAlgorithm => (Dnssec, "dnssec_deprecated_algorithm", Medium, WEAK_ALG,
        "Roll the zone to algorithm 13 (ECDSAP256SHA256) or 8 (RSASHA256)."),
    /// A DS uses a SHA-1 or GOST digest (RFC 8624 §3.3).
    DnssecWeakDigest => (Dnssec, "dnssec_weak_digest", Low, WEAK_ALG,
        "Publish a SHA-256 (digest type 2) DS record and remove the SHA-1 one."),
    /// An RSA DNSKEY shorter than 2048 bits.
    DnssecWeakRsaKey => (Dnssec, "dnssec_weak_rsa_key", Low, WEAK_KEY,
        "Roll to a 2048-bit RSA key or to algorithm 13."),
    /// A DNSKEY is malformed (protocol not 3, no zone flag, bad key data).
    DnssecInvalidKey => (Dnssec, "dnssec_invalid_key", Medium, CONFIG,
        "Remove or regenerate the malformed DNSKEY."),
    /// No DS record matches a DNSKEY: validating resolvers see the zone as
    /// bogus.
    DnssecDsMismatch => (Dnssec, "dnssec_ds_mismatch", High, CONFIG,
        "Update the DS at the parent to match a current key-signing key."),
    /// A signature has expired: validating resolvers fail the zone.
    DnssecSignatureExpired => (Dnssec, "dnssec_signature_expired", High, EXPIRY,
        "Re-sign the zone and fix the signer's refresh schedule."),
    /// A signature expires soon.
    DnssecSignatureExpiring => (Dnssec, "dnssec_signature_expiring", Medium, EXPIRY,
        "Re-sign the zone before the signatures expire."),
    /// A signature's inception lies in the future.
    DnssecSignatureNotYetValid => (Dnssec, "dnssec_signature_not_yet_valid", High, EXPIRY,
        "Check the signer's clock and re-sign the zone."),
}

impl IssueKind {
    /// The stable `rune_finding` check id, `dns.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("dns.{}", self.as_str())
    }

    /// The specification a remediation should point to.
    #[must_use]
    pub const fn reference(self) -> &'static str {
        match self.record() {
            RecordKind::Spf => "https://www.rfc-editor.org/rfc/rfc7208",
            RecordKind::Dkim => "https://www.rfc-editor.org/rfc/rfc6376",
            RecordKind::Dmarc => "https://www.rfc-editor.org/rfc/rfc7489",
            RecordKind::MtaSts | RecordKind::MtaStsPolicy => {
                "https://www.rfc-editor.org/rfc/rfc8461"
            }
            RecordKind::TlsRpt => "https://www.rfc-editor.org/rfc/rfc8460",
            RecordKind::Bimi => "https://bimigroup.org/",
            RecordKind::Caa => "https://www.rfc-editor.org/rfc/rfc8659",
            RecordKind::Tlsa => "https://www.rfc-editor.org/rfc/rfc6698",
            RecordKind::Dnssec => "https://www.rfc-editor.org/rfc/rfc8624",
        }
    }
}

impl fmt::Display for IssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weakness found in a record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Issue {
    /// The class of weakness.
    pub kind: IssueKind,
    /// How much it matters, in context.
    pub severity: Severity,
    /// A human-readable explanation.
    pub message: String,
    /// The offending record or term, when there is one.
    pub evidence: Option<String>,
}

impl Issue {
    /// An issue of `kind` at its default severity.
    #[must_use]
    pub fn new(kind: IssueKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity: kind.default_severity(),
            message: message.into(),
            evidence: None,
        }
    }

    /// Sets [`Issue::severity`].
    #[must_use]
    pub const fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets [`Issue::evidence`].
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// The "record missing" issue for `record`, or `None` for kinds where
    /// absence is not a weakness on its own (the MTA-STS policy file, TLSA,
    /// BIMI).
    #[must_use]
    pub fn missing(record: RecordKind) -> Option<Self> {
        let (kind, message) = match record {
            RecordKind::Spf => (IssueKind::SpfMissing, "SPF record missing"),
            RecordKind::Dkim => (IssueKind::DkimMissing, "DKIM key record missing"),
            RecordKind::Dmarc => (IssueKind::DmarcMissing, "DMARC record missing"),
            RecordKind::MtaSts => (IssueKind::MtaStsMissing, "MTA-STS record missing"),
            RecordKind::TlsRpt => (IssueKind::TlsRptMissing, "TLS-RPT record missing"),
            RecordKind::Caa => (IssueKind::CaaMissing, "no CAA records: any CA may issue"),
            RecordKind::Dnssec => (IssueKind::DnssecMissing, "zone is not DNSSEC-signed"),
            RecordKind::MtaStsPolicy | RecordKind::Bimi | RecordKind::Tlsa => return None,
        };
        Some(Self::new(kind, message))
    }

    /// The "invalid record" issue for a parse error, with the error as the
    /// message. [`Error::MultipleRecords`] maps to the "multiple records"
    /// kind where there is one.
    #[must_use]
    pub fn invalid(error: &Error) -> Self {
        let kind = match (error.record(), error) {
            (RecordKind::Spf, Error::MultipleRecords { .. }) => IssueKind::SpfMultipleRecords,
            (RecordKind::Dmarc, Error::MultipleRecords { .. }) => IssueKind::DmarcMultipleRecords,
            (RecordKind::Spf, _) => IssueKind::SpfInvalid,
            (RecordKind::Dkim, _) => IssueKind::DkimInvalid,
            (RecordKind::Dmarc, _) => IssueKind::DmarcInvalid,
            (RecordKind::MtaSts, _) => IssueKind::MtaStsInvalid,
            (RecordKind::MtaStsPolicy, _) => IssueKind::MtaStsPolicyInvalid,
            (RecordKind::TlsRpt, _) => IssueKind::TlsRptInvalid,
            (RecordKind::Bimi, _) => IssueKind::BimiInvalid,
            (RecordKind::Caa, _) => IssueKind::CaaInvalid,
            (RecordKind::Tlsa, _) => IssueKind::TlsaInvalid,
            (RecordKind::Dnssec, _) => IssueKind::DnssecInvalidKey,
        };
        Self::new(kind, error.to_string())
    }

    /// Converts the issue into a [`rune_finding::Finding`] for `domain`, at
    /// [`Location::Network`] `domain:53`.
    #[must_use]
    pub fn to_finding<X: Default>(&self, domain: &str) -> Finding<X> {
        self.to_finding_at(&Location::network(domain, DNS_PORT))
    }

    /// Converts the issue into a [`rune_finding::Finding`] at `location`,
    /// with check id `dns.<kind>`, CWE references, a remediation and the
    /// evidence as a `record` item.
    #[must_use]
    pub fn to_finding_at<X: Default>(&self, location: &Location) -> Finding<X> {
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Firm,
            location.clone(),
        )
        .with_remediation(
            Remediation::new(self.kind.remediation()).push_reference(self.kind.reference()),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(evidence) = &self.evidence {
            finding =
                finding.push_evidence(Evidence::new(self.kind.record().as_str(), evidence.clone()));
        }
        finding
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.kind, self.message)
    }
}

/// Issues sorted most severe first, keeping the order of equals.
pub fn sorted(mut issues: Vec<Issue>) -> Vec<Issue> {
    issues.sort_by_key(|issue| core::cmp::Reverse(issue.severity));
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ids_are_unique_and_prefixed_with_their_record() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in IssueKind::ALL {
            assert!(seen.insert(kind.as_str()), "duplicate {kind}");
            // Policy-file issues share the `mta_sts_` prefix.
            let record = kind.record().as_str().trim_end_matches("_policy");
            assert!(
                kind.as_str().starts_with(record),
                "{kind} does not start with {record}"
            );
            assert!(kind.check_id().starts_with("dns."));
            assert_ne!(kind.cwes(), [] as [u32; 0]);
        }
    }

    #[test]
    fn finding_carries_check_id_location_and_cwe() {
        let issue = Issue::new(IssueKind::SpfPermissiveAll, "SPF record uses +all")
            .with_evidence("v=spf1 +all");
        let finding = issue.to_finding::<()>("example.com");
        assert_eq!(finding.check_id, "dns.spf_permissive_all");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.location, Location::network("example.com", 53));
        assert!(finding.taxonomy.contains(&TaxonomyRef::cwe(290)));
        assert_eq!(finding.evidence[0].snippet, "v=spf1 +all");
    }

    #[test]
    fn missing_and_invalid_map_to_the_record_kind() {
        for record in RecordKind::ALL {
            if let Some(issue) = Issue::missing(record) {
                assert_eq!(issue.kind.record(), record);
            }
            let error = Error::NotThisRecord {
                record,
                reason: "test",
            };
            let issue = Issue::invalid(&error);
            assert_eq!(issue.kind.record(), record);
        }
        let multiple = Error::MultipleRecords {
            record: RecordKind::Spf,
            count: 2,
        };
        assert_eq!(
            Issue::invalid(&multiple).kind,
            IssueKind::SpfMultipleRecords
        );
    }
}

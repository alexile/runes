//! Known-answer tests on records in the shapes large providers publish,
//! and an end-to-end audit mapped to `rune_finding`.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::collections::HashMap;

use rune_dns_records::dkim::DkimKey;
use rune_dns_records::dmarc::{Dmarc, Policy};
use rune_dns_records::mta_sts::{Mode, MtaStsPolicy, MtaStsRecord};
use rune_dns_records::spf::{Qualifier, Spf};
use rune_dns_records::tls_rpt::TlsRpt;
use rune_dns_records::{IssueKind, RecordKind, issues_for};
use rune_finding::{Location, Severity};

#[test]
fn provider_spf_chain() {
    let records = HashMap::from([
        (
            "_spf.google.com",
            "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all",
        ),
        (
            "_netblocks.google.com",
            "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all",
        ),
        (
            "_netblocks2.google.com",
            "v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all",
        ),
        ("_netblocks3.google.com", "v=spf1 ~all"),
        (
            "spf.protection.outlook.com",
            "v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip4:52.102.0.0/16 ip4:52.103.0.0/16 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 include:spfd.protection.outlook.com -all",
        ),
        (
            "spfd.protection.outlook.com",
            "v=spf1 ip4:51.4.72.0/24 ip4:51.5.72.0/24 -all",
        ),
    ]);
    let fetch = |d: &str| records.get(d).map(|s| (*s).to_owned());
    let spf: Spf = "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"
        .parse()
        .unwrap();
    assert_eq!(spf.all(), Some(Qualifier::SoftFail));
    let report = spf.count_lookups("example.com", fetch);
    // 2 + 3 (Google) + 1 (Outlook).
    assert_eq!(report.lookups, 6);
    assert_eq!(report.issues().len(), 0);
    for text in records.values() {
        let record: Spf = text.parse().unwrap();
        assert_eq!(record.issues().len(), 0, "{text}");
        assert_eq!(record.to_string(), *text);
    }
}

#[test]
fn provider_dmarc_records() {
    let reject: Dmarc =
        "v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com; fo=1"
            .parse()
            .unwrap();
    assert_eq!(reject.policy, Policy::Reject);
    assert_eq!(reject.issues().len(), 0);
    let gmail: Dmarc = "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com"
        .parse()
        .unwrap();
    let kinds: Vec<_> = gmail.issues().iter().map(|i| i.kind).collect();
    assert_eq!(kinds, [IssueKind::DmarcPolicyNone]);
}

#[test]
fn provider_mta_sts_and_tls_rpt() {
    let record: MtaStsRecord = "v=STSv1; id=20190429T010101;".parse().unwrap();
    assert_eq!(record.id, "20190429T010101");
    let policy: MtaStsPolicy =
        "version: STSv1\nmode: enforce\nmx: smtp.google.com\nmx: aspmx.l.google.com\nmx: *.aspmx.l.google.com\nmax_age: 86400\n"
            .parse()
            .unwrap();
    assert_eq!(policy.mode, Mode::Enforce);
    assert!(policy.matches_mx("alt1.aspmx.l.google.com"));
    assert_eq!(policy.issues().len(), 0);
    let rpt: TlsRpt = "v=TLSRPTv1;rua=mailto:sts-reports@google.com"
        .parse()
        .unwrap();
    assert_eq!(rpt.rua.len(), 1);
}

#[test]
fn dkim_2048_bit_key() {
    // A 2048-bit SubjectPublicKeyInfo: header, then a 257-byte modulus
    // (leading zero) and exponent 65537.
    let mut der = vec![
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
        0x01, 0x01, 0x00,
    ];
    der.extend([0xc3; 256]);
    der.extend([0x02, 0x03, 0x01, 0x00, 0x01]);
    let text = format!("v=DKIM1; k=rsa; p={}", rune_base64::encode(&der));
    let key: DkimKey = text.parse().unwrap();
    assert_eq!(key.rsa_key_bits(), Some(2048));
    assert_eq!(key.issues().len(), 0);
}

#[test]
fn audit_maps_to_findings() {
    let apex = ["v=spf1 a mx +all"];
    let dmarc: [&str; 0] = [];
    let mut issues = issues_for(Spf::find(apex), RecordKind::Spf, Spf::issues);
    issues.extend(issues_for(
        Dmarc::find(dmarc),
        RecordKind::Dmarc,
        Dmarc::issues,
    ));
    let findings: Vec<_> = issues
        .iter()
        .map(|i| i.to_finding::<()>("example.com"))
        .collect();
    let ids: Vec<_> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(ids, ["dns.spf_permissive_all", "dns.dmarc_missing"]);
    assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    assert!(
        findings
            .iter()
            .all(|f| f.location == Location::network("example.com", 53))
    );
    assert_ne!(findings[0].fingerprint(), findings[1].fingerprint());
}

//! Real responses captured from a public resolver (1.1.1.1, November 2026;
//! shared with `rune-dns-wire`), decoded with `rune-dns-wire` and checked
//! with this crate.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test on bad input"
)]

use rune_dns_records::caa::{self, CaaRecord, Property};
use rune_dns_records::dnssec::{self, Validity};
use rune_dns_records::spf::Spf;
use rune_dns_records::tlsa::{CertUsage, MatchingType, Selector, TlsaRecord};
use rune_dns_records::{IssueKind, txt_to_string};
use rune_dns_wire::{Message, RData, Rrsig};

macro_rules! fixture {
    ($file:literal) => {
        Message::decode(include_bytes!(concat!("fixtures/", $file))).unwrap()
    };
}

fn rrsigs(message: &Message) -> Vec<Rrsig> {
    message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Rrsig(sig) => Some(sig.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn txt_spf_of_example_com() {
    let message = fixture!("txt-example-response.bin");
    let txts: Vec<String> = message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Txt(strings) => Some(txt_to_string(strings)),
            _ => None,
        })
        .collect();
    let spf = Spf::find(&txts).unwrap().unwrap();
    assert_eq!(spf.to_string(), "v=spf1 -all");
    assert_eq!(spf.issues().len(), 0);
}

#[test]
fn caa_of_google_com() {
    let message = fixture!("caa-google-response.bin");
    let rrset: Vec<_> = message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Caa(caa) => Some(caa.clone()),
            _ => None,
        })
        .collect();
    let record = CaaRecord::from_rdata(&rrset[0]).unwrap();
    let Property::Issue(value) = &record.property else {
        panic!("expected issue");
    };
    assert_eq!(value.issuer.as_deref(), Some("pki.goog"));
    assert_eq!(record.to_string(), r#"0 issue "pki.goog""#);
    assert!(caa::permits(&rrset, "pki.goog", false));
    assert!(caa::permits(&rrset, "pki.goog", true));
    assert!(!caa::permits(&rrset, "letsencrypt.org", false));
    let kinds: Vec<_> = caa::issues(&rrset).iter().map(|i| i.kind).collect();
    assert_eq!(kinds, [IssueKind::CaaNoIodef]);
}

#[test]
fn tlsa_of_mail_ietf_org() {
    let message = fixture!("tlsa-ietf-response.bin");
    let RData::Tlsa(tlsa) = &message.answers[0].data else {
        panic!("expected TLSA");
    };
    let record = TlsaRecord::from_rdata(tlsa).unwrap();
    assert_eq!(
        (record.usage, record.selector, record.matching_type),
        (CertUsage::DaneEe, Selector::Spki, MatchingType::Sha256)
    );
    assert_eq!(record.issues().len(), 0);
    assert_eq!(record.to_string().parse::<TlsaRecord>().unwrap(), record);
    assert_eq!(
        dnssec_owner(),
        message.questions[0].name,
        "owner name helper builds the queried name"
    );
}

fn dnssec_owner() -> rune_dns_wire::Name {
    rune_dns_records::tlsa::owner_name(25, "tcp", &"mail.ietf.org".parse().unwrap()).unwrap()
}

#[test]
fn dnskey_of_cloudflare_com() {
    let message = fixture!("dnskey-cloudflare-response.bin");
    let keys: Vec<_> = message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Dnskey(key) => Some(key.clone()),
            _ => None,
        })
        .collect();
    let sigs = rrsigs(&message);
    // The DNSKEY RRset is signed by the key-signing key; its key tag must
    // be the one in the RRSIG.
    let ksk = keys
        .iter()
        .find(|k| k.flags & dnssec::FLAG_SEP != 0)
        .unwrap();
    assert_eq!(dnssec::key_tag(ksk), sigs[0].key_tag);
    assert_eq!(dnssec::key_tag(ksk), 2371);

    let zone = message.questions[0].name.clone();
    let ds = rune_dns_wire::Ds {
        key_tag: 2371,
        algorithm: 13,
        digest_type: 2,
        digest: dnssec::ds_digest(&zone, ksk, dnssec::DigestType::SHA256).unwrap(),
    };
    let during = u64::from(sigs[0].inception) + 86_400;
    let issues = dnssec::issues(
        &zone,
        &[ds],
        &keys,
        &sigs,
        during,
        &dnssec::Options::default(),
    );
    assert_eq!(issues.len(), 0, "{issues:?}");
    let after = u64::from(sigs[0].expiration) + 1;
    assert_eq!(
        dnssec::signature_validity(&sigs[0], after),
        Validity::Expired { expired_for: 1 }
    );
}

#[test]
fn ds_and_rrsig_of_example_com() {
    let message = fixture!("ds-example-response.bin");
    let RData::Ds(ds) = &message.answers[0].data else {
        panic!("expected DS");
    };
    assert_eq!(
        dnssec::DigestType(ds.digest_type).status(),
        dnssec::Status::Must
    );
    assert_eq!(
        dnssec::Algorithm(ds.algorithm).signing_status(),
        dnssec::Status::Must
    );
    let sig = &rrsigs(&message)[0];
    let before = u64::from(sig.inception) - 60;
    assert_eq!(
        dnssec::signature_validity(sig, before),
        Validity::NotYetValid { starts_in: 60 }
    );
    let aaaa = fixture!("aaaa-dnssec-response.bin");
    let sig = &rrsigs(&aaaa)[0];
    let now = u64::from(sig.expiration) - 3_600;
    let zone = aaaa.questions[0].name.clone();
    let kinds: Vec<_> = dnssec::issues(
        &zone,
        std::slice::from_ref(ds),
        &[],
        std::slice::from_ref(sig),
        now,
        &dnssec::Options::default(),
    )
    .iter()
    .map(|i| i.kind)
    .collect();
    // No DNSKEYs passed: the DS cannot match; the signature is about to expire.
    assert_eq!(
        kinds,
        [
            IssueKind::DnssecDsMismatch,
            IssueKind::DnssecSignatureExpiring
        ]
    );
}

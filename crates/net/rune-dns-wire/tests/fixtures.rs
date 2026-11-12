//! Real packets: responses captured from a public resolver (1.1.1.1, over
//! TCP, November 2026) and a query captured from `dig` 9.18. Each one
//! decodes to the expected records and re-encodes to the exact same bytes.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test on bad input"
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use rune_dns_wire::{
    Caa, Class, Ds, EdnsOption, Message, Mx, Name, RData, Rcode, Record, RecordType, Srv, Tlsa,
};

macro_rules! fixture {
    ($file:literal) => {
        include_bytes!(concat!("fixtures/", $file))
    };
}

const FIXTURES: &[(&str, &[u8])] = &[
    ("aaaa-dnssec-response", fixture!("aaaa-dnssec-response.bin")),
    ("caa-google-response", fixture!("caa-google-response.bin")),
    (
        "cname-github-response",
        fixture!("cname-github-response.bin"),
    ),
    (
        "denial-dnssec-response",
        fixture!("denial-dnssec-response.bin"),
    ),
    ("dig-query", fixture!("dig-query.bin")),
    (
        "dnskey-cloudflare-response",
        fixture!("dnskey-cloudflare-response.bin"),
    ),
    ("ds-example-response", fixture!("ds-example-response.bin")),
    ("mx-example-response", fixture!("mx-example-response.bin")),
    ("ns-example-response", fixture!("ns-example-response.bin")),
    ("ptr-one-response", fixture!("ptr-one-response.bin")),
    ("soa-example-response", fixture!("soa-example-response.bin")),
    ("srv-google-response", fixture!("srv-google-response.bin")),
    ("tlsa-ietf-response", fixture!("tlsa-ietf-response.bin")),
    ("txt-example-response", fixture!("txt-example-response.bin")),
];

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes).unwrap()
}

#[test]
fn every_fixture_re_encodes_byte_for_byte() {
    for (label, bytes) in FIXTURES {
        let message = Message::decode(bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(&message.encode().unwrap(), bytes, "{label}");
        // Display never fails and names the question.
        let text = message.to_string();
        assert!(text.contains(";; QUESTION"), "{label}");
    }
}

#[test]
fn every_truncated_prefix_is_rejected() {
    for (label, bytes) in FIXTURES {
        for len in 0..bytes.len() {
            assert!(Message::decode(&bytes[..len]).is_err(), "{label} at {len}");
        }
    }
}

#[test]
fn dig_query() {
    let message = decode(fixture!("dig-query.bin"));
    assert!(!message.header.response);
    assert!(message.header.recursion_desired);
    assert!(message.header.authentic_data);
    assert_eq!(message.questions.len(), 1);
    assert_eq!(message.questions[0].name, name("www.example.org"));
    assert_eq!(message.questions[0].qtype, RecordType::AAAA);
    assert_eq!(message.questions[0].qclass, Class::IN);
    let edns = message.edns.unwrap();
    assert_eq!(edns.udp_payload_size, 1232);
    assert!(!edns.dnssec_ok());
    assert_eq!(edns.options.len(), 1);
    assert_eq!(edns.options[0].code, EdnsOption::COOKIE);
    assert_eq!(edns.options[0].data.len(), 8);
}

#[test]
fn aaaa_with_rrsig() {
    let message = decode(fixture!("aaaa-dnssec-response.bin"));
    assert!(message.header.response && message.header.authentic_data);
    assert!(message.edns.as_ref().unwrap().dnssec_ok());
    assert_eq!(message.answers.len(), 3);
    assert_eq!(
        message.answers[0].data,
        RData::Aaaa("2606:4700:10::6814:179a".parse::<Ipv6Addr>().unwrap())
    );
    let RData::Rrsig(sig) = &message.answers[2].data else {
        panic!("expected RRSIG, got {:?}", message.answers[2].data);
    };
    assert_eq!(sig.type_covered, RecordType::AAAA);
    assert_eq!(sig.algorithm, 13);
    assert_eq!(sig.labels, 2);
    assert_eq!(sig.original_ttl, 300);
    assert_eq!(sig.key_tag, 34505);
    assert_eq!(sig.signer_name, name("example.com"));
    assert_eq!(sig.signature.len(), 64);
    // The additional section held only the OPT record.
    assert_eq!(message.additionals, []);
}

#[test]
fn caa() {
    let message = decode(fixture!("caa-google-response.bin"));
    assert_eq!(
        message.answers,
        [Record::new(
            name("google.com"),
            86400,
            RData::Caa(Caa {
                flags: 0,
                tag: "issue".into(),
                value: b"pki.goog".to_vec(),
            })
        )]
    );
}

#[test]
fn cname_chain() {
    let message = decode(fixture!("cname-github-response.bin"));
    assert_eq!(message.answers[0].data, RData::Cname(name("github.com")));
    assert_eq!(
        message.answers[1].data,
        RData::A(Ipv4Addr::new(140, 82, 121, 3))
    );
}

#[test]
fn authenticated_denial_keeps_nsec_as_unknown() {
    let message = decode(fixture!("denial-dnssec-response.bin"));
    assert_eq!(message.header.rcode, Rcode::NOERROR);
    assert_eq!(message.answers, []);
    let types: Vec<_> = message.authorities.iter().map(Record::rtype).collect();
    assert_eq!(
        types,
        [
            RecordType::SOA,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::RRSIG
        ]
    );
    let RData::Soa(soa) = &message.authorities[0].data else {
        panic!("expected SOA");
    };
    assert_eq!(soa.mname, name("elliott.ns.cloudflare.com"));
    assert_eq!(soa.minimum, 1800);
    assert!(matches!(
        message.authorities[2].data,
        RData::Unknown { rtype: RecordType::NSEC, ref data } if data.len() == 49
    ));
}

#[test]
fn dnskey() {
    let message = decode(fixture!("dnskey-cloudflare-response.bin"));
    let flags: Vec<_> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::Dnskey(key) => {
                Some((key.flags, key.protocol, key.algorithm, key.public_key.len()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(flags, [(256, 3, 13, 64), (257, 3, 13, 64)]);
}

#[test]
fn ds() {
    let message = decode(fixture!("ds-example-response.bin"));
    let RData::Ds(Ds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    }) = &message.answers[0].data
    else {
        panic!("expected DS");
    };
    assert_eq!((*key_tag, *algorithm, *digest_type), (2371, 13, 2));
    assert_eq!(digest.len(), 32);
}

#[test]
fn null_mx() {
    let message = decode(fixture!("mx-example-response.bin"));
    assert_eq!(
        message.answers[0].data,
        RData::Mx(Mx {
            preference: 0,
            exchange: Name::root(),
        })
    );
}

#[test]
fn ns_ptr_soa_txt() {
    let ns = decode(fixture!("ns-example-response.bin"));
    assert_eq!(
        ns.answers[0].data,
        RData::Ns(name("hera.ns.cloudflare.com"))
    );
    let ptr = decode(fixture!("ptr-one-response.bin"));
    assert_eq!(ptr.questions[0].name, name("1.1.1.1.in-addr.arpa"));
    assert_eq!(ptr.answers[0].data, RData::Ptr(name("one.one.one.one")));
    let soa = decode(fixture!("soa-example-response.bin"));
    assert_eq!(soa.answers[0].rtype(), RecordType::SOA);
    let txt = decode(fixture!("txt-example-response.bin"));
    assert_eq!(
        txt.answers[0].data,
        RData::Txt(vec![b"v=spf1 -all".to_vec()])
    );
}

#[test]
fn srv() {
    let message = decode(fixture!("srv-google-response.bin"));
    assert_eq!(
        message.answers[1].data,
        RData::Srv(Srv {
            priority: 10,
            weight: 1,
            port: 5060,
            target: name("sip-anycast-1.voice.google.com"),
        })
    );
}

#[test]
fn tlsa() {
    let message = decode(fixture!("tlsa-ietf-response.bin"));
    let RData::Tlsa(Tlsa {
        usage,
        selector,
        matching_type,
        data,
    }) = &message.answers[0].data
    else {
        panic!("expected TLSA");
    };
    assert_eq!((*usage, *selector, *matching_type), (3, 1, 1));
    assert_eq!(data.len(), 32);
}

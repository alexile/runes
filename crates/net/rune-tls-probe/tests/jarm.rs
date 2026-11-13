//! JARM: the ten hellos as sent, answer parsing, and the fuzzy hash
//! against the fingerprints published with JARM and against hashes worked
//! out by hand.

#![allow(clippy::unwrap_used, reason = "test code")]
#![allow(clippy::cast_possible_truncation, reason = "probe indexes below 10")]

use rune_tls_hello::{
    CipherSuite, ClientHello, Extension, ExtensionType, KeyShareEntry, NamedGroup, ProtocolVersion,
    ServerHello,
};
use rune_tls_probe::jarm::{self, Entry, Fingerprint, Order, PROBES};

const GOOGLE: &str = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d";
const SALESFORCE: &str = "2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5";
const COBALT_STRIKE: &str = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";

fn hello(index: usize, host: &str) -> (Vec<u8>, ClientHello) {
    let wire = PROBES[index]
        .client_hello(host, &[index as u8; 32])
        .unwrap();
    let parsed = ClientHello::parse_records(&wire).unwrap();
    (wire, parsed)
}

fn codes(hello: &ClientHello) -> Vec<u16> {
    hello.cipher_suites.iter().map(|s| s.0).collect()
}

#[test]
fn probe_table() {
    let names: Vec<&str> = PROBES.iter().map(|p| p.name).collect();
    assert_eq!(
        names,
        [
            "tls1_2_forward",
            "tls1_2_reverse",
            "tls1_2_top_half",
            "tls1_2_bottom_half",
            "tls1_2_middle_out",
            "tls1_1_middle_out",
            "tls1_3_forward",
            "tls1_3_reverse",
            "tls1_3_invalid",
            "tls1_3_middle_out",
        ]
    );
}

#[test]
fn record_and_legacy_versions() {
    let expected = [
        ([22, 3, 3], ProtocolVersion::TLS_1_2),
        ([22, 3, 3], ProtocolVersion::TLS_1_2),
        ([22, 3, 3], ProtocolVersion::TLS_1_2),
        ([22, 3, 3], ProtocolVersion::TLS_1_2),
        ([22, 3, 3], ProtocolVersion::TLS_1_2),
        ([22, 3, 2], ProtocolVersion::TLS_1_1),
        ([22, 3, 1], ProtocolVersion::TLS_1_2),
        ([22, 3, 1], ProtocolVersion::TLS_1_2),
        ([22, 3, 1], ProtocolVersion::TLS_1_2),
        ([22, 3, 1], ProtocolVersion::TLS_1_2),
    ];
    for (i, (record, legacy)) in expected.into_iter().enumerate() {
        let (wire, hello) = hello(i, "example.com");
        assert_eq!(wire[..3], record, "{}", PROBES[i].name);
        assert_eq!(hello.legacy_version, legacy, "{}", PROBES[i].name);
        assert_eq!(hello.session_id.len(), 32);
        assert_eq!(hello.compression_methods, [0]);
        assert_eq!(hello.server_name(), Some("example.com"));
    }
}

#[test]
fn cipher_lists() {
    let forward = codes(&hello(0, "a.test").1);
    assert_eq!(forward.len(), 69);
    assert_eq!(forward[..3], [0x0016, 0x0033, 0x0067]);
    assert_eq!(forward[66..], [0x0007, 0x0004, 0x0005]);

    let mut reverse = codes(&hello(1, "a.test").1);
    reverse.reverse();
    assert_eq!(reverse, forward);

    // 69 suites: top half is the middle one then the first half reversed.
    let top = codes(&hello(2, "a.test").1);
    assert_eq!(top.len(), 35);
    assert_eq!(top[0], forward[34]);
    assert_eq!(
        top[1..],
        forward[..34].iter().rev().copied().collect::<Vec<_>>()[..]
    );
    let bottom = codes(&hello(3, "a.test").1);
    assert_eq!(bottom, forward[35..]);

    // Middle out, after one GREASE value.
    let middle = codes(&hello(4, "a.test").1);
    assert!(rune_tls_hello::is_grease(middle[0]));
    assert_eq!(middle[1..], Order::MiddleOut.apply(&forward)[..]);
    assert_eq!(middle[1..4], [forward[34], forward[35], forward[33]]);

    // The TLS 1.1 "middle out" probe really sends the forward order.
    assert_eq!(codes(&hello(5, "a.test").1), forward);
    // The invalid TLS 1.3 probe offers no TLS 1.3 suite.
    let invalid = codes(&hello(8, "a.test").1);
    assert_eq!(invalid.len(), 64);
    assert!(invalid.iter().all(|c| c >> 8 != 0x13));
    assert_eq!(
        invalid,
        forward
            .iter()
            .copied()
            .filter(|c| c >> 8 != 0x13)
            .collect::<Vec<_>>()
    );
}

#[test]
fn extensions_in_order() {
    let (_, h) = hello(0, "example.com");
    let types: Vec<u16> = h.extension_types().map(|t| t.0).collect();
    assert_eq!(
        types,
        [
            0x0000, 0x0017, 0x0001, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x000d, 0x0033, 0x002d,
            0x002b
        ]
    );
    // No supported_versions without TLS 1.2/1.3 support in the probe.
    let (_, h) = hello(2, "example.com");
    assert!(h.supported_versions().is_none());
    // GREASE first when the probe uses it.
    let (_, h) = hello(9, "example.com");
    assert!(h.extension_types().next().unwrap().is_grease());
    assert_eq!(h.extension_types().count(), 13);
}

#[test]
fn alpn_lists() {
    let alpn = |i: usize| -> Vec<String> {
        hello(i, "a.test")
            .1
            .alpn_protocols()
            .unwrap()
            .into_iter()
            .map(|p| String::from_utf8(p).unwrap())
            .collect()
    };
    let all = [
        "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq",
    ];
    let mut reversed = all;
    reversed.reverse();
    assert_eq!(alpn(0), reversed); // extension order REVERSE
    assert_eq!(alpn(1), all);
    assert_eq!(
        alpn(3),
        [
            "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"
        ]
    );
    // Rare list, reversed.
    assert_eq!(
        alpn(4),
        [
            "hq", "h2c", "spdy/3", "spdy/2", "spdy/1", "http/1.0", "http/0.9"
        ]
    );
}

#[test]
fn supported_versions_and_key_share() {
    use ProtocolVersion as V;
    let versions = |i: usize| {
        hello(i, "a.test")
            .1
            .supported_versions()
            .map(|v| v.into_iter().filter(|v| !v.is_grease()).collect::<Vec<_>>())
    };
    assert_eq!(versions(0), Some(vec![V::TLS_1_2, V::TLS_1_1, V::TLS_1_0]));
    assert_eq!(versions(1), Some(vec![V::TLS_1_0, V::TLS_1_1, V::TLS_1_2]));
    assert_eq!(
        versions(6),
        Some(vec![V::TLS_1_3, V::TLS_1_2, V::TLS_1_1, V::TLS_1_0])
    );
    assert_eq!(
        versions(7),
        Some(vec![V::TLS_1_0, V::TLS_1_1, V::TLS_1_2, V::TLS_1_3])
    );
    let (_, h) = hello(9, "a.test");
    assert!(h.supported_versions().unwrap()[0].is_grease());

    let shares = hello(0, "a.test").1.key_shares().unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].group, NamedGroup::X25519);
    assert_eq!(shares[0].key_exchange.len(), 32);
    let shares = hello(4, "a.test").1.key_shares().unwrap();
    assert!(shares[0].group.is_grease());
    assert_eq!(shares[0].key_exchange, [0]);
    assert_eq!(shares[1].group, NamedGroup::X25519);
}

#[test]
fn hellos_are_deterministic_per_seed() {
    let a = PROBES[4].client_hello("a.test", &[1; 32]).unwrap();
    let b = PROBES[4].client_hello("a.test", &[1; 32]).unwrap();
    let c = PROBES[4].client_hello("a.test", &[2; 32]).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    // JARM sends the target as SNI even when it is an address.
    let (_, h) = hello(0, "192.0.2.7");
    assert_eq!(h.server_name(), Some("192.0.2.7"));
    assert!(
        PROBES[0]
            .client_hello(&"a".repeat(70_000), &[0; 32])
            .is_err()
    );
}

#[test]
fn published_fingerprints_decode() {
    let tls12 = Some(ProtocolVersion::TLS_1_2);
    let suite = |a: &jarm::Answer| a.cipher_suite.map(|s| s.0);

    let google = jarm::decode(GOOGLE).unwrap();
    let got: Vec<Option<(Option<u16>, Option<ProtocolVersion>)>> = google
        .answers
        .iter()
        .map(|a| a.map(|a| (suite(&a), a.version)))
        .collect();
    assert_eq!(
        got,
        [
            Some((Some(0xc02b), tls12)), // forward: ECDHE-ECDSA AES-128-GCM
            Some((Some(0xcca9), tls12)), // reverse: ECDHE-ECDSA ChaCha20
            Some((Some(0xcca9), tls12)),
            Some((Some(0xc02f), tls12)), // bottom half: ECDHE-RSA AES-128-GCM
            Some((Some(0xcca9), tls12)),
            Some((Some(0xc009), Some(ProtocolVersion::TLS_1_1))),
            Some((Some(0x1302), tls12)), // TLS 1.3 answers say TLS 1.2 in legacy_version
            Some((Some(0x1303), tls12)),
            None, // TLS 1.3 hello without TLS 1.3 suites refused
            Some((Some(0x1301), tls12)),
        ]
    );
    assert_eq!(google.extensions_hash, "4689ee210389f4f6b4b5b1b93f92252d");

    let salesforce = jarm::decode(SALESFORCE).unwrap();
    let answered: Vec<bool> = salesforce.answers.iter().map(Option::is_some).collect();
    assert_eq!(
        answered,
        [
            true, true, false, true, true, false, true, true, false, false
        ]
    );
    assert_eq!(suite(&salesforce.answers[0].unwrap()), Some(0xc030));

    let cobalt = jarm::decode(COBALT_STRIKE).unwrap();
    assert_eq!(suite(&cobalt.answers[0].unwrap()), Some(0x0033)); // DHE-RSA AES-128-CBC-SHA
    assert_eq!(
        cobalt.answers[5].unwrap().version,
        Some(ProtocolVersion::TLS_1_1)
    );

    assert!(jarm::decode(&GOOGLE[1..]).is_none());
    assert!(jarm::decode(&GOOGLE.to_uppercase()).is_none());
    assert!(jarm::decode(&"z".repeat(62)).is_none());
    assert!(jarm::decode(&format!("00a{}", &GOOGLE[3..])).is_none());
}

/// The fuzzy part re-encoded from decoded answers is the original.
#[test]
fn decode_then_hash_round_trips_the_fuzzy_part() {
    for fp in [GOOGLE, SALESFORCE, COBALT_STRIKE] {
        let decoded = jarm::decode(fp).unwrap();
        let entries: Vec<Entry> = decoded
            .answers
            .iter()
            .map(|a| {
                a.map_or(Entry::NoAnswer, |a| {
                    Entry::answered(a.cipher_suite.unwrap().0, a.version.unwrap().0, "", [])
                })
            })
            .collect();
        let fingerprint = Fingerprint::new(entries.try_into().unwrap());
        assert_eq!(fingerprint.hash()[..30], fp[..30]);
    }
}

#[test]
fn hash_known_answers() {
    assert_eq!(Fingerprint::default().hash(), "0".repeat(62));
    assert!(Fingerprint::default().is_empty());

    // Worked out by hand: suite positions 0x29 (c02f), 0x2a (c030), 0x16
    // (009f), 0x21 (c013), 0x41 (1301), 0x43 (1303); then the SHA-256 of
    // the ALPN and extension fields concatenated.
    let raw = "c02f|0303|h2|ff01-0000-0001-000b-0023-0010,\
               c030|0303|http/1.1|ff01-0000-0001-000b-0023-0010,|||,\
               009f|0303||ff01-0000,|||,c013|0302||ff01,1301|0303|h2|002b-0033,\
               1303|0303|h2|002b-0033,|||,1301|0303||002b-0033";
    assert_eq!(
        jarm::hash(raw),
        "29d2ad00016d00021c41d43d00041d3443c8bf930475668bb882df2bca34cb"
    );

    // Answers without ALPN or extensions hash the empty string.
    let fp = Fingerprint::new([
        Entry::answered(0x0005, 0x0300, "", []),
        Entry::answered(0x1305, 0x0304, "", []),
        Entry::answered(0x1234, 0x0301, "", []),
        Entry::NoAnswer,
        Entry::NoAnswer,
        Entry::NoAnswer,
        Entry::NoAnswer,
        Entry::NoAnswer,
        Entry::NoAnswer,
        Entry::NoAnswer,
    ]);
    assert_eq!(
        fp.hash(),
        "02a45e46b000000000000000000000e3b0c44298fc1c149afbf4c8996fb924"
    );
    assert_eq!(fp.to_string(), fp.hash());
    assert!(!fp.is_empty());
}

#[test]
fn server_hello_entries() {
    let hello = ServerHello::new()
        .with_legacy_version(ProtocolVersion::TLS_1_2)
        .with_cipher_suite(CipherSuite(0xc02f))
        .with_extension(Extension::renegotiation_info(&[]).unwrap())
        .with_extension(Extension::new(ExtensionType(0x000b), vec![1, 0]))
        .with_extension(Extension::alpn(["h2"]).unwrap())
        .with_extension(Extension::empty(ExtensionType(0x0017)));
    let wire = hello.to_records(ProtocolVersion::TLS_1_2, 16_384).unwrap();
    assert_eq!(
        Entry::parse(&wire).to_string(),
        "c02f|0303|h2|ff01-000b-0010-0017"
    );

    // Split across reads, with a certificate following.
    let mut stream = wire;
    stream.extend([22, 3, 3, 0, 7, 11, 0, 0, 3, 0, 0, 0]);
    let mut reader = jarm::ResponseReader::new();
    assert_eq!(reader.feed(&stream[..10]), None);
    assert!(matches!(
        reader.feed(&stream[10..]),
        Some(Entry::Answered { .. })
    ));

    // No extension block at all.
    let bare = ServerHello::new()
        .with_legacy_version(ProtocolVersion::TLS_1_0)
        .with_cipher_suite(CipherSuite(0x002f))
        .without_extensions()
        .to_records(ProtocolVersion::TLS_1_0, 16_384)
        .unwrap();
    assert_eq!(Entry::parse(&bare).to_string(), "002f|0301||");

    // A HelloRetryRequest counts as an answer.
    let hrr = ServerHello::new()
        .with_random(rune_tls_hello::HELLO_RETRY_REQUEST_RANDOM)
        .with_cipher_suite(CipherSuite(0x1302))
        .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
        .with_extension(Extension::key_share_request(NamedGroup::SECP256R1))
        .to_records(ProtocolVersion::TLS_1_2, 16_384)
        .unwrap();
    assert_eq!(Entry::parse(&hrr).to_string(), "1302|0303||002b-0033");

    // Alerts, other protocols, empty or non-text ALPN: no answer.
    assert_eq!(Entry::parse(&[21, 3, 3, 0, 2, 2, 70]), Entry::NoAnswer);
    assert_eq!(
        Entry::parse(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
        Entry::NoAnswer
    );
    assert_eq!(Entry::parse(&[]), Entry::NoAnswer);
    for alpn in [vec![], vec![0, 3, 2, 0xff, 0xfe]] {
        let wire = ServerHello::new()
            .with_cipher_suite(CipherSuite(0xc02f))
            .with_extension(Extension::new(ExtensionType::ALPN, alpn))
            .to_records(ProtocolVersion::TLS_1_2, 16_384)
            .unwrap();
        assert_eq!(Entry::parse(&wire), Entry::NoAnswer);
    }
}

#[test]
fn a_scripted_server_end_to_end() {
    // Answers every hello the way a TLS 1.3 server preferring AES-256-GCM
    // and h2 would, without the cryptography.
    let server = |wire: &[u8]| -> Vec<u8> {
        let hello = ClientHello::parse_records(wire).unwrap();
        let tls13 = hello
            .supported_versions()
            .is_some_and(|v| v.contains(&ProtocolVersion::TLS_1_3));
        let prefs: &[u16] = if tls13 {
            &[0x1302, 0x1301]
        } else {
            &[0xc030, 0xc02f]
        };
        let Some(&suite) = prefs.iter().find(|s| hello.offers(CipherSuite(**s))) else {
            return vec![21, 3, 3, 0, 2, 2, 40];
        };
        let mut reply = ServerHello::new().with_cipher_suite(CipherSuite(suite));
        if tls13 {
            reply = reply
                .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
                .with_extension(
                    Extension::key_share(&KeyShareEntry::new(NamedGroup::X25519, vec![9; 32]))
                        .unwrap(),
                );
        } else {
            reply = reply
                .with_legacy_version(hello.legacy_version.min(ProtocolVersion::TLS_1_2))
                .with_extension(Extension::renegotiation_info(&[]).unwrap());
            let offers_h2 = hello
                .alpn_protocols()
                .is_some_and(|p| p.iter().any(|p| p == b"h2"));
            if offers_h2 {
                reply = reply.with_extension(Extension::alpn(["h2"]).unwrap());
            }
        }
        reply.to_records(ProtocolVersion::TLS_1_2, 16_384).unwrap()
    };
    let entries: Vec<Entry> = PROBES
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Entry::parse(&server(
                &p.client_hello("srv.test", &[i as u8; 32]).unwrap(),
            ))
        })
        .collect();
    let fp = Fingerprint::new(entries.try_into().unwrap());
    assert_eq!(
        fp.raw(),
        "c030|0303|h2|ff01-0010,c030|0303|h2|ff01-0010,|||,\
         c030|0303||ff01,c030|0303||ff01,c030|0302|h2|ff01-0010,\
         1302|0303||002b-0033,1302|0303||002b-0033,|||,1302|0303||002b-0033"
    );
    // The top-half hello offers neither AES-GCM suite; the invalid TLS 1.3
    // hello offers no TLS 1.3 suite.
    let hash = fp.hash();
    assert_eq!(&hash[..30], "2ad2ad0002ad2ad2ac42d42d00042d");
    assert_eq!(hash, jarm::hash(&fp.raw()));
}

#[test]
fn hostile_alpn_cannot_reshape_the_fingerprint() {
    // A server can answer with any ALPN bytes, including the `,` and `|`
    // that separate entries and fields in the raw form.
    let wire = ServerHello::new()
        .with_legacy_version(ProtocolVersion::TLS_1_2)
        .with_cipher_suite(CipherSuite(0xc02f))
        .with_extension(Extension::new(
            ExtensionType::ALPN,
            b"\x00\x0d\x0c|0303|,,c02f".to_vec(),
        ))
        .to_records(ProtocolVersion::TLS_1_2, 16_384)
        .unwrap();
    let mut fp = Fingerprint::default();
    fp.entries[0] = Entry::parse(&wire);
    assert!(matches!(fp.entries[0], Entry::Answered { .. }));
    let hash = fp.hash();
    assert_eq!(hash.len(), jarm::HASH_LEN, "{hash}");
    // Only the first probe answered; the others stay empty.
    assert!(hash.starts_with("29d000000000000000000000000000"), "{hash}");
    assert!(
        jarm::decode(&hash).unwrap().answers[1..]
            .iter()
            .all(Option::is_none)
    );
}

#[test]
fn raw_hash_is_always_62_characters() {
    for raw in [
        "",
        "c02f|0303||",
        &"|||,".repeat(20),
        "c02f|0303|h2|0010,,,,",
    ] {
        assert_eq!(jarm::hash(raw).len(), jarm::HASH_LEN, "{raw:?}");
    }
    // Missing entries count as empty ones.
    assert_eq!(
        jarm::hash("c02f|0303|h2|0010"),
        jarm::hash("c02f|0303|h2|0010,|||,|||,|||,|||,|||,|||,|||,|||,|||")
    );
}

//! Property tests: `decode(encode(m)) == m` for arbitrary valid messages,
//! the decoder never panics, and whatever it accepts re-encodes stably.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::collection::vec;
use proptest::prelude::*;
use rune_dns_wire::{
    Caa, Class, Dnskey, Ds, Edns, EdnsOption, Error, Header, MAX_NAME_LEN, Message, Mx, Name,
    Opcode, Question, RData, Rcode, Record, RecordType, Rrsig, Soa, Srv, Tlsa,
};

/// Labels from a small alphabet, so names often share suffixes and the
/// compressor gets exercised, plus arbitrary octets now and then.
fn label() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => prop::sample::select(vec![&b"a"[..], b"B", b"example", b"com", b"ns1", b"_tcp"])
            .prop_map(<[u8]>::to_vec),
        1 => vec(any::<u8>(), 1..=63),
    ]
}

fn name() -> impl Strategy<Value = Name> {
    vec(label(), 0..6).prop_map(|labels| {
        // Drop labels from the end until the name fits.
        let mut labels = labels;
        loop {
            if let Ok(name) = Name::from_labels(&labels) {
                return name;
            }
            labels.pop();
        }
    })
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..=max)
}

/// Types this crate decodes into typed variants, and OPT.
const MODELLED: [u16; 15] = [1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 43, 46, 48, 52, 257];

fn rdata() -> impl Strategy<Value = RData> {
    prop_oneof![
        any::<u32>().prop_map(|ip| RData::A(Ipv4Addr::from(ip))),
        any::<u128>().prop_map(|ip| RData::Aaaa(Ipv6Addr::from(ip))),
        name().prop_map(RData::Ns),
        name().prop_map(RData::Cname),
        name().prop_map(RData::Ptr),
        (any::<u16>(), name()).prop_map(|(preference, exchange)| RData::Mx(Mx {
            preference,
            exchange
        })),
        vec(bytes(255), 0..4).prop_map(RData::Txt),
        (name(), name(), any::<[u32; 5]>()).prop_map(|(mname, rname, n)| RData::Soa(Soa {
            mname,
            rname,
            serial: n[0],
            refresh: n[1],
            retry: n[2],
            expire: n[3],
            minimum: n[4],
        })),
        (any::<[u16; 3]>(), name()).prop_map(|(n, target)| RData::Srv(Srv {
            priority: n[0],
            weight: n[1],
            port: n[2],
            target,
        })),
        (any::<u8>(), "[a-zA-Z0-9]{1,15}", bytes(40))
            .prop_map(|(flags, tag, value)| { RData::Caa(Caa { flags, tag, value }) }),
        (any::<[u8; 3]>(), bytes(64)).prop_map(|(n, data)| RData::Tlsa(Tlsa {
            usage: n[0],
            selector: n[1],
            matching_type: n[2],
            data,
        })),
        (any::<u16>(), any::<[u8; 2]>(), bytes(48)).prop_map(|(key_tag, n, digest)| {
            RData::Ds(Ds {
                key_tag,
                algorithm: n[0],
                digest_type: n[1],
                digest,
            })
        }),
        (any::<u16>(), any::<[u8; 2]>(), bytes(64)).prop_map(|(flags, n, public_key)| {
            RData::Dnskey(Dnskey {
                flags,
                protocol: n[0],
                algorithm: n[1],
                public_key,
            })
        }),
        (
            any::<(u16, u8, u8, u32, u32, u32, u16)>(),
            name(),
            bytes(64)
        )
            .prop_map(|(n, signer_name, signature)| RData::Rrsig(Rrsig {
                type_covered: RecordType(n.0),
                algorithm: n.1,
                labels: n.2,
                original_ttl: n.3,
                expiration: n.4,
                inception: n.5,
                key_tag: n.6,
                signer_name,
                signature,
            })),
        (
            any::<u16>().prop_filter("modelled type", |t| !MODELLED.contains(t)),
            bytes(64)
        )
            .prop_map(|(rtype, data)| RData::Unknown {
                rtype: RecordType(rtype),
                data,
            }),
    ]
}

fn record() -> impl Strategy<Value = Record> {
    (name(), any::<u16>(), any::<u32>(), rdata()).prop_map(|(name, class, ttl, data)| Record {
        name,
        class: Class(class),
        ttl,
        data,
    })
}

fn edns() -> impl Strategy<Value = Edns> {
    (
        any::<u16>(),
        any::<u8>(),
        any::<u16>(),
        vec((any::<u16>(), bytes(16)), 0..3),
    )
        .prop_map(|(size, version, flags, options)| Edns {
            udp_payload_size: size,
            version,
            flags,
            options: options
                .into_iter()
                .map(|(code, data)| EdnsOption::new(code, data))
                .collect(),
        })
}

fn header(extended_rcode: bool) -> impl Strategy<Value = Header> {
    let max_rcode: u16 = if extended_rcode { 0xFFF } else { 0xF };
    (any::<u16>(), 0..16_u8, any::<[bool; 9]>(), 0..=max_rcode).prop_map(
        |(id, opcode, b, rcode)| Header {
            id,
            response: b[0],
            opcode: Opcode(opcode),
            authoritative: b[1],
            truncated: b[2],
            recursion_desired: b[3],
            recursion_available: b[4],
            z: b[5],
            authentic_data: b[6],
            checking_disabled: b[7],
            rcode: Rcode(rcode),
        },
    )
}

fn message() -> impl Strategy<Value = Message> {
    prop::option::of(edns()).prop_flat_map(|edns| {
        (
            header(edns.is_some()),
            vec(
                (name(), any::<u16>(), any::<u16>()).prop_map(|(name, t, c)| Question {
                    name,
                    qtype: RecordType(t),
                    qclass: Class(c),
                }),
                0..3,
            ),
            vec(record(), 0..5),
            vec(record(), 0..3),
            vec(
                record().prop_filter("OPT goes in edns", |r| r.rtype() != RecordType::OPT),
                0..3,
            ),
            Just(edns),
        )
            .prop_map(
                |(header, questions, answers, authorities, additionals, edns)| Message {
                    header,
                    questions,
                    answers,
                    authorities,
                    additionals,
                    edns,
                },
            )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn message_round_trips(message in message()) {
        let bytes = message.encode().unwrap();
        prop_assert_eq!(Message::decode(&bytes).unwrap(), message);
    }

    #[test]
    fn truncated_encoding_fits_and_decodes(message in message(), limit in 12_usize..1500) {
        match message.encode_with_limit(limit) {
            Ok(bytes) => {
                prop_assert!(bytes.len() <= limit);
                let decoded = Message::decode(&bytes).unwrap();
                // Whatever was kept is a prefix of each section.
                prop_assert_eq!(&decoded.questions, &message.questions);
                prop_assert_eq!(&message.answers[..decoded.answers.len()], &decoded.answers[..]);
                prop_assert_eq!(&decoded.edns, &message.edns);
            }
            Err(error) => prop_assert!(matches!(error, Error::MessageTooLong { .. }), "{error}"),
        }
    }

    #[test]
    fn name_text_round_trips(name in name()) {
        prop_assert_eq!(&Name::from_ascii(&name.to_string()).unwrap(), &name);
        prop_assert!(name.wire_len() <= MAX_NAME_LEN);
        prop_assert_eq!(Name::from_labels(name.labels()).unwrap(), name);
    }

    #[test]
    fn name_parser_never_panics(text in "\\PC{0,300}") {
        let _ = Name::from_ascii(&text);
        let _ = text.parse::<RecordType>();
    }

    #[test]
    fn decoder_never_panics(data in bytes(600)) {
        if let Ok(message) = Message::decode(&data) {
            // Anything accepted re-encodes (or is too large once
            // decompressed) and decodes back to the same message.
            match message.encode() {
                Ok(bytes) => prop_assert_eq!(Message::decode(&bytes).unwrap(), message),
                Err(error) => prop_assert!(
                    matches!(error, Error::MessageTooLong { .. } | Error::RdataTooLong { .. }),
                    "{error}"
                ),
            }
        }
    }

    #[test]
    fn mutated_valid_messages_never_panic(
        message in message(),
        flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let mut bytes = message.encode().unwrap();
        for (index, value) in flips {
            let at = index.index(bytes.len());
            bytes[at] = value;
        }
        let decoded = Message::decode(&bytes);
        if let Some((decoded, again)) = decoded.ok().and_then(|d| d.encode().ok().map(|a| (d, a))) {
            prop_assert_eq!(Message::decode(&again).unwrap(), decoded);
        }
    }
}

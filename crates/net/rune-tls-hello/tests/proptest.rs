//! Property tests: hellos round-trip through every encoding layer, the
//! stream reader is independent of how input is chunked, and no input makes
//! a parser panic. Whatever parses re-encodes to the same bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail loudly by design"
)]

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rune_tls_hello::{
    ClientHello, ContentType, Extension, ExtensionType, HELLO_RETRY_REQUEST_RANDOM,
    HandshakeMessage, KeyShareEntry, Message, MessageReader, NamedGroup, ProtocolVersion, Record,
    ServerHello, SignatureScheme,
};

/// Extension types whose bodies the parser validates.
const TYPED: [u16; 11] = [0, 10, 11, 13, 16, 22, 23, 43, 50, 51, 0xff01];

fn u16s(max: usize) -> impl Strategy<Value = Vec<u16>> {
    vec(any::<u16>(), 0..max)
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..max)
}

/// A well-formed `ClientHello` extension of a typed kind.
fn typed_client_extension() -> impl Strategy<Value = Extension> {
    prop_oneof![
        "[a-z0-9.-]{0,40}".prop_map(|host| Extension::server_name(&host).unwrap()),
        u16s(8).prop_map(|g| {
            Extension::supported_groups(&g.into_iter().map(NamedGroup).collect::<Vec<_>>()).unwrap()
        }),
        bytes(4).prop_map(|f| Extension::ec_point_formats(&f).unwrap()),
        u16s(8).prop_map(|s| {
            Extension::signature_algorithms(&s.into_iter().map(SignatureScheme).collect::<Vec<_>>())
                .unwrap()
        }),
        vec(bytes(12), 0..4).prop_map(|p| Extension::alpn(p).unwrap()),
        u16s(6).prop_map(|v| {
            Extension::supported_versions(&v.into_iter().map(ProtocolVersion).collect::<Vec<_>>())
                .unwrap()
        }),
        vec((any::<u16>(), bytes(40)), 0..3).prop_map(|entries| {
            let entries: Vec<_> = entries
                .into_iter()
                .map(|(g, k)| KeyShareEntry::new(NamedGroup(g), k))
                .collect();
            Extension::key_shares(&entries).unwrap()
        }),
        bytes(12).prop_map(|r| Extension::renegotiation_info(&r).unwrap()),
        Just(Extension::empty(ExtensionType::EXTENDED_MASTER_SECRET)),
    ]
}

/// An extension of a type the parser does not interpret, GREASE included.
fn opaque_extension() -> impl Strategy<Value = Extension> {
    (any::<u16>(), bytes(24))
        .prop_filter("untyped", |(t, _)| !TYPED.contains(t))
        .prop_map(|(t, data)| Extension::new(ExtensionType(t), data))
}

/// Extensions with unique types, in arbitrary order.
fn extensions(typed: BoxedStrategy<Extension>) -> impl Strategy<Value = Vec<Extension>> {
    vec(prop_oneof![typed, opaque_extension()], 0..10).prop_flat_map(|list| {
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<_> = list
            .into_iter()
            .filter(|e| seen.insert(e.extension_type))
            .collect();
        Just(unique).prop_shuffle()
    })
}

prop_compose! {
    fn client_hello()(
        version in any::<u16>(),
        random in any::<[u8; 32]>(),
        session_id in bytes(36),
        suites in u16s(40),
        compression in bytes(4),
        exts in option::weighted(0.9, extensions(typed_client_extension().boxed())),
    ) -> ClientHello {
        let hello = ClientHello::new()
            .with_legacy_version(ProtocolVersion(version))
            .with_random(random)
            .with_session_id(session_id)
            .with_cipher_suites(suites.into_iter().map(Into::into))
            .with_compression_methods(compression);
        match exts {
            Some(exts) => hello.with_extensions(exts),
            None => hello.without_extensions(),
        }
    }
}

fn server_extension(hrr: bool) -> BoxedStrategy<Extension> {
    if hrr {
        prop_oneof![
            any::<u16>().prop_map(|v| Extension::selected_version(ProtocolVersion(v))),
            any::<u16>().prop_map(|g| Extension::key_share_request(NamedGroup(g))),
        ]
        .boxed()
    } else {
        prop_oneof![
            any::<u16>().prop_map(|v| Extension::selected_version(ProtocolVersion(v))),
            (any::<u16>(), bytes(40)).prop_map(|(g, k)| {
                Extension::key_share(&KeyShareEntry::new(NamedGroup(g), k)).unwrap()
            }),
            bytes(12).prop_map(|p| Extension::alpn([p]).unwrap()),
            Just(Extension::empty(ExtensionType::SERVER_NAME)),
            bytes(12).prop_map(|r| Extension::renegotiation_info(&r).unwrap()),
        ]
        .boxed()
    }
}

fn server_hello() -> impl Strategy<Value = ServerHello> {
    any::<bool>().prop_flat_map(|hrr| {
        (
            any::<u16>(),
            any::<[u8; 32]>(),
            bytes(33),
            any::<u16>(),
            any::<u8>(),
            option::weighted(0.9, extensions(server_extension(hrr))),
        )
            .prop_map(
                move |(version, random, session_id, suite, compression, exts)| {
                    let random = if hrr {
                        HELLO_RETRY_REQUEST_RANDOM
                    } else {
                        random
                    };
                    let hello = ServerHello::new()
                        .with_legacy_version(ProtocolVersion(version))
                        .with_random(random)
                        .with_session_id(session_id)
                        .with_cipher_suite(suite.into())
                        .with_compression_method(compression);
                    match exts {
                        Some(exts) => exts.into_iter().fold(hello, ServerHello::with_extension),
                        None => hello.without_extensions(),
                    }
                },
            )
    })
}

/// Feeds `bytes` to a reader in chunks of the given sizes (cycled) and
/// collects every message.
fn read_chunked(bytes: &[u8], sizes: &[usize]) -> Vec<Message> {
    let mut reader = MessageReader::new();
    let mut messages = Vec::new();
    let mut rest = bytes;
    let mut sizes = sizes.iter().copied().cycle();
    while !rest.is_empty() {
        let n = sizes.next().unwrap_or(1).clamp(1, rest.len());
        let (chunk, tail) = rest.split_at(n);
        reader.feed(chunk);
        rest = tail;
        while let Some(message) = reader.next_message().unwrap() {
            messages.push(message);
        }
    }
    messages
}

proptest! {
    #[test]
    fn client_hello_round_trips(
        hello in client_hello(),
        frag in 1usize..300,
        sizes in vec(1usize..64, 1..5),
    ) {
        prop_assume!(hello.session_id.len() <= 32);
        let body = hello.to_body().unwrap();
        prop_assert_eq!(&ClientHello::parse(&body).unwrap(), &hello);

        let message = hello.to_message().unwrap();
        prop_assert_eq!(&ClientHello::parse_message(&message).unwrap(), &hello);
        let (parsed, used) = HandshakeMessage::parse(&message).unwrap();
        prop_assert_eq!(used, message.len());
        prop_assert_eq!(parsed.to_bytes().unwrap(), message);

        let records = hello.to_records(ProtocolVersion::TLS_1_0, frag).unwrap();
        prop_assert_eq!(&ClientHello::parse_records(&records).unwrap(), &hello);
        prop_assert_eq!(
            read_chunked(&records, &sizes),
            vec![Message::Handshake(HandshakeMessage::ClientHello(hello))]
        );
    }

    #[test]
    fn client_hello_accessors_agree_with_extensions(hello in client_hello()) {
        prop_assume!(hello.session_id.len() <= 32);
        let parsed = ClientHello::parse(&hello.to_body().unwrap()).unwrap();
        let has = |t| parsed.extension(t).is_some();
        prop_assert_eq!(parsed.alpn_protocols().is_some(), has(ExtensionType::ALPN));
        prop_assert_eq!(parsed.supported_groups().is_some(), has(ExtensionType::SUPPORTED_GROUPS));
        prop_assert_eq!(parsed.key_shares().is_some(), has(ExtensionType::KEY_SHARE));
        prop_assert_eq!(
            parsed.supported_versions().is_some(),
            has(ExtensionType::SUPPORTED_VERSIONS)
        );
        let max = parsed.max_version();
        prop_assert!(!max.is_grease() || max == parsed.legacy_version);
        if parsed.server_name().is_some() {
            prop_assert!(has(ExtensionType::SERVER_NAME));
        }
    }

    #[test]
    fn server_hello_round_trips(
        hello in server_hello(),
        frag in 1usize..100,
        sizes in vec(1usize..64, 1..5),
    ) {
        prop_assume!(hello.session_id.len() <= 32);
        let body = hello.to_body().unwrap();
        prop_assert_eq!(&ServerHello::parse(&body).unwrap(), &hello);
        let records = hello.to_records(ProtocolVersion::TLS_1_2, frag).unwrap();
        prop_assert_eq!(&ServerHello::parse_records(&records).unwrap(), &hello);
        prop_assert_eq!(
            read_chunked(&records, &sizes),
            vec![Message::Handshake(HandshakeMessage::ServerHello(hello))]
        );
    }

    #[test]
    fn oversized_session_ids_are_refused(hello in client_hello()) {
        prop_assert_eq!(hello.to_body().is_ok(), hello.session_id.len() <= 32);
    }

    #[test]
    fn records_round_trip(content_type in 20u8..=24, version in any::<u16>(), fragment in bytes(600)) {
        let record = Record::new(ContentType(content_type), ProtocolVersion(0x0300 | (version & 0xff)), &fragment);
        let mut out = Vec::new();
        record.encode(&mut out).unwrap();
        prop_assert_eq!(Record::parse(&out).unwrap(), (record, out.len()));
    }

    #[test]
    fn parsers_never_panic_and_are_canonical(input in bytes(400)) {
        if let Ok(hello) = ClientHello::parse(&input) {
            prop_assert_eq!(hello.to_body().unwrap(), input.clone());
        }
        if let Ok(hello) = ServerHello::parse(&input) {
            prop_assert_eq!(hello.to_body().unwrap(), input.clone());
        }
        if let Ok((message, used)) = HandshakeMessage::parse(&input) {
            prop_assert_eq!(message.to_bytes().unwrap(), input[..used].to_vec());
        }
        let _ = ClientHello::parse_records(&input);
        let _ = ServerHello::parse_records(&input);
        let mut reader = MessageReader::new();
        reader.feed(&input);
        while let Ok(Some(_)) = reader.next_message() {}
    }

    #[test]
    fn mutated_hellos_never_panic(hello in client_hello(), flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..4)) {
        prop_assume!(hello.session_id.len() <= 32);
        let mut records = hello.to_records(ProtocolVersion::TLS_1_2, 1 << 14).unwrap();
        for (index, value) in flips {
            let i = index.index(records.len());
            records[i] ^= value;
        }
        if let Ok(parsed) = ClientHello::parse_records(&records) {
            let body = parsed.to_body().unwrap();
            prop_assert_eq!(&ClientHello::parse(&body).unwrap(), &parsed);
            // Every typed view of the extensions must hold up too.
            let _ = (parsed.server_name(), parsed.alpn_protocols(), parsed.supported_versions());
            let _ = (parsed.supported_groups(), parsed.signature_algorithms(), parsed.ec_point_formats());
            let _ = (parsed.key_shares(), parsed.max_version(), parsed.offers_fallback_scsv());
            let _ = (parsed.offers_secure_renegotiation(), parsed.extension_types().count());
        }
        // The stream reader, fed in uneven pieces.
        let mut reader = MessageReader::new();
        for chunk in records.chunks(7) {
            reader.feed(chunk);
            while let Ok(Some(_)) = reader.next_message() {}
        }
    }

    #[test]
    fn mutated_server_hellos_never_panic(flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..6)) {
        let hello = ServerHello::new()
            .with_random([7; 32])
            .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
            .with_extension(Extension::key_share(&KeyShareEntry::new(NamedGroup::X25519, vec![9; 32])).unwrap())
            .with_extension(Extension::alpn([b"h2"]).unwrap());
        let mut records = hello.to_records(ProtocolVersion::TLS_1_2, 1 << 14).unwrap();
        for (index, value) in flips {
            let i = index.index(records.len());
            records[i] ^= value;
        }
        if let Ok(parsed) = ServerHello::parse_records(&records) {
            let _ = (parsed.selected_version(), parsed.alpn_protocol(), parsed.key_share_group());
            let _ = (parsed.downgrade_sentinel(), parsed.secure_renegotiation(), parsed.kind());
            let _ = (parsed.is_hello_retry_request(), parsed.extension_types().count());
        }
    }
}

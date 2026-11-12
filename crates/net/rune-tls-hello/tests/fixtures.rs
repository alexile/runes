//! Hellos captured from real TLS stacks over loopback: OpenSSL 3.5
//! (`s_client`, `s_server`) for TLS 1.0 to 1.3, and `GnuTLS` (`wget`) for
//! TLS 1.3. `fixtures/capture.py` regenerates them.
//!
//! Every hello must parse, show the fields the client and server were
//! configured with, and re-encode to exactly the captured bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail loudly by design"
)]

use rune_tls_hello::{
    AlertDescription, CipherSuite, ClientHello, DowngradeSentinel, Error, ExtensionType,
    HandshakeMessage, HandshakeType, Message, MessageReader, NamedGroup, ProtocolVersion, Record,
    ServerHello,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

/// Parses a captured `ClientHello` stream and checks it re-encodes exactly.
fn client_hello(name: &str) -> ClientHello {
    let bytes = fixture(name);
    let hello = ClientHello::parse_records(&bytes).unwrap();
    let (record, used) = Record::parse(&bytes).unwrap();
    assert_eq!(used, bytes.len(), "{name}: one record");
    assert_eq!(
        hello.to_records(record.version, 1 << 14).unwrap(),
        bytes,
        "{name}"
    );
    assert_eq!(hello.to_message().unwrap(), record.fragment, "{name}");
    hello
}

/// Reads a captured server flight; checks the `ServerHello` re-encodes
/// exactly and returns it with the types of the messages after it.
fn server_flight(name: &str) -> (ServerHello, Vec<String>) {
    let bytes = fixture(name);
    let hello = ServerHello::parse_records(&bytes).unwrap();
    let (record, _) = Record::parse(&bytes).unwrap();
    let (message, used) = HandshakeMessage::parse(record.fragment).unwrap();
    assert_eq!(message, HandshakeMessage::ServerHello(hello.clone()));
    assert_eq!(
        hello.to_message().unwrap(),
        record.fragment[..used],
        "{name}"
    );

    // Byte-at-a-time feeding gives the same messages as one big feed.
    let mut whole = MessageReader::new();
    whole.feed(&bytes);
    let mut trickle = MessageReader::new();
    let mut from_trickle = Vec::new();
    for byte in &bytes {
        trickle.feed(std::slice::from_ref(byte));
        while let Some(message) = trickle.next_message().unwrap() {
            from_trickle.push(message);
        }
    }
    let mut messages = Vec::new();
    while let Some(message) = whole.next_message().unwrap() {
        messages.push(message);
    }
    assert_eq!(messages, from_trickle, "{name}");
    assert_eq!(whole.buffered_len(), 0, "{name}");

    let mut rest = messages.into_iter();
    assert_eq!(
        rest.next(),
        Some(Message::Handshake(HandshakeMessage::ServerHello(
            hello.clone()
        )))
    );
    let kinds = rest
        .map(|message| match message {
            Message::Handshake(m) => m.msg_type().to_string(),
            Message::ChangeCipherSpec(_) => "change_cipher_spec".into(),
            Message::ApplicationData(_) => "application_data".into(),
            other => format!("{other:?}"),
        })
        .collect();
    (hello, kinds)
}

fn alpn_h2_http11() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

#[test]
fn openssl_tls1_0_client_hello() {
    let hello = client_hello("openssl-client-hello-tls1_0.bin");
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_0);
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_0);
    assert_eq!(hello.supported_versions(), None);
    assert_eq!(hello.server_name(), Some("example.com"));
    assert_eq!(hello.alpn_protocols(), Some(alpn_h2_http11()));
    assert_eq!(hello.compression_methods, [0]);
    // TLS 1.0 has no signature_algorithms; renegotiation is signalled by SCSV.
    assert_eq!(hello.signature_algorithms(), None);
    assert!(hello.offers(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV));
    assert!(hello.offers_secure_renegotiation());
    assert_eq!(
        hello.supported_groups().and_then(|g| g.first().copied()),
        Some(NamedGroup::X25519)
    );
}

#[test]
fn openssl_tls1_1_client_hello() {
    let hello = client_hello("openssl-client-hello-tls1_1.bin");
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_1);
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_1);
    assert_eq!(hello.server_name(), Some("example.com"));
    assert!(hello.extension(ExtensionType::RENEGOTIATION_INFO).is_some());
}

#[test]
fn openssl_tls1_2_client_hello() {
    let hello = client_hello("openssl-client-hello-tls1_2.bin");
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_2);
    assert_eq!(hello.alpn_protocols(), Some(alpn_h2_http11()));
    assert!(hello.signature_algorithms().is_some_and(|s| !s.is_empty()));
    assert!(!hello.offers_fallback_scsv());
    assert!(
        hello
            .extension(ExtensionType::EXTENDED_MASTER_SECRET)
            .is_some()
    );
}

#[test]
fn openssl_tls1_3_client_hello() {
    let hello = client_hello("openssl-client-hello-tls1_3.bin");
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_3);
    assert_eq!(
        hello.supported_versions(),
        Some(vec![ProtocolVersion::TLS_1_3, ProtocolVersion::TLS_1_2])
    );
    assert_eq!(hello.session_id.len(), 32, "middlebox compatibility mode");
    let groups: Vec<_> = hello
        .key_shares()
        .unwrap()
        .iter()
        .map(|k| k.group)
        .collect();
    assert_eq!(groups, [NamedGroup::X25519_MLKEM768, NamedGroup::X25519]);
    assert!(hello.offers(CipherSuite::TLS_AES_256_GCM_SHA384));
    assert_eq!(hello.server_name(), Some("example.com"));
}

#[test]
fn gnutls_tls1_3_client_hello() {
    let hello = client_hello("gnutls-client-hello-tls1_3.bin");
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_3);
    assert_eq!(hello.server_name(), Some("localhost"));
    assert_eq!(hello.alpn_protocols(), None);
    assert!(hello.extension(ExtensionType::PADDING).is_some());
    let groups: Vec<_> = hello
        .key_shares()
        .unwrap()
        .iter()
        .map(|k| k.group)
        .collect();
    assert_eq!(groups, [NamedGroup::SECP256R1, NamedGroup::X25519]);
}

#[test]
fn openssl_fallback_scsv_client_hello() {
    let hello = client_hello("openssl-client-hello-fallback-scsv.bin");
    assert!(hello.offers_fallback_scsv());
    assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_2);
}

#[test]
fn openssl_legacy_server_flights() {
    for (name, version) in [
        ("openssl-server-flight-tls1_0.bin", ProtocolVersion::TLS_1_0),
        ("openssl-server-flight-tls1_1.bin", ProtocolVersion::TLS_1_1),
    ] {
        let (hello, rest) = server_flight(name);
        assert_eq!(hello.selected_version(), version, "{name}");
        assert_eq!(hello.legacy_version, version, "{name}");
        // ECDHE-ECDSA-AES256-SHA
        assert_eq!(hello.cipher_suite, CipherSuite(0xc00a), "{name}");
        assert_eq!(hello.compression_method, 0);
        assert!(hello.secure_renegotiation());
        assert_eq!(
            hello.downgrade_sentinel(),
            None,
            "server capped at {version}"
        );
        assert_eq!(
            rest,
            ["certificate", "server_key_exchange", "server_hello_done"],
            "{name}"
        );
    }
}

#[test]
fn openssl_tls1_2_server_flight() {
    let (hello, rest) = server_flight("openssl-server-flight-tls1_2.bin");
    assert_eq!(hello.selected_version(), ProtocolVersion::TLS_1_2);
    // ECDHE-ECDSA-AES256-GCM-SHA384
    assert_eq!(hello.cipher_suite, CipherSuite(0xc02c));
    assert_eq!(hello.alpn_protocol(), Some(b"h2".to_vec()));
    assert_eq!(hello.downgrade_sentinel(), None, "server capped at TLS 1.2");
    assert_eq!(
        rest,
        ["certificate", "server_key_exchange", "server_hello_done"]
    );
}

#[test]
fn openssl_tls1_3_server_flight() {
    let (hello, rest) = server_flight("openssl-server-flight-tls1_3.bin");
    assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(hello.selected_version(), ProtocolVersion::TLS_1_3);
    assert!(!hello.is_hello_retry_request());
    assert_eq!(hello.cipher_suite, CipherSuite::TLS_AES_256_GCM_SHA384);
    assert_eq!(hello.key_share_group(), Some(NamedGroup::X25519_MLKEM768));
    // Everything after the ServerHello is encrypted.
    assert_eq!(rest.first().map(String::as_str), Some("change_cipher_spec"));
    assert!(rest.iter().skip(1).all(|kind| kind == "application_data"));
}

#[test]
fn openssl_hello_retry_request() {
    let (hello, rest) = server_flight("openssl-server-hrr-tls1_3.bin");
    assert!(hello.is_hello_retry_request());
    assert_eq!(hello.selected_version(), ProtocolVersion::TLS_1_3);
    assert_eq!(hello.key_share_group(), Some(NamedGroup::SECP384R1));
    assert_eq!(rest, ["change_cipher_spec"]);
}

#[test]
fn openssl_downgrade_sentinel() {
    // A TLS 1.3 server answering a TLS 1.2-only client marks its random.
    let (hello, _) = server_flight("openssl-server-downgrade-tls1_2.bin");
    assert_eq!(hello.selected_version(), ProtocolVersion::TLS_1_2);
    assert_eq!(hello.downgrade_sentinel(), Some(DowngradeSentinel::Tls12));
}

#[test]
fn openssl_alerts() {
    for (name, description) in [
        (
            "openssl-server-alert-protocol_version.bin",
            AlertDescription::PROTOCOL_VERSION,
        ),
        (
            "openssl-server-alert-inappropriate_fallback.bin",
            AlertDescription::INAPPROPRIATE_FALLBACK,
        ),
    ] {
        let bytes = fixture(name);
        let mut reader = MessageReader::new();
        reader.feed(&bytes);
        let Ok(Some(Message::Alert(alert))) = reader.next_message() else {
            panic!("{name}: an alert");
        };
        assert!(alert.is_fatal());
        assert_eq!(alert.description, description, "{name}");
        assert!(matches!(
            ServerHello::parse_records(&bytes),
            Err(Error::UnexpectedContentType { .. })
        ));
    }
}

#[test]
fn client_hello_is_not_a_server_hello() {
    let bytes = fixture("openssl-client-hello-tls1_3.bin");
    assert_eq!(
        ServerHello::parse_records(&bytes),
        Err(Error::UnexpectedHandshakeType {
            expected: HandshakeType::SERVER_HELLO,
            found: HandshakeType::CLIENT_HELLO,
        })
    );
}

#[test]
fn every_prefix_of_a_capture_is_incomplete() {
    let bytes = fixture("openssl-client-hello-tls1_3.bin");
    for len in 0..bytes.len() {
        assert!(
            ClientHello::parse_records(&bytes[..len]).is_err_and(|e| e.is_incomplete()),
            "prefix {len}"
        );
    }
}

#[test]
fn refragmented_capture_still_parses() {
    let hello = client_hello("openssl-client-hello-tls1_3.bin");
    for size in [1, 7, 100, 1000] {
        let records = hello.to_records(ProtocolVersion::TLS_1_0, size).unwrap();
        assert_eq!(
            ClientHello::parse_records(&records).unwrap(),
            hello,
            "{size}"
        );
    }
}

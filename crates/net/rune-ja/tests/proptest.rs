//! Property tests: the parsers never panic, and the fingerprints have the
//! invariances their specifications promise.

#![allow(clippy::unwrap_used, reason = "proptest bodies")]

use proptest::prelude::*;
use rune_ja::{
    Database, HttpRequest, HttpVersion, TcpSyn, ja3, ja4, ja4h, ja4h_original, ja4s, ja4t,
};
use rune_tls_hello::{
    CipherSuite, ClientHello, Extension, ExtensionType, NamedGroup, ProtocolVersion, ServerHello,
    SignatureScheme, is_grease,
};

fn non_grease() -> impl Strategy<Value = u16> {
    any::<u16>().prop_filter("not GREASE", |v| !is_grease(*v))
}

fn grease() -> impl Strategy<Value = u16> {
    (0u16..16).prop_map(|i| 0x0a0a + 0x1010 * i)
}

/// A hello with distinct non-GREASE ciphers and plain extension types,
/// plus SNI, ALPN and signature algorithms.
fn hello() -> impl Strategy<Value = ClientHello> {
    (
        prop::collection::btree_set(non_grease(), 0..40),
        prop::collection::btree_set(
            non_grease().prop_filter("plain", |&e| ![0, 10, 13, 16, 43].contains(&e)),
            0..20,
        ),
        prop::collection::vec(non_grease(), 1..10),
        prop::collection::vec(non_grease(), 1..6),
        "[a-z0-9]{1,8}",
    )
        .prop_map(|(ciphers, extensions, sigs, groups, alpn)| {
            let mut hello = ClientHello::new()
                .with_cipher_suites(ciphers.into_iter().map(CipherSuite))
                .with_extension(Extension::server_name("example.com").unwrap())
                .with_extension(Extension::alpn([alpn]).unwrap())
                .with_extension(
                    Extension::signature_algorithms(
                        &sigs.into_iter().map(SignatureScheme).collect::<Vec<_>>(),
                    )
                    .unwrap(),
                )
                .with_extension(
                    Extension::supported_groups(
                        &groups.into_iter().map(NamedGroup).collect::<Vec<_>>(),
                    )
                    .unwrap(),
                )
                .with_extension(
                    Extension::supported_versions(&[ProtocolVersion::TLS_1_3]).unwrap(),
                );
            for e in extensions {
                hello = hello.with_extension(Extension::empty(ExtensionType(e)));
            }
            hello
        })
}

proptest! {
    #[test]
    fn http1_parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(request) = HttpRequest::parse_http1(&bytes) {
            let _ = ja4h(&request);
            let _ = ja4h_original(&request);
        }
    }

    #[test]
    fn http1_request_lines_parse(text in "[A-Za-z]{1,6} [!-~]{1,20} HTTP/1\\.[01](\r?\n[ -~\t]{0,40}){0,8}") {
        let request = HttpRequest::parse_http1(text.as_bytes()).unwrap();
        let fp = ja4h(&request);
        prop_assert_eq!(fp.hash.split('_').count(), 4);
    }

    #[test]
    fn tcp_options_parser_never_panics(window in any::<u16>(), bytes in prop::collection::vec(any::<u8>(), 0..60)) {
        if let Ok(syn) = TcpSyn::parse_options(window, &bytes) {
            let fp = ja4t(&syn);
            let window_part = window.to_string();
            prop_assert!(fp.starts_with(&window_part));
            prop_assert_eq!(fp.split('_').count(), 4);
        }
    }

    #[test]
    fn database_parser_never_panics(text in "\\PC{0,200}") {
        let _ = Database::parse(&text);
    }

    #[test]
    fn hello_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(hello) = ClientHello::parse(&bytes) {
            let _ = ja3(&hello);
            let fp = ja4(&hello);
            prop_assert_eq!(fp.hash.len(), 10 + 1 + 12 + 1 + 12);
        }
        if let Ok(hello) = ServerHello::parse(&bytes) {
            let _ = ja4s(&hello);
            let _ = rune_ja::ja3s(&hello);
        }
    }

    /// GREASE values anywhere change neither JA3 nor JA4.
    #[test]
    fn grease_is_invisible(hello in hello(), g1 in grease(), g2 in grease(), at in 0usize..8) {
        let mut greased = hello.clone();
        let at_c = at.min(greased.cipher_suites.len());
        greased.cipher_suites.insert(at_c, CipherSuite(g1));
        let extensions = greased.extensions.as_mut().unwrap();
        let at_e = at.min(extensions.len());
        extensions.insert(at_e, Extension::empty(ExtensionType(g2)));
        prop_assert_eq!(ja3(&hello), ja3(&greased));
        prop_assert_eq!(ja4(&hello), ja4(&greased));
    }

    /// Sorted JA4 does not depend on cipher or extension order, while JA3
    /// keeps wire order.
    #[test]
    fn sorted_ja4_ignores_order(hello in hello(), seed in any::<u64>()) {
        let mut shuffled = hello.clone();
        shuffled.cipher_suites.reverse();
        let extensions = shuffled.extensions.as_mut().unwrap();
        let n = extensions.len();
        extensions.rotate_left(usize::try_from(seed % n as u64).unwrap());
        prop_assert_eq!(ja4(&hello), ja4(&shuffled));
    }

    /// Each hashed section is the truncated SHA-256 of the raw section.
    #[test]
    fn hash_is_derived_from_raw(hello in hello()) {
        let fp = ja4(&hello);
        let (a, rest) = fp.raw.split_once('_').unwrap();
        let (b, c) = rest.split_once('_').unwrap();
        let h = |s: &str| {
            if s.is_empty() {
                "000000000000".to_owned()
            } else {
                rune_sha256::hash_bytes(s.as_bytes())[..12].to_owned()
            }
        };
        prop_assert_eq!(fp.hash, format!("{a}_{}_{}", h(b), h(c)));
        prop_assert_eq!(ja3(&hello).hash, rune_md5::hash_bytes(ja3(&hello).raw.as_bytes()));
    }

    /// Sorted JA4H does not depend on cookie order.
    #[test]
    fn sorted_ja4h_ignores_cookie_order(cookies in prop::collection::vec("[a-z]{1,5}=[a-z0-9]{0,5}", 1..8)) {
        let forward = HttpRequest::new("GET", HttpVersion::Http11)
            .with_header("Cookie", cookies.join("; "));
        let mut reversed = cookies;
        reversed.reverse();
        let backward = HttpRequest::new("GET", HttpVersion::Http11)
            .with_header("Cookie", reversed.join("; "));
        prop_assert_eq!(ja4h(&forward), ja4h(&backward));
    }
}

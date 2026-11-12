//! Fingerprints of captured hellos, requests and SYNs.
//!
//! `foxio-*` fixtures were extracted from the test captures of the `FoxIO`
//! JA4+ repository (<https://github.com/FoxIO-LLC/ja4/tree/main/pcap>): the
//! TLS records holding the first `ClientHello` or `ServerHello` of a stream, or
//! the head of the first HTTP request. Their expected JA4, JA4S, JA4H and
//! JA4T values are the ones the `FoxIO` reference implementation publishes
//! for those captures (`rust/ja4/src/snapshots`). The TCP option bytes are
//! copied from the same captures' SYNs.
//!
//! `openssl-*` and `gnutls-*` fixtures are loopback captures shared with
//! `rune-tls-hello` (see its `tests/fixtures/capture.py`).
//!
//! JA3 and JA3S values for every fixture were cross-checked with an
//! independent implementation of the JA3 README algorithm.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail loudly by design"
)]

use rune_ja::{Database, HttpRequest, Kind, TcpSyn, ja3, ja3s, ja4, ja4h, ja4s, ja4t};
use rune_tls_hello::{ClientHello, ServerHello};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn client(name: &str) -> ClientHello {
    ClientHello::parse_records(&fixture(name)).unwrap()
}

fn server(name: &str) -> ServerHello {
    ServerHello::parse_records(&fixture(name)).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `(capture, JA4, JA4S)`, the JA4S empty when the capture has no
/// `ServerHello`.
const FOXIO_TLS: [(&str, &str, &str); 7] = [
    ("tls12", "t13d1715h2_5b57614c22b0_3d5424432f57", ""),
    (
        "tls-alpn-h2",
        "t12d4605h2_85626a9a5f7f_aaf95bb78ec9",
        "t1204h2_cca9_1428ce7b4018",
    ),
    (
        "sigalg-grease",
        "t13d1517h2_8daaf6152771_cb7bf5808d99",
        "t130200_1302_234ea6891581",
    ),
    (
        "macos-tcp-flags",
        "t13d2613h2_2802a3db6c62_845d286b0d67",
        "t130200_1301_234ea6891581",
    ),
    (
        "latest-52936",
        "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "t1206h2_c02f_3603f09c43ba",
    ),
    (
        "latest-52937",
        "t12d190800_d83cc789557e_7af1ed941c26",
        "t120600_c02f_51ad275821ba",
    ),
    (
        "latest-52938",
        "t13d1516h2_8daaf6152771_9b887d9acb53",
        "t130300_1301_6bbbaf601ed8",
    ),
];

#[test]
fn foxio_ja4_and_ja4s() {
    for (capture, want_ja4, want_ja4s) in FOXIO_TLS {
        let hello = client(&format!("foxio-{capture}-client.bin"));
        assert_eq!(ja4(&hello).hash, want_ja4, "{capture}");
        if !want_ja4s.is_empty() {
            let hello = server(&format!("foxio-{capture}-server.bin"));
            assert_eq!(ja4s(&hello).hash, want_ja4s, "{capture}");
        }
    }
}

#[test]
fn grease_alpn_follows_the_spec() {
    // The client's first ALPN value is the GREASE-style 0xba 0xad, which is
    // not alphanumeric. The JA4 specification prints the first and last hex
    // characters ("bd"); the FoxIO Rust tool's snapshot shows "99" because it
    // replaces non-ASCII characters with '9'. We follow the specification.
    let hello = client("foxio-tls-non-ascii-alpn-client.bin");
    assert_eq!(
        hello.alpn_protocols().unwrap().first().map(Vec::as_slice),
        Some(&[0xba, 0xad][..])
    );
    assert_eq!(ja4(&hello).hash, "t13d1516bd_8daaf6152771_e5627efa2ab1");
    let hello = server("foxio-tls-non-ascii-alpn-server.bin");
    assert_eq!(ja4s(&hello).hash, "t130200_1301_234ea6891581");
}

#[test]
fn foxio_ja4t() {
    for (capture, options, want) in [
        (
            "tls-alpn-h2",
            "02040542010303060101080a6e69087c0000000004020000",
            "65535_2-1-3-1-1-8-4-0-0_1346_6",
        ),
        (
            "sigalg-grease",
            "020405b4010303060101080a90f1df200000000004020000",
            "65535_2-1-3-1-1-8-4-0-0_1460_6",
        ),
        (
            "macos_tcp_flags",
            "020405b4010303060101080a780321b50000000004020000",
            "65535_2-1-3-1-1-8-4-0-0_1460_6",
        ),
        (
            "http1-with-cookies",
            "02043fd8010303060101080a7fefde580000000004020000",
            "65535_2-1-3-1-1-8-4-0-0_16344_6",
        ),
        (
            "http-empty-useragent",
            "02043fc4010303050101080a42f903ad0000000004020000",
            "65535_2-1-3-1-1-8-4-0-0_16324_5",
        ),
        (
            "latest",
            "020405b40103030801010402",
            "64240_2-1-3-1-1-4_1460_8",
        ),
    ] {
        let window = want.split('_').next().unwrap().parse().unwrap();
        let syn = TcpSyn::parse_options(window, &hex(options)).unwrap();
        assert_eq!(ja4t(&syn), want, "{capture}");
    }
}

#[test]
fn foxio_ja4h() {
    for (capture, want) in [
        (
            "http1-with-cookies",
            "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442",
        ),
        (
            "http-empty-useragent",
            "ge10nn010000_b8bcd45ac095_000000000000_000000000000",
        ),
        (
            "single-packets-49677",
            "ge11cr06enus_8c2f9ef95269_2a79f5d9f8b3_7b4d78c057bc",
        ),
        (
            "single-packets-49654",
            "ge11cr07enus_45c71a3fb6ea_a25bf252eb59_43a9e3e95c85",
        ),
        (
            "single-packets-49683",
            "ge11nr06enus_8c2f9ef95269_000000000000_000000000000",
        ),
        (
            "single-packets-49708",
            "po11cr09enus_130d8cd1913c_f81c0e5c6793_90689f748de6",
        ),
        (
            "single-packets-49735",
            "ge11cr07enus_45c71a3fb6ea_9ee64e91aa30_109254663367",
        ),
        (
            "single-packets-49733",
            "ge11nr06enus_8c2f9ef95269_000000000000_000000000000",
        ),
        (
            "single-packets-49743",
            "ge11nr06enus_8c2f9ef95269_000000000000_000000000000",
        ),
        (
            "single-packets-49738",
            "ge11cr06enus_8c2f9ef95269_d23bf79698dc_69e42fa741fe",
        ),
    ] {
        let request = HttpRequest::parse_http1(&fixture(&format!("foxio-{capture}.http"))).unwrap();
        assert_eq!(ja4h(&request).hash, want, "{capture}");
    }
}

#[test]
fn ja3_of_every_fixture() {
    for (name, want) in [
        ("foxio-tls12-client.bin", "579ccef312d18482fc42e2b822ca2430"),
        (
            "foxio-tls-alpn-h2-client.bin",
            "3faa4ad39f690c4ef1c3160caa375465",
        ),
        (
            "foxio-sigalg-grease-client.bin",
            "2cd149ce869b7ee2a404f6149b4b41b7",
        ),
        (
            "foxio-macos-tcp-flags-client.bin",
            "6fa3244afc6bb6f9fad207b6b52af26b",
        ),
        (
            "foxio-tls-non-ascii-alpn-client.bin",
            "1c258ebef8eee2dfa3df6d8d07285af9",
        ),
        (
            "foxio-latest-52936-client.bin",
            "8883b2acda8ceb1a4f416c16d9b6c42f",
        ),
        (
            "foxio-latest-52937-client.bin",
            "a0e9f5d64349fb13191bc781f81f42e1",
        ),
        (
            "foxio-latest-52938-client.bin",
            "d81fcba3f82df97ae9971d938da5caa6",
        ),
        (
            "openssl-client-hello-tls1_2.bin",
            "e1934f32e97b0bd52227953ca7d30118",
        ),
        (
            "openssl-client-hello-tls1_3.bin",
            "8ecf4858a704c8936042f20a8bedee04",
        ),
        (
            "gnutls-client-hello-tls1_3.bin",
            "1c9727ec8a970ac69653c4bf38ec83ac",
        ),
    ] {
        assert_eq!(ja3(&client(name)).hash, want, "{name}");
    }
    // Spot-check one raw string: GREASE (0x0a0a…) is gone from every field.
    assert_eq!(
        ja3(&client("foxio-sigalg-grease-client.bin")).raw,
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         65037-16-23-51-17613-65281-10-13-35-43-11-51764-45-0-5-27-18,4588-29-23-24,0"
    );
}

#[test]
fn ja3s_of_every_fixture() {
    for (name, want) in [
        (
            "foxio-tls-alpn-h2-server.bin",
            "7f76f3e952a1bc7d407366fafe1db7ed",
        ),
        (
            "foxio-sigalg-grease-server.bin",
            "907bf3ecef1c987c889946b737b43de8",
        ),
        (
            "foxio-macos-tcp-flags-server.bin",
            "eb1d94daa7e0344597e756a1fb6e7054",
        ),
        (
            "foxio-tls-non-ascii-alpn-server.bin",
            "eb1d94daa7e0344597e756a1fb6e7054",
        ),
        (
            "foxio-latest-52936-server.bin",
            "bfc90d56141386ee83b56cda231cccfc",
        ),
        (
            "foxio-latest-52937-server.bin",
            "7da0ae90f9693272ed42e89898421495",
        ),
        (
            "foxio-latest-52938-server.bin",
            "2b0648ab686ee45e0e7c35fcfb0eea7e",
        ),
        (
            "openssl-server-flight-tls1_2.bin",
            "e195432758194ce2d482396b82e0d48e",
        ),
        (
            "openssl-server-flight-tls1_3.bin",
            "15af977ce25de452b96affa2addb1036",
        ),
    ] {
        assert_eq!(ja3s(&server(name)).hash, want, "{name}");
    }
    assert_eq!(
        ja3s(&server("foxio-latest-52936-server.bin")).raw,
        "771,49199,0-11-65281-16-35-23"
    );
}

#[test]
fn builtin_database_recognises_chrome_capture() {
    let db = Database::builtin();
    let fp = ja4(&client("foxio-latest-52936-client.bin"));
    assert_eq!(db.lookup(Kind::Ja4, &fp.hash), ["Chromium-based browser"]);
}

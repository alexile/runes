//! Known-answer vectors for the built-in transforms.

use std::fmt::Write as _;

use rune_transform::{Direction, TransformRegistry};

/// Encode with a built-in; an error comes back as text, so the assertion
/// that follows fails and shows it.
fn enc(id: &str, input: &[u8]) -> Vec<u8> {
    TransformRegistry::builtin()
        .encode(id, input)
        .unwrap_or_else(|error| format!("ERROR {id} encode: {error}").into_bytes())
}

/// Decode with a built-in; errors as for [`enc`].
fn dec(id: &str, input: &[u8]) -> Vec<u8> {
    TransformRegistry::builtin()
        .decode(id, input)
        .unwrap_or_else(|error| format!("ERROR {id} decode: {error}").into_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn codec_round_trips() {
    let data = b"Hello, <World> & \"friends\" 'too'!";
    for id in [
        "base64",
        "base64url",
        "base64url_nopad",
        "base32",
        "url",
        "html",
        "hex",
        "gzip",
        "rot13",
    ] {
        assert_eq!(dec(id, &enc(id, data)), data, "{id}");
    }
}

#[test]
fn encodings() {
    assert_eq!(enc("base64", b"foobar"), b"Zm9vYmFy");
    assert_eq!(enc("base64", b"fo"), b"Zm8=");
    assert_eq!(enc("base64url", b"\xfb\xff"), b"-_8=");
    assert_eq!(enc("base64url_nopad", b"\xfb\xff"), b"-_8");
    assert_eq!(dec("base64", b"Zm9v\nYmFy"), b"foobar");
    assert_eq!(dec("base64url", b"-_8"), b"\xfb\xff");
    assert_eq!(enc("base32", b"foobar"), b"MZXW6YTBOI======");
    assert_eq!(enc("hex", b"\x01\xab"), b"01ab");
    assert_eq!(enc("hex_upper", b"\x01\xab"), b"01AB");
    assert_eq!(enc("hex_space", b"\x01\xab"), b"01 ab");
    assert_eq!(enc("hex_0x", b"\x01\xab"), b"0x01ab");
    assert_eq!(dec("hex", b"0X01 AB\n"), b"\x01\xab");
    assert_eq!(enc("url", b"a b/c"), b"a%20b%2Fc");
    assert_eq!(enc("url_encode_all", b"ab"), b"%61%62");
    assert_eq!(enc("double_url", b" "), b"%2520");
    assert_eq!(dec("double_url", b"%2520"), b" ");
    assert_eq!(dec("url", b"%ff%00"), b"\xff\x00");
}

#[test]
fn html_entities_and_numeric_refs() {
    // rune-html-encode writes `'` as `&#x27;`, not `&apos;`.
    assert_eq!(
        enc("html", b"<a href=\"x\">&'"),
        b"&lt;a href=&quot;x&quot;&gt;&amp;&#x27;"
    );
    assert_eq!(dec("html", b"&#65;&#x42;&lt;&apos;"), b"AB<'");
    assert_eq!(
        enc("html_entity_decimal", "A\u{e9}".as_bytes()),
        b"&#65;&#233;"
    );
    assert_eq!(enc("html_entity_hex", b"A<"), b"&#x41;&#x3c;");
}

#[test]
fn escapes() {
    assert_eq!(enc("js_hex_escape", b"A\n"), b"\\x41\\x0a");
    assert_eq!(dec("js_hex_escape", b"\\x41\\x0A"), b"A\n");
    assert_eq!(
        enc("js_unicode_escape", "a\u{1F600}".as_bytes()),
        b"\\u0061\\ud83d\\ude00"
    );
    assert_eq!(
        dec("js_unicode_escape", b"\\ud83d\\ude00"),
        "\u{1F600}".as_bytes()
    );
    assert_eq!(enc("percent_u_escape", b"<"), b"%u003c");
    assert_eq!(enc("octal_escape", b"A\xff"), b"\\101\\377");
    assert_eq!(enc("decimal_escape", b"A\xff"), b"\\065\\255");
    let registry = TransformRegistry::builtin();
    for (id, bad) in [
        ("js_hex_escape", &b"\\x4"[..]),
        ("js_hex_escape", b"A"),
        ("js_hex_escape", b"\\x+1"),
        ("octal_escape", b"\\400"),
        ("decimal_escape", b"\\256"),
        ("js_unicode_escape", b"\\ud83d"),
    ] {
        assert!(registry.decode(id, bad).is_err(), "{id} {bad:?}");
    }
}

#[test]
fn numeric() {
    assert_eq!(enc("binary", b"AB"), b"0100000101000010");
    assert_eq!(enc("binary_spaced", b"AB"), b"01000001 01000010");
    assert_eq!(dec("binary_spaced", b"01000001\t01000010\n"), b"AB");
    assert_eq!(enc("ascii_decimal", b"AB\x00"), b"65 66 0");
    assert_eq!(dec("ascii_decimal", b" 65  66 "), b"AB");
    assert!(
        TransformRegistry::builtin()
            .decode("ascii_decimal", b"+65")
            .is_err()
    );
    assert!(
        TransformRegistry::builtin()
            .decode("binary", b"0101")
            .is_err()
    );
}

#[test]
fn ciphers() {
    assert_eq!(enc("rot13", b"Hello"), b"Uryyb");
    assert_eq!(enc("rot5", b"a0189"), b"a5634");
    assert_eq!(enc("rot47", b"Hello"), b"w6==@");
    assert_eq!(enc("atbash", b"abcXYZ"), b"zyxCBA");
    assert_eq!(enc("reverse", b"abc"), b"cba");
    assert_eq!(enc("nibble_swap", b"\x12\xab"), b"\x21\xba");
    assert_eq!(enc("bitwise_not", b"\x00\xf0"), b"\xff\x0f");
    assert_eq!(enc("swap_case", b"aB1"), b"Ab1");
}

#[test]
fn digests() {
    let cases = [
        ("md5", "900150983cd24fb0d6963f7d28e17f72"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "sha224",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            "sha256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha384",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ];
    for (id, expected) in cases {
        assert_eq!(hex(&enc(id, b"abc")), expected, "{id}");
    }
    assert_eq!(
        hex(&enc("sha256", b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(TransformRegistry::builtin().decode("md5", b"x").is_err());
}

#[test]
fn text() {
    assert_eq!(
        enc("upper_case", "ab\u{e9}".as_bytes()),
        "AB\u{e9}".as_bytes()
    );
    assert_eq!(enc("lower_case", b"AbC"), b"abc");
    assert_eq!(enc("leetspeak", b"Elite Hacker"), b"31173 H4ck3r");
}

#[test]
fn jwt_decode_known_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                 dummysig";
    for input in [token.to_owned(), format!("  {token}\n")] {
        let out = enc("jwt_decode", input.as_bytes());
        let value: serde_json::Value = match serde_json::from_slice(&out) {
            Ok(value) => value,
            Err(error) => panic!("json: {error}"),
        };
        assert_eq!(value["header"]["alg"], "HS256");
        assert_eq!(value["header"]["typ"], "JWT");
        assert_eq!(value["payload"]["sub"], "1234567890");
        assert_eq!(value["payload"]["name"], "John Doe");
    }
    // An unsigned `header.payload` is accepted too.
    let unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0";
    let out = String::from_utf8(enc("jwt_decode", unsigned.as_bytes())).unwrap_or_default();
    assert!(out.contains("\"alg\": \"none\""), "{out}");
    let registry = TransformRegistry::builtin();
    assert_eq!(
        registry
            .encode("jwt_decode", b"nope")
            .err()
            .map(|e| e.code()),
        Some("transform.malformed")
    );
}

#[test]
fn chain_applies_in_order() {
    let registry = TransformRegistry::builtin();
    let out = registry
        .chain(&["hex", "base64"])
        .and_then(|c| c.encode(b"hi"));
    assert_eq!(out.ok(), Some(b"Njg2OQ==".to_vec()));
    let chain = registry.parse_chain("hex base64").ok();
    assert_eq!(
        chain.and_then(|c| c.decode(b"Njg2OQ==").ok()),
        Some(b"hi".to_vec())
    );
    assert_eq!(
        registry
            .apply("base64", Direction::Decode, b"Njg2OQ==")
            .ok(),
        Some(b"6869".to_vec())
    );
}

#[test]
fn text_transforms_reject_non_utf8() {
    let registry = TransformRegistry::builtin();
    for id in ["html", "html_entity_hex", "js_unicode_escape", "jwt_decode"] {
        assert_eq!(
            registry.encode(id, b"\xff").err().map(|e| e.code()),
            Some("transform.utf8"),
            "{id}"
        );
    }
}

//! Known-answer tests from the JOSE / JWT specifications.
//!
//! Signatures are not verified by this crate; the vectors check that every
//! section decodes to exactly the octets the RFCs list.

use rune_jwt::{JwtError, Section, algorithm, claims, decode, decode_raw, expiry, header, subject};
use serde_json::json;

/// RFC 7519 §3.1 / RFC 7515 §A.1: HS256-signed JWT whose header and claims
/// contain CRLF line breaks.
const RFC7519_3_1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// RFC 7519 §6.1 / RFC 7515 §A.5: unsecured JWT (`alg: none`, empty
/// signature).
const RFC7519_6_1: &str = "eyJhbGciOiJub25lIn0.\
     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

/// RFC 8037 §A.4: Ed25519 JWS over the plain-text payload
/// "Example of Ed25519 signing".
const RFC8037_A_4: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
     hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// The claims set shared by RFC 7519 §3.1 and §6.1.
const JOE_CLAIMS: &[u8] =
    b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

#[test]
fn rfc7519_3_1_hs256() {
    let decoded = decode(RFC7519_3_1).unwrap();
    assert_eq!(decoded.header, json!({"typ": "JWT", "alg": "HS256"}));
    assert_eq!(
        decoded.payload,
        json!({"iss": "joe", "exp": 1_300_819_380, "http://example.com/is_root": true})
    );
    assert_eq!(
        decoded.signature,
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );

    assert_eq!(algorithm(RFC7519_3_1).unwrap(), "HS256");
    assert_eq!(expiry(RFC7519_3_1).unwrap(), Some(1_300_819_380));
    assert_eq!(subject(RFC7519_3_1).unwrap(), None);
    assert_eq!(header(RFC7519_3_1).unwrap(), decoded.header);
    assert_eq!(claims(RFC7519_3_1).unwrap(), decoded.payload);
}

#[test]
fn rfc7515_a_1_octets() {
    let raw = decode_raw(RFC7519_3_1).unwrap();
    // RFC 7515 §A.1.1: the JWS Protected Header octets.
    assert_eq!(
        raw.header,
        [
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103,
            34, 58, 34, 72, 83, 50, 53, 54, 34, 125
        ]
    );
    assert_eq!(raw.payload, JOE_CLAIMS);
    // RFC 7515 §A.1.1: the HMAC SHA-256 output.
    assert_eq!(
        raw.signature,
        [
            116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212,
            37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
        ]
    );
}

#[test]
fn rfc7519_6_1_unsecured() {
    let decoded = decode(RFC7519_6_1).unwrap();
    assert_eq!(decoded.header, json!({"alg": "none"}));
    assert_eq!(decoded.payload["iss"], "joe");
    assert_eq!(decoded.signature, "");
    assert_eq!(algorithm(RFC7519_6_1).unwrap(), "none");

    let raw = decode_raw(RFC7519_6_1).unwrap();
    assert_eq!(raw.header, br#"{"alg":"none"}"#);
    assert_eq!(raw.payload, JOE_CLAIMS);
    assert_eq!(raw.signature, b"");
}

#[test]
fn rfc8037_a_4_ed25519() {
    let raw = decode_raw(RFC8037_A_4).unwrap();
    assert_eq!(raw.header, br#"{"alg":"EdDSA"}"#);
    assert_eq!(raw.payload, b"Example of Ed25519 signing");
    let hex = raw.signature.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
        hex
    });
    assert_eq!(
        hex,
        "860c98d2297f3060a33f42739672d61b53cf3adefed3d3c672f320dc021b411e\
         9d59b8628dc351e248b88b29468e0e41855b0fb7d83bb15be902bfccb8cd0a02"
    );

    // The header decodes, but the payload is not a JWT claims set.
    assert_eq!(algorithm(RFC8037_A_4).unwrap(), "EdDSA");
    assert!(matches!(
        decode(RFC8037_A_4).unwrap_err(),
        JwtError::Json {
            section: Section::Payload,
            ..
        }
    ));
}

#[test]
fn rfc7515_a_4_es512_plain_payload() {
    // RFC 7515 §A.4.1: header {"alg":"ES512"}, payload "Payload".
    let raw = decode_raw("eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.").unwrap();
    assert_eq!(raw.header, br#"{"alg":"ES512"}"#);
    assert_eq!(raw.payload, b"Payload");
}

#[test]
fn rfc4648_base64url_vectors() {
    // RFC 4648 §10 test vectors, in base64url without padding, as the
    // signature section of an otherwise empty token.
    for (encoded, expected) in [
        ("", &b""[..]),
        ("Zg", b"f"),
        ("Zm8", b"fo"),
        ("Zm9v", b"foo"),
        ("Zm9vYg", b"foob"),
        ("Zm9vYmE", b"fooba"),
        ("Zm9vYmFy", b"foobar"),
    ] {
        let raw = decode_raw(&format!("..{encoded}")).unwrap();
        assert_eq!(raw.signature, expected, "{encoded}");
    }
}

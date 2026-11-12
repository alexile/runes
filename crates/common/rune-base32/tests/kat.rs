//! RFC 4648 §10 known-answer vectors.
//!
//! <https://www.rfc-editor.org/rfc/rfc4648#section-10>

use rune_base32::{decode, decode_hex, encode, encode_hex, encode_no_pad};

const BASE32: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "MY======"),
    (b"fo", "MZXQ===="),
    (b"foo", "MZXW6==="),
    (b"foob", "MZXW6YQ="),
    (b"fooba", "MZXW6YTB"),
    (b"foobar", "MZXW6YTBOI======"),
];

const BASE32_HEX: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "CO======"),
    (b"fo", "CPNG===="),
    (b"foo", "CPNMU==="),
    (b"foob", "CPNMUOG="),
    (b"fooba", "CPNMUOJ1"),
    (b"foobar", "CPNMUOJ1E8======"),
];

#[test]
fn rfc4648_base32() {
    for (data, text) in BASE32 {
        assert_eq!(encode(data), text, "encode {data:?}");
        assert_eq!(decode(text).unwrap(), data, "decode {text:?}");
        assert_eq!(encode_no_pad(data), text.trim_end_matches('='));
    }
}

#[test]
fn rfc4648_base32_hex() {
    for (data, text) in BASE32_HEX {
        assert_eq!(encode_hex(data), text, "encode {data:?}");
        assert_eq!(decode_hex(text).unwrap(), data, "decode {text:?}");
    }
}

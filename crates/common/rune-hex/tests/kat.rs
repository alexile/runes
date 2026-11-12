//! RFC 4648 §10 Base16 known-answer vectors.
//!
//! <https://www.rfc-editor.org/rfc/rfc4648#section-10>

use rune_hex::{decode, encode, encode_upper};

const BASE16: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "66"),
    (b"fo", "666F"),
    (b"foo", "666F6F"),
    (b"foob", "666F6F62"),
    (b"fooba", "666F6F6261"),
    (b"foobar", "666F6F626172"),
];

#[test]
fn rfc4648_base16() {
    for (data, text) in BASE16 {
        assert_eq!(encode_upper(data), text, "encode {data:?}");
        assert_eq!(encode(data), text.to_lowercase());
        assert_eq!(decode(text).unwrap(), data, "decode {text:?}");
        assert_eq!(decode(&text.to_lowercase()).unwrap(), data);
    }
}

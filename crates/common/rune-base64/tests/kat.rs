//! RFC 4648 §10 known-answer vectors.
//!
//! <https://www.rfc-editor.org/rfc/rfc4648#section-10>

use rune_base64::{decode, encode, encode_no_pad, encode_url, encode_url_no_pad};

const BASE64: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "Zg=="),
    (b"fo", "Zm8="),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy"),
];

#[test]
fn rfc4648_base64() {
    for (data, text) in BASE64 {
        assert_eq!(encode(data), text, "encode {data:?}");
        assert_eq!(decode(text).unwrap(), data, "decode {text:?}");
        let unpadded = text.trim_end_matches('=');
        assert_eq!(encode_no_pad(data), unpadded);
        assert_eq!(decode(unpadded).unwrap(), data, "decode {unpadded:?}");
        // The vectors use no `+` or `/`, so the URL-safe forms agree.
        assert_eq!(encode_url(data), text);
        assert_eq!(encode_url_no_pad(data), unpadded);
    }
}

/// RFC 4648 §9 example bytes `14 fb 9c 03 d9 7e`, and their §5 URL-safe form.
#[test]
fn rfc4648_alphabet_differences() {
    let data = [0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e];
    assert_eq!(encode(&data), "FPucA9l+");
    assert_eq!(encode_url(&data), "FPucA9l-");
    assert_eq!(decode("FPucA9l+").unwrap(), data);
    let data = [0x14, 0xfb, 0x9c, 0x03, 0xd9];
    assert_eq!(encode(&data), "FPucA9k=");
    let data = [0x14, 0xfb, 0x9c, 0x03];
    assert_eq!(encode(&data), "FPucAw==");
    assert_eq!(encode(&[0xfb, 0xff]), "+/8=");
    assert_eq!(encode_url(&[0xfb, 0xff]), "-_8=");
}

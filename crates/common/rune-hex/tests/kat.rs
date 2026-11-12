//! Known-answer vectors.

use rune_hex::{DecodeOptions, HexError, ct, decode, decode_array, encode, encode_upper};

/// RFC 4648 section 10, Base16.
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
        assert_eq!(decode(text).as_deref(), Ok(data), "decode {text:?}");
        assert_eq!(decode(text.to_lowercase()).as_deref(), Ok(data));
        assert_eq!(ct::decode(text).as_deref(), Ok(data));
    }
}

#[test]
fn every_byte_value() {
    let all: Vec<u8> = (0..=255).collect();
    let lower = encode(&all);
    assert!(lower.starts_with("000102030405060708090a0b0c0d0e0f10"));
    assert!(lower.ends_with("f9fafbfcfdfeff"));
    assert_eq!(encode_upper(&all), lower.to_uppercase());
    assert_eq!(decode(&lower), Ok(all));
}

#[test]
fn sha256_of_empty_input() {
    let text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let digest: [u8; 32] = decode_array(text).unwrap_or_default();
    assert_eq!(digest[..4], [0xe3, 0xb0, 0xc4, 0x42]);
    assert_eq!(encode(digest), text);
    assert_eq!(ct::decode_array::<32>(text), Ok(digest));
}

#[test]
fn fingerprint_and_mac_formats() {
    let opts = DecodeOptions::lenient();
    assert_eq!(
        opts.decode_array("01:23:45:67:89:AB"),
        Ok([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])
    );
    assert_eq!(
        opts.decode_array("01-23-45-67-89-ab"),
        Ok([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])
    );
    assert_eq!(
        opts.decode("0x 0011\r\n2233\n"),
        Ok(vec![0x00, 0x11, 0x22, 0x33])
    );
}

#[test]
fn error_offsets_count_the_prefix() {
    assert_eq!(
        decode("0x00fg"),
        Err(HexError::InvalidByte {
            byte: b'g',
            offset: 5
        })
    );
    assert_eq!(
        decode("00 111"),
        Err(HexError::InvalidByte {
            byte: b' ',
            offset: 2
        })
    );
    assert_eq!(
        decode("é00"),
        Err(HexError::InvalidByte {
            byte: 0xc3,
            offset: 0
        })
    );
    assert_eq!(decode("0x0"), Err(HexError::OddLength));
}

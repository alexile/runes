//! CRC-32 (ISO-HDLC, as used by zlib, gzip, PNG and Ethernet) known-answer
//! vectors.
//!
//! The check value comes from the CRC catalogue
//! (<https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32-iso-hdlc>);
//! the rest are the outputs of zlib's reference `crc32`.

use rune_crc32::{checksum, checksum_hex};

/// The repeating byte sequence `0, 1, …, 250`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

#[test]
fn catalogue_check_value() {
    assert_eq!(checksum(b"123456789"), 0xcbf4_3926);
    assert_eq!(checksum_hex(b"123456789"), "cbf43926");
}

#[test]
fn zlib_reference_values() {
    let cases: [(&[u8], u32); 5] = [
        (b"", 0),
        (b"a", 0xe8b7_be43),
        (b"abc", 0x3524_41c2),
        (b"The quick brown fox jumps over the lazy dog", 0x414f_a339),
        (b"123456789", 0xcbf4_3926),
    ];
    for (data, crc) in cases {
        assert_eq!(checksum(data), crc, "{data:?}");
    }
    for (len, crc) in [
        (5551, 0xae20_01f4),
        (5552, 0x0b7a_9550),
        (5553, 0x436d_f98f),
        (65536, 0x7faa_50d3),
        (1_000_000, 0x27c4_42b8),
    ] {
        assert_eq!(checksum(&pattern(len)), crc, "pattern of {len} bytes");
    }
}

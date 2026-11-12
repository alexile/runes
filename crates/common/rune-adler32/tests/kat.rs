//! Adler-32 (RFC 1950 §8.2) known-answer vectors.
//!
//! RFC 1950 publishes no vectors, so these are the outputs of zlib's
//! reference `adler32` (by RFC 1950's authors). Lengths around 5552 (zlib's
//! `NMAX`) and long runs of `0xff` stress the modular reduction.
//! <https://www.rfc-editor.org/rfc/rfc1950#section-8.2>

use rune_adler32::{checksum, checksum_hex};

/// The repeating byte sequence `0, 1, …, 250`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

#[test]
fn short_inputs() {
    let cases: [(&[u8], u32); 6] = [
        (b"", 0x0000_0001),
        (b"a", 0x0062_0062),
        (b"abc", 0x024d_0127),
        (b"123456789", 0x091e_01de),
        (b"Wikipedia", 0x11e6_0398),
        (b"The quick brown fox jumps over the lazy dog", 0x5bdc_0fda),
    ];
    for (data, sum) in cases {
        assert_eq!(checksum(data), sum, "{data:?}");
    }
    assert_eq!(checksum_hex(b"123456789"), "091e01de");
}

#[test]
fn long_inputs() {
    for (len, sum, sum_ff) in [
        (5551, 0x049d_8a77, 0x5603_9a8d),
        (5552, 0x8f31_8a94, 0xf18f_9b8c),
        (5553, 0x19f2_8ab2, 0x8e29_9c8b),
        (65536, 0x7332_fc3c, 0x7797_0ef2),
        (1_000_000, 0x4fd0_c1a6, 0x3843_e1be),
    ] {
        assert_eq!(checksum(&pattern(len)), sum, "pattern of {len} bytes");
        assert_eq!(checksum(&vec![0xff; len]), sum_ff, "{len} bytes of 0xff");
    }
}

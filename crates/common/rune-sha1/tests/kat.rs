//! SHA-1 known-answer vectors: FIPS 180 examples, RFC 3174 §7.3 and NIST CAVP.
//!
//! <https://www.rfc-editor.org/rfc/rfc3174#section-7.3>, <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing>

use std::fmt::Write as _;

use rune_sha1::{hash_bytes, hash_raw};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn check(message: &[u8], expected: &str) {
    assert_eq!(
        hash_bytes(message),
        expected,
        "message of {} bytes",
        message.len()
    );
    assert_eq!(hex(&hash_raw(message)), expected);
}

const M448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/// RFC 3174 §7.3 TEST1–TEST4 (TEST1/TEST2 are the FIPS 180 examples).
#[test]
fn rfc3174_tests() {
    check(b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    check(M448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    check(
        &b"a".repeat(1_000_000),
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
    );
    check(
        &b"01234567".repeat(80),
        "dea356a2cddd90c7a7ecedc5ebb563934f460452",
    );
}

/// NIST CAVP `SHA1ShortMsg.rsp`, `Len = 0` and `Len = 8`.
#[test]
fn cavp_short_msg() {
    check(b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    check(&[0x36], "c1dfd96eea8cc2b62785275bca38ac261256e278");
}

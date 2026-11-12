//! SHA-512 known-answer vectors: FIPS 180 examples and NIST CAVP.
//!
//! <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>, <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing>

use std::fmt::Write as _;

use rune_sha512::{hash_bytes, hash_raw};

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
const M896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/// NIST example values: one block, two blocks, and one million `a`.
#[test]
fn fips180_examples() {
    check(
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    check(
        M448,
        "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
    );
    check(
        M896,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    );
    check(
        &b"a".repeat(1_000_000),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    );
}

/// NIST CAVP `SHA512ShortMsg.rsp`, `Len` 0 and 8.
#[test]
fn cavp_short_msg() {
    check(
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );
    check(
        &[0x21],
        "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a",
    );
}

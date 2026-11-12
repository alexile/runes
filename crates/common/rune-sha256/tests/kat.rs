//! SHA-256 known-answer vectors: FIPS 180 examples and NIST CAVP.
//!
//! <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>, <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing>

use std::fmt::Write as _;

use rune_sha256::{hash_bytes, hash_raw};

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
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    check(
        M448,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    check(
        M896,
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    );
    check(
        &b"a".repeat(1_000_000),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
}

/// NIST CAVP `SHA256ShortMsg.rsp`, `Len` 0, 8 and 16.
#[test]
fn cavp_short_msg() {
    check(
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    check(
        &[0xd3],
        "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
    );
    check(
        &[0x11, 0xaf],
        "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98",
    );
}

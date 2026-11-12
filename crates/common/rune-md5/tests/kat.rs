//! RFC 1321 Appendix A.5 test suite.
//!
//! <https://www.rfc-editor.org/rfc/rfc1321#appendix-A.5>

use std::fmt::Write as _;

use rune_md5::{hash_bytes, hash_raw};

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

#[test]
fn rfc1321_test_suite() {
    let suite: [(&[u8], &str); 7] = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (message, digest) in suite {
        check(message, digest);
    }
}

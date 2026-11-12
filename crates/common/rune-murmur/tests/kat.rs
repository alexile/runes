//! `SMHasher` verification values for `MurmurHash3`.
//!
//! `VerificationTest` in Austin Appleby's reference `SMHasher`
//! (<https://github.com/aappleby/smhasher/blob/master/src/KeysetTest.cpp>)
//! hashes the keys `[]`, `[0]`, `[0, 1]`, … `[0, …, 254]` with seed
//! `256 - len`, concatenates the digests, hashes that with seed 0, and reads
//! the first four bytes little-endian. `src/main.cpp` lists the expected
//! values: `0xB0F57EE3` for `MurmurHash3_x86_32`, `0x6384BA69` for
//! `MurmurHash3_x64_128`.

use rune_murmur::{murmurhash3_x64_128, murmurhash3_x86_32};

fn verification(hash: impl Fn(&[u8], u32) -> Vec<u8>) -> u32 {
    let key: Vec<u8> = (0..=255).collect();
    let mut digests = Vec::new();
    for len in 0..256 {
        let seed = 256 - u32::try_from(len).unwrap_or(0);
        digests.extend(hash(&key[..len], seed));
    }
    let last = hash(&digests, 0);
    u32::from_le_bytes([last[0], last[1], last[2], last[3]])
}

#[test]
fn smhasher_x86_32() {
    let value = verification(|data, seed| murmurhash3_x86_32(data, seed).to_le_bytes().to_vec());
    assert_eq!(value, 0xB0F5_7EE3);
}

/// The reference writes `h1` then `h2`, each little-endian; the `u128` holds
/// `h1` in the low half, so its little-endian bytes are the same.
#[test]
fn smhasher_x64_128() {
    let value = verification(|data, seed| murmurhash3_x64_128(data, seed).to_le_bytes().to_vec());
    assert_eq!(value, 0x6384_BA69);
}

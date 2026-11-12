//! Official FNV test vectors.
//!
//! The 203 inputs and expected values of Landon Curt Noll's reference
//! `test_fnv.c` (<https://github.com/lcn2/fnv>), the test suite the FNV
//! authors publish alongside draft-eastlake-fnv. Inputs include the empty
//! string, short ASCII strings, strings with embedded NUL bytes, and 500-fold
//! repetitions.

use rune_fnv::{fnv1_32, fnv1_64, fnv1a_32, fnv1a_64};

const VECTORS: &str = include_str!("fnv_test_vectors.txt");

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text == "-" {
        return Some(Vec::new());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[test]
fn reference_test_vectors() {
    let mut count = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [input, plain_32, alternate_32, plain_64, alternate_64] = fields[..] else {
            panic!("malformed vector line: {line:?}");
        };
        let data = unhex(input).unwrap();
        assert_eq!(
            fnv1_32(&data),
            u32::from_str_radix(plain_32, 16).unwrap(),
            "FNV-1/32 {input}"
        );
        assert_eq!(
            fnv1a_32(&data),
            u32::from_str_radix(alternate_32, 16).unwrap(),
            "FNV-1a/32 {input}"
        );
        assert_eq!(
            fnv1_64(&data),
            u64::from_str_radix(plain_64, 16).unwrap(),
            "FNV-1/64 {input}"
        );
        assert_eq!(
            fnv1a_64(&data),
            u64::from_str_radix(alternate_64, 16).unwrap(),
            "FNV-1a/64 {input}"
        );
        count += 1;
    }
    assert_eq!(count, 203);
}

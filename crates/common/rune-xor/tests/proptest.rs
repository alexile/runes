//! Known-answer vectors (Cryptopals set 1) and properties: XOR is an
//! involution, Hamming distance is a metric, brute-force candidates are
//! consistent and sorted, and the analysis helpers never panic.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_xor::{
    break_repeating_key_xor, brute_force, brute_force_with, english_score, guess_key_sizes,
    hamming_distance, xor, xor_single,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const GETTYSBURG: &[u8] = b"four score and seven years ago our fathers brought forth on \
this continent a new nation conceived in liberty and dedicated to the proposition \
that all men are created equal now we are engaged in a great civil war testing \
whether that nation or any nation so conceived and so dedicated can long endure";

#[test]
fn cryptopals_1_2_fixed_xor() {
    let a = hex("1c0111001f010100061a024b53535009181c");
    let b = hex("686974207468652062756c6c277320657965");
    assert_eq!(xor(&a, &b), hex("746865206b696420646f6e277420706c6179"));
}

#[test]
fn cryptopals_1_3_single_byte_xor() {
    let ct = hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let best = &brute_force(&ct)[0];
    assert_eq!(best.key, b'X');
    assert_eq!(best.plaintext, b"Cooking MC's like a pound of bacon");
}

#[test]
fn cryptopals_1_5_repeating_key_xor() {
    let pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let expected = hex(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20\
430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    );
    assert_eq!(xor(pt, b"ICE"), expected);
    assert_eq!(xor(&expected, b"ICE"), pt);
}

#[test]
fn cryptopals_1_6_hamming() {
    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
}

#[test]
fn brute_force_recovers_every_single_byte_key() {
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    for key in 0..=u8::MAX {
        let best = &brute_force(&xor_single(plaintext, key))[0];
        assert_eq!(best.key, key, "key {key:#04x}");
        assert_eq!(best.plaintext, plaintext);
    }
}

#[test]
fn break_repeating_key_recovers_fixed_keys() {
    for key in [&b"KEY"[..], b"ICE", b"Go", b"rune", b"\x01\xfe\x7f"] {
        let candidates = break_repeating_key_xor(&xor(GETTYSBURG, key));
        assert!(
            candidates.iter().any(|c| c.plaintext == GETTYSBURG),
            "key {key:?} not recovered"
        );
    }
}

#[test]
fn guess_key_sizes_accepts_zero_min_size() {
    // Regression: `min_size == 0` used to divide by zero.
    let ct = xor(GETTYSBURG, b"KEY");
    let guesses = guess_key_sizes(&ct, 0, 6, 4);
    assert!(guesses.iter().all(|g| (1..=6).contains(&g.size)));
    assert_eq!(guesses.len(), 6);
    assert!(guess_key_sizes(&ct, 0, 0, 4).is_empty());
    assert!(guess_key_sizes(b"", 0, 10, 4).is_empty());
}

proptest! {
    #[test]
    fn xor_is_involution(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        key in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let ct = xor(&data, &key);
        prop_assert_eq!(ct.len(), data.len());
        prop_assert_eq!(xor(&ct, &key), data);
    }

    #[test]
    fn xor_matches_reference(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        key in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let expected: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        prop_assert_eq!(xor(&data, &key), expected);
    }

    #[test]
    fn xor_single_matches_one_byte_key(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        key in any::<u8>(),
    ) {
        prop_assert_eq!(xor_single(&data, key), xor(&data, &[key]));
        prop_assert_eq!(xor_single(&xor_single(&data, key), key), data);
    }

    #[test]
    fn hamming_is_a_metric(
        triple in (0usize..64).prop_flat_map(|n| (
            proptest::collection::vec(any::<u8>(), n),
            proptest::collection::vec(any::<u8>(), n),
            proptest::collection::vec(any::<u8>(), n),
        ))
    ) {
        let (a, b, c) = triple;
        prop_assert_eq!(hamming_distance(&a, &a), 0);
        prop_assert_eq!(hamming_distance(&a, &b), hamming_distance(&b, &a));
        prop_assert!(
            hamming_distance(&a, &c) <= hamming_distance(&a, &b) + hamming_distance(&b, &c)
        );
        let popcount: usize = xor_or_empty(&a, &b).iter().map(|x| x.count_ones() as usize).sum();
        prop_assert_eq!(hamming_distance(&a, &b), popcount);
        prop_assert!(hamming_distance(&a, &b) <= 8 * a.len());
    }

    #[test]
    fn english_score_is_finite(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let score = english_score(&bytes);
        prop_assert!(score.is_finite());
        prop_assert!((-200.0..=12.7).contains(&score));
    }

    #[test]
    fn brute_force_candidates_are_consistent(ct in proptest::collection::vec(any::<u8>(), 0..64)) {
        let candidates = brute_force(&ct);
        prop_assert_eq!(candidates.len(), 256);
        let mut keys: Vec<u8> = candidates.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        prop_assert_eq!(keys, (0..=u8::MAX).collect::<Vec<_>>());
        for c in &candidates {
            prop_assert_eq!(&c.plaintext, &xor_single(&ct, c.key));
            prop_assert_eq!(c.score.to_bits(), english_score(&c.plaintext).to_bits());
        }
        for pair in candidates.windows(2) {
            prop_assert!(pair[0].score >= pair[1].score);
        }
    }

    #[test]
    fn brute_force_with_custom_scorer_picks_its_maximum(
        ct in proptest::collection::vec(any::<u8>(), 1..32),
        target in any::<u8>(),
    ) {
        // A scorer that rewards plaintexts starting with `target` must rank the
        // key `ct[0] ^ target` first.
        let best = &brute_force_with(&ct, |pt| f64::from(u8::from(pt[0] == target)))[0];
        prop_assert_eq!(best.key, ct[0] ^ target);
    }

    #[test]
    fn guess_key_sizes_never_panics(
        ct in proptest::collection::vec(any::<u8>(), 0..128),
        min in 0usize..20,
        max in 0usize..80,
        blocks in 0usize..8,
    ) {
        let guesses = guess_key_sizes(&ct, min, max, blocks);
        for g in &guesses {
            prop_assert!(g.size >= min.max(1) && g.size <= max);
            prop_assert!(2 * g.size <= ct.len());
            prop_assert!(g.normalized_distance.is_finite());
            prop_assert!((0.0..=8.0).contains(&g.normalized_distance));
        }
        for pair in guesses.windows(2) {
            prop_assert!(pair[0].normalized_distance <= pair[1].normalized_distance);
        }
    }

}

proptest! {
    // The cracker brute-forces every column of up to ten key sizes, so keep
    // the case count low for debug-mode test runs.
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn break_repeating_key_is_self_consistent(ct in proptest::collection::vec(any::<u8>(), 0..256)) {
        let candidates = break_repeating_key_xor(&ct);
        prop_assert!(candidates.len() <= 10);
        for c in &candidates {
            prop_assert!(!c.key.is_empty());
            prop_assert_eq!(&c.plaintext, &xor(&ct, &c.key));
        }
        for pair in candidates.windows(2) {
            prop_assert!(pair[0].score >= pair[1].score);
        }
    }
}

fn xor_or_empty(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

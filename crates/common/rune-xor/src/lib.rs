//! XOR cipher for byte streams and files.
//!
//! Applies XOR with a repeating key of any length, plus English-frequency
//! scoring for brute-forcing unknown keys — a staple of CTF crypto challenges.
//! Includes a full repeating-key XOR cracker using Hamming distance key-size
//! detection (Matasano/Cryptopals challenge 6 technique).
//!
//! The library has zero dependencies.
//!
//! # Features
//!
//! - [`xor`] — repeating-key XOR over any byte slice.
//! - [`xor_single`] — convenience wrapper for single-byte keys.
//! - [`english_score`] — letter-frequency score; higher means more English-like.
//! - [`brute_force`] — tries all 256 single-byte keys, returns [`Candidate`]s sorted best-first.
//! - [`brute_force_with`] — same, but with a caller-supplied scoring function.
//! - [`hamming_distance`] — count differing bits between two equal-length byte slices.
//! - [`guess_key_sizes`] — rank likely repeating-key lengths by normalised Hamming distance.
//! - [`break_repeating_key_xor`] — full repeating-key cracker; returns [`MultiKeyCandidate`]s sorted best-first.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_xor::{xor, brute_force};
//!
//! let ciphertext = xor(b"Hello, world!", b"\x42");
//! let candidates = brute_force(&ciphertext);
//! assert_eq!(candidates[0].plaintext, b"Hello, world!");
//! ```
//!
//! # Repeating-Key Cracking
//!
//! ```rust
//! use rune_xor::{xor, break_repeating_key_xor};
//!
//! # let plaintext = b"four score and seven years ago our fathers brought forth on \
//! # this continent a new nation conceived in liberty and dedicated to the proposition \
//! # that all men are created equal now we are engaged in a great civil war testing \
//! # whether that nation or any nation so conceived and so dedicated can long endure";
//! # let ciphertext = xor(plaintext, b"KEY");
//! let candidates = break_repeating_key_xor(&ciphertext);
//! assert!(candidates.iter().any(|c| c.plaintext == plaintext.as_ref()));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-xor --key "SECRET" message.bin   # encrypt / decrypt
//! rune-xor --brute cipher.bin           # brute-force single-byte key
//! rune-xor --break cipher.bin           # crack repeating-key XOR
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// XOR `data` with a repeating `key`, cycling it as needed.
///
/// Encryption and decryption are the same operation.
///
/// # Panics
///
/// Panics if `key` is empty.
///
/// # Examples
///
/// ```rust
/// use rune_xor::xor;
///
/// let ct = xor(b"Attack at dawn", b"KEY");
/// let pt = xor(&ct, b"KEY");
/// assert_eq!(pt, b"Attack at dawn");
/// ```
#[must_use]
pub fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty(), "XOR key must not be empty");
    data.iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// XOR every byte of `data` with a single-byte `key`.
///
/// # Examples
///
/// ```rust
/// use rune_xor::xor_single;
///
/// let ct = xor_single(b"secret", 0x42);
/// let pt = xor_single(&ct, 0x42);
/// assert_eq!(pt, b"secret");
/// ```
#[must_use]
pub fn xor_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

/// Relative frequency (%) of each letter `a..=z` in English text.
const LETTER_FREQUENCY: [f64; 26] = [
    8.20, 1.50, 2.80, 4.30, 12.70, 2.20, 2.00, 6.10, 7.00, 0.15, 0.77, 4.00, 2.40, //
    6.70, 7.50, 1.90, 0.10, 6.00, 6.30, 9.10, 2.80, 0.98, 2.40, 0.15, 2.00, 0.07,
];

const fn letter_frequency(byte: u8) -> f64 {
    let lower = byte.to_ascii_lowercase();
    if lower.is_ascii_lowercase() {
        LETTER_FREQUENCY[(lower - b'a') as usize]
    } else {
        0.0
    }
}

/// Score bytes as English plaintext using letter frequency analysis.
///
/// Returns a score where higher values indicate more English-like content.
/// Letters score their English frequency, spaces score highest, other
/// printable ASCII and common whitespace score a little, and non-printable
/// bytes apply a heavy penalty. Useful for ranking
/// [`brute_force`] and [`break_repeating_key_xor`] candidates.
///
/// # Examples
///
/// ```rust
/// use rune_xor::english_score;
///
/// assert!(english_score(b"the quick brown fox") > english_score(b"\x00\x01\xff\xfe"));
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn english_score(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut score = 0.0_f64;
    let mut non_printable: usize = 0;

    for &byte in bytes {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => score += letter_frequency(byte),
            // Only the space earns the word-separator bonus. Rewarding tabs and
            // newlines as much let a key that turns every space into `\n` beat
            // the real plaintext (Cryptopals set 1, challenge 3).
            b' ' => score += 12.0,
            b'\t' | b'\n' | b'\r' | 33..=126 => score += 2.0,
            _ => non_printable += 1,
        }
    }

    // `f64::mul_add` needs `std`; the unfused form keeps the crate `no_std`.
    #[allow(clippy::suboptimal_flops, reason = "f64::mul_add is not in core")]
    {
        score -= non_printable as f64 * 200.0;
    }
    score / bytes.len() as f64
}

/// A single-byte XOR brute-force candidate.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The key byte that produced this decryption.
    pub key: u8,
    /// English-text likelihood score — higher is better.
    pub score: f64,
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Try all 256 single-byte keys and return [`Candidate`]s sorted best-first.
///
/// The first element is the most likely plaintext. Equivalent to
/// `brute_force_with(ciphertext, english_score)`.
///
/// # Examples
///
/// ```rust
/// use rune_xor::{xor_single, brute_force};
///
/// let ciphertext = xor_single(b"the quick brown fox jumps over the lazy dog", 0x42);
/// let best = &brute_force(&ciphertext)[0];
/// assert_eq!(best.key, 0x42);
/// ```
pub fn brute_force(ciphertext: &[u8]) -> Vec<Candidate> {
    brute_force_with(ciphertext, english_score)
}

/// Try all 256 single-byte keys with a caller-supplied scoring function.
///
/// Returns [`Candidate`]s sorted best-first by the scorer's return value.
/// Higher scores win. Use this when the target plaintext is not English —
/// pass a custom frequency table, entropy function, or pattern matcher.
///
/// # Examples
///
/// ```rust
/// use rune_xor::{xor_single, brute_force_with, english_score};
///
/// let ciphertext = xor_single(b"the quick brown fox jumps over the lazy dog", 0x42);
/// let best = &brute_force_with(&ciphertext, english_score)[0];
/// assert_eq!(best.key, 0x42);
/// ```
pub fn brute_force_with<F>(ciphertext: &[u8], mut scorer: F) -> Vec<Candidate>
where
    F: FnMut(&[u8]) -> f64,
{
    let mut candidates: Vec<Candidate> = (0u8..=255)
        .map(|key| {
            let plaintext = xor_single(ciphertext, key);
            let score = scorer(&plaintext);
            Candidate {
                key,
                score,
                plaintext,
            }
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    candidates
}

/// Count differing bits between two equal-length byte slices.
///
/// This is the population count of `a XOR b`, also known as the Hamming distance.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths.
///
/// # Examples
///
/// ```rust
/// use rune_xor::hamming_distance;
///
/// // canonical Cryptopals test vector
/// assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
#[must_use]
pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "slices must have equal length");
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| usize::from((x ^ y).count_ones() as u8))
        .sum()
}

/// A key-size guess produced by [`guess_key_sizes`].
#[derive(Debug, Clone)]
pub struct KeySizeGuess {
    /// Candidate key length in bytes.
    pub size: usize,
    /// Normalised Hamming distance — lower means more likely correct.
    pub normalized_distance: f64,
}

/// Rank repeating-key XOR key lengths by normalised Hamming distance.
///
/// For each candidate size in `min_size..=max_size`, computes the average
/// Hamming distance between adjacent `size`-byte blocks (up to `n_blocks`
/// pairs), normalised by `size`. The correct key length produces a low
/// normalised distance because adjacent blocks share the same key byte per
/// column, so their XOR reflects English-text similarity rather than noise.
/// Multiples of the correct key size score equally well (they also cancel the
/// key), so the top results typically contain the true key size and its multiples.
///
/// Results are sorted ascending by `normalized_distance`. Key sizes for which
/// fewer than two full blocks fit in the ciphertext are omitted, and a
/// `min_size` of zero is treated as one.
///
/// > [!NOTE]
/// > Use [`break_repeating_key_xor`] to automatically try the top candidates
/// > and select the one that produces the most English-like plaintext.
///
/// # Examples
///
/// ```rust
/// use rune_xor::{xor, guess_key_sizes};
///
/// # let plaintext = b"four score and seven years ago our fathers brought forth on \
/// # this continent a new nation conceived in liberty and dedicated to the proposition \
/// # that all men are created equal now we are engaged in a great civil war testing \
/// # whether that nation or any nation so conceived and so dedicated can long endure";
/// # let ciphertext = xor(plaintext, b"KEY");
/// let guesses = guess_key_sizes(&ciphertext, 2, 15, usize::MAX);
/// assert!(guesses.iter().take(3).any(|g| g.size % 3 == 0));
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn guess_key_sizes(
    ciphertext: &[u8],
    min_size: usize,
    max_size: usize,
    n_blocks: usize,
) -> Vec<KeySizeGuess> {
    let n_blocks = n_blocks.max(1);
    // A zero-length key is meaningless (and would divide by zero below).
    let min_size = min_size.max(1);
    let max_size = max_size.min(ciphertext.len() / 2);

    let mut guesses: Vec<KeySizeGuess> = (min_size..=max_size)
        .filter_map(|size| {
            let available_pairs = (ciphertext.len() / size).saturating_sub(1);
            if available_pairs == 0 {
                return None;
            }
            let pairs = available_pairs.min(n_blocks);
            let total_distance: f64 = (0..pairs)
                .map(|i| {
                    let a = &ciphertext[i * size..(i + 1) * size];
                    let b = &ciphertext[(i + 1) * size..(i + 2) * size];
                    hamming_distance(a, b) as f64
                })
                .sum();
            let normalized_distance = total_distance / (pairs as f64 * size as f64);
            Some(KeySizeGuess {
                size,
                normalized_distance,
            })
        })
        .collect();

    guesses.sort_by(|a, b| {
        a.normalized_distance
            .partial_cmp(&b.normalized_distance)
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    guesses
}

/// A repeating-key XOR cracking candidate produced by [`break_repeating_key_xor`].
#[derive(Debug, Clone)]
pub struct MultiKeyCandidate {
    /// Recovered key bytes.
    pub key: Vec<u8>,
    /// English-text likelihood score for the decrypted plaintext — higher is better.
    pub score: f64,
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Crack a repeating-key XOR cipher using Hamming distance key-size detection.
///
/// This implements the Matasano/Cryptopals challenge 6 technique:
///
/// 1. Rank candidate key sizes by normalised Hamming distance (see [`guess_key_sizes`]).
/// 2. For each top candidate size, transpose the ciphertext into `size` independent
///    single-byte-XOR streams and solve each with [`brute_force`].
/// 3. Score the reconstructed plaintext with [`english_score`] and sort best-first.
///
/// Returns up to ten candidates sorted by English score — check with `.iter().any()`
/// rather than trusting only `[0]`, as frequency scoring is heuristic. Returns an
/// empty `Vec` if `ciphertext` is empty.
///
/// > [!NOTE]
/// > Works best when the ciphertext is at least 20× the key length. Very short
/// > inputs may produce unreliable results.
///
/// # Examples
///
/// ```rust
/// use rune_xor::{xor, break_repeating_key_xor};
///
/// # let plaintext = b"four score and seven years ago our fathers brought forth on \
/// # this continent a new nation conceived in liberty and dedicated to the proposition \
/// # that all men are created equal now we are engaged in a great civil war testing \
/// # whether that nation or any nation so conceived and so dedicated can long endure";
/// # let ciphertext = xor(plaintext, b"KEY");
/// let candidates = break_repeating_key_xor(&ciphertext);
/// assert!(candidates.iter().any(|c| c.plaintext == plaintext.as_ref()));
/// ```
#[must_use]
pub fn break_repeating_key_xor(ciphertext: &[u8]) -> Vec<MultiKeyCandidate> {
    if ciphertext.is_empty() {
        return Vec::new();
    }

    let max_key_size = (ciphertext.len() / 8).min(40);
    let size_guesses = guess_key_sizes(ciphertext, 1, max_key_size, usize::MAX);

    let mut candidates: Vec<MultiKeyCandidate> = size_guesses
        .iter()
        .take(10)
        .map(|guess| {
            let key_size = guess.size;
            let key: Vec<u8> = (0..key_size)
                .map(|offset| {
                    let column: Vec<u8> = ciphertext
                        .iter()
                        .skip(offset)
                        .step_by(key_size)
                        .copied()
                        .collect();
                    brute_force(&column)[0].key
                })
                .collect();
            let plaintext = xor(ciphertext, &key);
            let score = english_score(&plaintext);
            MultiKeyCandidate {
                key,
                score,
                plaintext,
            }
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_roundtrip_single_byte_key() {
        let plaintext = b"Hello, world!";
        assert_eq!(xor(&xor(plaintext, b"\x42"), b"\x42"), plaintext);
    }

    #[test]
    fn xor_roundtrip_multi_byte_key() {
        let plaintext = b"Attack at dawn";
        let key = b"ICE";
        assert_eq!(xor(&xor(plaintext, key), key), plaintext);
    }

    #[test]
    fn xor_single_roundtrip() {
        let plaintext = b"secret data";
        assert_eq!(xor_single(&xor_single(plaintext, 0xAB), 0xAB), plaintext);
    }

    #[test]
    fn xor_key_cycles() {
        assert_eq!(xor(b"ABCDE", b"AB"), vec![0, 0, 2, 6, 4]);
    }

    #[test]
    fn english_score_ranks_correctly() {
        let english = b"the quick brown fox jumps over the lazy dog";
        let garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a";
        assert!(english_score(english) > english_score(garbage));
    }

    #[test]
    fn english_score_empty() {
        assert_eq!(english_score(b""), 0.0);
    }

    #[test]
    fn brute_force_finds_correct_key() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext = xor_single(plaintext, 0x42);
        let best = &brute_force(&ciphertext)[0];
        assert_eq!(best.key, 0x42);
        assert_eq!(best.plaintext, plaintext.as_ref());
    }

    #[test]
    fn brute_force_returns_256_candidates() {
        assert_eq!(brute_force(b"test").len(), 256);
    }

    #[test]
    fn brute_force_sorted_descending() {
        let candidates = brute_force(b"Hello World this is plaintext");
        for pair in candidates.windows(2) {
            assert!(pair[0].score >= pair[1].score);
        }
    }

    #[test]
    #[should_panic(expected = "XOR key must not be empty")]
    fn xor_panics_on_empty_key() {
        let _ = xor(b"data", b"");
    }

    #[test]
    fn brute_force_with_custom_scorer() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext = xor_single(plaintext, 0x42);
        let best = &brute_force_with(&ciphertext, english_score)[0];
        assert_eq!(best.key, 0x42);
    }

    #[test]
    fn hamming_distance_known_value() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn hamming_distance_identical() {
        assert_eq!(hamming_distance(b"same", b"same"), 0);
    }

    #[test]
    #[should_panic(expected = "slices must have equal length")]
    fn hamming_distance_panics_on_length_mismatch() {
        let _ = hamming_distance(b"abc", b"ab");
    }

    #[test]
    fn guess_key_sizes_multiples_rank_high() {
        let plaintext = b"four score and seven years ago our fathers brought forth on \
this continent a new nation conceived in liberty and dedicated to the proposition \
that all men are created equal now we are engaged in a great civil war testing \
whether that nation or any nation so conceived and so dedicated can long endure";
        let ciphertext = xor(plaintext, b"KEY");
        let guesses = guess_key_sizes(&ciphertext, 2, 15, usize::MAX);
        assert!(
            guesses.iter().take(3).any(|g| g.size % 3 == 0),
            "no multiple of key period 3 in top 3: {guesses:?}",
        );
    }

    #[test]
    fn guess_key_sizes_sorted_ascending() {
        let ciphertext = xor(
            b"the quick brown fox jumps over the lazy dog the quick brown fox",
            b"HELLO",
        );
        let guesses = guess_key_sizes(&ciphertext, 2, 10, 4);
        for pair in guesses.windows(2) {
            assert!(pair[0].normalized_distance <= pair[1].normalized_distance);
        }
    }

    #[test]
    fn break_repeating_key_xor_recovers_plaintext() {
        let plaintext = b"four score and seven years ago our fathers brought forth on \
this continent a new nation conceived in liberty and dedicated to the proposition \
that all men are created equal now we are engaged in a great civil war testing \
whether that nation or any nation so conceived and so dedicated can long endure";
        let ciphertext = xor(plaintext, b"KEY");
        let candidates = break_repeating_key_xor(&ciphertext);
        assert!(
            candidates.iter().any(|c| c.plaintext == plaintext.as_ref()),
            "correct plaintext not in top candidates",
        );
    }

    #[test]
    fn break_repeating_key_xor_empty_input() {
        assert!(break_repeating_key_xor(b"").is_empty());
    }
}

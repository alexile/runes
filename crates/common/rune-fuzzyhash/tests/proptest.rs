//! Property tests: small edits give small distances, unrelated inputs
//! large ones; digests round-trip; parsers never panic.

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use rune_fuzzyhash::{Ssdeep, Tlsh, TlshBuilder, ssdeep, tlsh};

/// Varied, text-like input: random words from a random alphabet.
fn document(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::collection::vec(b'!'..=b'~', 1..10).prop_map(|mut w| {
            w.push(b' ');
            w
        }),
        len,
    )
    .prop_map(|words| words.concat())
}

proptest! {
    // Similarity is statistical, so the seed is fixed: the suite is
    // reproducible and cannot flake.
    #![proptest_config(ProptestConfig {
        cases: 96,
        rng_seed: RngSeed::Fixed(0x2240),
        ..ProptestConfig::default()
    })]

    #[test]
    fn small_edit_small_distance_unrelated_large(
        base in document(800..1500),
        other in document(800..1500),
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let mut edited = base.clone();
        for (at, byte) in &edits {
            let i = at.index(edited.len());
            edited[i] = *byte;
        }
        let (a, b, c) = (Tlsh::hash(&base).unwrap(), Tlsh::hash(&edited).unwrap(), Tlsh::hash(&other).unwrap());
        prop_assert!(a.distance(&b) <= tlsh::RECOMMENDED_MAX_DISTANCE, "edit distance {}", a.distance(&b));
        prop_assert!(a.distance(&c) > tlsh::RECOMMENDED_MAX_DISTANCE, "unrelated distance {}", a.distance(&c));

        let (a, b, c) = (Ssdeep::hash(&base).unwrap(), Ssdeep::hash(&edited).unwrap(), Ssdeep::hash(&other).unwrap());
        prop_assert!(a.compare(&b) >= ssdeep::RECOMMENDED_MIN_SCORE, "{a} vs {b}: {}", a.compare(&b));
        prop_assert_eq!(a.compare(&c), 0, "{} vs {}", a, c);
    }

    #[test]
    fn identical_inputs_are_identical(data in prop::collection::vec(any::<u8>(), 0..4000)) {
        if let Ok(t) = Tlsh::hash(&data) {
            prop_assert_eq!(t.distance(&t), 0);
        }
        let s = Ssdeep::hash(&data).unwrap();
        prop_assert_eq!(s.compare(&s), 100);
    }

    #[test]
    fn digests_round_trip(data in prop::collection::vec(any::<u8>(), 0..4000)) {
        if let Ok(t) = Tlsh::hash(&data) {
            prop_assert_eq!(t.to_string().parse::<Tlsh>().unwrap(), t);
        }
        let s = Ssdeep::hash(&data).unwrap();
        prop_assert_eq!(s.to_string().parse::<Ssdeep>().unwrap(), s);
    }

    #[test]
    fn tlsh_chunking_does_not_matter(data in prop::collection::vec(any::<u8>(), 50..3000), cut in 1usize..200) {
        let mut b = TlshBuilder::new();
        data.chunks(cut).for_each(|c| b.update(c));
        prop_assert_eq!(b.finish(), Tlsh::hash(&data));
    }

    #[test]
    fn distances_are_symmetric(a in prop::collection::vec(any::<u8>(), 64..2000), b in prop::collection::vec(any::<u8>(), 64..2000)) {
        if let (Ok(x), Ok(y)) = (Tlsh::hash(&a), Tlsh::hash(&b)) {
            prop_assert_eq!(x.distance(&y), y.distance(&x));
            prop_assert!(x.distance_ignoring_len(&y) <= x.distance(&y));
        }
    }

    #[test]
    fn parsers_never_panic(s in "\\PC{0,120}") {
        let _ = s.parse::<Tlsh>();
        if let Ok(d) = s.parse::<Ssdeep>() {
            prop_assert!(d.compare(&d) <= 100);
        }
    }

    #[test]
    fn digest_like_strings_never_panic(
        bs in 0u64..10_000,
        d1 in "[A-Za-z0-9+/]{0,64}",
        d2 in "[A-Za-z0-9+/]{0,64}",
        e1 in "[A-Za-z0-9+/]{0,64}",
        e2 in "[A-Za-z0-9+/]{0,64}",
        hex in "T1[0-9A-Fa-f]{70}",
    ) {
        let a: Ssdeep = format!("{bs}:{d1}:{d2}").parse().unwrap();
        for other_bs in [bs, bs * 2, bs / 2] {
            let b: Ssdeep = format!("{other_bs}:{e1}:{e2}").parse().unwrap();
            prop_assert!(a.compare(&b) <= 100);
        }
        let t: Tlsh = hex.parse().unwrap();
        prop_assert_eq!(t.distance(&t), 0);
    }
}

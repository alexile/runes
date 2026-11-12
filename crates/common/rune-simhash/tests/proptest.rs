//! Property tests: near-duplicates cluster together, unrelated texts do not.

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use rune_simhash::{
    ClusterOptions, Clusterer, MinHasher, ShingleOptions, SimHash, shingles, strip_html,
};

/// A random document of `len` words drawn from a 2000-word vocabulary.
fn doc(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u16>> {
    prop::collection::vec(0u16..2000, len)
}

fn render(words: &[u16]) -> String {
    words
        .iter()
        .map(|w| format!("w{w}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Applies up to `edits` single-word substitutions.
fn mutate(words: &[u16], edits: &[(usize, u16)]) -> Vec<u16> {
    let mut out = words.to_vec();
    for &(pos, w) in edits {
        let i = pos % out.len();
        out[i] = w;
    }
    out
}

proptest! {
    // SimHash separation is statistical (see the comments below), so the
    // seed is fixed: the suite is reproducible and cannot flake in CI.
    #![proptest_config(ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5eed_2230),
        ..ProptestConfig::default()
    })]

    #[test]
    fn simhash_near_duplicates_cluster_and_unrelated_do_not(
        base in doc(500..900),
        other in doc(500..900),
        edits in prop::collection::vec((any::<usize>(), 0u16..2000), 1..3),
    ) {
        // One or two edited words change at most 6 of 500+ shingles, which
        // flips each bit with probability acos(1 − 6/500)/π ≈ 0.05: about
        // 3 ± 2 bits, and more than 12 with probability ~1e-5. Unrelated
        // texts differ in 32 ± 4 bits; 12 or fewer has probability ~2e-7.
        let o = ShingleOptions::default();
        let a = SimHash::from_text(&render(&base), &o).unwrap();
        let near = SimHash::from_text(&render(&mutate(&base, &edits)), &o).unwrap();
        let far = SimHash::from_text(&render(&other), &o).unwrap();

        let mut c = Clusterer::new(ClusterOptions::default().with_threshold(0.8)).unwrap();
        let ia = c.assign(a).cluster;
        prop_assert_eq!(c.assign(near).cluster, ia, "hamming {}", a.hamming(near));
        prop_assert_ne!(c.assign(far).cluster, ia, "hamming {}", a.hamming(far));
    }

    #[test]
    fn minhash_near_duplicates_cluster_and_unrelated_do_not(
        base in doc(150..300),
        other in doc(150..300),
        edits in prop::collection::vec((any::<usize>(), 0u16..2000), 1..4),
    ) {
        let o = ShingleOptions::default();
        let h = MinHasher::new(128, 7).unwrap();
        let a = h.signature_text(&render(&base), &o).unwrap();
        let near = h.signature_text(&render(&mutate(&base, &edits)), &o).unwrap();
        let far = h.signature_text(&render(&other), &o).unwrap();

        let opts = ClusterOptions::default().with_threshold(0.75).with_bands(Some(32));
        let mut c = Clusterer::new(opts).unwrap();
        let ia = c.assign(a).cluster;
        prop_assert_eq!(c.assign(near).cluster, ia);
        prop_assert_ne!(c.assign(far).cluster, ia);
    }

    #[test]
    fn simhash_is_deterministic_and_symmetric(a in ".{0,200}", b in ".{0,200}") {
        let o = ShingleOptions::default();
        let fa = SimHash::from_text(&a, &o).unwrap();
        let fb = SimHash::from_text(&b, &o).unwrap();
        prop_assert_eq!(fa, SimHash::from_text(&a, &o).unwrap());
        prop_assert_eq!(fa.hamming(fb), fb.hamming(fa));
        prop_assert_eq!(fa.hamming(fa), 0);
    }

    #[test]
    fn tokenizer_and_html_stripper_never_panic(s in "\\PC{0,300}", k in 1usize..6) {
        let _ = strip_html(&s);
        let o = ShingleOptions::default().with_size(k).with_strip_html(true);
        let n = shingles(&s, &o).unwrap().len();
        prop_assert!(n <= s.len());
    }

    #[test]
    fn html_markup_noise_is_ignored(words in doc(20..80), attr in "[a-z]{1,8}") {
        let text = render(&words);
        let html = format!("<div class=\"{attr}\"><p>{text}</p><script>var {attr} = 1;</script></div>");
        let o = ShingleOptions::default().with_strip_html(true);
        prop_assert_eq!(
            SimHash::from_text(&html, &o).unwrap(),
            SimHash::from_text(&text, &ShingleOptions::default()).unwrap()
        );
    }
}

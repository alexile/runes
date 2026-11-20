//! Metric math checked against the Python reference implementations.

#![allow(
    clippy::float_cmp,
    clippy::many_single_char_names,
    reason = "reference values are exact; short names mirror the formulas"
)]

use rune_chain_eval::metrics::{
    Smoothing, corpus_bleu, lcs_len, levenshtein, levenshtein_similarity, normalize_answer,
    rouge_l, sentence_bleu, tokenize,
};
use rune_chain_eval::rag::average_precision;
use rune_chain_eval::stats::{BootstrapConfig, SeededRng, bootstrap_mean_ci, percentile_sorted};

fn words(s: &str) -> Vec<&str> {
    s.split(' ').collect()
}

const HYP1: &str = "It is a guide to action which ensures that the military always obeys the commands of the party";
const REF1A: &str =
    "It is a guide to action that ensures that the military will forever heed Party commands";
const REF1B: &str = "It is the guiding principle which guarantees the military forces always being under the command of the Party";
const REF1C: &str =
    "It is the practical guide for the army always to heed the directions of the party";

#[test]
fn sentence_bleu_matches_nltk_docs() {
    // nltk.translate.bleu_score.sentence_bleu docstring: 0.5045666840058485
    let (h, a, b, c) = (words(HYP1), words(REF1A), words(REF1B), words(REF1C));
    let v = sentence_bleu(&h, &[&a, &b, &c], 4, Smoothing::None);
    assert!((v - 0.504_566_684_005_848_5).abs() < 1e-12, "{v}");
    // No zero counts here, so smoothing must not change it.
    let e = sentence_bleu(&h, &[&a, &b, &c], 4, Smoothing::Epsilon);
    assert!((e - v).abs() < 1e-15);
}

#[test]
fn corpus_bleu_matches_nltk_docs() {
    // nltk corpus_bleu docstring: 0.5920778868801042
    let (h1, a, b, c) = (words(HYP1), words(REF1A), words(REF1B), words(REF1C));
    let h2 = words("he read the book because he was interested in world history");
    let r2 = words("he was interested in world history because he read the book");
    let refs = vec![
        vec![a.as_slice(), b.as_slice(), c.as_slice()],
        vec![r2.as_slice()],
    ];
    let v = corpus_bleu(&[h1.as_slice(), h2.as_slice()], &refs, 4, Smoothing::None);
    assert!((v - 0.592_077_886_880_104_2).abs() < 1e-12, "{v}");
}

#[test]
fn bleu_edge_cases() {
    let the = words("the the the the the the the");
    let cat = words("the cat is on the mat");
    // Unigram precision is clipped to 2/7; no bigram match.
    assert_eq!(sentence_bleu(&the, &[&cat], 4, Smoothing::None), 0.0);
    assert_eq!(sentence_bleu(&the, &[&cat], 1, Smoothing::None), 2.0 / 7.0);
    let smoothed = sentence_bleu(&the, &[&cat], 4, Smoothing::Epsilon);
    assert!(smoothed > 0.0 && smoothed < 2.0 / 7.0);
    let add_one = sentence_bleu(&the, &[&cat], 4, Smoothing::AddOne);
    assert!(add_one > 0.0 && add_one.is_finite());
    let empty: [&str; 0] = [];
    assert_eq!(sentence_bleu(&empty, &[&cat], 4, Smoothing::Epsilon), 0.0);
    assert_eq!(sentence_bleu(&cat, &[&empty], 4, Smoothing::Epsilon), 0.0);
    // Brevity penalty: a correct prefix scores below 1.
    let short = words("the cat is on");
    let v = sentence_bleu(&short, &[&cat], 2, Smoothing::None);
    assert!((v - (1.0f64 - 6.0 / 4.0).exp()).abs() < 1e-12);
}

#[test]
fn rouge_l_matches_rouge_score_readme() {
    // rouge_score README: precision 0.625, recall 0.5555555555555556,
    // fmeasure 0.5882352941176471.
    let s = rouge_l(
        &tokenize("The quick brown dog jumps on the log."),
        &tokenize("The quick brown fox jumps over the lazy dog"),
    );
    assert_eq!(s.precision, 0.625);
    assert!((s.recall - 0.555_555_555_555_555_6).abs() < 1e-15);
    assert!((s.f1 - 0.588_235_294_117_647_1).abs() < 1e-15);
    let none = rouge_l::<String>(&[], &tokenize("x"));
    assert_eq!(none.f1, 0.0);
}

#[test]
fn lcs_and_levenshtein() {
    assert_eq!(lcs_len(&tokenize("a b c d e"), &tokenize("a c e x")), 3);
    assert_eq!(levenshtein("kitten", "sitting"), 3);
    assert_eq!(levenshtein("flaw", "lawn"), 2);
    assert_eq!(levenshtein("", ""), 0);
    assert_eq!(levenshtein("ünï", "uni"), 2);
    assert_eq!(levenshtein_similarity("", ""), 1.0);
    assert!((levenshtein_similarity("kitten", "sitting") - (1.0 - 3.0 / 7.0)).abs() < 1e-12);
}

#[test]
fn normalization_and_tokens() {
    assert_eq!(normalize_answer("The Answer is: A cat!"), "answer is cat");
    assert_eq!(tokenize("Don't stop—now"), ["don", "t", "stop", "now"]);
}

#[test]
fn percentiles_match_numpy() {
    // numpy.percentile([12,7,3,45,9,18,22,5,31,14], [50, 95]) = [13.0, 38.7]
    let mut v = [12.0, 7.0, 3.0, 45.0, 9.0, 18.0, 22.0, 5.0, 31.0, 14.0];
    v.sort_by(f64::total_cmp);
    assert_eq!(percentile_sorted(&v, 0.5), Some(13.0));
    assert!((percentile_sorted(&v, 0.95).unwrap() - 38.7).abs() < 1e-9);
    assert_eq!(percentile_sorted(&[], 0.5), None);
    assert_eq!(percentile_sorted(&v, 1.5), None);
    assert_eq!(percentile_sorted(&[4.0], 0.95), Some(4.0));
}

#[test]
fn bootstrap_is_deterministic_and_sane() {
    let scores: Vec<f64> = (0..50).map(|i| f64::from(i % 3 == 0)).collect();
    let cfg = BootstrapConfig {
        resamples: 500,
        level: 0.9,
        seed: 11,
    };
    let a = bootstrap_mean_ci(&scores, &cfg).unwrap();
    assert_eq!(a, bootstrap_mean_ci(&scores, &cfg).unwrap());
    let mean = scores.iter().sum::<f64>() / 50.0;
    assert!(a.low < mean && mean < a.high && a.level == 0.9);
    let other = bootstrap_mean_ci(&scores, &BootstrapConfig { seed: 12, ..cfg }).unwrap();
    assert_ne!(a, other);
    // Constant data has a zero-width interval.
    let c = bootstrap_mean_ci(&[0.5; 10], &cfg).unwrap();
    assert_eq!((c.low, c.high), (0.5, 0.5));
    assert!(bootstrap_mean_ci(&[], &cfg).is_none());
    assert!(bootstrap_mean_ci(&scores, &BootstrapConfig { level: 1.0, ..cfg }).is_none());
    assert!(
        bootstrap_mean_ci(
            &scores,
            &BootstrapConfig {
                resamples: 0,
                ..cfg
            }
        )
        .is_none()
    );
}

#[test]
fn rng_is_stable_and_unbiased_enough() {
    let mut r = SeededRng::new(42);
    let first: Vec<u64> = (0..3).map(|_| r.next_u64()).collect();
    let mut r2 = SeededRng::new(42);
    assert_eq!(first, (0..3).map(|_| r2.next_u64()).collect::<Vec<_>>());
    let mut counts = [0usize; 3];
    for _ in 0..30_000 {
        counts[r.below(3)] += 1;
    }
    assert!(
        counts.iter().all(|&c| (9_000..11_000).contains(&c)),
        "{counts:?}"
    );
    assert_eq!(r.below(0), 0);
}

#[test]
fn average_precision_matches_ragas_formula() {
    assert_eq!(average_precision(&[true, true, true]), 1.0);
    assert!((average_precision(&[false, true]) - 0.5).abs() < 1e-12);
    assert!((average_precision(&[true, false, true]) - 5.0 / 6.0).abs() < 1e-12);
    assert_eq!(average_precision(&[]), 0.0);
}

//! Pure text metrics: normalization, tokenization, Levenshtein distance,
//! BLEU and ROUGE-L. They match the usual Python references (NLTK's
//! `sentence_bleu` / `corpus_bleu` and Google's `rouge-score`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// SQuAD-style answer normalization: lower-case, drop punctuation and the
/// articles `a`, `an`, `the`, and collapse whitespace.
///
/// ```rust
/// use rune_chain_eval::metrics::normalize_answer;
///
/// assert_eq!(normalize_answer("  The  Eiffel Tower!"), "eiffel tower");
/// ```
#[must_use]
pub fn normalize_answer(text: &str) -> String {
    let lowered: String = text
        .chars()
        .flat_map(char::to_lowercase)
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    lowered
        .split_whitespace()
        .filter(|w| !matches!(*w, "a" | "an" | "the"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `rouge-score`'s default tokenizer: lower-case, every run of characters
/// other than ASCII letters and digits is a separator.
///
/// ```rust
/// use rune_chain_eval::metrics::tokenize;
///
/// assert_eq!(tokenize("The log, it's 9."), ["the", "log", "it", "s", "9"]);
/// ```
#[must_use]
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Levenshtein (edit) distance over `char`s, in `O(min(n, m))` memory.
///
/// ```rust
/// use rune_chain_eval::metrics::levenshtein;
///
/// assert_eq!(levenshtein("kitten", "sitting"), 3);
/// assert_eq!(levenshtein("", "abc"), 3);
/// ```
#[must_use]
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut row: Vec<usize> = (0..=short.len()).collect();
    for (i, lc) in long.iter().enumerate() {
        let mut diag = row[0];
        row[0] = i + 1;
        for (j, sc) in short.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if lc == sc {
                diag
            } else {
                1 + diag.min(above).min(row[j])
            };
            diag = above;
        }
    }
    row[short.len()]
}

/// `1 - distance / max(len)`, in `0.0..=1.0`; two empty strings score `1.0`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn levenshtein_similarity(a: &str, b: &str) -> f64 {
    let max = a.chars().count().max(b.chars().count());
    if max == 0 {
        return 1.0;
    }
    1.0 - levenshtein(a, b) as f64 / max as f64
}

/// Length of the longest common subsequence of two token slices.
#[must_use]
pub fn lcs_len<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut row = vec![0usize; short.len() + 1];
    for x in long {
        let mut diag = 0;
        for (j, y) in short.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if x == y { diag + 1 } else { above.max(row[j]) };
            diag = above;
        }
    }
    row[short.len()]
}

/// Precision, recall and F1 of an overlap metric.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Prf {
    /// Overlap over candidate length.
    pub precision: f64,
    /// Overlap over reference length.
    pub recall: f64,
    /// Harmonic mean of the two.
    pub f1: f64,
}

/// ROUGE-L between token sequences (`rouge-score`'s `rougeL`, no
/// stemming).
///
/// ```rust
/// use rune_chain_eval::metrics::{rouge_l, tokenize};
///
/// let s = rouge_l(
///     &tokenize("The quick brown dog jumps on the log."),
///     &tokenize("The quick brown fox jumps over the lazy dog"),
/// );
/// assert_eq!(s.precision, 0.625);
/// assert!((s.f1 - 0.588_235_294_117_647_1).abs() < 1e-12);
/// ```
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn rouge_l<T: PartialEq>(candidate: &[T], reference: &[T]) -> Prf {
    if candidate.is_empty() || reference.is_empty() {
        return Prf {
            precision: 0.0,
            recall: 0.0,
            f1: 0.0,
        };
    }
    let lcs = lcs_len(candidate, reference) as f64;
    let precision = lcs / candidate.len() as f64;
    let recall = lcs / reference.len() as f64;
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    Prf {
        precision,
        recall,
        f1,
    }
}

/// How BLEU handles n-gram orders with no matches.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Smoothing {
    /// None: any order without a match makes the score `0.0` (NLTK's
    /// default; fine for corpus BLEU, harsh for single sentences).
    None,
    /// Replace a zero match count with `epsilon` (NLTK `method1`, `0.1`).
    #[default]
    Epsilon,
    /// Add one to the matches and the total of orders `n >= 2` (Lin and
    /// Och, 2004).
    AddOne,
}

type Counts = (Vec<u64>, Vec<u64>, u64, u64);

fn ngram_counts<T: Eq + std::hash::Hash>(tokens: &[T], n: usize) -> HashMap<&[T], u64> {
    let mut m = HashMap::new();
    if tokens.len() >= n {
        for w in tokens.windows(n) {
            *m.entry(w).or_insert(0) += 1;
        }
    }
    m
}

/// Clipped matches and totals per order, plus hypothesis and closest
/// reference lengths.
fn bleu_counts<T: Eq + std::hash::Hash>(
    hypothesis: &[T],
    references: &[&[T]],
    max_n: usize,
) -> Counts {
    let mut matches = vec![0u64; max_n];
    let mut totals = vec![0u64; max_n];
    for n in 1..=max_n {
        let hyp = ngram_counts(hypothesis, n);
        let mut max_ref: HashMap<&[T], u64> = HashMap::new();
        for r in references {
            for (g, c) in ngram_counts(r, n) {
                if hyp.contains_key(g) {
                    let e = max_ref.entry(g).or_insert(0);
                    *e = (*e).max(c);
                }
            }
        }
        matches[n - 1] = hyp
            .iter()
            .map(|(g, &c)| c.min(max_ref.get(g).copied().unwrap_or(0)))
            .sum();
        totals[n - 1] = hyp.values().sum();
    }
    let hyp_len = hypothesis.len() as u64;
    // Closest reference length; ties go to the shorter one.
    let ref_len = references
        .iter()
        .map(|r| r.len() as u64)
        .min_by_key(|&l| (l.abs_diff(hyp_len), l))
        .unwrap_or(0);
    (matches, totals, hyp_len, ref_len)
}

#[allow(clippy::cast_precision_loss)]
fn bleu_from_counts(c: &Counts, smoothing: Smoothing) -> f64 {
    let (matches, totals, hyp_len, ref_len) = c;
    let max_n = matches.len();
    if *hyp_len == 0 || max_n == 0 || matches[0] == 0 {
        return 0.0;
    }
    let mut log_sum = 0.0;
    for n in 0..max_n {
        let (m, t) = (matches[n] as f64, totals[n] as f64);
        let p = match smoothing {
            Smoothing::None => {
                if m == 0.0 {
                    return 0.0;
                }
                m / t
            }
            Smoothing::Epsilon => {
                if m == 0.0 {
                    0.1 / t.max(1.0)
                } else {
                    m / t
                }
            }
            Smoothing::AddOne => {
                if n == 0 {
                    m / t
                } else {
                    (m + 1.0) / (t + 1.0)
                }
            }
        };
        log_sum += p.ln() / max_n as f64;
    }
    let bp = if hyp_len > ref_len {
        1.0
    } else {
        (1.0 - *ref_len as f64 / *hyp_len as f64).exp()
    };
    bp * log_sum.exp()
}

/// Sentence BLEU with uniform weights up to `max_n`-grams (use 4),
/// clipped counts over several references, the closest-reference brevity
/// penalty and the given smoothing. Same as NLTK's `sentence_bleu`.
///
/// ```rust
/// use rune_chain_eval::metrics::{Smoothing, sentence_bleu};
///
/// let hyp: Vec<&str> = "the cat sat on the mat".split(' ').collect();
/// let reference: Vec<&str> = "the cat sat on the mat".split(' ').collect();
/// assert_eq!(sentence_bleu(&hyp, &[&reference], 4, Smoothing::None), 1.0);
/// ```
#[must_use]
pub fn sentence_bleu<T: Eq + std::hash::Hash>(
    hypothesis: &[T],
    references: &[&[T]],
    max_n: usize,
    smoothing: Smoothing,
) -> f64 {
    bleu_from_counts(&bleu_counts(hypothesis, references, max_n), smoothing)
}

/// Corpus BLEU (NLTK's `corpus_bleu`).
///
/// N-gram matches and lengths are summed over all pairs before the
/// precisions are combined. `hypotheses` and
/// `references` pair up by position; extra items on either side are
/// ignored.
#[must_use]
pub fn corpus_bleu<T: Eq + std::hash::Hash>(
    hypotheses: &[&[T]],
    references: &[Vec<&[T]>],
    max_n: usize,
    smoothing: Smoothing,
) -> f64 {
    let mut acc: Counts = (vec![0; max_n], vec![0; max_n], 0, 0);
    for (h, refs) in hypotheses.iter().zip(references) {
        let (m, t, hl, rl) = bleu_counts(h, refs, max_n);
        for n in 0..max_n {
            acc.0[n] += m[n];
            acc.1[n] += t[n];
        }
        acc.2 += hl;
        acc.3 += rl;
    }
    bleu_from_counts(&acc, smoothing)
}

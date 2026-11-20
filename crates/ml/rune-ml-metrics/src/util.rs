//! Shared helpers: input validation, compensated summation and label encoding.

use std::collections::HashMap;
use std::hash::Hash;

use rune_ml_core::Float;

use crate::{MetricsError, Result};

/// Neumaier (improved Kahan) compensated sum. The error stays around one ulp
/// of the result instead of growing with the number of terms.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sum {
    sum: f64,
    comp: f64,
}

impl Sum {
    #[inline]
    pub fn add(&mut self, x: f64) {
        let t = self.sum + x;
        if self.sum.abs() >= x.abs() {
            self.comp += (self.sum - t) + x;
        } else {
            self.comp += (x - t) + self.sum;
        }
        self.sum = t;
    }

    #[inline]
    pub fn value(self) -> f64 {
        self.sum + self.comp
    }
}

pub fn stable_sum(it: impl IntoIterator<Item = f64>) -> f64 {
    let mut s = Sum::default();
    for x in it {
        s.add(x);
    }
    s.value()
}

/// `n as f64`. Exact below 2^53, which covers any sample count that fits in memory.
#[allow(clippy::cast_precision_loss, reason = "counts stay far below 2^53")]
#[inline]
pub const fn to_f64(n: usize) -> f64 {
    n as f64
}

/// Both slices non-empty and of equal length.
pub const fn check_pair<A, B>(a: &[A], b: &[B]) -> Result<()> {
    if a.len() != b.len() {
        return Err(MetricsError::LengthMismatch {
            expected: a.len(),
            found: b.len(),
        });
    }
    if a.is_empty() {
        return Err(MetricsError::Empty);
    }
    Ok(())
}

pub fn check_finite<F: Float>(v: &[F]) -> Result<()> {
    v.iter()
        .position(|x| !x.is_finite())
        .map_or(Ok(()), |index| Err(MetricsError::NonFinite { index }))
}

/// Finite and inside `[0, 1]`.
pub fn check_probabilities<F: Float>(v: &[F]) -> Result<()> {
    check_finite(v)?;
    v.iter()
        .position(|&x| x < F::ZERO || x > F::ONE)
        .map_or(Ok(()), |index| {
            Err(MetricsError::InvalidProbability { index })
        })
}

/// Sorted distinct labels of `a` and `b`, plus each sample's class index.
pub struct Encoded<L> {
    pub classes: Vec<L>,
    pub a: Vec<usize>,
    pub b: Vec<usize>,
}

/// Encodes two label slices against the sorted union of their values, the
/// way scikit-learn's `unique_labels` orders classes.
pub fn encode_sorted<L: Ord + Clone>(a: &[L], b: &[L]) -> Encoded<L> {
    let mut refs: Vec<&L> = a.iter().chain(b).collect();
    refs.sort_unstable();
    refs.dedup();
    let idx = |l: &L| refs.binary_search(&l).unwrap_or_default();
    let ea = a.iter().map(idx).collect();
    let eb = b.iter().map(idx).collect();
    Encoded {
        classes: refs.into_iter().cloned().collect(),
        a: ea,
        b: eb,
    }
}

/// Encodes labels to `0..k` in first-seen order. Returns the codes and `k`.
pub fn encode_hashed<L: Eq + Hash>(labels: &[L]) -> (Vec<usize>, usize) {
    let mut map: HashMap<&L, usize> = HashMap::new();
    let codes = labels
        .iter()
        .map(|l| {
            let next = map.len();
            *map.entry(l).or_insert(next)
        })
        .collect();
    (codes, map.len())
}

/// Per-class counts of codes in `0..k`.
pub fn bincount(codes: &[usize], k: usize) -> Vec<usize> {
    let mut c = vec![0usize; k];
    for &i in codes {
        c[i] += 1;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neumaier_beats_naive() {
        let v = [1.0, 1e100, 1.0, -1e100];
        assert_eq!(stable_sum(v), 2.0);
        assert_eq!(v.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn encoding() {
        let e = encode_sorted(&["b", "a"], &["c", "a"]);
        assert_eq!(e.classes, ["a", "b", "c"]);
        assert_eq!(e.a, [1, 0]);
        assert_eq!(e.b, [2, 0]);
        assert_eq!(encode_hashed(&[5, 3, 5, 9]), (vec![0, 1, 0, 2], 3));
    }
}

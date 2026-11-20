//! Record and query validation, scoring and the bounded top-k heap.
//!
//! These mirror the checks `rune-vectorstore`'s in-memory indexes run, so
//! this store accepts and rejects exactly the same input and scores with the
//! same arithmetic.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use rune_vectorstore::{Hit, Metric, Query, Record, StoreError, dot, euclidean, norm};

/// Check `v` for `metric` and return its norm.
pub fn check_vector(metric: Metric, v: &[f32]) -> Result<f32, StoreError> {
    if v.is_empty() {
        return Err(StoreError::InvalidVector("vector is empty"));
    }
    if v.iter().any(|x| !x.is_finite()) {
        return Err(StoreError::InvalidVector("vector contains NaN or infinity"));
    }
    let n = norm(v);
    if !n.is_finite() {
        return Err(StoreError::InvalidVector("vector norm overflows f32"));
    }
    if metric == Metric::Cosine && n == 0.0 {
        return Err(StoreError::InvalidVector(
            "zero vector has no direction under the cosine metric",
        ));
    }
    Ok(n)
}

/// Validate an upsert batch against `dimension` (or fix it from the first
/// record). Returns the batch dimension and each record's norm.
pub fn check_batch(
    metric: Metric,
    dimension: Option<usize>,
    records: &[Record],
) -> Result<(Option<usize>, Vec<f32>), StoreError> {
    let mut dim = dimension;
    let mut seen = HashSet::with_capacity(records.len());
    let mut norms = Vec::with_capacity(records.len());
    for r in records {
        if r.id.is_empty() {
            return Err(StoreError::EmptyId);
        }
        if !seen.insert(r.id.as_str()) {
            return Err(StoreError::DuplicateId(r.id.clone()));
        }
        let expected = *dim.get_or_insert(r.vector.len());
        if r.vector.len() != expected {
            return Err(StoreError::DimensionMismatch {
                expected,
                actual: r.vector.len(),
            });
        }
        norms.push(check_vector(metric, &r.vector)?);
    }
    Ok((dim, norms))
}

/// Validate the store-independent parts of a query.
pub fn check_query(query: &Query) -> Result<(), StoreError> {
    if query.min_score.is_some_and(f32::is_nan) {
        return Err(StoreError::InvalidQuery("min_score is NaN"));
    }
    query.filter.validate()
}

/// Validate a query vector against the store and return its norm.
pub fn check_query_vector(
    metric: Metric,
    dimension: Option<usize>,
    v: &[f32],
) -> Result<f32, StoreError> {
    if let Some(expected) = dimension
        && v.len() != expected
    {
        return Err(StoreError::DimensionMismatch {
            expected,
            actual: v.len(),
        });
    }
    check_vector(metric, v)
}

/// Score `a` against `b` exactly as the in-memory indexes do.
pub fn score(metric: Metric, a: &[f32], na: f32, b: &[f32], nb: f32) -> f32 {
    let s = match metric {
        Metric::Cosine => {
            if na == 0.0 || nb == 0.0 {
                0.0
            } else {
                dot(a, b) / (na * nb)
            }
        }
        Metric::DotProduct => dot(a, b),
        _ => -euclidean(a, b),
    };
    if s.is_nan() { f32::NEG_INFINITY } else { s }
}

/// `true` if `score` passes the query's threshold.
pub fn passes(query: &Query, score: f32) -> bool {
    query.min_score.is_none_or(|m| score >= m)
}

/// Sort hits best first, ties by id.
pub fn sort_hits(hits: &mut [Hit]) {
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.record.id.cmp(&b.record.id))
    });
}

/// One candidate in the top-k heap.
#[derive(Debug)]
pub struct Candidate<T> {
    pub score: f32,
    pub id: String,
    pub data: T,
}

impl<T> Candidate<T> {
    /// "Better" means a higher score, then a smaller id.
    fn better(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.id.cmp(&self.id))
    }
}

impl<T> PartialEq for Candidate<T> {
    fn eq(&self, other: &Self) -> bool {
        self.better(other) == Ordering::Equal
    }
}

impl<T> Eq for Candidate<T> {}

impl<T> PartialOrd for Candidate<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Candidate<T> {
    /// Reversed, so the `BinaryHeap` top is the worst kept candidate.
    fn cmp(&self, other: &Self) -> Ordering {
        other.better(self)
    }
}

/// Keeps the `k` best candidates seen so far in `O(k)` memory.
#[derive(Debug)]
pub struct TopK<T> {
    k: usize,
    heap: BinaryHeap<Candidate<T>>,
}

impl<T> TopK<T> {
    pub fn new(k: usize) -> Self {
        Self {
            k,
            heap: BinaryHeap::with_capacity(k.min(1024)),
        }
    }

    /// `true` if a candidate with this score and id would be kept. Lets the
    /// caller skip copying the id and checking metadata for losers.
    pub fn admits(&self, score: f32, id: &str) -> bool {
        if self.heap.len() < self.k {
            return true;
        }
        self.heap.peek().is_some_and(|worst| {
            score
                .total_cmp(&worst.score)
                .then_with(|| worst.id.as_str().cmp(id))
                == Ordering::Greater
        })
    }

    pub fn push(&mut self, candidate: Candidate<T>) {
        if self.k == 0 {
            return;
        }
        if self.heap.len() < self.k {
            self.heap.push(candidate);
        } else if let Some(mut worst) = self.heap.peek_mut()
            && candidate.better(&worst) == Ordering::Greater
        {
            *worst = candidate;
        }
    }

    pub fn into_vec(self) -> Vec<Candidate<T>> {
        self.heap.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_keeps_best_with_id_ties() {
        let mut top = TopK::new(2);
        for (s, id) in [(0.5, "b"), (0.9, "z"), (0.5, "a"), (0.1, "c")] {
            if top.admits(s, id) {
                top.push(Candidate {
                    score: s,
                    id: id.to_owned(),
                    data: (),
                });
            }
        }
        let mut ids: Vec<_> = top.into_vec().into_iter().map(|c| c.id).collect();
        ids.sort();
        assert_eq!(ids, ["a", "z"]);
    }

    #[test]
    fn zero_k_keeps_nothing() {
        let mut top = TopK::new(0);
        assert!(!top.admits(1.0, "a"));
        top.push(Candidate {
            score: 1.0,
            id: "a".into(),
            data: (),
        });
        assert_eq!(top.into_vec().len(), 0);
    }

    #[test]
    fn vectors_are_checked() {
        assert!(check_vector(Metric::Cosine, &[]).is_err());
        assert!(check_vector(Metric::Cosine, &[0.0]).is_err());
        assert!(check_vector(Metric::DotProduct, &[0.0]).is_ok());
        assert!(check_vector(Metric::Euclidean, &[f32::NAN]).is_err());
        assert!(check_vector(Metric::Euclidean, &[f32::NEG_INFINITY]).is_err());
        assert!(check_vector(Metric::Euclidean, &[f32::MAX, f32::MAX]).is_err());
    }
}

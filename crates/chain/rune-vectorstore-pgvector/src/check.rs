//! Record and query validation, shared with the in-memory store's rules.
//!
//! These mirror the checks `rune-vectorstore`'s in-memory indexes run, so
//! this store accepts and rejects exactly the same input.

use std::collections::HashSet;

use rune_vectorstore::{Hit, Metric, Query, Record, StoreError, norm};

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

#[cfg(test)]
mod tests {
    use super::*;

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

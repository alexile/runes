//! Maximal marginal relevance over stored vectors.

use crate::{Hit, Metric, StoreError};

/// Re-rank `hits` by maximal marginal relevance (Carbonell & Goldstein, 1998).
///
/// Greedily picks up to `k` hits, each maximising
/// `λ · sim(query, d) − (1 − λ) · max_{s ∈ picked} sim(d, s)` where `sim` is
/// `metric`'s score. `λ = 1` is pure relevance and `λ = 0` pure diversity.
/// Returns indexes into `hits` in pick order; ties go to the earlier hit,
/// so the result is deterministic.
///
/// This works on the vectors the store already holds, so no re-embedding
/// is needed. Hits must carry their vectors (the default; see
/// [`Query::include_vectors`](crate::Query::include_vectors)). Cosine keeps
/// both terms on the same `[-1, 1]` scale; with dot product or Euclidean the
/// scales are whatever the vectors make them.
///
/// # Errors
///
/// [`StoreError::InvalidQuery`] if `lambda` is outside `[0, 1]` or NaN.
/// [`StoreError::DimensionMismatch`] if a hit's vector length differs from
/// the query's (for example, vectors were not requested).
///
/// # Example
///
/// ```
/// use rune_vectorstore::{Hit, Metric, Record, mmr};
///
/// let hits = vec![
///     Hit::new(1.0, Record::new("a", vec![1.0, 0.0])),
///     Hit::new(0.99, Record::new("a-copy", vec![0.99, 0.01])),
///     Hit::new(0.7, Record::new("b", vec![0.7, 0.7])),
/// ];
/// // The near-duplicate loses to the more diverse third hit.
/// assert_eq!(mmr(Metric::Cosine, &[1.0, 0.0], &hits, 2, 0.3)?, [0, 2]);
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// ```
pub fn mmr(
    metric: Metric,
    query: &[f32],
    hits: &[Hit],
    k: usize,
    lambda: f32,
) -> Result<Vec<usize>, StoreError> {
    if !(0.0..=1.0).contains(&lambda) {
        return Err(StoreError::InvalidQuery("MMR lambda must be within [0, 1]"));
    }
    if let Some(h) = hits.iter().find(|h| h.record.vector.len() != query.len()) {
        return Err(StoreError::DimensionMismatch {
            expected: query.len(),
            actual: h.record.vector.len(),
        });
    }
    let sim = |a: &[f32], b: &[f32]| {
        let s = metric.score(a, b);
        if s.is_nan() { f32::NEG_INFINITY } else { s }
    };
    let relevance: Vec<f32> = hits.iter().map(|h| sim(query, &h.record.vector)).collect();
    let mut redundancy: Vec<Option<f32>> = vec![None; hits.len()];
    let mut picked = vec![false; hits.len()];
    let want = k.min(hits.len());
    let mut order = Vec::with_capacity(want);
    while order.len() < want {
        let mut best: Option<(usize, f32)> = None;
        for (i, &rel) in relevance.iter().enumerate() {
            if picked[i] {
                continue;
            }
            let penalty = redundancy[i].unwrap_or(0.0);
            let score = (1.0 - lambda).mul_add(-penalty, lambda * rel);
            if best.is_none_or(|(_, b)| score > b) {
                best = Some((i, score));
            }
        }
        let Some((chosen, _)) = best else { break };
        picked[chosen] = true;
        order.push(chosen);
        for (i, hit) in hits.iter().enumerate() {
            if !picked[i] {
                let s = sim(&hit.record.vector, &hits[chosen].record.vector);
                redundancy[i] = Some(redundancy[i].map_or(s, |r| r.max(s)));
            }
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Record;

    fn hits(vs: &[[f32; 2]]) -> Vec<Hit> {
        vs.iter()
            .enumerate()
            .map(|(i, v)| Hit::new(0.0, Record::new(i.to_string(), v.to_vec())))
            .collect()
    }

    #[test]
    fn lambda_one_is_relevance_order() {
        let h = hits(&[[0.5, 0.5], [1.0, 0.0], [1.0, 0.01]]);
        assert_eq!(
            mmr(Metric::Cosine, &[1.0, 0.0], &h, 3, 1.0).unwrap(),
            [1, 2, 0]
        );
    }

    #[test]
    fn lambda_zero_prefers_diversity() {
        let h = hits(&[[1.0, 0.0], [1.0, 0.01], [0.0, 1.0]]);
        assert_eq!(mmr(Metric::Cosine, &[1.0, 0.0], &h, 2, 0.0).unwrap()[1], 2);
    }

    #[test]
    fn edge_cases() {
        let h = hits(&[[1.0, 0.0]]);
        assert_eq!(
            mmr(Metric::Cosine, &[1.0, 0.0], &h, 0, 0.5).unwrap(),
            Vec::<usize>::new()
        );
        assert_eq!(
            mmr(Metric::Cosine, &[1.0, 0.0], &[], 3, 0.5).unwrap(),
            Vec::<usize>::new()
        );
        assert_eq!(mmr(Metric::Cosine, &[1.0, 0.0], &h, 5, 0.5).unwrap(), [0]);
        assert!(mmr(Metric::Cosine, &[1.0, 0.0], &h, 1, 1.5).is_err());
        assert!(mmr(Metric::Cosine, &[1.0, 0.0], &h, 1, f32::NAN).is_err());
        assert!(matches!(
            mmr(Metric::Cosine, &[1.0], &h, 1, 0.5),
            Err(StoreError::DimensionMismatch { .. })
        ));
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::try_join_all;

use crate::error::{RetrievalError, check_non_negative};
use crate::retriever::Retriever;
use crate::scored::{ScoredDocument, sort_by_score};

/// Default `k` constant of reciprocal rank fusion (Cormack et al., 2009).
pub const DEFAULT_RRF_K: f32 = 60.0;

/// How [`weighted_score_fusion`] makes scores from different retrievers
/// comparable before weighting them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Normalization {
    /// Min-max scale each list to `[0, 1]` (a list whose scores are all
    /// equal maps to `1.0`). The default.
    #[default]
    MinMax,
    /// Divide each list by its largest score (assumes non-negative scores).
    Max,
    /// Use raw scores. Only meaningful if all retrievers share a scale.
    None,
}

/// Reciprocal rank fusion: `score(d) = Σ_lists weight / (k + rank)`.
///
/// Ranks are 1-based. Documents are matched across lists by content hash; the
/// first-seen copy (and its metadata) is kept. Ties keep first-seen order.
///
/// `weights` must be empty (all `1.0`) or have one entry per list.
///
/// # Errors
///
/// [`RetrievalError::InvalidArgument`] if `k` or a weight is negative or not
/// finite, or the weight count does not match.
///
/// ```rust
/// use rune_chain_retrieval::{Document, ScoredDocument, reciprocal_rank_fusion};
///
/// let sd = |t: &str| ScoredDocument::new(Document::new(t), 0.0);
/// let fused = reciprocal_rank_fusion(
///     &[vec![sd("a"), sd("b")], vec![sd("b"), sd("c")]],
///     &[],
///     60.0,
/// )?;
/// assert_eq!(fused[0].document.content, "b"); // in both lists
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "ranks are small; precision loss is irrelevant for fused scores"
)]
pub fn reciprocal_rank_fusion(
    lists: &[Vec<ScoredDocument>],
    weights: &[f32],
    k: f32,
) -> Result<Vec<ScoredDocument>, RetrievalError> {
    check_non_negative("rrf k", k)?;
    let weights = resolve_weights(lists.len(), weights)?;
    Ok(accumulate(lists, |list_idx, rank, _| {
        weights[list_idx] / (k + rank as f32 + 1.0)
    }))
}

/// Weighted score fusion of normalised scores.
///
/// Normalises each list (see [`Normalization`]), then `score(d) = Σ_lists weight · normalised_score`. A document missing
/// from a list, or with a non-finite score in it, contributes 0 for it.
/// Documents are matched by content hash.
///
/// `weights` must be empty (all `1.0`) or have one entry per list.
///
/// # Errors
///
/// [`RetrievalError::InvalidArgument`] if a weight is negative or not
/// finite, or the weight count does not match.
pub fn weighted_score_fusion(
    lists: &[Vec<ScoredDocument>],
    weights: &[f32],
    normalization: Normalization,
) -> Result<Vec<ScoredDocument>, RetrievalError> {
    let weights = resolve_weights(lists.len(), weights)?;
    let scales: Vec<(f32, f32)> = lists
        .iter()
        .map(|list| scale_for(list, normalization))
        .collect();
    Ok(accumulate(lists, |list_idx, _, score| {
        if !score.is_finite() {
            return 0.0;
        }
        let (offset, divisor) = scales[list_idx];
        let normalised = if divisor > 0.0 {
            (score - offset) / divisor
        } else {
            1.0
        };
        weights[list_idx] * normalised
    }))
}

/// `(offset, divisor)` so that `(score - offset) / divisor` is normalised;
/// a zero divisor means "every score maps to 1.0".
fn scale_for(list: &[ScoredDocument], normalization: Normalization) -> (f32, f32) {
    let finite = list.iter().map(|d| d.score).filter(|s| s.is_finite());
    match normalization {
        Normalization::None => (0.0, 1.0),
        Normalization::Max => {
            let max = finite.fold(f32::NEG_INFINITY, f32::max);
            if max > 0.0 { (0.0, max) } else { (0.0, 0.0) }
        }
        Normalization::MinMax => {
            let (min, max) = finite.fold((f32::INFINITY, f32::NEG_INFINITY), |(lo, hi), s| {
                (lo.min(s), hi.max(s))
            });
            if max > min {
                (min, max - min)
            } else {
                (0.0, 0.0)
            }
        }
    }
}

fn resolve_weights(lists: usize, weights: &[f32]) -> Result<Vec<f32>, RetrievalError> {
    if weights.is_empty() {
        return Ok(vec![1.0; lists]);
    }
    if weights.len() != lists {
        return Err(RetrievalError::InvalidArgument(format!(
            "{} weights for {lists} result lists",
            weights.len()
        )));
    }
    weights
        .iter()
        .map(|&w| check_non_negative("weight", w))
        .collect()
}

/// Sum `contribution(list, rank, score)` per distinct document; non-finite
/// contributions count as 0.
fn accumulate(
    lists: &[Vec<ScoredDocument>],
    contribution: impl Fn(usize, usize, f32) -> f32,
) -> Vec<ScoredDocument> {
    let mut slots: HashMap<[u8; 32], usize> = HashMap::new();
    let mut fused: Vec<ScoredDocument> = Vec::new();
    for (list_idx, list) in lists.iter().enumerate() {
        for (rank, doc) in list.iter().enumerate() {
            let c = contribution(list_idx, rank, doc.score);
            let c = if c.is_finite() { c } else { 0.0 };
            let hash = doc.document.content_hash();
            if let Some(&slot) = slots.get(&hash) {
                if let Some(entry) = fused.get_mut(slot) {
                    entry.score += c;
                }
            } else {
                slots.insert(hash, fused.len());
                fused.push(ScoredDocument::new(doc.document.clone(), c));
            }
        }
    }
    sort_by_score(&mut fused);
    fused
}

/// How [`HybridRetriever`] fuses its retrievers' results.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum FusionStrategy {
    /// [`reciprocal_rank_fusion`] with this `k`. Scale-free, robust default.
    ReciprocalRank {
        /// The `k` constant (default [`DEFAULT_RRF_K`]).
        k: f32,
    },
    /// [`weighted_score_fusion`] with this normalisation.
    WeightedScore {
        /// How scores are normalised before weighting.
        normalization: Normalization,
    },
}

impl Default for FusionStrategy {
    fn default() -> Self {
        Self::ReciprocalRank { k: DEFAULT_RRF_K }
    }
}

/// Hybrid search: queries several retrievers concurrently (typically
/// [`Bm25Retriever`](crate::Bm25Retriever) for keywords plus a vector
/// retriever for semantics) and fuses their rankings.
///
/// Each retriever is asked for `max(top_k, fetch_k)` candidates
/// (`fetch_k` defaults to 20) so that documents ranked moderately by
/// several retrievers can surface.
///
/// ```rust
/// use std::sync::Arc;
/// use rune_chain_retrieval::{Bm25Retriever, Document, FusionStrategy, HybridRetriever, Retriever};
///
/// # tokio_test::block_on(async {
/// let docs = vec![Document::new("rust ownership"), Document::new("python typing")];
/// let keyword = Arc::new(Bm25Retriever::from_documents(docs.clone()));
/// let other = Arc::new(Bm25Retriever::from_documents(docs));
/// let hybrid = HybridRetriever::new()
///     .with_retriever(keyword, 0.7)?
///     .with_retriever(other, 0.3)?
///     .with_strategy(FusionStrategy::ReciprocalRank { k: 60.0 })?;
/// let hits = hybrid.retrieve("rust", 1).await?;
/// assert_eq!(hits[0].document.content, "rust ownership");
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// # }).unwrap();
/// ```
#[derive(Clone, Default)]
pub struct HybridRetriever {
    retrievers: Vec<(Arc<dyn Retriever>, f32)>,
    strategy: FusionStrategy,
    fetch_k: Option<usize>,
}

impl std::fmt::Debug for HybridRetriever {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridRetriever")
            .field("retrievers", &self.retrievers.len())
            .field("strategy", &self.strategy)
            .field("fetch_k", &self.fetch_k)
            .finish()
    }
}

impl HybridRetriever {
    /// No retrievers yet, RRF with `k = 60`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a retriever with a fusion weight.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if `weight` is negative or not finite.
    pub fn with_retriever(
        mut self,
        retriever: Arc<dyn Retriever>,
        weight: f32,
    ) -> Result<Self, RetrievalError> {
        let weight = check_non_negative("weight", weight)?;
        self.retrievers.push((retriever, weight));
        Ok(self)
    }

    /// Choose how results are fused.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if the RRF `k` is negative or not finite.
    pub fn with_strategy(mut self, strategy: FusionStrategy) -> Result<Self, RetrievalError> {
        if let FusionStrategy::ReciprocalRank { k } = strategy {
            check_non_negative("rrf k", k)?;
        }
        self.strategy = strategy;
        Ok(self)
    }

    /// Candidates requested from each retriever (default 20; never fewer
    /// than `top_k`).
    #[must_use]
    pub const fn with_fetch_k(mut self, fetch_k: usize) -> Self {
        self.fetch_k = Some(fetch_k);
        self
    }
}

#[async_trait]
impl Retriever for HybridRetriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 || self.retrievers.is_empty() {
            return Ok(Vec::new());
        }
        let fetch = top_k.max(self.fetch_k.unwrap_or(20));
        let lists = try_join_all(
            self.retrievers
                .iter()
                .map(|(r, _)| r.retrieve(query, fetch)),
        )
        .await?;
        let weights: Vec<f32> = self.retrievers.iter().map(|(_, w)| *w).collect();
        let mut fused = match self.strategy {
            FusionStrategy::ReciprocalRank { k } => reciprocal_rank_fusion(&lists, &weights, k)?,
            FusionStrategy::WeightedScore { normalization } => {
                weighted_score_fusion(&lists, &weights, normalization)?
            }
        };
        fused.truncate(top_k);
        Ok(fused)
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;
    use crate::document::Document;

    fn sd(text: &str, score: f32) -> ScoredDocument {
        ScoredDocument::new(Document::new(text), score)
    }

    fn contents(docs: &[ScoredDocument]) -> Vec<&str> {
        docs.iter().map(|d| d.document.content.as_str()).collect()
    }

    #[test]
    fn rrf_matches_formula() {
        let fused = reciprocal_rank_fusion(
            &[vec![sd("a", 9.0), sd("b", 1.0)], vec![sd("b", 0.5)]],
            &[],
            60.0,
        )
        .unwrap();
        assert_eq!(contents(&fused), ["b", "a"]);
        assert!((fused[0].score - (1.0 / 62.0 + 1.0 / 61.0)).abs() < 1e-7);
        assert!((fused[1].score - 1.0 / 61.0).abs() < 1e-7);
    }

    #[test]
    fn rrf_weights_shift_ranking() {
        let lists = [vec![sd("a", 0.0)], vec![sd("b", 0.0)]];
        let fused = reciprocal_rank_fusion(&lists, &[0.2, 1.0], 60.0).unwrap();
        assert_eq!(contents(&fused), ["b", "a"]);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let lists = [vec![sd("a", 0.0)]];
        assert!(reciprocal_rank_fusion(&lists, &[], -1.0).is_err());
        assert!(reciprocal_rank_fusion(&lists, &[1.0, 1.0], 60.0).is_err());
        assert!(weighted_score_fusion(&lists, &[f32::NAN], Normalization::MinMax).is_err());
        assert!(
            HybridRetriever::new()
                .with_strategy(FusionStrategy::ReciprocalRank { k: f32::INFINITY })
                .is_err()
        );
    }

    #[test]
    fn minmax_puts_retrievers_on_one_scale() {
        // BM25-like scores (large) vs cosine (small): without normalisation
        // the first list would dominate.
        let bm25 = vec![sd("a", 12.0), sd("b", 6.0), sd("c", 0.0)];
        let cosine = vec![sd("c", 0.9), sd("b", 0.8), sd("a", 0.1)];
        let fused =
            weighted_score_fusion(&[bm25.clone(), cosine.clone()], &[], Normalization::MinMax)
                .unwrap();
        // a: 1 + 0, b: 0.5 + 0.875, c: 0 + 1
        assert_eq!(contents(&fused), ["b", "a", "c"]);
        assert!((fused[0].score - 1.375).abs() < 1e-6);

        let raw = weighted_score_fusion(&[bm25, cosine], &[], Normalization::None).unwrap();
        assert_eq!(contents(&raw)[0], "a");
    }

    #[test]
    fn constant_list_normalises_to_one_and_nan_is_ignored() {
        let fused = weighted_score_fusion(
            &[vec![sd("a", 3.0), sd("b", 3.0), sd("n", f32::NAN)]],
            &[],
            Normalization::MinMax,
        )
        .unwrap();
        assert!((fused[0].score - 1.0).abs() < 1e-6);
        assert!((fused[1].score - 1.0).abs() < 1e-6);
        assert_eq!(fused[2].document.content, "n");
        assert!(fused[2].score.abs() < f32::EPSILON);
    }

    #[test]
    fn max_normalisation() {
        let fused =
            weighted_score_fusion(&[vec![sd("a", 4.0), sd("b", 1.0)]], &[], Normalization::Max)
                .unwrap();
        assert!((fused[1].score - 0.25).abs() < 1e-6);
    }

    #[test]
    fn empty_inputs() {
        assert!(reciprocal_rank_fusion(&[], &[], 60.0).unwrap().is_empty());
        assert!(
            weighted_score_fusion(&[vec![]], &[], Normalization::MinMax)
                .unwrap()
                .is_empty()
        );
    }
}

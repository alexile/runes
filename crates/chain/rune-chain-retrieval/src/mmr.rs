use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_embed::{Embedder, cosine_similarity};

use crate::error::{RetrievalError, check_unit};
use crate::retriever::Retriever;
use crate::scored::ScoredDocument;

/// Maximal marginal relevance (Carbonell & Goldstein, 1998).
///
/// Greedily picks up to `k` candidates, each maximising
/// `λ · sim(query, d) − (1 − λ) · max_{s ∈ selected} sim(d, s)` (cosine
/// similarity). `λ = 1` is pure relevance, `λ = 0` pure diversity. Returns
/// indices into `candidates`, in pick order; ties go to the earlier
/// candidate, so the result is deterministic.
///
/// # Errors
///
/// [`RetrievalError::InvalidArgument`] if `lambda` is outside `[0, 1]`.
///
/// ```rust
/// use rune_chain_retrieval::maximal_marginal_relevance;
///
/// let query = [1.0, 0.0];
/// let candidates = [vec![1.0, 0.0], vec![0.99, 0.01], vec![0.7, 0.7]];
/// // The near-duplicate second candidate loses to the diverse third one.
/// assert_eq!(maximal_marginal_relevance(&query, &candidates, 2, 0.3)?, [0, 2]);
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// ```
pub fn maximal_marginal_relevance(
    query: &[f32],
    candidates: &[Vec<f32>],
    k: usize,
    lambda: f32,
) -> Result<Vec<usize>, RetrievalError> {
    let lambda = check_unit("lambda", lambda)?;
    let relevance: Vec<f32> = candidates
        .iter()
        .map(|c| finite_or_min(cosine_similarity(query, c)))
        .collect();
    // Highest similarity of each candidate to anything selected so far.
    let mut redundancy = vec![f32::NEG_INFINITY; candidates.len()];
    let mut picked = vec![false; candidates.len()];
    let mut selected = Vec::with_capacity(k.min(candidates.len()));

    while selected.len() < k.min(candidates.len()) {
        let mut best: Option<(usize, f32)> = None;
        for (i, &rel) in relevance.iter().enumerate() {
            if picked[i] {
                continue;
            }
            let penalty = if redundancy[i].is_finite() {
                redundancy[i]
            } else {
                0.0
            };
            let score = lambda.mul_add(rel, -(1.0 - lambda) * penalty);
            if best.is_none_or(|(_, b)| score > b) {
                best = Some((i, score));
            }
        }
        let Some((chosen, _)) = best else { break };
        picked[chosen] = true;
        selected.push(chosen);
        for (i, cand) in candidates.iter().enumerate() {
            if !picked[i] {
                let sim = finite_or_min(cosine_similarity(cand, &candidates[chosen]));
                redundancy[i] = redundancy[i].max(sim);
            }
        }
    }
    Ok(selected)
}

const fn finite_or_min(x: f32) -> f32 {
    if x.is_finite() { x } else { -1.0 }
}

/// Diversifying [`Retriever`] using maximal marginal relevance.
///
/// Fetches `fetch_k` candidates from an inner
/// retriever, embeds them, and keeps `top_k` chosen by
/// [`maximal_marginal_relevance`]. Output scores are each document's cosine
/// similarity to the query, in MMR pick order.
///
/// Costs one embedding batch (query + candidates) per call.
pub struct MmrRetriever {
    inner: Arc<dyn Retriever>,
    embedder: Arc<dyn Embedder>,
    lambda: f32,
    fetch_k: usize,
}

impl std::fmt::Debug for MmrRetriever {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmrRetriever")
            .field("lambda", &self.lambda)
            .field("fetch_k", &self.fetch_k)
            .finish_non_exhaustive()
    }
}

impl MmrRetriever {
    /// MMR over `inner`'s candidates with `λ = 0.5` and `fetch_k = 20`.
    pub fn new(inner: Arc<dyn Retriever>, embedder: Arc<dyn Embedder>) -> Self {
        Self {
            inner,
            embedder,
            lambda: 0.5,
            fetch_k: 20,
        }
    }

    /// Relevance/diversity trade-off in `[0, 1]` (1 = relevance only).
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if `lambda` is outside `[0, 1]`.
    pub fn with_lambda(mut self, lambda: f32) -> Result<Self, RetrievalError> {
        self.lambda = check_unit("lambda", lambda)?;
        Ok(self)
    }

    /// Candidates fetched before diversification (never fewer than `top_k`).
    #[must_use]
    pub const fn with_fetch_k(mut self, fetch_k: usize) -> Self {
        self.fetch_k = fetch_k;
        self
    }
}

#[async_trait]
impl Retriever for MmrRetriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let candidates = self.inner.retrieve(query, top_k.max(self.fetch_k)).await?;
        if candidates.is_empty() {
            return Ok(candidates);
        }
        let mut texts: Vec<&str> = Vec::with_capacity(candidates.len() + 1);
        texts.push(query);
        texts.extend(candidates.iter().map(|c| c.document.content.as_str()));
        let mut embeddings = self.embedder.embed_batch(&texts).await?;
        if embeddings.len() != texts.len() {
            return Err(RetrievalError::Embed(format!(
                "embedder returned {} vectors for {} texts",
                embeddings.len(),
                texts.len()
            )));
        }
        let doc_embeddings = embeddings.split_off(1);
        let query_embedding = embeddings.pop().unwrap_or_default();
        let order =
            maximal_marginal_relevance(&query_embedding, &doc_embeddings, top_k, self.lambda)?;
        let mut slots: Vec<Option<ScoredDocument>> = candidates.into_iter().map(Some).collect();
        Ok(order
            .into_iter()
            .filter_map(|i| {
                let mut doc = slots.get_mut(i)?.take()?;
                doc.score = cosine_similarity(&query_embedding, &doc_embeddings[i]);
                Some(doc)
            })
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    #[test]
    fn lambda_one_is_pure_relevance() {
        let q = [1.0, 0.0];
        let c = [vec![0.5, 0.5], vec![1.0, 0.0], vec![1.0, 0.01]];
        assert_eq!(
            maximal_marginal_relevance(&q, &c, 3, 1.0).unwrap(),
            [1, 2, 0]
        );
    }

    #[test]
    fn lambda_zero_prefers_diversity_after_first() {
        let q = [1.0, 0.0];
        let c = [vec![1.0, 0.0], vec![1.0, 0.01], vec![0.0, 1.0]];
        assert_eq!(maximal_marginal_relevance(&q, &c, 2, 0.0).unwrap()[1], 2);
    }

    #[test]
    fn edge_cases() {
        assert!(
            maximal_marginal_relevance(&[1.0], &[vec![1.0]], 0, 0.5)
                .unwrap()
                .is_empty()
        );
        assert!(
            maximal_marginal_relevance(&[1.0], &[], 3, 0.5)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            maximal_marginal_relevance(&[1.0], &[vec![1.0]], 5, 0.5).unwrap(),
            [0]
        );
        assert!(maximal_marginal_relevance(&[1.0], &[vec![1.0]], 1, 1.5).is_err());
        assert!(maximal_marginal_relevance(&[1.0], &[vec![1.0]], 1, f32::NAN).is_err());
        // NaN vectors do not panic and still produce k picks.
        let picks =
            maximal_marginal_relevance(&[1.0], &[vec![f32::NAN], vec![1.0]], 2, 0.5).unwrap();
        assert_eq!(picks, [1, 0]);
    }
}

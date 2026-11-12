use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::document::Document;

/// A retrieved [`Document`] with the score that ranked it.
///
/// What the score means depends on where it came from: cosine similarity
/// for vector search, an Okapi BM25 score for [`Bm25Retriever`](crate::Bm25Retriever),
/// a fused score for [`HybridRetriever`](crate::HybridRetriever), or a
/// relevance score from a [`Reranker`](crate::Reranker). Higher is better.
/// Compare scores only within one result list.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredDocument {
    /// The document.
    pub document: Document,
    /// Its score; higher means more relevant.
    pub score: f32,
}

impl ScoredDocument {
    /// Pair `document` with `score`.
    #[must_use]
    pub const fn new(document: Document, score: f32) -> Self {
        Self { document, score }
    }
}

impl Document {
    /// SHA-256 of the document's content (metadata is ignored).
    ///
    /// Used to deduplicate and to identify the same document across the
    /// result lists of different retrievers.
    ///
    /// ```rust
    /// use rune_chain_retrieval::Document;
    ///
    /// let a = Document::new("same text").with_meta("source", "a.md");
    /// let b = Document::new("same text").with_meta("source", "b.md");
    /// assert_eq!(a.content_hash(), b.content_hash());
    /// ```
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        Sha256::digest(self.content.as_bytes()).into()
    }
}

/// Sort key that ranks `NaN` below every real score.
const fn rank_key(score: f32) -> f32 {
    if score.is_nan() {
        f32::NEG_INFINITY
    } else {
        score
    }
}

/// Sort `docs` by descending score. The sort is stable (ties keep their
/// order) and `NaN` scores sink to the bottom.
pub fn sort_by_score(docs: &mut [ScoredDocument]) {
    docs.sort_by(|a, b| rank_key(b.score).total_cmp(&rank_key(a.score)));
}

/// Drop every document whose content hash was already seen, keeping the
/// first occurrence (the best ranked one when `docs` is sorted).
///
/// ```rust
/// use rune_chain_retrieval::{Document, ScoredDocument, dedupe_by_content};
///
/// let docs = vec![
///     ScoredDocument::new(Document::new("a"), 0.9),
///     ScoredDocument::new(Document::new("b"), 0.8),
///     ScoredDocument::new(Document::new("a"), 0.1),
/// ];
/// let kept = dedupe_by_content(docs);
/// assert_eq!(kept.len(), 2);
/// assert_eq!(kept[0].score, 0.9);
/// ```
#[must_use]
pub fn dedupe_by_content(docs: Vec<ScoredDocument>) -> Vec<ScoredDocument> {
    let mut seen = HashSet::with_capacity(docs.len());
    docs.into_iter()
        .filter(|d| seen.insert(d.document.content_hash()))
        .collect()
}

/// Keep only documents whose score is at least `min_score` (`NaN` scores
/// are always dropped).
#[must_use]
pub fn filter_min_score(docs: Vec<ScoredDocument>, min_score: f32) -> Vec<ScoredDocument> {
    docs.into_iter().filter(|d| d.score >= min_score).collect()
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    fn sd(text: &str, score: f32) -> ScoredDocument {
        ScoredDocument::new(Document::new(text), score)
    }

    #[test]
    fn sort_is_descending_stable_and_sinks_nan() {
        let mut docs = vec![
            sd("a", 0.5),
            sd("nan", f32::NAN),
            sd("b", 0.9),
            sd("c", 0.5),
        ];
        sort_by_score(&mut docs);
        let order: Vec<&str> = docs.iter().map(|d| d.document.content.as_str()).collect();
        assert_eq!(order, ["b", "a", "c", "nan"]);
    }

    #[test]
    fn threshold_drops_low_and_nan() {
        let kept = filter_min_score(vec![sd("a", 0.5), sd("b", 0.2), sd("n", f32::NAN)], 0.3);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].document.content, "a");
    }

    #[test]
    fn hash_ignores_metadata() {
        let a = Document::new("x").with_meta("k", "1");
        assert_eq!(a.content_hash(), Document::new("x").content_hash());
        assert_ne!(a.content_hash(), Document::new("y").content_hash());
    }
}

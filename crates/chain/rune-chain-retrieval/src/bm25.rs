use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::document::Document;
use crate::error::{RetrievalError, check_non_negative, check_unit};
use crate::retriever::Retriever;
use crate::scored::{ScoredDocument, sort_by_score};

/// Splits text into index terms for [`Bm25Index`].
pub trait Tokenizer: Send + Sync {
    /// The terms of `text`, in order (duplicates kept: they are term counts).
    fn tokenize(&self, text: &str) -> Vec<String>;
}

/// Unicode-aware word tokenizer.
///
/// A token is a maximal run of alphanumeric characters
/// ([`char::is_alphanumeric`], so `café`, `Straße`, `東京` and `42` are all
/// words); everything else separates tokens. Tokens are lowercased with the
/// full Unicode mapping, tokens shorter than `min_len` characters are dropped,
/// and so are configured stop words (compared after lowercasing).
///
/// Scripts written without spaces (Chinese, Japanese, Thai) come out as one
/// token per run; implement [`Tokenizer`] with a segmenter for those.
///
/// ```rust
/// use rune_chain_retrieval::{SimpleTokenizer, Tokenizer};
///
/// let t = SimpleTokenizer::new().with_stop_words(["the"]);
/// assert_eq!(t.tokenize("The Café, the CAFÉ-owner!"), ["café", "café", "owner"]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct SimpleTokenizer {
    min_len: usize,
    stop_words: HashSet<String>,
}

impl SimpleTokenizer {
    /// Tokenizer keeping every token, with no stop words.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop tokens with fewer than `min_len` characters.
    #[must_use]
    pub const fn with_min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    /// Drop these words (case-insensitive).
    #[must_use]
    pub fn with_stop_words<I, S>(mut self, words: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.stop_words
            .extend(words.into_iter().map(|w| w.as_ref().to_lowercase()));
        self
    }
}

impl Tokenizer for SimpleTokenizer {
    fn tokenize(&self, text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .filter(|t| t.chars().count() >= self.min_len && !self.stop_words.contains(t))
            .collect()
    }
}

/// Okapi BM25 parameters.
///
/// - `k1` (default `1.2`): term-frequency saturation; `0` ignores term counts.
/// - `b` (default `0.75`): document-length normalisation, `0` (none) to `1` (full).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm25Params {
    k1: f32,
    b: f32,
}

impl Bm25Params {
    /// Validated parameters.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if `k1` is negative or not finite,
    /// or `b` is outside `[0, 1]`.
    pub fn new(k1: f32, b: f32) -> Result<Self, RetrievalError> {
        Ok(Self {
            k1: check_non_negative("k1", k1)?,
            b: check_unit("b", b)?,
        })
    }

    /// The `k1` parameter.
    #[must_use]
    pub const fn k1(&self) -> f32 {
        self.k1
    }

    /// The `b` parameter.
    #[must_use]
    pub const fn b(&self) -> f32 {
        self.b
    }
}

impl Default for Bm25Params {
    fn default() -> Self {
        Self { k1: 1.2, b: 0.75 }
    }
}

/// In-memory Okapi BM25 index (sans-I/O; see [`Bm25Retriever`] for the
/// async [`Retriever`]).
///
/// Scoring uses the non-negative IDF variant used by Lucene,
/// `ln(1 + (N - n + 0.5) / (n + 0.5))`, and
/// `idf · tf·(k1+1) / (tf + k1·(1 - b + b·dl/avgdl))` summed over the
/// distinct query terms. Documents matching no query term are not returned.
///
/// ```rust
/// use rune_chain_retrieval::{Bm25Index, Document};
///
/// let mut index = Bm25Index::new();
/// index.add(Document::new("Rust is memory safe"));
/// index.add(Document::new("Python is dynamically typed"));
/// let hits = index.search("memory safety in rust", 5);
/// assert_eq!(hits.len(), 1);
/// assert_eq!(hits[0].document.content, "Rust is memory safe");
/// ```
pub struct Bm25Index {
    params: Bm25Params,
    tokenizer: Arc<dyn Tokenizer>,
    docs: Vec<Document>,
    doc_lens: Vec<u32>,
    total_len: u64,
    /// term -> postings (document index, term frequency)
    postings: HashMap<String, Vec<(usize, u32)>>,
}

impl std::fmt::Debug for Bm25Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bm25Index")
            .field("params", &self.params)
            .field("documents", &self.docs.len())
            .field("terms", &self.postings.len())
            .finish_non_exhaustive()
    }
}

impl Default for Bm25Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm25Index {
    /// Empty index with default parameters and [`SimpleTokenizer`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(Bm25Params::default(), Arc::new(SimpleTokenizer::new()))
    }

    /// Empty index with the given parameters and tokenizer.
    #[must_use]
    pub fn with_config(params: Bm25Params, tokenizer: Arc<dyn Tokenizer>) -> Self {
        Self {
            params,
            tokenizer,
            docs: Vec::new(),
            doc_lens: Vec::new(),
            total_len: 0,
            postings: HashMap::new(),
        }
    }

    /// Index one document.
    pub fn add(&mut self, document: Document) {
        let idx = self.docs.len();
        let mut tf: HashMap<String, u32> = HashMap::new();
        let mut len: u32 = 0;
        for term in self.tokenizer.tokenize(&document.content) {
            *tf.entry(term).or_default() += 1;
            len = len.saturating_add(1);
        }
        for (term, count) in tf {
            self.postings.entry(term).or_default().push((idx, count));
        }
        self.doc_lens.push(len);
        self.total_len += u64::from(len);
        self.docs.push(document);
    }

    /// Index several documents.
    pub fn extend(&mut self, documents: impl IntoIterator<Item = Document>) {
        for doc in documents {
            self.add(doc);
        }
    }

    /// Number of indexed documents.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.docs.len()
    }

    /// `true` if nothing is indexed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// The `top_k` best-scoring documents for `query`, best first; ties keep
    /// insertion order. `top_k = 0` returns an empty list.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "document counts and lengths far below 2^24 in practice; scores tolerate rounding"
    )]
    pub fn search(&self, query: &str, top_k: usize) -> Vec<ScoredDocument> {
        if top_k == 0 || self.docs.is_empty() {
            return Vec::new();
        }
        let n = self.docs.len() as f32;
        let avgdl = (self.total_len as f32 / n).max(f32::MIN_POSITIVE);
        let Bm25Params { k1, b } = self.params;

        let mut seen = HashSet::new();
        let mut scores: HashMap<usize, f32> = HashMap::new();
        for term in self.tokenizer.tokenize(query) {
            if !seen.insert(term.clone()) {
                continue;
            }
            let Some(postings) = self.postings.get(&term) else {
                continue;
            };
            let df = postings.len() as f32;
            let idf = ((n - df + 0.5) / (df + 0.5)).ln_1p();
            for &(idx, tf) in postings {
                let tf = tf as f32;
                let dl = self.doc_lens.get(idx).copied().unwrap_or(0) as f32;
                let norm = k1.mul_add(1.0 - b + b * dl / avgdl, tf);
                let term_score = idf * tf * (k1 + 1.0) / norm.max(f32::MIN_POSITIVE);
                *scores.entry(idx).or_default() += term_score;
            }
        }

        let mut hits: Vec<(usize, f32)> = scores.into_iter().collect();
        hits.sort_by_key(|&(idx, _)| idx);
        let mut ranked: Vec<ScoredDocument> = hits
            .into_iter()
            .filter_map(|(idx, score)| {
                self.docs
                    .get(idx)
                    .map(|d| ScoredDocument::new(d.clone(), score))
            })
            .collect();
        sort_by_score(&mut ranked);
        ranked.truncate(top_k);
        ranked
    }
}

/// Keyword [`Retriever`] backed by a [`Bm25Index`] behind an async lock, so
/// documents can be added while it serves queries.
///
/// ```rust
/// use rune_chain_retrieval::{Bm25Retriever, Document, Retriever};
///
/// # tokio_test::block_on(async {
/// let retriever = Bm25Retriever::from_documents(vec![
///     Document::new("The capital of France is Paris."),
///     Document::new("The capital of Germany is Berlin."),
/// ]);
/// let hits = retriever.retrieve("paris france", 1).await?;
/// assert_eq!(hits[0].document.content, "The capital of France is Paris.");
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// # }).unwrap();
/// ```
#[derive(Debug)]
pub struct Bm25Retriever {
    index: RwLock<Bm25Index>,
}

impl Bm25Retriever {
    /// Retriever over `index`.
    #[must_use]
    pub fn new(index: Bm25Index) -> Self {
        Self {
            index: RwLock::new(index),
        }
    }

    /// Index `documents` with default parameters and [`SimpleTokenizer`].
    pub fn from_documents(documents: impl IntoIterator<Item = Document>) -> Self {
        let mut index = Bm25Index::new();
        index.extend(documents);
        Self::new(index)
    }

    /// Index more documents.
    pub async fn add_documents(&self, documents: impl IntoIterator<Item = Document> + Send) {
        self.index.write().await.extend(documents);
    }

    /// Number of indexed documents.
    pub async fn len(&self) -> usize {
        self.index.read().await.len()
    }

    /// `true` if nothing is indexed.
    pub async fn is_empty(&self) -> bool {
        self.index.read().await.is_empty()
    }
}

#[async_trait]
impl Retriever for Bm25Retriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        Ok(self.index.read().await.search(query, top_k))
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    fn index(texts: &[&str]) -> Bm25Index {
        let mut idx = Bm25Index::new();
        idx.extend(texts.iter().map(|t| Document::new(*t)));
        idx
    }

    #[test]
    fn tokenizer_is_unicode_aware() {
        let t = SimpleTokenizer::new();
        assert_eq!(
            t.tokenize("ÜBER straße—naïve 東京 x2"),
            ["über", "straße", "naïve", "東京", "x2"]
        );
        assert_eq!(
            SimpleTokenizer::new().with_min_len(3).tokenize("a an the"),
            ["the"]
        );
    }

    #[test]
    fn params_validation() {
        assert!(Bm25Params::new(-0.1, 0.5).is_err());
        assert!(Bm25Params::new(f32::NAN, 0.5).is_err());
        assert!(Bm25Params::new(1.2, 1.1).is_err());
        assert!(Bm25Params::new(0.0, 0.0).is_ok());
    }

    /// Hand-computed reference: 2 docs, "a b" and "a a c"; query "a".
    /// avgdl = 2.5, df(a) = 2, idf = ln(1 + 0.5/2.5) = ln 1.2.
    #[test]
    fn matches_reference_score() {
        let idx = index(&["a b", "a a c"]);
        let hits = idx.search("a", 2);
        let idf = 1.2f32.ln();
        let s1 = idf * 1.0 * 2.2 / 1.2f32.mul_add(1.0 - 0.75 + 0.75 * 2.0 / 2.5, 1.0);
        let s2 = idf * 2.0 * 2.2 / 1.2f32.mul_add(1.0 - 0.75 + 0.75 * 3.0 / 2.5, 2.0);
        assert_eq!(hits[0].document.content, "a a c");
        assert!((hits[0].score - s2).abs() < 1e-6);
        assert!((hits[1].score - s1).abs() < 1e-6);
    }

    #[test]
    fn rare_terms_outweigh_common_ones() {
        let idx = index(&["the cat", "the dog", "the bird", "the zebra"]);
        let hits = idx.search("the zebra", 4);
        assert_eq!(hits[0].document.content, "the zebra");
        assert_eq!(hits.len(), 4);
    }

    #[test]
    fn zero_k_empty_index_and_no_match() {
        let idx = index(&["alpha"]);
        assert!(idx.search("alpha", 0).is_empty());
        assert!(idx.search("beta", 3).is_empty());
        assert!(Bm25Index::new().search("alpha", 3).is_empty());
        assert!(idx.search("", 3).is_empty());
    }

    #[test]
    fn k1_zero_ignores_term_frequency() {
        let params = Bm25Params::new(0.0, 0.75).unwrap();
        let mut idx = Bm25Index::with_config(params, Arc::new(SimpleTokenizer::new()));
        idx.extend([Document::new("x"), Document::new("x x x y")]);
        let hits = idx.search("x", 2);
        assert!((hits[0].score - hits[1].score).abs() < 1e-6);
    }

    #[test]
    fn ties_keep_insertion_order() {
        let idx = index(&["same words", "same words", "same words"]);
        let mut a = idx.search("same", 3);
        let b = idx.search("same", 3);
        a.iter_mut().zip(&b).for_each(|(x, y)| assert_eq!(x, y));
        assert_eq!(a.len(), 3);
    }

    #[tokio::test]
    async fn retriever_adds_documents() {
        let r = Bm25Retriever::from_documents([Document::new("one")]);
        r.add_documents([Document::new("two")]).await;
        assert_eq!(r.len().await, 2);
        let hits = r.retrieve("two", 5).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert!(r.retrieve("two", 0).await.unwrap().is_empty());
    }
}

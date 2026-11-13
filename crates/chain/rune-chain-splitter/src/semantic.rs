//! Embedding-based semantic chunking.

use std::ops::Range;

use crate::chunk::{Chunk, char_len, chunks_from_ranges};
use crate::error::SplitError;
use crate::recursive::{RecursiveSplitter, split_recursive};

const DEFAULT_BUFFER_SIZE: usize = 1;
const DEFAULT_BATCH_SIZE: usize = 64;

/// How [`SemanticChunker`] turns adjacent-sentence distances into breakpoints.
///
/// A breakpoint after sentence `i` is placed where the cosine distance
/// between the embeddings of sentences `i` and `i + 1` exceeds the threshold.
/// The variants mirror `LangChain`'s `SemanticChunker`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum BreakpointThreshold {
    /// Break where the distance exceeds this percentile (0–100) of all
    /// distances. `LangChain`'s default, with 95.
    Percentile(f64),
    /// Break where the distance exceeds `mean + k · std_dev` (default `k = 3`).
    StandardDeviation(f64),
    /// Break where the distance exceeds `mean + k · IQR` (default `k = 1.5`).
    Interquartile(f64),
    /// Break where the gradient of the distances exceeds this percentile
    /// (0–100) of all gradients (default 95). Suited to highly correlated
    /// text such as legal or medical documents.
    Gradient(f64),
    /// Break at the `n - 1` largest distances, aiming for `n` chunks (fewer
    /// when the text has fewer sentences).
    ChunkCount(usize),
}

impl Default for BreakpointThreshold {
    fn default() -> Self {
        Self::Percentile(95.0)
    }
}

impl BreakpointThreshold {
    fn validate(self) -> Result<(), SplitError> {
        let bad = |msg: &str| Err(SplitError::InvalidConfig(msg.to_owned()));
        match self {
            Self::Percentile(p) | Self::Gradient(p) if !(0.0..=100.0).contains(&p) => {
                bad("percentile must be within 0..=100")
            }
            Self::StandardDeviation(k) | Self::Interquartile(k) if !k.is_finite() => {
                bad("threshold factor must be finite")
            }
            Self::ChunkCount(0) => bad("chunk count must be at least 1"),
            _ => Ok(()),
        }
    }
}

/// Split text where the meaning shifts, using sentence embeddings.
///
/// The text is cut into sentences ([`sentence_spans`]); each sentence is
/// embedded together with `buffer_size` neighbours on each side; the cosine
/// distance between consecutive embeddings is computed; and the text is
/// broken after every sentence whose distance to the next exceeds the
/// [`BreakpointThreshold`]. This is the algorithm of `LangChain`'s
/// `SemanticChunker` (Greg Kamradt's "semantic chunking").
///
/// Chunks are verbatim slices of the input and concatenate back to it. Each
/// carries `"sentence_start"` / `"sentence_end"` metadata (sentence indices,
/// end exclusive). Optional `min_chunk_chars` suppresses breakpoints that
/// would leave a chunk too short, and `max_chunk_chars` re-splits oversized
/// chunks recursively.
///
/// # Sans-I/O core and late chunking
///
/// [`chunk`](SemanticChunker::chunk) (feature `embed`, on by default) calls
/// any [`rune_chain_embed::Embedder`]. Everything else is synchronous:
/// [`chunk_with_embeddings`](SemanticChunker::chunk_with_embeddings) accepts
/// precomputed per-sentence vectors. For *late chunking*, embed the whole
/// document once with a long-context model, mean-pool its token vectors over
/// each sentence span with [`pool_spans`], pass the result here, and pool the
/// same token vectors over the returned chunks' `byte_range`s to get
/// context-aware chunk embeddings.
///
/// # Example
///
/// ```rust
/// use rune_chain_splitter::{BreakpointThreshold, SemanticChunker, sentence_spans};
///
/// let text = "Cats purr. Cats nap. Rockets fly. Rockets burn.";
/// let sentences = sentence_spans(text);
/// // Precomputed embeddings: two cat sentences, then two rocket sentences.
/// let embeddings = vec![vec![1.0, 0.0], vec![1.0, 0.1], vec![0.0, 1.0], vec![0.1, 1.0]];
/// let chunker = SemanticChunker::new().threshold(BreakpointThreshold::ChunkCount(2));
/// let chunks = chunker.chunk_with_embeddings(text, &sentences, &embeddings).unwrap();
/// assert_eq!(chunks[0].text, "Cats purr. Cats nap. ");
/// assert_eq!(chunks[1].text, "Rockets fly. Rockets burn.");
/// ```
#[derive(Debug, Clone)]
pub struct SemanticChunker {
    threshold: BreakpointThreshold,
    buffer_size: usize,
    min_chunk_chars: usize,
    max_chunk_chars: Option<usize>,
    batch_size: usize,
}

impl Default for SemanticChunker {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticChunker {
    /// Create a chunker: 95th-percentile threshold, `buffer_size = 1`, no
    /// size limits, 64 inputs per embedding request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            threshold: BreakpointThreshold::Percentile(95.0),
            buffer_size: DEFAULT_BUFFER_SIZE,
            min_chunk_chars: 0,
            max_chunk_chars: None,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Set the breakpoint rule.
    #[must_use]
    pub const fn threshold(mut self, threshold: BreakpointThreshold) -> Self {
        self.threshold = threshold;
        self
    }

    /// Number of neighbouring sentences on each side embedded together with
    /// each sentence (0 embeds sentences alone). Smooths out noise.
    #[must_use]
    pub const fn buffer_size(mut self, sentences: usize) -> Self {
        self.buffer_size = sentences;
        self
    }

    /// Skip breakpoints that would close a chunk shorter than `chars`
    /// characters; a too-short last chunk joins the previous one.
    #[must_use]
    pub const fn min_chunk_chars(mut self, chars: usize) -> Self {
        self.min_chunk_chars = chars;
        self
    }

    /// Re-split chunks longer than `chars` characters with the
    /// [`RecursiveSplitter`] rules (no overlap).
    #[must_use]
    pub const fn max_chunk_chars(mut self, chars: Option<usize>) -> Self {
        self.max_chunk_chars = chars;
        self
    }

    /// Maximum number of texts per [`Embedder::embed_batch`](rune_chain_embed::Embedder::embed_batch) call.
    #[must_use]
    pub const fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Check the settings.
    ///
    /// # Errors
    ///
    /// [`SplitError::InvalidConfig`] for an out-of-range threshold, a zero
    /// batch size, or `min_chunk_chars > max_chunk_chars`;
    /// [`SplitError::ZeroChunkSize`] for `max_chunk_chars(Some(0))`.
    pub fn validate(&self) -> Result<(), SplitError> {
        self.threshold.validate()?;
        if self.batch_size == 0 {
            return Err(SplitError::InvalidConfig(
                "batch size must be at least 1".into(),
            ));
        }
        match self.max_chunk_chars {
            Some(0) => Err(SplitError::ZeroChunkSize),
            Some(max) if self.min_chunk_chars > max => Err(SplitError::InvalidConfig(format!(
                "min_chunk_chars ({}) exceeds max_chunk_chars ({max})",
                self.min_chunk_chars
            ))),
            _ => Ok(()),
        }
    }

    /// The texts to embed, one per sentence: each sentence with
    /// `buffer_size` neighbours on either side, whitespace-trimmed.
    ///
    /// ```rust
    /// use rune_chain_splitter::{SemanticChunker, sentence_spans};
    ///
    /// let text = "A. B. C.";
    /// let inputs = SemanticChunker::new().embedding_inputs(text, &sentence_spans(text));
    /// assert_eq!(inputs, ["A. B.", "A. B. C.", "B. C."]);
    /// ```
    #[must_use]
    pub fn embedding_inputs<'t>(&self, text: &'t str, sentences: &[Range<usize>]) -> Vec<&'t str> {
        let n = sentences.len();
        (0..n)
            .map(|i| {
                let first = i.saturating_sub(self.buffer_size);
                let last = i.saturating_add(self.buffer_size).min(n - 1);
                text.get(sentences[first].start..sentences[last].end)
                    .unwrap_or_default()
                    .trim()
            })
            .collect()
    }

    /// Indices `i` such that the text breaks after sentence `i`, given the
    /// distances between consecutive sentences (`distances[i]` is between
    /// sentences `i` and `i + 1`). Sorted ascending.
    ///
    /// ```rust
    /// use rune_chain_splitter::{BreakpointThreshold, SemanticChunker};
    ///
    /// let c = SemanticChunker::new().threshold(BreakpointThreshold::Percentile(50.0));
    /// assert_eq!(c.breakpoints(&[0.1, 0.9, 0.2, 0.8]), [1, 3]);
    /// ```
    #[must_use]
    pub fn breakpoints(&self, distances: &[f64]) -> Vec<usize> {
        if distances.is_empty() {
            return Vec::new();
        }
        let above = |values: &[f64], t: f64| -> Vec<usize> {
            values
                .iter()
                .enumerate()
                .filter(|&(_, &v)| v > t)
                .map(|(i, _)| i)
                .collect()
        };
        match self.threshold {
            BreakpointThreshold::Percentile(p) => above(distances, percentile(distances, p)),
            BreakpointThreshold::StandardDeviation(k) => {
                let (mean, std) = mean_std(distances);
                above(distances, k.mul_add(std, mean))
            }
            BreakpointThreshold::Interquartile(k) => {
                let (mean, _) = mean_std(distances);
                let iqr = percentile(distances, 75.0) - percentile(distances, 25.0);
                above(distances, k.mul_add(iqr, mean))
            }
            BreakpointThreshold::Gradient(p) => {
                let g = gradient(distances);
                above(&g, percentile(&g, p))
            }
            BreakpointThreshold::ChunkCount(n) => {
                let mut order: Vec<usize> = (0..distances.len()).collect();
                order.sort_by(|&a, &b| distances[b].total_cmp(&distances[a]).then(a.cmp(&b)));
                order.truncate(n.saturating_sub(1));
                order.sort_unstable();
                order
            }
        }
    }

    /// Chunk `text` given its sentence spans and one embedding per sentence.
    ///
    /// `sentences` must be ordered, non-overlapping byte spans on `char`
    /// boundaries (as from [`sentence_spans`]); when they tile the text, the
    /// chunks concatenate back to it.
    ///
    /// # Errors
    ///
    /// Invalid settings ([`validate`](Self::validate)), an invalid span,
    /// a count or dimension mismatch, or a non-finite embedding value.
    pub fn chunk_with_embeddings(
        &self,
        text: &str,
        sentences: &[Range<usize>],
        embeddings: &[Vec<f32>],
    ) -> Result<Vec<Chunk>, SplitError> {
        self.validate()?;
        check_spans(text, sentences)?;
        if sentences.len() != embeddings.len() {
            return Err(SplitError::EmbeddingCountMismatch {
                expected: sentences.len(),
                got: embeddings.len(),
            });
        }
        let distances = cosine_distances(embeddings)?;
        Ok(self.assemble(text, sentences, &self.breakpoints(&distances)))
    }

    /// Split `text` into sentences, embed them with `embedder`, and chunk.
    ///
    /// Makes no embedding request for text with fewer than two sentences.
    ///
    /// # Errors
    ///
    /// Invalid settings, [`SplitError::Embed`] when the embedder fails, or
    /// the embedding checks of [`chunk_with_embeddings`](Self::chunk_with_embeddings).
    #[cfg(feature = "embed")]
    pub async fn chunk<E>(&self, text: &str, embedder: &E) -> Result<Vec<Chunk>, SplitError>
    where
        E: rune_chain_embed::Embedder + ?Sized,
    {
        self.validate()?;
        let sentences = sentence_spans(text);
        if sentences.len() < 2 {
            return Ok(self.assemble(text, &sentences, &[]));
        }
        let inputs = self.embedding_inputs(text, &sentences);
        let mut embeddings = Vec::with_capacity(inputs.len());
        for batch in inputs.chunks(self.batch_size) {
            let vectors = embedder
                .embed_batch(batch)
                .await
                .map_err(|e| SplitError::Embed(Box::new(e)))?;
            if vectors.len() != batch.len() {
                return Err(SplitError::EmbeddingCountMismatch {
                    expected: batch.len(),
                    got: vectors.len(),
                });
            }
            embeddings.extend(vectors);
        }
        let distances = cosine_distances(&embeddings)?;
        Ok(self.assemble(text, &sentences, &self.breakpoints(&distances)))
    }

    /// Group sentences at `breaks`, apply the size limits, build chunks.
    fn assemble(&self, text: &str, sentences: &[Range<usize>], breaks: &[usize]) -> Vec<Chunk> {
        // Sentence groups as (first, last_exclusive).
        let mut groups: Vec<(usize, usize)> = Vec::new();
        let mut first = 0;
        let span_chars =
            |a: usize, b: usize| char_len(&text[sentences[a].start..sentences[b - 1].end]);
        for &b in breaks {
            let end = b + 1;
            if end <= first || end >= sentences.len() {
                continue;
            }
            if span_chars(first, end) >= self.min_chunk_chars {
                groups.push((first, end));
                first = end;
            }
        }
        if first < sentences.len() {
            match groups.last_mut() {
                Some(last) if span_chars(first, sentences.len()) < self.min_chunk_chars => {
                    last.1 = sentences.len();
                }
                _ => groups.push((first, sentences.len())),
            }
        }

        let separators = RecursiveSplitter::default_separators();
        let mut ranges = Vec::new();
        let mut owners = Vec::new();
        for &(a, b) in &groups {
            let range = sentences[a].start..sentences[b - 1].end;
            let before = ranges.len();
            match self.max_chunk_chars {
                Some(max) => split_recursive(text, range, &separators, max.max(1), 0, &mut ranges),
                None if !range.is_empty() => ranges.push(range),
                None => {}
            }
            owners.extend(std::iter::repeat_n((a, b), ranges.len() - before));
        }
        let mut chunks = chunks_from_ranges(text, &ranges);
        for (chunk, (a, b)) in chunks.iter_mut().zip(owners) {
            chunk
                .metadata
                .insert("sentence_start".into(), a.to_string());
            chunk.metadata.insert("sentence_end".into(), b.to_string());
        }
        chunks
    }
}

/// Split `text` into sentence spans that tile it exactly.
///
/// A sentence ends after `.`, `!`, `?` or `…` (plus any closing quotes or
/// brackets) followed by whitespace, after `。`, `！` or `？`, or at a blank
/// line. Trailing whitespace belongs to the sentence it follows; leading
/// whitespace to the first sentence. Decimal points (`3.14`) do not split;
/// abbreviations (`e.g. x`) do, as in `LangChain`.
///
/// ```rust
/// use rune_chain_splitter::sentence_spans;
///
/// let text = "Pi is 3.14! Really? \"Yes.\" 好。对\n\nNew para";
/// let s: Vec<&str> = sentence_spans(text).into_iter().map(|r| &text[r]).collect();
/// assert_eq!(s, ["Pi is 3.14! ", "Really? ", "\"Yes.\" ", "好。", "对\n\n", "New para"]);
/// ```
#[must_use]
pub fn sentence_spans(text: &str) -> Vec<Range<usize>> {
    const TERMINAL: [char; 4] = ['.', '!', '?', '…'];
    const CJK_TERMINAL: [char; 3] = ['。', '！', '？'];
    const CLOSERS: [char; 10] = ['"', '\'', ')', ']', '}', '”', '’', '»', '」', '』'];

    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let n = chars.len();
    let at = |j: usize| chars.get(j).map_or(text.len(), |&(p, _)| p);
    let mut spans = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < n {
        let c = chars[i].1;
        if TERMINAL.contains(&c) || CJK_TERMINAL.contains(&c) {
            let mut cjk = CJK_TERMINAL.contains(&c);
            let mut j = i + 1;
            while j < n
                && (TERMINAL.contains(&chars[j].1)
                    || CJK_TERMINAL.contains(&chars[j].1)
                    || CLOSERS.contains(&chars[j].1))
            {
                cjk |= CJK_TERMINAL.contains(&chars[j].1);
                j += 1;
            }
            let ws_start = j;
            while j < n && chars[j].1.is_whitespace() {
                j += 1;
            }
            if (j > ws_start || cjk) && j < n {
                spans.push(start..at(j));
                start = at(j);
            }
            i = j;
        } else if c == '\n' {
            let mut j = i + 1;
            let mut newlines = 1;
            while j < n && chars[j].1.is_whitespace() {
                newlines += usize::from(chars[j].1 == '\n');
                j += 1;
            }
            if newlines >= 2 && j < n {
                spans.push(start..at(j));
                start = at(j);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if start < text.len() {
        spans.push(start..text.len());
    }
    spans
}

/// Cosine distance (`1 - cosine similarity`) between each pair of
/// consecutive embeddings; `n` embeddings give `n - 1` distances.
///
/// A zero vector has similarity 0 (distance 1) to everything.
///
/// # Errors
///
/// [`SplitError::DimensionMismatch`] or [`SplitError::NonFiniteEmbedding`].
///
/// ```rust
/// use rune_chain_splitter::cosine_distances;
///
/// let d = cosine_distances(&[vec![1.0, 0.0], vec![1.0, 0.0], vec![0.0, 1.0]]).unwrap();
/// assert_eq!(d, [0.0, 1.0]);
/// ```
pub fn cosine_distances(embeddings: &[Vec<f32>]) -> Result<Vec<f64>, SplitError> {
    let dim = embeddings.first().map_or(0, Vec::len);
    for (index, e) in embeddings.iter().enumerate() {
        if e.len() != dim {
            return Err(SplitError::DimensionMismatch {
                index,
                expected: dim,
                got: e.len(),
            });
        }
        if e.iter().any(|v| !v.is_finite()) {
            return Err(SplitError::NonFiniteEmbedding { index });
        }
    }
    Ok(embeddings
        .windows(2)
        .map(|w| 1.0 - cosine(&w[0], &w[1]))
        .collect())
}

/// Mean-pool `token_vectors` over each span, for late chunking.
///
/// `token_offsets[i]` is the byte span of token `i` in the document (as
/// returned by a tokenizer's offset mapping) and `token_vectors[i]` its
/// contextual embedding. A token belongs to a span when their byte ranges
/// intersect. A span without tokens pools to a zero vector.
///
/// # Errors
///
/// [`SplitError::EmbeddingCountMismatch`] when the two slices differ in
/// length, plus the checks of [`cosine_distances`].
///
/// ```rust
/// use rune_chain_splitter::pool_spans;
///
/// let offsets = [0..3, 4..7, 8..11];
/// let vectors = [vec![1.0, 0.0], vec![3.0, 0.0], vec![0.0, 2.0]];
/// let pooled = pool_spans(&offsets, &vectors, &[0..8, 8..11]).unwrap();
/// assert_eq!(pooled, [vec![2.0, 0.0], vec![0.0, 2.0]]);
/// ```
pub fn pool_spans(
    token_offsets: &[Range<usize>],
    token_vectors: &[Vec<f32>],
    spans: &[Range<usize>],
) -> Result<Vec<Vec<f32>>, SplitError> {
    if token_offsets.len() != token_vectors.len() {
        return Err(SplitError::EmbeddingCountMismatch {
            expected: token_offsets.len(),
            got: token_vectors.len(),
        });
    }
    cosine_distances(token_vectors)?;
    let dim = token_vectors.first().map_or(0, Vec::len);
    Ok(spans
        .iter()
        .map(|span| {
            let mut sum = vec![0.0f64; dim];
            let mut count = 0u32;
            for (off, v) in token_offsets.iter().zip(token_vectors) {
                if off.start < span.end && span.start < off.end {
                    for (s, x) in sum.iter_mut().zip(v) {
                        *s += f64::from(*x);
                    }
                    count += 1;
                }
            }
            #[allow(
                clippy::cast_possible_truncation,
                reason = "back to the embedding precision"
            )]
            sum.into_iter()
                .map(|s| {
                    if count == 0 {
                        0.0
                    } else {
                        (s / f64::from(count)) as f32
                    }
                })
                .collect()
        })
        .collect())
}

fn check_spans(text: &str, spans: &[Range<usize>]) -> Result<(), SplitError> {
    let mut prev_end = 0;
    for (index, s) in spans.iter().enumerate() {
        if s.start < prev_end || s.start > s.end || text.get(s.clone()).is_none() {
            return Err(SplitError::InvalidSpan {
                index,
                start: s.start,
                end: s.end,
            });
        }
        prev_end = s.end;
    }
    Ok(())
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot = x.mul_add(y, dot);
        na = x.mul_add(x, na);
        nb = y.mul_add(y, nb);
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (dot / (na.sqrt() * nb.sqrt())).clamp(-1.0, 1.0)
}

/// Percentile with linear interpolation (`numpy.percentile`'s default).
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "indices of in-memory slices fit f64 exactly"
)]
fn percentile(values: &[f64], p: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let Some(&last) = sorted.last() else {
        return 0.0;
    };
    let rank = (p.clamp(0.0, 100.0) / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = rank - rank.floor();
    if lo >= sorted.len() {
        return last;
    }
    (sorted[hi] - sorted[lo]).mul_add(frac, sorted[lo])
}

/// Mean and population standard deviation.
#[allow(clippy::cast_precision_loss, reason = "lengths fit f64 exactly")]
fn mean_std(values: &[f64]) -> (f64, f64) {
    let n = values.len().max(1) as f64;
    let mean = values.iter().sum::<f64>() / n;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

/// `numpy.gradient` with unit spacing: one-sided at the ends, central inside.
fn gradient(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    if n < 2 {
        return vec![0.0; n];
    }
    (0..n)
        .map(|i| match i {
            0 => values[1] - values[0],
            i if i == n - 1 => values[n - 1] - values[n - 2],
            i => (values[i + 1] - values[i - 1]) / 2.0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::single_range_in_vec_init,
        reason = "test assertions on single spans"
    )]

    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn percentile_matches_numpy() {
        assert!(close(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.5));
        assert!(close(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 3.85));
        assert!(close(percentile(&[4.0, 1.0, 3.0, 2.0], 0.0), 1.0));
        assert!(close(percentile(&[7.0], 95.0), 7.0));
    }

    #[test]
    fn gradient_matches_numpy() {
        assert_eq!(gradient(&[1.0, 2.0, 4.0, 7.0]), [1.0, 1.5, 2.5, 3.0]);
        assert_eq!(gradient(&[5.0]), [0.0]);
    }

    #[test]
    fn std_and_iqr_thresholds() {
        let d = [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.9];
        let std = SemanticChunker::new().threshold(BreakpointThreshold::StandardDeviation(2.0));
        assert_eq!(std.breakpoints(&d), [7]);
        let iqr = SemanticChunker::new().threshold(BreakpointThreshold::Interquartile(1.5));
        assert_eq!(iqr.breakpoints(&d), [7]);
    }

    #[test]
    fn chunk_count_picks_largest_distances() {
        let c = SemanticChunker::new().threshold(BreakpointThreshold::ChunkCount(3));
        assert_eq!(c.breakpoints(&[0.5, 0.1, 0.9, 0.5]), [0, 2]);
        let one = SemanticChunker::new().threshold(BreakpointThreshold::ChunkCount(1));
        assert_eq!(one.breakpoints(&[0.5, 0.9]), [] as [usize; 0]);
    }

    #[test]
    fn invalid_settings_are_rejected() {
        for t in [
            BreakpointThreshold::Percentile(101.0),
            BreakpointThreshold::Gradient(f64::NAN),
            BreakpointThreshold::StandardDeviation(f64::INFINITY),
            BreakpointThreshold::ChunkCount(0),
        ] {
            assert!(
                SemanticChunker::new().threshold(t).validate().is_err(),
                "{t:?}"
            );
        }
        assert!(SemanticChunker::new().batch_size(0).validate().is_err());
        assert!(matches!(
            SemanticChunker::new().max_chunk_chars(Some(0)).validate(),
            Err(SplitError::ZeroChunkSize)
        ));
        assert!(
            SemanticChunker::new()
                .min_chunk_chars(10)
                .max_chunk_chars(Some(5))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn embedding_checks() {
        let text = "A. B.";
        let s = sentence_spans(text);
        let c = SemanticChunker::new();
        assert!(matches!(
            c.chunk_with_embeddings(text, &s, &[vec![1.0]]),
            Err(SplitError::EmbeddingCountMismatch {
                expected: 2,
                got: 1
            })
        ));
        assert!(matches!(
            c.chunk_with_embeddings(text, &s, &[vec![1.0], vec![1.0, 2.0]]),
            Err(SplitError::DimensionMismatch { index: 1, .. })
        ));
        assert!(matches!(
            c.chunk_with_embeddings(text, &s, &[vec![1.0], vec![f32::NAN]]),
            Err(SplitError::NonFiniteEmbedding { index: 1 })
        ));
        assert!(matches!(
            c.chunk_with_embeddings("é", &[0..1], &[vec![1.0]]),
            Err(SplitError::InvalidSpan { index: 0, .. })
        ));
    }

    #[test]
    fn min_and_max_chunk_chars() {
        let text = "Aa. Bb. Cc. Dd.";
        let s = sentence_spans(text);
        let e: Vec<Vec<f32>> = (0..4)
            .map(|i| {
                if i % 2 == 0 {
                    vec![1.0, 0.0]
                } else {
                    vec![0.0, 1.0]
                }
            })
            .collect();
        let every = SemanticChunker::new().threshold(BreakpointThreshold::Percentile(0.0));
        // All distances are equal (1.0), so nothing exceeds the 0th percentile.
        assert_eq!(every.chunk_with_embeddings(text, &s, &e).unwrap().len(), 1);
        let split_all = SemanticChunker::new().threshold(BreakpointThreshold::ChunkCount(4));
        assert_eq!(
            split_all.chunk_with_embeddings(text, &s, &e).unwrap().len(),
            4
        );
        let min = split_all.min_chunk_chars(7);
        let texts: Vec<String> = min
            .chunk_with_embeddings(text, &s, &e)
            .unwrap()
            .into_iter()
            .map(|c| c.text)
            .collect();
        assert_eq!(texts, ["Aa. Bb. ", "Cc. Dd."]);
        let max = SemanticChunker::new()
            .threshold(BreakpointThreshold::ChunkCount(1))
            .max_chunk_chars(Some(5));
        let chunks = max.chunk_with_embeddings(text, &s, &e).unwrap();
        assert!(chunks.iter().all(|c| c.text.chars().count() <= 5));
        assert_eq!(
            chunks.iter().map(|c| c.text.as_str()).collect::<String>(),
            text
        );
    }

    #[test]
    fn sentence_spans_edge_cases() {
        assert_eq!(sentence_spans(""), []);
        assert_eq!(sentence_spans("   "), [0..3]);
        assert_eq!(sentence_spans("No terminator"), [0..13]);
        assert_eq!(sentence_spans("End.  "), [0..6]);
    }
}

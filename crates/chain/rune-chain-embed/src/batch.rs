//! Splitting large batches into bounded, concurrent, order-preserving requests.

use std::future::Future;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt, stream};

use crate::{EmbedError, Embedder};

/// Embed `texts` in chunks of at most `max_batch` inputs, with at most
/// `max_concurrency` chunks in flight, concatenating results in input order.
/// Fails fast on the first chunk error, and checks every chunk returns one
/// vector per input.
pub async fn run_batched<'a, F, Fut>(
    texts: &'a [&'a str],
    max_batch: usize,
    max_concurrency: usize,
    mut embed_chunk: F,
) -> Result<Vec<Vec<f32>>, EmbedError>
where
    F: FnMut(&'a [&'a str]) -> Fut,
    Fut: Future<Output = Result<Vec<Vec<f32>>, EmbedError>>,
{
    if max_batch == 0 || max_concurrency == 0 {
        return Err(EmbedError::InvalidConfig(
            "max_batch_size and max_concurrency must be at least 1".into(),
        ));
    }
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    // Build the futures up front (they are lazy, nothing runs yet): a
    // closure stored in the stream would trip async-trait's `Send` inference.
    let mut pending = Vec::with_capacity(texts.len().div_ceil(max_batch));
    for chunk in texts.chunks(max_batch) {
        pending.push(checked(chunk.len(), embed_chunk(chunk)));
    }
    let chunks: Vec<Vec<Vec<f32>>> = stream::iter(pending)
        .buffered(max_concurrency)
        .try_collect()
        .await?;
    Ok(chunks.into_iter().flatten().collect())
}

async fn checked(
    expected: usize,
    fut: impl Future<Output = Result<Vec<Vec<f32>>, EmbedError>>,
) -> Result<Vec<Vec<f32>>, EmbedError> {
    let vectors = fut.await?;
    if vectors.len() == expected {
        Ok(vectors)
    } else {
        Err(EmbedError::InvalidResponse(format!(
            "expected {expected} embeddings, got {}",
            vectors.len()
        )))
    }
}

/// Wraps any [`Embedder`] to split large batches into bounded requests.
///
/// Each request carries at most `max_batch_size` inputs, with at most
/// `max_concurrency` requests in flight. Results keep input order; the first
/// failing request fails the whole call.
///
/// The HTTP providers in this crate already batch this way (see their
/// `max_batch_size` / `max_concurrency` builders); use this wrapper for other
/// embedders such as a self-hosted model with a small batch limit.
///
/// ```rust
/// use rune_chain_embed::{BatchingEmbedder, EmbedError, Embedder};
/// use async_trait::async_trait;
///
/// struct Lengths;
///
/// #[async_trait]
/// impl Embedder for Lengths {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         assert!(texts.len() <= 2, "provider limit");
///         Ok(texts.iter().map(|t| vec![t.len() as f32]).collect())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let embedder = BatchingEmbedder::new(Lengths, 2).max_concurrency(3);
/// let vectors = embedder.embed_batch(&["a", "bb", "ccc", "dddd", "eeeee"]).await.unwrap();
/// assert_eq!(vectors, vec![vec![1.0], vec![2.0], vec![3.0], vec![4.0], vec![5.0]]);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct BatchingEmbedder<E> {
    inner: E,
    max_batch_size: usize,
    max_concurrency: usize,
}

impl<E: Embedder> BatchingEmbedder<E> {
    /// Wrap `inner`, sending at most `max_batch_size` inputs per call and one
    /// call at a time (see [`max_concurrency`](Self::max_concurrency)).
    pub const fn new(inner: E, max_batch_size: usize) -> Self {
        Self {
            inner,
            max_batch_size,
            max_concurrency: 1,
        }
    }

    /// Most calls in flight at once (default 1).
    #[must_use]
    pub const fn max_concurrency(mut self, requests: usize) -> Self {
        self.max_concurrency = requests;
        self
    }

    /// The wrapped embedder.
    pub const fn inner(&self) -> &E {
        &self.inner
    }

    /// Unwrap into the inner embedder.
    pub fn into_inner(self) -> E {
        self.inner
    }
}

#[async_trait]
impl<E: Embedder> Embedder for BatchingEmbedder<E> {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        run_batched(texts, self.max_batch_size, self.max_concurrency, |c| {
            self.inner.embed_batch(c)
        })
        .await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.inner.embed(text).await
    }

    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.inner.embed_query(text).await
    }

    async fn embed_documents(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        run_batched(texts, self.max_batch_size, self.max_concurrency, |c| {
            self.inner.embed_documents(c)
        })
        .await
    }

    fn model_id(&self) -> Option<String> {
        self.inner.model_id()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    /// Records chunk sizes and peak concurrency; later chunks finish first.
    #[derive(Default)]
    struct Probe {
        chunks: Mutex<Vec<usize>>,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    #[async_trait]
    impl Embedder for Probe {
        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            self.chunks.lock().unwrap().push(texts.len());
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            // Earlier inputs sleep longer, so completion order is reversed.
            let first: u64 = texts[0].parse().unwrap_or(0);
            tokio::time::sleep(Duration::from_millis(40u64.saturating_sub(first * 4))).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if texts.contains(&"fail") {
                return Err(EmbedError::Other("boom".into()));
            }
            Ok(texts.iter().map(|t| vec![t.parse().unwrap()]).collect())
        }
    }

    #[tokio::test]
    async fn splits_bounds_concurrency_and_preserves_order() {
        let inputs: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        let embedder = BatchingEmbedder::new(Probe::default(), 3).max_concurrency(2);
        let out = embedder.embed_documents(&refs).await.unwrap();
        #[allow(clippy::cast_precision_loss, reason = "small test values")]
        let expected: Vec<Vec<f32>> = (0..10).map(|i| vec![i as f32]).collect();
        assert_eq!(out, expected);
        let mut chunks = embedder.inner().chunks.lock().unwrap().clone();
        chunks.sort_unstable();
        assert_eq!(chunks, vec![1, 3, 3, 3]);
        assert_eq!(embedder.inner().peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn first_error_fails_the_call() {
        let embedder = BatchingEmbedder::new(Probe::default(), 1).max_concurrency(4);
        assert!(embedder.embed_batch(&["1", "fail", "3"]).await.is_err());
    }

    #[tokio::test]
    async fn zero_limits_are_config_errors_and_empty_is_free() {
        let embedder = BatchingEmbedder::new(Probe::default(), 0);
        assert!(matches!(
            embedder.embed_batch(&["1"]).await,
            Err(EmbedError::InvalidConfig(_))
        ));
        let ok = BatchingEmbedder::new(Probe::default(), 2);
        assert_eq!(ok.embed_batch(&[]).await.unwrap().len(), 0);
        assert!(ok.inner().chunks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn short_chunk_reply_is_invalid() {
        struct Short;
        #[async_trait]
        impl Embedder for Short {
            async fn embed_batch(&self, _: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
                Ok(vec![vec![0.0]])
            }
        }
        let err = BatchingEmbedder::new(Short, 2)
            .embed_batch(&["a", "b", "c"])
            .await
            .unwrap_err();
        assert!(matches!(err, EmbedError::InvalidResponse(m) if m.contains("expected 2")));
    }
}

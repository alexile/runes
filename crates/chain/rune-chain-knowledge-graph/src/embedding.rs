use async_trait::async_trait;

use crate::error::{BoxError, KgError};

/// Turns entity names and queries into vectors, for merging near-duplicate
/// entities and for finding seed entities by meaning rather than by words.
///
/// Implement it for your embedding client, or enable the `embed` feature and
/// wrap any `rune_chain_embed::Embedder` in [`FromEmbedder`].
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_knowledge_graph::{BoxError, EntityEmbedder};
///
/// /// A toy embedder: one dimension per lowercase ASCII letter.
/// struct Letters;
///
/// #[async_trait]
/// impl EntityEmbedder for Letters {
///     async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, BoxError> {
///         Ok(texts
///             .iter()
///             .map(|t| {
///                 let mut v = vec![0.0; 26];
///                 for b in t.to_ascii_lowercase().bytes().filter(u8::is_ascii_lowercase) {
///                     v[usize::from(b - b'a')] += 1.0;
///                 }
///                 v
///             })
///             .collect())
///     }
/// }
/// ```
#[async_trait]
pub trait EntityEmbedder: Send + Sync {
    /// Embed entity names, one vector per input, in order.
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, BoxError>;

    /// Embed a retrieval query. Defaults to [`embed`](Self::embed).
    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, BoxError> {
        self.embed(&[query])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| "embedder returned no vector".into())
    }
}

/// Adapts a `rune_chain_embed::Embedder` to [`EntityEmbedder`].
///
/// Entity names go through `embed_documents`, queries through
/// `embed_query`, so providers with asymmetric query/document modes work as
/// intended.
#[cfg(feature = "embed")]
#[derive(Debug, Clone)]
pub struct FromEmbedder<E>(pub E);

#[cfg(feature = "embed")]
#[async_trait]
impl<E: rune_chain_embed::Embedder> EntityEmbedder for FromEmbedder<E> {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, BoxError> {
        Ok(self.0.embed_documents(texts).await?)
    }

    async fn embed_query(&self, query: &str) -> Result<Vec<f32>, BoxError> {
        Ok(self.0.embed_query(query).await?)
    }
}

/// Check that an embedder returned `expected` finite vectors of one length.
pub fn check_vectors(vectors: &[Vec<f32>], expected: usize) -> Result<(), KgError> {
    if vectors.len() != expected {
        return Err(KgError::Embed(
            format!("expected {expected} vectors, got {}", vectors.len()).into(),
        ));
    }
    if let Some(first) = vectors.first() {
        let dim = first.len();
        if dim == 0 {
            return Err(KgError::Embed("embedder returned an empty vector".into()));
        }
        if vectors
            .iter()
            .any(|v| v.len() != dim || v.iter().any(|x| !x.is_finite()))
        {
            return Err(KgError::Embed(
                "embedder returned vectors of mixed length or non-finite values".into(),
            ));
        }
    }
    Ok(())
}

/// Cosine similarity; `None` when lengths differ or a vector is zero.
pub fn cosine(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (&x, &y) in a.iter().zip(b) {
        let (x, y) = (f64::from(x), f64::from(y));
        dot = x.mul_add(y, dot);
        na = x.mul_add(x, na);
        nb = y.mul_add(y, nb);
    }
    if na == 0.0 || nb == 0.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, reason = "cosine is within [-1, 1]")]
    Some((dot / (na.sqrt() * nb.sqrt())) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_known_values() {
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]).unwrap_or(0.0) - 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).unwrap_or(1.0).abs() < 1e-6);
        assert!((cosine(&[1.0, 0.0], &[-2.0, 0.0]).unwrap_or(0.0) + 1.0).abs() < 1e-6);
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), None);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 2.0]), None);
    }

    #[test]
    fn vector_checks() {
        assert!(check_vectors(&[vec![1.0], vec![2.0]], 2).is_ok());
        assert!(check_vectors(&[vec![1.0]], 2).is_err());
        assert!(check_vectors(&[vec![1.0], vec![1.0, 2.0]], 2).is_err());
        assert!(check_vectors(&[vec![f32::NAN]], 1).is_err());
        assert!(check_vectors(&[vec![]], 1).is_err());
        assert!(check_vectors(&[], 0).is_ok());
    }
}

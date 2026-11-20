//! Embed [`Embed`] documents into `rune-vectorstore` records.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use async_trait::async_trait;
use rune_vectorstore::{Record, StoreError, VectorStore};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Embed, EmbedError, Embedder};

/// Errors from [`to_records`] and [`VectorStoreExt::add_documents`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IngestError {
    /// The embedder failed or returned the wrong number of vectors.
    #[error(transparent)]
    Embed(#[from] EmbedError),
    /// The store rejected the records.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A document could not be serialized into record metadata.
    #[error("document {index} could not be serialized: {message}")]
    Serialize {
        /// Position of the document in the input.
        index: usize,
        /// The serializer's message.
        message: String,
    },
}

/// Embed `docs` in one [`Embedder::embed_documents`] call and build one
/// [`Record`] per non-blank text.
///
/// - **id**: [`Embed::embed_id`], or else the first 32 hex digits of the
///   SHA-256 of the document's JSON, so re-adding the same document replaces
///   it. A document with several texts gets `"{id}#{n}"`, where `n` is the
///   text's position among the document's texts.
/// - **content**: the embedded text.
/// - **metadata**: the document's serialized fields (a document that does
///   not serialize to a JSON object goes under the `"document"` key).
///
/// Blank texts are skipped (providers reject them), so a document with no
/// text yields no record. Wrap the embedder in a
/// [`BatchingEmbedder`](crate::BatchingEmbedder) to split large inputs into
/// several requests.
///
/// # Example
///
/// ```
/// use async_trait::async_trait;
/// use rune_chain_embed::{EmbedError, Embedder, to_records};
///
/// struct Len;
///
/// #[async_trait]
/// impl Embedder for Len {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         Ok(texts.iter().map(|t| vec![t.len() as f32, 1.0]).collect())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let records = to_records(&Len, &["hello", "world!"]).await.unwrap();
/// assert_eq!(records.len(), 2);
/// assert_eq!(records[1].content, "world!");
/// assert_eq!(records[1].vector, [6.0, 1.0]);
/// # });
/// ```
pub async fn to_records<E, T>(embedder: &E, docs: &[T]) -> Result<Vec<Record>, IngestError>
where
    E: Embedder + ?Sized,
    T: Embed + Serialize + Sync,
{
    struct Pending<'a> {
        id: String,
        metadata: BTreeMap<String, Value>,
        /// (position among the document's texts, text)
        texts: Vec<(usize, &'a str)>,
        single: bool,
    }

    let mut pending = Vec::with_capacity(docs.len());
    let mut total = 0usize;
    for (index, doc) in docs.iter().enumerate() {
        let all = doc.texts();
        let single = all.len() == 1;
        let texts: Vec<(usize, &str)> = all
            .into_iter()
            .enumerate()
            .filter(|(_, t)| !t.trim().is_empty())
            .collect();
        if texts.is_empty() {
            continue;
        }
        let value = serde_json::to_value(doc).map_err(|e| IngestError::Serialize {
            index,
            message: e.to_string(),
        })?;
        let id = doc.embed_id().unwrap_or_else(|| content_id(&value));
        let metadata = match value {
            Value::Object(map) => map.into_iter().collect(),
            other => BTreeMap::from([("document".to_owned(), other)]),
        };
        total += texts.len();
        pending.push(Pending {
            id,
            metadata,
            texts,
            single,
        });
    }
    if total == 0 {
        return Ok(Vec::new());
    }

    let flat: Vec<&str> = pending
        .iter()
        .flat_map(|p| p.texts.iter().map(|&(_, t)| t))
        .collect();
    let vectors = embedder.embed_documents(&flat).await?;
    if vectors.len() != flat.len() {
        return Err(EmbedError::InvalidResponse(format!(
            "expected {} embeddings, got {}",
            flat.len(),
            vectors.len()
        ))
        .into());
    }

    let mut vectors = vectors.into_iter();
    let mut records = Vec::with_capacity(total);
    for p in pending {
        let last = p.texts.len() - 1;
        let mut metadata = Some(p.metadata);
        for (i, (pos, text)) in p.texts.into_iter().enumerate() {
            let Some(vector) = vectors.next() else { break };
            let id = if p.single {
                p.id.clone()
            } else {
                format!("{}#{pos}", p.id)
            };
            // Move the metadata into the last record instead of cloning it.
            let meta = if i == last {
                metadata.take().unwrap_or_default()
            } else {
                metadata.clone().unwrap_or_default()
            };
            let mut record = Record::new(id, vector).with_content(text);
            record.metadata = meta;
            records.push(record);
        }
    }
    Ok(records)
}

/// 128-bit content hash of a serialized document, as hex.
fn content_id(value: &Value) -> String {
    let digest = Sha256::digest(value.to_string().as_bytes());
    let mut id = String::with_capacity(32);
    for b in &digest[..16] {
        let _ = write!(id, "{b:02x}");
    }
    id
}

/// One-call ingestion for any [`VectorStore`].
///
/// # Example
///
/// ```
/// use async_trait::async_trait;
/// use rune_chain_embed::{EmbedError, Embedder, VectorStoreExt};
/// use rune_vectorstore::{InMemoryVectorStore, Options, VectorStore};
///
/// struct Len;
///
/// #[async_trait]
/// impl Embedder for Len {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         Ok(texts.iter().map(|t| vec![t.len() as f32, 1.0]).collect())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let store = InMemoryVectorStore::new(Options::default());
/// let added = store.add_documents(&Len, &["a", "bb", "ccc"]).await.unwrap();
/// assert_eq!(added, 3);
/// assert_eq!(store.len().await.unwrap(), 3);
/// # });
/// ```
#[async_trait]
pub trait VectorStoreExt: VectorStore {
    /// Embed `docs` with [`to_records`] and upsert the records. Returns the
    /// number of records written.
    async fn add_documents<E, T>(&self, embedder: &E, docs: &[T]) -> Result<usize, IngestError>
    where
        E: Embedder + ?Sized,
        T: Embed + Serialize + Sync;
}

#[async_trait]
impl<S: VectorStore + ?Sized> VectorStoreExt for S {
    async fn add_documents<E, T>(&self, embedder: &E, docs: &[T]) -> Result<usize, IngestError>
    where
        E: Embedder + ?Sized,
        T: Embed + Serialize + Sync,
    {
        let records = to_records(embedder, docs).await?;
        let n = records.len();
        if n > 0 {
            self.upsert(records).await?;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EmbedText;

    struct Len;

    #[async_trait]
    impl Embedder for Len {
        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            Ok(texts
                .iter()
                .map(|t| vec![f32::from(u16::try_from(t.len()).unwrap_or(0)), 1.0])
                .collect())
        }
    }

    struct Short;

    #[async_trait]
    impl Embedder for Short {
        async fn embed_batch(&self, _: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            Ok(vec![vec![1.0]])
        }
    }

    #[derive(Serialize)]
    struct Doc {
        id: u32,
        texts: Vec<String>,
    }

    impl Embed for Doc {
        fn embed_texts<'a>(&'a self, out: &mut Vec<&'a str>) {
            self.texts.push_texts(out);
        }
        fn embed_id(&self) -> Option<String> {
            Some(self.id.to_string())
        }
    }

    #[tokio::test]
    async fn multi_text_docs_get_suffixed_ids_and_shared_metadata() {
        let docs = [
            Doc {
                id: 7,
                texts: vec!["ab".into(), "  ".into(), "abcd".into()],
            },
            Doc {
                id: 8,
                texts: vec!["x".into()],
            },
            Doc {
                id: 9,
                texts: vec![],
            },
        ];
        let r = to_records(&Len, &docs).await.unwrap();
        let ids: Vec<&str> = r.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["7#0", "7#2", "8"]);
        assert_eq!(r[1].content, "abcd");
        assert_eq!(r[1].vector, [4.0, 1.0]);
        assert_eq!(r[0].metadata["id"], 7);
        assert_eq!(r[1].metadata["id"], 7);
        assert_eq!(r[2].metadata["texts"], serde_json::json!(["x"]));
    }

    #[tokio::test]
    async fn content_ids_are_stable_and_distinct() {
        let a = to_records(&Len, &["same", "other"]).await.unwrap();
        let b = to_records(&Len, &["same"]).await.unwrap();
        assert_eq!(a[0].id, b[0].id);
        assert_ne!(a[0].id, a[1].id);
        assert_eq!(a[0].id.len(), 32);
        assert_eq!(a[0].metadata["document"], "same");
    }

    #[tokio::test]
    async fn wrong_vector_count_is_an_error_not_a_panic() {
        let err = to_records(&Short, &["a", "b"]).await.unwrap_err();
        assert!(matches!(
            err,
            IngestError::Embed(EmbedError::InvalidResponse(_))
        ));
    }

    #[tokio::test]
    async fn nothing_to_embed_skips_the_embedder() {
        let r = to_records(&Short, &["", " \n"]).await.unwrap();
        assert_eq!(r, []);
    }

    #[tokio::test]
    async fn store_errors_surface() {
        use rune_vectorstore::InMemoryVectorStore;
        let store =
            InMemoryVectorStore::new(rune_vectorstore::Options::default().with_dimension(3));
        let err = store.add_documents(&Len, &["dim 2"]).await.unwrap_err();
        assert!(matches!(err, IngestError::Store(_)));
    }
}

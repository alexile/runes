use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use rune_vectorstore::{Query, Record, Value};

use crate::document::{Document, StoreError};
use crate::store::VectorStore;

/// Adapter that runs [`RetrievalQaChain`](crate::RetrievalQaChain) on any
/// [`rune_vectorstore::VectorStore`] backend.
///
/// [`VectorStore::add`] assigns each document a fresh id
/// (`<prefix><counter>`, default prefix `doc-`) and upserts it with its
/// content and metadata (as JSON strings); [`VectorStore::search`] runs a
/// top-`k` query. Non-string metadata written to the backend directly comes
/// back as its JSON text.
/// Use a distinct prefix per adapter if several write to the same backend,
/// and reach the backend through [`inner`](Self::inner) for upserts by your
/// own ids, deletes, filters or scores.
///
/// # Example
///
/// ```rust
/// use rune_chain_retrieval::{Document, VectorStore, VectorStoreBackend};
/// use rune_vectorstore::{InMemoryVectorStore, Options};
///
/// # tokio_test::block_on(async {
/// let store = VectorStoreBackend::new(InMemoryVectorStore::new(Options::default()));
/// store.add(&[
///     (Document::new("Paris is in France."), vec![1.0, 0.0]),
///     (Document::new("Berlin is in Germany."), vec![0.0, 1.0]),
/// ]).await?;
///
/// let docs = store.search(&[0.9, 0.1], 1).await?;
/// assert_eq!(docs[0].content, "Paris is in France.");
/// # Ok::<(), rune_chain_retrieval::StoreError>(())
/// # }).unwrap();
/// ```
#[derive(Debug)]
pub struct VectorStoreBackend<S> {
    inner: S,
    prefix: String,
    next_id: AtomicU64,
}

impl<S: rune_vectorstore::VectorStore> VectorStoreBackend<S> {
    /// Wrap `inner`, generating ids `doc-0`, `doc-1`, ….
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            prefix: "doc-".to_owned(),
            next_id: AtomicU64::new(0),
        }
    }

    /// Use `prefix` for generated ids instead of `doc-`.
    #[must_use]
    pub fn with_id_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The wrapped backend.
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

/// [`Document`] metadata is string-valued: strings pass through, any other
/// JSON value (written to the backend directly) is rendered as JSON text.
fn meta_to_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn store_err(err: &rune_vectorstore::StoreError) -> StoreError {
    StoreError::Other(err.to_string())
}

#[async_trait]
impl<S: rune_vectorstore::VectorStore> VectorStore for VectorStoreBackend<S> {
    async fn add(&self, documents: &[(Document, Vec<f32>)]) -> Result<(), StoreError> {
        if documents.is_empty() {
            return Ok(());
        }
        let records = documents
            .iter()
            .map(|(doc, vector)| {
                let n = self.next_id.fetch_add(1, Ordering::Relaxed);
                let mut record = Record::new(format!("{}{n}", self.prefix), vector.clone())
                    .with_content(doc.content.clone());
                record.metadata.extend(
                    doc.metadata
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone()))),
                );
                record
            })
            .collect();
        self.inner.upsert(records).await.map_err(|e| store_err(&e))
    }

    async fn search(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<Document>, StoreError> {
        let hits = self
            .inner
            .query(&Query::new(query_embedding.to_vec(), top_k))
            .await
            .map_err(|e| store_err(&e))?;
        Ok(hits
            .into_iter()
            .map(|hit| Document {
                content: hit.record.content,
                metadata: hit
                    .record
                    .metadata
                    .into_iter()
                    .map(|(k, v)| (k, meta_to_string(v)))
                    .collect(),
            })
            .collect())
    }
}

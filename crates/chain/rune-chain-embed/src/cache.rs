//! Caching embeddings: [`CacheBackedEmbedder`] over a pluggable
//! [`EmbeddingStore`], with the bounded in-memory [`LruStore`].

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{EmbedError, Embedder, check_dimensions};

/// A key-value store for embedding vectors, used by [`CacheBackedEmbedder`].
///
/// Keys are built by [`cache_key`]. Implement this for Redis, a database
/// table, a file, …; [`LruStore`] is the bounded in-memory implementation.
/// Store errors are returned to the caller of the embedder (use
/// [`EmbedError::Other`] for them).
#[async_trait]
pub trait EmbeddingStore: Send + Sync {
    /// Look up `keys`, returning one entry per key in the same order
    /// (`None` for a miss).
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<Vec<f32>>>, EmbedError>;

    /// Store `entries`, replacing any existing value for the same key.
    async fn put_many(&self, entries: Vec<(String, Vec<f32>)>) -> Result<(), EmbedError>;
}

#[async_trait]
impl<S: EmbeddingStore + ?Sized> EmbeddingStore for Arc<S> {
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<Vec<f32>>>, EmbedError> {
        (**self).get_many(keys).await
    }

    async fn put_many(&self, entries: Vec<(String, Vec<f32>)>) -> Result<(), EmbedError> {
        (**self).put_many(entries).await
    }
}

/// Whether a text is embedded as a search query or as a document; part of
/// the [`cache_key`], since some providers embed the two differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InputKind {
    /// A search query ([`Embedder::embed`], [`Embedder::embed_query`]).
    Query,
    /// A document ([`Embedder::embed_batch`], [`Embedder::embed_documents`]).
    Document,
}

/// The cache key of `text`: `"{namespace}:{q|d}:{sha256(text) as hex}"`.
///
/// The text itself is not stored in the key, so keys have a bounded size and
/// do not leak content into the store's key space.
///
/// ```rust
/// use rune_chain_embed::{InputKind, cache_key};
///
/// assert_eq!(
///     cache_key("text-embedding-3-small", InputKind::Document, "abc"),
///     "text-embedding-3-small:d:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
#[must_use]
pub fn cache_key(namespace: &str, kind: InputKind, text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let tag = match kind {
        InputKind::Query => 'q',
        InputKind::Document => 'd',
    };
    let mut key = String::with_capacity(namespace.len() + 3 + 64);
    key.push_str(namespace);
    key.push(':');
    key.push(tag);
    key.push(':');
    for byte in digest {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// A bounded, thread-safe, in-memory least-recently-used [`EmbeddingStore`].
///
/// Holds at most `capacity` vectors; storing one more evicts the entry that
/// was least recently read or written. Clones share the same cache.
///
/// ```rust
/// use rune_chain_embed::{EmbeddingStore, LruStore};
///
/// # tokio_test::block_on(async {
/// let store = LruStore::new(2);
/// store.put_many(vec![("a".into(), vec![1.0]), ("b".into(), vec![2.0])]).await.unwrap();
/// store.get_many(&["a".into()]).await.unwrap(); // touch "a"
/// store.put_many(vec![("c".into(), vec![3.0])]).await.unwrap(); // evicts "b"
/// let hits = store.get_many(&["a".into(), "b".into(), "c".into()]).await.unwrap();
/// assert_eq!(hits, vec![Some(vec![1.0]), None, Some(vec![3.0])]);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct LruStore {
    inner: Arc<Mutex<Lru>>,
}

#[derive(Debug)]
struct Lru {
    capacity: usize,
    tick: u64,
    entries: HashMap<String, (Vec<f32>, u64)>,
    order: BTreeMap<u64, String>,
}

impl Lru {
    fn touch(&mut self, key: &str) -> Option<Vec<f32>> {
        self.tick += 1;
        let tick = self.tick;
        let (vector, used) = self.entries.get_mut(key)?;
        self.order.remove(used);
        *used = tick;
        self.order.insert(tick, key.to_owned());
        Some(vector.clone())
    }

    fn insert(&mut self, key: String, vector: Vec<f32>) {
        if self.capacity == 0 {
            return;
        }
        self.tick += 1;
        if let Some((_, used)) = self.entries.insert(key.clone(), (vector, self.tick)) {
            self.order.remove(&used);
        }
        self.order.insert(self.tick, key);
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

impl LruStore {
    /// A store holding at most `capacity` vectors (`0` stores nothing).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Lru {
                capacity,
                tick: 0,
                entries: HashMap::new(),
                order: BTreeMap::new(),
            })),
        }
    }

    /// Number of cached vectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The maximum number of cached vectors.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Remove every entry.
    pub fn clear(&self) {
        let mut lru = self.lock();
        lru.entries.clear();
        lru.order.clear();
    }

    fn lock(&self) -> MutexGuard<'_, Lru> {
        // The map is consistent after every statement, so a poisoned lock
        // (a panic elsewhere while holding it) is safe to keep using.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl EmbeddingStore for LruStore {
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<Vec<f32>>>, EmbedError> {
        let mut lru = self.lock();
        Ok(keys.iter().map(|k| lru.touch(k)).collect())
    }

    async fn put_many(&self, entries: Vec<(String, Vec<f32>)>) -> Result<(), EmbedError> {
        {
            let mut lru = self.lock();
            for (key, vector) in entries {
                lru.insert(key, vector);
            }
        }
        Ok(())
    }
}

/// An [`Embedder`] that caches another embedder's vectors in an
/// [`EmbeddingStore`], like `LangChain`'s `CacheBackedEmbeddings`.
///
/// Entries are keyed by namespace (by default the inner embedder's
/// [`model_id`](Embedder::model_id)), input kind and the SHA-256 of the text
/// (see [`cache_key`]). A batch looks every text up at once and sends only
/// the misses — each distinct text once — to the inner embedder.
///
/// Documents ([`embed_batch`](Embedder::embed_batch),
/// [`embed_documents`](Embedder::embed_documents)) are always cached.
/// Queries ([`embed`](Embedder::embed), [`embed_query`](Embedder::embed_query))
/// are passed through unless [`cache_queries`](Self::cache_queries) is set,
/// since they rarely repeat and would evict documents from a bounded store.
///
/// ```rust
/// use rune_chain_embed::{CacheBackedEmbedder, EmbedError, Embedder, LruStore};
/// use async_trait::async_trait;
///
/// struct Lengths;
///
/// #[async_trait]
/// impl Embedder for Lengths {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         Ok(texts.iter().map(|t| vec![t.len() as f32]).collect())
///     }
///     fn model_id(&self) -> Option<String> {
///         Some("lengths-v1".into())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let cached = CacheBackedEmbedder::new(Lengths, LruStore::new(10_000)).unwrap();
/// let first = cached.embed_batch(&["a", "bb"]).await.unwrap(); // two misses
/// let again = cached.embed_batch(&["bb", "ccc"]).await.unwrap(); // embeds only "ccc"
/// assert_eq!(again, vec![vec![2.0], vec![3.0]]);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct CacheBackedEmbedder<E, S> {
    inner: E,
    store: S,
    namespace: String,
    cache_queries: bool,
}

impl<E: Embedder, S: EmbeddingStore> CacheBackedEmbedder<E, S> {
    /// Cache `inner` in `store`, namespaced by `inner.model_id()`.
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] when `inner` reports no model id; use
    /// [`with_namespace`](Self::with_namespace) then.
    pub fn new(inner: E, store: S) -> Result<Self, EmbedError> {
        let namespace = inner.model_id().ok_or_else(|| {
            EmbedError::InvalidConfig(
                "the embedder reports no model_id; name a cache namespace with \
                 CacheBackedEmbedder::with_namespace"
                    .into(),
            )
        })?;
        Ok(Self::with_namespace(inner, store, namespace))
    }

    /// Cache `inner` in `store` under an explicit `namespace`. Use a distinct
    /// namespace for every model and option set that changes the vectors.
    pub fn with_namespace(inner: E, store: S, namespace: impl Into<String>) -> Self {
        Self {
            inner,
            store,
            namespace: namespace.into(),
            cache_queries: false,
        }
    }

    /// Also cache query embeddings (default `false`), keyed separately from
    /// documents.
    #[must_use]
    pub const fn cache_queries(mut self, yes: bool) -> Self {
        self.cache_queries = yes;
        self
    }

    /// The cache namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The wrapped embedder.
    pub const fn inner(&self) -> &E {
        &self.inner
    }

    /// The store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    async fn cached(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = texts
            .iter()
            .map(|t| cache_key(&self.namespace, kind, t))
            .collect();
        let mut found = self.store.get_many(&keys).await?;
        if found.len() != keys.len() {
            return Err(EmbedError::Other(format!(
                "embedding store returned {} entries for {} keys",
                found.len(),
                keys.len()
            )));
        }

        // Distinct missing texts, each embedded once.
        let mut slot_of: HashMap<&str, usize> = HashMap::new();
        let mut misses: Vec<&str> = Vec::new();
        let mut miss_keys: Vec<String> = Vec::new();
        for (i, hit) in found.iter().enumerate() {
            if hit.is_none() && !slot_of.contains_key(texts[i]) {
                slot_of.insert(texts[i], misses.len());
                misses.push(texts[i]);
                miss_keys.push(keys[i].clone());
            }
        }

        if !misses.is_empty() {
            let fresh = match kind {
                InputKind::Query => {
                    let mut out = Vec::with_capacity(misses.len());
                    for text in &misses {
                        out.push(self.inner.embed_query(text).await?);
                    }
                    out
                }
                InputKind::Document => self.inner.embed_documents(&misses).await?,
            };
            if fresh.len() != misses.len() {
                return Err(EmbedError::InvalidResponse(format!(
                    "expected {} embeddings, got {}",
                    misses.len(),
                    fresh.len()
                )));
            }
            check_dimensions(&fresh, None)?;
            for (i, slot) in found.iter_mut().enumerate() {
                if slot.is_none()
                    && let Some(&j) = slot_of.get(texts[i])
                {
                    *slot = Some(fresh[j].clone());
                }
            }
            self.store
                .put_many(miss_keys.into_iter().zip(fresh).collect())
                .await?;
        }

        let vectors: Vec<Vec<f32>> = found.into_iter().flatten().collect();
        if vectors.len() != texts.len() {
            return Err(EmbedError::Other("embedding cache lost an entry".into()));
        }
        // A cached vector from another vector space shows up as a length
        // mismatch with the fresh ones.
        check_dimensions(&vectors, None)?;
        Ok(vectors)
    }

    async fn single(&self, text: &str, kind: InputKind) -> Result<Vec<f32>, EmbedError> {
        self.cached(&[text], kind)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| EmbedError::Other("embedding cache returned no vector".into()))
    }
}

#[async_trait]
impl<E: Embedder, S: EmbeddingStore> Embedder for CacheBackedEmbedder<E, S> {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.cached(texts, InputKind::Document).await
    }

    async fn embed_documents(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.cached(texts, InputKind::Document).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        if self.cache_queries {
            self.single(text, InputKind::Query).await
        } else {
            self.inner.embed(text).await
        }
    }

    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        if self.cache_queries {
            self.single(text, InputKind::Query).await
        } else {
            self.inner.embed_query(text).await
        }
    }

    fn model_id(&self) -> Option<String> {
        self.inner.model_id()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;

    /// Embeds as `[len]` and records every call's inputs.
    #[derive(Default)]
    struct Recording {
        calls: StdMutex<Vec<Vec<String>>>,
        queries: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl Embedder for Recording {
        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            self.calls
                .lock()
                .unwrap()
                .push(texts.iter().map(ToString::to_string).collect());
            #[allow(clippy::cast_precision_loss, reason = "short test strings")]
            Ok(texts.iter().map(|t| vec![t.len() as f32, 1.0]).collect())
        }
        async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            self.queries.lock().unwrap().push(text.to_string());
            #[allow(clippy::cast_precision_loss, reason = "short test strings")]
            Ok(vec![text.len() as f32, -1.0])
        }
        fn model_id(&self) -> Option<String> {
            Some("rec".into())
        }
    }

    fn calls(e: &CacheBackedEmbedder<Recording, LruStore>) -> Vec<Vec<String>> {
        e.inner().calls.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn batch_embeds_only_distinct_misses_in_order() {
        let cached = CacheBackedEmbedder::new(Recording::default(), LruStore::new(100)).unwrap();
        assert_eq!(cached.namespace(), "rec");
        let out = cached.embed_batch(&["aa", "b", "aa"]).await.unwrap();
        assert_eq!(out, vec![vec![2.0, 1.0], vec![1.0, 1.0], vec![2.0, 1.0]]);
        let out = cached.embed_documents(&["ccc", "b", "aa"]).await.unwrap();
        assert_eq!(out, vec![vec![3.0, 1.0], vec![1.0, 1.0], vec![2.0, 1.0]]);
        assert_eq!(calls(&cached), vec![vec!["aa", "b"], vec!["ccc"]]);
        assert_eq!(cached.store().len(), 3);
        // Fully cached: no call at all.
        cached.embed_batch(&["b", "ccc"]).await.unwrap();
        assert_eq!(cached.embed_batch(&[]).await.unwrap().len(), 0);
        assert_eq!(calls(&cached).len(), 2);
    }

    #[tokio::test]
    async fn queries_pass_through_unless_enabled_and_are_keyed_apart() {
        let store = LruStore::new(100);
        let plain = CacheBackedEmbedder::new(Recording::default(), store.clone()).unwrap();
        assert_eq!(plain.embed_query("q").await.unwrap(), vec![1.0, -1.0]);
        assert!(store.is_empty());

        let cached = CacheBackedEmbedder::new(Recording::default(), store.clone())
            .unwrap()
            .cache_queries(true);
        cached.embed_batch(&["q"]).await.unwrap();
        assert_eq!(cached.embed_query("q").await.unwrap(), vec![1.0, -1.0]);
        assert_eq!(cached.embed("q").await.unwrap(), vec![1.0, -1.0]);
        assert_eq!(cached.inner().queries.lock().unwrap().len(), 1);
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn namespaces_isolate_models() {
        struct Anonymous;
        #[async_trait]
        impl Embedder for Anonymous {
            async fn embed_batch(&self, t: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
                Ok(t.iter().map(|_| vec![9.0]).collect())
            }
        }
        let store = LruStore::new(10);
        assert!(matches!(
            CacheBackedEmbedder::new(Anonymous, store.clone()),
            Err(EmbedError::InvalidConfig(_))
        ));
        let other = CacheBackedEmbedder::with_namespace(Anonymous, store.clone(), "anon");
        let rec = CacheBackedEmbedder::new(Recording::default(), store.clone()).unwrap();
        assert_eq!(other.embed_batch(&["x"]).await.unwrap(), vec![vec![9.0]]);
        assert_eq!(rec.embed_batch(&["x"]).await.unwrap(), vec![vec![1.0, 1.0]]);
    }

    #[tokio::test]
    async fn poisoned_entry_is_a_dimension_error() {
        let store = LruStore::new(10);
        let rec = CacheBackedEmbedder::new(Recording::default(), store.clone()).unwrap();
        store
            .put_many(vec![(
                cache_key("rec", InputKind::Document, "x"),
                vec![1.0, 2.0, 3.0],
            )])
            .await
            .unwrap();
        assert!(matches!(
            rec.embed_batch(&["x", "y"]).await,
            Err(EmbedError::DimensionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn lru_is_bounded() {
        let store = LruStore::new(2);
        assert_eq!(store.capacity(), 2);
        for k in ["a", "b", "c"] {
            store.put_many(vec![(k.into(), vec![0.0])]).await.unwrap();
        }
        assert_eq!(store.len(), 2);
        let got = store.get_many(&["a".into(), "c".into()]).await.unwrap();
        assert_eq!(got, vec![None, Some(vec![0.0])]);
        // Overwrite keeps the size.
        store.put_many(vec![("c".into(), vec![1.0])]).await.unwrap();
        assert_eq!(store.len(), 2);
        store.clear();
        assert!(store.is_empty());
        let none = LruStore::new(0);
        none.put_many(vec![("a".into(), vec![0.0])]).await.unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn keys_differ_by_kind_and_namespace() {
        let d = cache_key("m", InputKind::Document, "t");
        assert_ne!(d, cache_key("m", InputKind::Query, "t"));
        assert_ne!(d, cache_key("n", InputKind::Document, "t"));
        assert_eq!(d.len(), "m:d:".len() + 64);
    }
}

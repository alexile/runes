//! Response caching for [`Llm`] calls.
//!
//! [`LlmExt::with_cache`](crate::LlmExt::with_cache) wraps a model so that a
//! request it has already answered is served from an [`LlmCache`] instead of
//! calling the provider again. [`InMemoryLlmCache`] is a bounded LRU.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    hash::{Hash, Hasher},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;

use crate::{
    EventStream, FunctionDefinition, GenerateResult, Llm, LlmError, Message, ResponseFormat,
    StreamAccumulator, ToolChoice, ext::LlmStream, stream_event::result_stream,
};

/// Identifies one model request: the method, an optional namespace, the
/// messages, tools, tool choice and response format.
///
/// The key keeps the request's canonical bytes (compact JSON), and equality
/// compares them, so two different requests never share an entry in
/// [`InMemoryLlmCache`]. [`stable_hash`](Self::stable_hash) is a 64-bit
/// FNV-1a digest of those bytes that stays the same across processes, for
/// use as a lookup key in external stores. It is not collision resistant:
/// an external cache shared between users should store and compare
/// [`as_bytes`](Self::as_bytes) (or a cryptographic digest of it) as well.
#[derive(Clone, PartialEq, Eq)]
pub struct CacheKey {
    bytes: Arc<[u8]>,
}

impl CacheKey {
    /// Build the key for a request. `namespace` should name the model and
    /// any settings that change its output (temperature, max tokens, …).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{CacheKey, Message};
    ///
    /// let a = CacheKey::new("gpt-x", &[Message::human("hi")], &[], None, None);
    /// let b = CacheKey::new("gpt-x", &[Message::human("hi")], &[], None, None);
    /// let c = CacheKey::new("gpt-y", &[Message::human("hi")], &[], None, None);
    /// assert_eq!(a, b);
    /// assert_eq!(a.stable_hash(), b.stable_hash());
    /// assert_ne!(a, c);
    /// ```
    pub fn new(
        namespace: &str,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<&ToolChoice>,
        format: Option<&ResponseFormat>,
    ) -> Self {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            ns: &'a str,
            messages: &'a [Message],
            tools: &'a [FunctionDefinition],
            tool_choice: Option<&'a ToolChoice>,
            format: Option<&'a ResponseFormat>,
        }
        let mut bytes = Vec::new();
        let request = Request {
            ns: namespace,
            messages,
            tools,
            tool_choice,
            format,
        };
        // Serialising these types cannot fail (all map keys are strings).
        // If it ever did, end the key with a unique tag so it never matches
        // anything: a cache miss is fine, a wrong hit is not.
        if serde_json::to_writer(&mut bytes, &request).is_err() {
            static UNIQUE: AtomicU64 = AtomicU64::new(0);
            let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
            bytes.push(0);
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        Self {
            bytes: bytes.into(),
        }
    }

    /// The canonical request bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The size of the canonical request in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the key holds no bytes (never the case for keys built by
    /// [`CacheKey::new`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 64-bit FNV-1a of [`as_bytes`](Self::as_bytes); stable across
    /// processes and platforms.
    #[must_use]
    pub fn stable_hash(&self) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        self.bytes
            .iter()
            .fold(OFFSET, |h, &b| (h ^ u64::from(b)).wrapping_mul(PRIME))
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The bytes are the prompt: show only the digest and size.
        f.debug_struct("CacheKey")
            .field("hash", &format_args!("{:016x}", self.stable_hash()))
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A store of model responses, keyed by request.
///
/// Implementations must be safe to share between tasks. Lookups are
/// synchronous; keep them fast (an in-memory map, or a local cache in front
/// of a remote one).
pub trait LlmCache: Send + Sync {
    /// The cached response for `key`, if any.
    fn get(&self, key: &CacheKey) -> Option<GenerateResult>;
    /// Store the response for `key`.
    fn put(&self, key: CacheKey, value: GenerateResult);
}

impl<T: LlmCache + ?Sized> LlmCache for Arc<T> {
    fn get(&self, key: &CacheKey) -> Option<GenerateResult> {
        (**self).get(key)
    }

    fn put(&self, key: CacheKey, value: GenerateResult) {
        (**self).put(key, value);
    }
}

/// Default per-entry size limit of [`InMemoryLlmCache`]: 1 MiB.
pub const DEFAULT_MAX_CACHE_ENTRY_BYTES: usize = 1 << 20;

/// A bounded, thread-safe, least-recently-used [`LlmCache`].
///
/// It holds at most `capacity` entries and skips any entry whose request
/// plus response text is larger than [`max_entry_bytes`](Self::max_entry_bytes)
/// (1 MiB by default), so memory use is bounded by roughly
/// `capacity × max_entry_bytes`. Lookups and inserts are `O(log n)`.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{CacheKey, GenerateResult, InMemoryLlmCache, LlmCache, Message};
///
/// let cache = InMemoryLlmCache::new(2);
/// let key = CacheKey::new("m", &[Message::human("hi")], &[], None, None);
/// cache.put(key.clone(), GenerateResult::from_text("hello"));
/// assert_eq!(cache.get(&key).unwrap().generation, "hello");
/// ```
pub struct InMemoryLlmCache {
    capacity: usize,
    max_entry_bytes: usize,
    state: Mutex<Lru>,
}

#[derive(Default)]
struct Lru {
    entries: HashMap<CacheKey, (GenerateResult, u64)>,
    order: BTreeMap<u64, CacheKey>,
    tick: u64,
}

impl Lru {
    const fn bump(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
}

impl InMemoryLlmCache {
    /// A cache holding at most `capacity` entries (`0` disables caching).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            max_entry_bytes: DEFAULT_MAX_CACHE_ENTRY_BYTES,
            state: Mutex::default(),
        }
    }

    /// Skip entries whose request plus response text exceeds `bytes`.
    #[must_use]
    pub const fn max_entry_bytes(mut self, bytes: usize) -> Self {
        self.max_entry_bytes = bytes;
        self
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// `true` when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry.
    pub fn clear(&self) {
        let mut lru = self.lock();
        lru.entries.clear();
        lru.order.clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Lru> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for InMemoryLlmCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryLlmCache")
            .field("capacity", &self.capacity)
            .field("max_entry_bytes", &self.max_entry_bytes)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl LlmCache for InMemoryLlmCache {
    fn get(&self, key: &CacheKey) -> Option<GenerateResult> {
        let mut lru = self.lock();
        let tick = lru.bump();
        let (value, used) = lru.entries.get_mut(key)?;
        let old = std::mem::replace(used, tick);
        let value = value.clone();
        if let Some(k) = lru.order.remove(&old) {
            lru.order.insert(tick, k);
        }
        drop(lru);
        Some(value)
    }

    fn put(&self, key: CacheKey, value: GenerateResult) {
        if self.capacity == 0
            || key.len().saturating_add(value.generation.len()) > self.max_entry_bytes
        {
            return;
        }
        let mut lru = self.lock();
        let tick = lru.bump();
        if let Some((_, old)) = lru.entries.insert(key.clone(), (value, tick)) {
            lru.order.remove(&old);
        }
        lru.order.insert(tick, key);
        while lru.entries.len() > self.capacity {
            let Some((_, oldest)) = lru.order.pop_first() else {
                break;
            };
            lru.entries.remove(&oldest);
        }
        drop(lru);
    }
}

/// An [`Llm`] that answers repeated requests from an [`LlmCache`]; built by
/// [`LlmExt::with_cache`](crate::LlmExt::with_cache).
///
/// [`generate`](Llm::generate), [`generate_with_tools`](Llm::generate_with_tools)
/// and [`generate_structured`](Llm::generate_structured) are cached; errors
/// are not. [`stream`](Llm::stream) always goes to the model.
/// [`stream_events`](Llm::stream_events) with tools shares the
/// `generate_with_tools` entry: a hit is replayed as events, and a stream
/// that ends cleanly is stored.
///
/// The key covers only the request, not the model's settings, so give each
/// model configuration that shares a cache its own
/// [`namespace`](Self::namespace).
pub struct CachedLlm<L> {
    inner: L,
    cache: Arc<dyn LlmCache>,
    namespace: Arc<str>,
}

impl<L> CachedLlm<L> {
    pub(crate) fn new(inner: L, cache: Arc<dyn LlmCache>) -> Self {
        Self {
            inner,
            cache,
            namespace: Arc::from(""),
        }
    }

    /// Keep this model's entries apart from other models sharing the cache.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<Arc<str>>) -> Self {
        self.namespace = namespace.into();
        self
    }

    async fn cached<F>(&self, key: CacheKey, fut: F) -> Result<GenerateResult, LlmError>
    where
        F: Future<Output = Result<GenerateResult, LlmError>> + Send,
        L: Sync,
    {
        if let Some(hit) = self.cache.get(&key) {
            return Ok(hit);
        }
        let result = fut.await?;
        self.cache.put(key, result.clone());
        Ok(result)
    }
}

impl<L> fmt::Debug for CachedLlm<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedLlm")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<L: Llm> Llm for CachedLlm<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let key = CacheKey::new(&self.namespace, messages, &[], None, None);
        self.cached(key, self.inner.generate(messages)).await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        // An empty tool list is still a different call from `generate`, so
        // mark it with an explicit choice.
        let choice = tool_choice.clone().unwrap_or(ToolChoice::Auto);
        let key = CacheKey::new(&self.namespace, messages, tools, Some(&choice), None);
        self.cached(
            key,
            self.inner.generate_with_tools(messages, tools, tool_choice),
        )
        .await
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.inner.stream(messages).await
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        let Some(tools) = tools.filter(|t| !t.is_empty()) else {
            return self.inner.stream_events(messages, tools, tool_choice).await;
        };
        let choice = tool_choice.clone().unwrap_or(ToolChoice::Auto);
        let key = CacheKey::new(&self.namespace, messages, tools, Some(&choice), None);
        if let Some(hit) = self.cache.get(&key) {
            return Ok(result_stream(hit));
        }
        let mut inner = self
            .inner
            .stream_events(messages, Some(tools), tool_choice)
            .await?;
        let cache = Arc::clone(&self.cache);
        let mut acc = Some(StreamAccumulator::new());
        Ok(Box::pin(futures::stream::poll_fn(move |cx| {
            let item = futures::ready!(futures::StreamExt::poll_next_unpin(&mut inner, cx));
            match &item {
                Some(Ok(event)) => {
                    if let Some(a) = acc.as_mut()
                        && a.push(event).is_err()
                    {
                        acc = None;
                    }
                }
                Some(Err(_)) => acc = None,
                None => {
                    if let Some(a) = acc.take() {
                        cache.put(key.clone(), a.finish());
                    }
                }
            }
            std::task::Poll::Ready(item)
        })))
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        let key = CacheKey::new(&self.namespace, messages, &[], None, Some(format));
        self.cached(key, self.inner.generate_structured(messages, format))
            .await
    }
}

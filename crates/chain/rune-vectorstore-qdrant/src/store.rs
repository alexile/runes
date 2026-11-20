//! The Qdrant-backed [`VectorStore`].

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Method;
use rune_vectorstore::{Filter, Hit, Metric, Query, Record, StoreError, VectorStore};
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value, json};

use crate::config::QdrantConfig;
use crate::filter::{QdrantFilter, qdrant_filter};
use crate::http::{CallError, Transport};
use crate::id::PointId;

const POINTS_PREFIX: &[u8] = b"{\"points\":[";
const POINTS_SUFFIX: &[u8] = b"]}";

/// A [`VectorStore`] on a Qdrant collection, over Qdrant's REST API.
///
/// - **Collections** are created on first use (unless
///   [`create_collection(false)`](QdrantConfig::create_collection)) with the
///   configured metric, size and on-disk options. An existing collection must
///   use the same metric and size, or calls fail with a clear error.
/// - **Ids**: record ids map to point ids with [`PointId::from_record_id`];
///   the original id is kept in the payload.
/// - **Upserts** are validated up front (ids, duplicates, dimensions,
///   NaN/inf, zero vectors under cosine), then sent in batches bounded by
///   point count and body size, each acknowledged by the server before the
///   next (`wait=true`). A batch that fails leaves earlier batches applied.
/// - **Scores** follow [`Metric`]: higher is more similar, so Euclidean
///   scores are the negated Qdrant distance and `min_score` becomes Qdrant's
///   `score_threshold` accordingly.
/// - **Filters** are translated by [`qdrant_filter`]; a filter Qdrant cannot
///   express is an error, never silently dropped.
/// - **Cosine**: Qdrant normalises vectors when it stores them, so vectors
///   read back are unit length.
///
/// Reading from a collection that does not exist yet behaves like an empty
/// store.
///
/// # Example
///
/// ```no_run
/// use rune_vectorstore::{Filter, Query, Record, VectorStore};
/// use rune_vectorstore_qdrant::{QdrantConfig, QdrantStore};
///
/// # async fn run() -> Result<(), rune_vectorstore::StoreError> {
/// let store = QdrantStore::new(QdrantConfig::new("http://localhost:6333", "docs"))?;
/// store
///     .upsert(vec![
///         Record::new("rust", vec![0.9, 0.1]).with_content("Rust").with_meta("year", 2015),
///         Record::new("go", vec![0.8, 0.3]).with_content("Go").with_meta("year", 2012),
///     ])
///     .await?;
/// let q = Query::new(vec![1.0, 0.0], 1).with_filter(Filter::lt("year", 2014));
/// assert_eq!(store.query(&q).await?[0].record.content, "Go");
/// # Ok(()) }
/// ```
pub struct QdrantStore {
    transport: Transport,
    collection: String,
    metric: Metric,
    dimension: Option<usize>,
    vector_name: Option<String>,
    create_collection: bool,
    on_disk_payload: bool,
    on_disk_vectors: bool,
    batch_size: usize,
    max_batch_bytes: usize,
    keys: Keys,
    /// The verified collection size, once the collection is known to exist.
    known: Mutex<Option<usize>>,
}

struct Keys {
    content: String,
    metadata: String,
    id: String,
}

impl fmt::Debug for QdrantStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QdrantStore")
            .field("transport", &self.transport)
            .field("collection", &self.collection)
            .field("metric", &self.metric)
            .field("dimension", &self.dimension)
            .field("vector_name", &self.vector_name)
            .finish_non_exhaustive()
    }
}

impl QdrantStore {
    /// A store for `config`. No request is sent until the first call.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for an invalid configuration: a bad URL, an
    /// API key over plain HTTP to a remote host, a collection or vector name
    /// that is not plain ASCII, or clashing payload keys.
    pub fn new(config: QdrantConfig) -> Result<Self, StoreError> {
        config.validate()?;
        if !matches!(
            config.metric,
            Metric::Cosine | Metric::DotProduct | Metric::Euclidean
        ) {
            return Err(StoreError::Backend(format!(
                "metric {:?} has no Qdrant distance",
                config.metric
            )));
        }
        let client = config.build_client();
        Ok(Self {
            transport: Transport {
                base_url: config.url,
                api_key: config.api_key,
                client,
                timeout: config.timeout,
                max_retries: config.max_retries,
                max_response_bytes: config.max_response_bytes,
            },
            collection: config.collection,
            metric: config.metric,
            dimension: config.dimension,
            vector_name: config.vector_name,
            create_collection: config.create_collection,
            on_disk_payload: config.on_disk_payload,
            on_disk_vectors: config.on_disk_vectors,
            batch_size: config.batch_size,
            max_batch_bytes: config.max_batch_bytes,
            keys: Keys {
                content: config.content_key,
                metadata: config.metadata_key,
                id: config.id_key,
            },
            known: Mutex::new(None),
        })
    }

    /// The collection name.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// The store's metric.
    #[must_use]
    pub const fn metric(&self) -> Metric {
        self.metric
    }

    /// Check the collection, creating it if needed, and return its vector
    /// size.
    ///
    /// # Errors
    ///
    /// The collection is missing and cannot be created (creation is off, or
    /// no [`dimension`](QdrantConfig::dimension) is configured), it uses a
    /// different metric or size, or the server fails.
    pub async fn ensure_collection(&self) -> Result<usize, StoreError> {
        self.ensure(None, true)
            .await?
            .ok_or_else(|| self.missing_error())
    }

    /// Delete the collection. Returns `false` if it did not exist.
    ///
    /// # Errors
    ///
    /// Server or transport failures.
    pub async fn drop_collection(&self) -> Result<bool, StoreError> {
        self.forget();
        match self
            .transport
            .call(Method::DELETE, &self.collection_path(""), None)
            .await
        {
            Ok(v) => Ok(v.get("result").and_then(Value::as_bool).unwrap_or(true)),
            Err(e) if e.is_missing_collection() => Ok(false),
            Err(e) => Err(e.into_store()),
        }
    }

    /// Exact number of points matching `filter`.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] for a filter Qdrant cannot express, or
    /// server and transport failures.
    pub async fn count(&self, filter: &Filter) -> Result<usize, StoreError> {
        let filter = qdrant_filter(filter, &self.keys.metadata)?;
        self.count_translated(&filter).await
    }

    /// Delete every point matching `filter`; returns how many matched just
    /// before the delete (the count and the delete are two requests).
    ///
    /// # Errors
    ///
    /// As for [`count`](Self::count).
    pub async fn delete_where(&self, filter: &Filter) -> Result<usize, StoreError> {
        let translated = qdrant_filter(filter, &self.keys.metadata)?;
        let n = self.count_translated(&translated).await?;
        if n == 0 {
            return Ok(0);
        }
        let body = json!({ "filter": filter_value(translated) });
        self.post(&self.collection_path("/points/delete?wait=true"), &body)
            .await?;
        Ok(n)
    }

    async fn count_translated(&self, filter: &QdrantFilter) -> Result<usize, StoreError> {
        let mut body = json!({ "exact": true });
        match filter {
            QdrantFilter::Nothing => return Ok(0),
            QdrantFilter::All => {}
            QdrantFilter::Filter(f) => body["filter"] = f.clone(),
        }
        if self.ensure(None, false).await?.is_none() {
            return Ok(0);
        }
        let Some(v) = self
            .post_or_missing(&self.collection_path("/points/count"), &body)
            .await?
        else {
            return Ok(0);
        };
        v.pointer("/result/count")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| bad_response("count without result.count"))
    }

    fn collection_path(&self, rest: &str) -> String {
        format!("/collections/{}{rest}", self.collection)
    }

    fn missing_error(&self) -> StoreError {
        StoreError::Backend(format!(
            "qdrant collection {:?} does not exist and cannot be created: {}",
            self.collection,
            if self.create_collection {
                "its vector size is unknown (set QdrantConfig::dimension or upsert first)"
            } else {
                "create_collection is off"
            }
        ))
    }

    fn forget(&self) {
        if let Ok(mut k) = self.known.lock() {
            *k = None;
        }
    }

    fn known(&self) -> Option<usize> {
        self.known.lock().ok().and_then(|k| *k)
    }

    fn remember(&self, size: usize) {
        if let Ok(mut k) = self.known.lock() {
            *k = Some(size);
        }
    }

    /// Make sure the collection exists and matches the configuration, and
    /// return its size; `None` when it does not exist and is not to be
    /// created now. `hint` is the size of vectors about to be written.
    async fn ensure(&self, hint: Option<usize>, create: bool) -> Result<Option<usize>, StoreError> {
        if let Some(size) = self.known() {
            return Ok(Some(size));
        }
        // Two rounds: a concurrent writer may create the collection between
        // our check and our create.
        for _ in 0..2 {
            match self
                .transport
                .call(Method::GET, &self.collection_path(""), None)
                .await
            {
                Ok(info) => {
                    let size = self.check_info(&info)?;
                    self.remember(size);
                    return Ok(Some(size));
                }
                Err(e) if e.is_missing_collection() => {}
                Err(e) => return Err(e.into_store()),
            }
            let Some(size) = self.dimension.or(hint) else {
                return Ok(None);
            };
            if !(create && self.create_collection) {
                return Ok(None);
            }
            match self
                .transport
                .call(
                    Method::PUT,
                    &self.collection_path(""),
                    Some(Bytes::from(self.create_body(size).to_string())),
                )
                .await
            {
                Ok(_) => {
                    self.remember(size);
                    return Ok(Some(size));
                }
                Err(CallError::Status { status, message })
                    if status == 409 || message.contains("already exists") => {}
                Err(e) => return Err(e.into_store()),
            }
        }
        Err(StoreError::Backend(format!(
            "qdrant collection {:?} could not be created or read",
            self.collection
        )))
    }

    fn create_body(&self, size: usize) -> Value {
        let mut params = json!({ "size": size, "distance": distance_name(self.metric) });
        if self.on_disk_vectors {
            params["on_disk"] = Value::Bool(true);
        }
        let vectors = match &self.vector_name {
            Some(name) => json!({ name.as_str(): params }),
            None => params,
        };
        json!({ "vectors": vectors, "on_disk_payload": self.on_disk_payload })
    }

    /// Check an existing collection's vector config against ours; return its size.
    fn check_info(&self, info: &Value) -> Result<usize, StoreError> {
        let vectors = info
            .pointer("/result/config/params/vectors")
            .ok_or_else(|| bad_response("collection info without config.params.vectors"))?;
        let params = match &self.vector_name {
            Some(name) => vectors.get(name).ok_or_else(|| {
                StoreError::Backend(format!(
                    "qdrant collection {:?} has no vector named {name:?}",
                    self.collection
                ))
            })?,
            None if vectors.get("size").is_some() => vectors,
            None => {
                return Err(StoreError::Backend(format!(
                    "qdrant collection {:?} uses named vectors; set QdrantConfig::vector_name",
                    self.collection
                )));
            }
        };
        let size = params
            .get("size")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| bad_response("vector params without size"))?;
        let distance = params.get("distance").and_then(Value::as_str).unwrap_or("");
        if distance != distance_name(self.metric) {
            return Err(StoreError::Backend(format!(
                "qdrant collection {:?} uses {distance} distance, but the store is configured for {}",
                self.collection,
                distance_name(self.metric)
            )));
        }
        if let Some(want) = self.dimension
            && want != size
        {
            return Err(StoreError::DimensionMismatch {
                expected: size,
                actual: want,
            });
        }
        Ok(size)
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, StoreError> {
        self.transport
            .call(Method::POST, path, Some(Bytes::from(body.to_string())))
            .await
            .map_err(CallError::into_store)
    }

    /// POST, treating "collection doesn't exist" as `None` (and forgetting
    /// what we knew about it: it was dropped behind our back).
    async fn post_or_missing(&self, path: &str, body: &Value) -> Result<Option<Value>, StoreError> {
        match self
            .transport
            .call(Method::POST, path, Some(Bytes::from(body.to_string())))
            .await
        {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is_missing_collection() => {
                self.forget();
                Ok(None)
            }
            Err(e) => Err(e.into_store()),
        }
    }

    fn check_vector(&self, v: &[f32]) -> Result<(), StoreError> {
        if v.is_empty() {
            return Err(StoreError::InvalidVector("vector is empty"));
        }
        if v.iter().any(|x| !x.is_finite()) {
            return Err(StoreError::InvalidVector("vector contains NaN or infinity"));
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if !norm.is_finite() {
            return Err(StoreError::InvalidVector("vector norm overflows f32"));
        }
        if self.metric == Metric::Cosine && norm == 0.0 {
            return Err(StoreError::InvalidVector(
                "zero vector has no direction under the cosine metric",
            ));
        }
        Ok(())
    }

    /// Validate a batch up front so a bad record fails before anything is sent.
    fn check_records(&self, records: &[Record]) -> Result<usize, StoreError> {
        let dim = self.dimension.unwrap_or(records[0].vector.len());
        let mut seen = HashSet::with_capacity(records.len());
        for r in records {
            if r.id.is_empty() {
                return Err(StoreError::EmptyId);
            }
            if !seen.insert(r.id.as_str()) {
                return Err(StoreError::DuplicateId(r.id.clone()));
            }
            self.check_vector(&r.vector)?;
            if r.vector.len() != dim {
                return Err(StoreError::DimensionMismatch {
                    expected: dim,
                    actual: r.vector.len(),
                });
            }
        }
        Ok(dim)
    }

    async fn send_points(&self, body: &mut Vec<u8>) -> Result<(), StoreError> {
        body.extend_from_slice(POINTS_SUFFIX);
        let bytes = Bytes::from(std::mem::take(body));
        self.transport
            .call(
                Method::PUT,
                &self.collection_path("/points?wait=true"),
                Some(bytes),
            )
            .await
            .map_err(CallError::into_store)?;
        body.extend_from_slice(POINTS_PREFIX);
        Ok(())
    }

    /// Reject a malformed query before any request goes out.
    fn precheck(&self, q: &Query) -> Result<(), StoreError> {
        if q.min_score.is_some_and(f32::is_nan) {
            return Err(StoreError::InvalidQuery("min_score is NaN"));
        }
        qdrant_filter(&q.filter, &self.keys.metadata)?;
        self.check_vector(&q.vector)?;
        if let Some(dim) = self.dimension
            && q.vector.len() != dim
        {
            return Err(StoreError::DimensionMismatch {
                expected: dim,
                actual: q.vector.len(),
            });
        }
        Ok(())
    }

    /// The JSON body of one query, or `None` when it cannot match anything.
    fn query_body(&self, q: &Query, dim: usize) -> Result<Option<Value>, StoreError> {
        if q.min_score.is_some_and(f32::is_nan) {
            return Err(StoreError::InvalidQuery("min_score is NaN"));
        }
        let filter = qdrant_filter(&q.filter, &self.keys.metadata)?;
        self.check_vector(&q.vector)?;
        if q.vector.len() != dim {
            return Err(StoreError::DimensionMismatch {
                expected: dim,
                actual: q.vector.len(),
            });
        }
        if q.top_k == 0 || matches!(filter, QdrantFilter::Nothing) {
            return Ok(None);
        }
        let mut body = json!({
            "query": q.vector,
            "limit": q.top_k,
            "with_payload": true,
            "with_vector": q.include_vectors,
        });
        if let Some(name) = &self.vector_name {
            body["using"] = Value::String(name.clone());
        }
        if let QdrantFilter::Filter(f) = filter {
            body["filter"] = f;
        }
        if let Some(min) = q.min_score {
            let threshold = if self.metric == Metric::Euclidean {
                // Scores are negated distances, never above zero.
                if min > 0.0 {
                    return Ok(None);
                }
                -min
            } else {
                min
            };
            body["score_threshold"] = json!(threshold);
        }
        if let Some(ef) = q.ef_search {
            body["params"] = json!({ "hnsw_ef": ef });
        }
        Ok(Some(body))
    }

    fn hits(&self, q: &Query, points: &Value) -> Result<Vec<Hit>, StoreError> {
        let points = points
            .as_array()
            .ok_or_else(|| bad_response("query result without points"))?;
        let mut hits = Vec::with_capacity(points.len().min(q.top_k));
        for p in points {
            let raw = p
                .get("score")
                .and_then(Value::as_f64)
                .ok_or_else(|| bad_response("point without score"))?;
            #[allow(clippy::cast_possible_truncation, reason = "scores are f32")]
            let mut score = raw as f32;
            if self.metric == Metric::Euclidean {
                score = -score;
            }
            if q.min_score.is_some_and(|m| score < m) {
                continue;
            }
            hits.push(Hit::new(score, self.record(p, q.include_vectors)?));
        }
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.record.id.cmp(&b.record.id))
        });
        hits.truncate(q.top_k);
        Ok(hits)
    }

    /// Rebuild a record from a point.
    fn record(&self, p: &Value, with_vector: bool) -> Result<Record, StoreError> {
        let payload = p.get("payload").and_then(Value::as_object);
        let field = |k: &str| payload.and_then(|m| m.get(k));
        let id = match field(&self.keys.id).and_then(Value::as_str) {
            Some(id) => id.to_owned(),
            None => match p.get("id") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => return Err(bad_response("point without id")),
            },
        };
        let vector = if with_vector {
            let v = match (p.get("vector"), &self.vector_name) {
                (Some(Value::Object(named)), Some(name)) => named.get(name),
                (Some(v @ Value::Array(_)), None) => Some(v),
                _ => None,
            };
            parse_vector(v)?
        } else {
            Vec::new()
        };
        let content = field(&self.keys.content)
            .and_then(Value::as_str)
            .unwrap_or_default();
        let metadata: BTreeMap<String, Value> = match field(&self.keys.metadata) {
            Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            _ => BTreeMap::new(),
        };
        let mut r = Record::new(id, vector).with_content(content);
        r.metadata = metadata;
        Ok(r)
    }

    /// Look up points by id, without payload or vectors.
    async fn existing(&self, ids: &[PointId]) -> Result<Vec<Value>, StoreError> {
        let body = json!({ "ids": ids, "with_payload": false, "with_vector": false });
        let Some(v) = self
            .post_or_missing(&self.collection_path("/points"), &body)
            .await?
        else {
            return Ok(Vec::new());
        };
        match v.get("result") {
            Some(Value::Array(points)) => {
                Ok(points.iter().filter_map(|p| p.get("id").cloned()).collect())
            }
            _ => Err(bad_response("retrieve without a result array")),
        }
    }
}

#[async_trait]
impl VectorStore for QdrantStore {
    async fn upsert(&self, records: Vec<Record>) -> Result<(), StoreError> {
        if records.is_empty() {
            return Ok(());
        }
        let dim = self.check_records(&records)?;
        let size = self
            .ensure(Some(dim), true)
            .await?
            .ok_or_else(|| self.missing_error())?;
        if size != dim {
            return Err(StoreError::DimensionMismatch {
                expected: size,
                actual: dim,
            });
        }
        let overhead = POINTS_PREFIX.len() + POINTS_SUFFIX.len();
        let mut body = Vec::with_capacity(self.max_batch_bytes.min(1 << 20));
        body.extend_from_slice(POINTS_PREFIX);
        let mut in_batch = 0;
        for r in &records {
            let point = PointOut {
                id: PointId::from_record_id(&r.id),
                record: r,
                store: self,
            };
            let start = body.len();
            if in_batch > 0 {
                body.push(b',');
            }
            serde_json::to_writer(&mut body, &point)
                .map_err(|e| StoreError::Backend(format!("failed to encode a point: {e}")))?;
            let full = in_batch == self.batch_size;
            if in_batch > 0 && (full || body.len() + POINTS_SUFFIX.len() > self.max_batch_bytes) {
                // This point starts the next batch.
                let point_bytes = body[start + 1..].to_vec();
                body.truncate(start);
                self.send_points(&mut body).await?;
                body.extend_from_slice(&point_bytes);
                in_batch = 0;
            }
            let point_len = body.len() - POINTS_PREFIX.len();
            if in_batch == 0 && point_len + overhead > self.max_batch_bytes {
                return Err(StoreError::LimitExceeded {
                    what: "qdrant point size",
                    limit: self.max_batch_bytes as u64,
                    actual: (point_len + overhead) as u64,
                });
            }
            in_batch += 1;
        }
        self.send_points(&mut body).await
    }

    async fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        self.precheck(query)?;
        let Some(dim) = self.ensure(None, false).await? else {
            return Ok(Vec::new());
        };
        let Some(body) = self.query_body(query, dim)? else {
            return Ok(Vec::new());
        };
        let Some(v) = self
            .post_or_missing(&self.collection_path("/points/query"), &body)
            .await?
        else {
            return Ok(Vec::new());
        };
        let points = v
            .pointer("/result/points")
            .ok_or_else(|| bad_response("query without result.points"))?;
        self.hits(query, points)
    }

    async fn query_batch(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>, StoreError> {
        let mut out = vec![Vec::new(); queries.len()];
        if queries.is_empty() {
            return Ok(out);
        }
        for q in queries {
            self.precheck(q)?;
        }
        let Some(dim) = self.ensure(None, false).await? else {
            return Ok(out);
        };
        let mut sent = Vec::new();
        let mut searches = Vec::new();
        for (i, q) in queries.iter().enumerate() {
            if let Some(body) = self.query_body(q, dim)? {
                sent.push(i);
                searches.push(body);
            }
        }
        if searches.is_empty() {
            return Ok(out);
        }
        let body = json!({ "searches": searches });
        let Some(v) = self
            .post_or_missing(&self.collection_path("/points/query/batch"), &body)
            .await?
        else {
            return Ok(out);
        };
        let results = v
            .get("result")
            .and_then(Value::as_array)
            .filter(|r| r.len() == sent.len())
            .ok_or_else(|| bad_response("batch query result count differs from the request"))?;
        for (&i, r) in sent.iter().zip(results) {
            let points = r
                .get("points")
                .ok_or_else(|| bad_response("batch query result without points"))?;
            out[i] = self.hits(&queries[i], points)?;
        }
        Ok(out)
    }

    async fn delete(&self, ids: &[&str]) -> Result<usize, StoreError> {
        let mut seen = HashSet::with_capacity(ids.len());
        let points: Vec<PointId> = ids
            .iter()
            .filter(|id| !id.is_empty() && seen.insert(**id))
            .map(|id| PointId::from_record_id(id))
            .collect();
        if points.is_empty() || self.ensure(None, false).await?.is_none() {
            return Ok(0);
        }
        let mut removed = 0;
        for chunk in points.chunks(self.batch_size) {
            let existing = self.existing(chunk).await?;
            if existing.is_empty() {
                continue;
            }
            removed += existing.len();
            let body = json!({ "points": existing });
            self.post(&self.collection_path("/points/delete?wait=true"), &body)
                .await?;
        }
        Ok(removed)
    }

    async fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        if id.is_empty() || self.ensure(None, false).await?.is_none() {
            return Ok(None);
        }
        let body = json!({
            "ids": [PointId::from_record_id(id)],
            "with_payload": true,
            "with_vector": true,
        });
        let Some(v) = self
            .post_or_missing(&self.collection_path("/points"), &body)
            .await?
        else {
            return Ok(None);
        };
        let Some(p) = v
            .get("result")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        else {
            return Ok(None);
        };
        let record = self.record(p, true)?;
        // A point written by someone else under the same point id.
        Ok((record.id == id).then_some(record))
    }

    async fn len(&self) -> Result<usize, StoreError> {
        self.count_translated(&QdrantFilter::All).await
    }
}

/// One point as Qdrant wants it, serialised straight from the record.
struct PointOut<'a> {
    id: PointId,
    record: &'a Record,
    store: &'a QdrantStore,
}

impl Serialize for PointOut<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(3))?;
        m.serialize_entry("id", &self.id)?;
        match &self.store.vector_name {
            Some(name) => {
                m.serialize_entry("vector", &Named(name, &self.record.vector))?;
            }
            None => m.serialize_entry("vector", &self.record.vector)?,
        }
        m.serialize_entry(
            "payload",
            &PayloadOut {
                record: self.record,
                keys: &self.store.keys,
            },
        )?;
        m.end()
    }
}

/// `{name: vector}` for a named vector.
struct Named<'a>(&'a str, &'a [f32]);

impl Serialize for Named<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry(self.0, self.1)?;
        m.end()
    }
}

struct PayloadOut<'a> {
    record: &'a Record,
    keys: &'a Keys,
}

impl Serialize for PayloadOut<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(3))?;
        m.serialize_entry(&self.keys.content, &self.record.content)?;
        m.serialize_entry(&self.keys.metadata, &self.record.metadata)?;
        m.serialize_entry(&self.keys.id, &self.record.id)?;
        m.end()
    }
}

const fn distance_name(metric: Metric) -> &'static str {
    match metric {
        Metric::DotProduct => "Dot",
        Metric::Euclidean => "Euclid",
        // Other metrics are refused by `QdrantStore::new`.
        _ => "Cosine",
    }
}

fn filter_value(filter: QdrantFilter) -> Value {
    match filter {
        QdrantFilter::Filter(f) => f,
        QdrantFilter::All | QdrantFilter::Nothing => Value::Object(Map::new()),
    }
}

#[allow(clippy::cast_possible_truncation, reason = "vectors are f32")]
fn parse_vector(v: Option<&Value>) -> Result<Vec<f32>, StoreError> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    let items = v
        .as_array()
        .ok_or_else(|| bad_response("vector is not an array"))?;
    items
        .iter()
        .map(|x| {
            x.as_f64()
                .map(|f| f as f32)
                .ok_or_else(|| bad_response("vector element is not a number"))
        })
        .collect()
}

fn bad_response(what: &str) -> StoreError {
    StoreError::Backend(format!("unexpected qdrant response: {what}"))
}

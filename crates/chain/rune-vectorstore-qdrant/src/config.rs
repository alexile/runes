//! Store configuration.

use std::fmt;
use std::time::Duration;

use rune_vectorstore::{Metric, StoreError};

use crate::http::ApiKey;

/// Default number of points per upsert request.
pub const DEFAULT_BATCH_SIZE: usize = 256;
/// Default cap on one upsert request body (Qdrant's own default limit is 32 MiB).
pub const DEFAULT_MAX_BATCH_BYTES: usize = 8 << 20;
/// Default cap on a response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 << 20;
/// Default timeout of one request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default connect timeout of the built-in HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default number of retries after a rate limit, 502/503/504 or a
/// connection failure.
pub const DEFAULT_MAX_RETRIES: u32 = 2;

/// How to reach a Qdrant collection and how to lay out its points.
///
/// Points are stored as
/// `{"page_content": content, "metadata": {...}, "doc_id": id}` by default,
/// the layout `LangChain`'s Qdrant integration uses for content and metadata,
/// so existing collections can be read. Change the keys with
/// [`payload_keys`](Self::payload_keys).
///
/// The API key is never shown by `Debug`.
///
/// # Example
///
/// ```
/// use rune_vectorstore::Metric;
/// use rune_vectorstore_qdrant::QdrantConfig;
///
/// let config = QdrantConfig::new("http://localhost:6333", "docs")
///     .api_key("s3cret-key")
///     .metric(Metric::DotProduct)
///     .dimension(384)
///     .on_disk_payload(true);
/// assert!(!format!("{config:?}").contains("s3cret"));
/// ```
#[derive(Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent builder switches"
)]
pub struct QdrantConfig {
    pub(crate) url: String,
    pub(crate) collection: String,
    pub(crate) api_key: Option<ApiKey>,
    pub(crate) metric: Metric,
    pub(crate) dimension: Option<usize>,
    pub(crate) vector_name: Option<String>,
    pub(crate) create_collection: bool,
    pub(crate) on_disk_payload: bool,
    pub(crate) on_disk_vectors: bool,
    pub(crate) batch_size: usize,
    pub(crate) max_batch_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_retries: u32,
    pub(crate) content_key: String,
    pub(crate) metadata_key: String,
    pub(crate) id_key: String,
    pub(crate) allow_insecure_http: bool,
    pub(crate) http_client: Option<reqwest::Client>,
}

impl fmt::Debug for QdrantConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QdrantConfig")
            .field("url", &self.url)
            .field("collection", &self.collection)
            .field("api_key", &self.api_key)
            .field("metric", &self.metric)
            .field("dimension", &self.dimension)
            .field("vector_name", &self.vector_name)
            .field("create_collection", &self.create_collection)
            .field("on_disk_payload", &self.on_disk_payload)
            .field("on_disk_vectors", &self.on_disk_vectors)
            .field("batch_size", &self.batch_size)
            .field("max_batch_bytes", &self.max_batch_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl QdrantConfig {
    /// A collection on the server at `url` (e.g. `http://localhost:6333`
    /// or a Qdrant Cloud URL), with cosine similarity, collection creation
    /// on first use, and the defaults above.
    #[must_use]
    pub fn new(url: impl Into<String>, collection: impl Into<String>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_owned(),
            collection: collection.into(),
            api_key: None,
            metric: Metric::Cosine,
            dimension: None,
            vector_name: None,
            create_collection: true,
            on_disk_payload: false,
            on_disk_vectors: false,
            batch_size: DEFAULT_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            content_key: "page_content".into(),
            metadata_key: "metadata".into(),
            id_key: "doc_id".into(),
            allow_insecure_http: false,
            http_client: None,
        }
    }

    /// `QDRANT_URL` (default `http://localhost:6333`) and, when set,
    /// `QDRANT_API_KEY`.
    #[must_use]
    pub fn from_env(collection: impl Into<String>) -> Self {
        let url = std::env::var("QDRANT_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:6333".into());
        let config = Self::new(url, collection);
        match std::env::var("QDRANT_API_KEY") {
            Ok(key) if !key.is_empty() => config.api_key(key),
            _ => config,
        }
    }

    /// Send this API key in the `api-key` header.
    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(ApiKey::new(key));
        self
    }

    /// Similarity metric: cosine (Qdrant `Cosine`), dot product (`Dot`) or
    /// Euclidean (`Euclid`). An existing collection must use the same one.
    #[must_use]
    pub const fn metric(mut self, metric: Metric) -> Self {
        self.metric = metric;
        self
    }

    /// Vector size. Without it the size comes from an existing collection,
    /// or from the first upsert when the collection is created.
    #[must_use]
    pub const fn dimension(mut self, dimension: usize) -> Self {
        self.dimension = Some(dimension);
        self
    }

    /// Use a named vector instead of the collection's default one.
    #[must_use]
    pub fn vector_name(mut self, name: impl Into<String>) -> Self {
        self.vector_name = Some(name.into());
        self
    }

    /// Create the collection when it does not exist (default `true`).
    #[must_use]
    pub const fn create_collection(mut self, create: bool) -> Self {
        self.create_collection = create;
        self
    }

    /// Keep payloads on disk in a newly created collection (default `false`).
    #[must_use]
    pub const fn on_disk_payload(mut self, on_disk: bool) -> Self {
        self.on_disk_payload = on_disk;
        self
    }

    /// Keep vectors on disk (memory-mapped) in a newly created collection
    /// (default `false`).
    #[must_use]
    pub const fn on_disk_vectors(mut self, on_disk: bool) -> Self {
        self.on_disk_vectors = on_disk;
        self
    }

    /// Most points per upsert or delete request (default 256, at least 1).
    #[must_use]
    pub const fn batch_size(mut self, points: usize) -> Self {
        self.batch_size = if points == 0 { 1 } else { points };
        self
    }

    /// Largest upsert request body in bytes (default 8 MiB). A single point
    /// bigger than this is refused with [`StoreError::LimitExceeded`].
    #[must_use]
    pub const fn max_batch_bytes(mut self, bytes: usize) -> Self {
        self.max_batch_bytes = bytes;
        self
    }

    /// Largest response body read (default 32 MiB).
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Timeout of each request, including reading the response (default 30 s).
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect timeout of the built-in HTTP client (default 10 s).
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Retries after a rate limit, 502/503/504 or a connection failure
    /// (default 2). Every request this crate sends is idempotent.
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Payload keys for the content, the metadata object and the original
    /// record id (default `page_content`, `metadata`, `doc_id`).
    #[must_use]
    pub fn payload_keys(
        mut self,
        content: impl Into<String>,
        metadata: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        self.content_key = content.into();
        self.metadata_key = metadata.into();
        self.id_key = id.into();
        self
    }

    /// Allow sending an API key over plain `http://` to a host other than
    /// localhost (default `false`; use only on a trusted network).
    #[must_use]
    pub const fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Use your own HTTP client (proxies, TLS roots, …). Its timeouts and
    /// redirect policy are yours to set; disabling redirects is advised so
    /// the API key never follows one.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        let bad = |m: String| Err(StoreError::Backend(format!("invalid Qdrant config: {m}")));
        let url = match reqwest::Url::parse(&self.url) {
            Ok(u) => u,
            Err(e) => return bad(format!("URL: {e}")),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return bad("URL must not embed credentials; use api_key".into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return bad("URL must not have a query or fragment".into());
        }
        match url.scheme() {
            "https" => {}
            "http" if self.api_key.is_none() || self.allow_insecure_http || is_loopback(&url) => {}
            "http" => {
                return bad(
                    "refusing to send the API key over plain HTTP; use https:// \
                     or allow_insecure_http(true)"
                        .into(),
                );
            }
            other => return bad(format!("unsupported URL scheme `{other}`")),
        }
        if !is_plain_name(&self.collection) {
            return bad(format!(
                "collection name {:?} must be 1-255 letters, digits, '-', '_' or '.'",
                self.collection
            ));
        }
        if let Some(name) = &self.vector_name
            && !is_plain_name(name)
        {
            return bad(format!(
                "vector name {name:?} must be letters, digits, '-', '_' or '.'"
            ));
        }
        if self.dimension == Some(0) {
            return bad("dimension must be at least 1".into());
        }
        for (what, key) in [
            ("content", &self.content_key),
            ("metadata", &self.metadata_key),
            ("id", &self.id_key),
        ] {
            if key.is_empty() || key.contains(['.', '[', ']', '"']) {
                return bad(format!(
                    "{what} payload key {key:?} must be non-empty without '.', '[', ']' or '\"'"
                ));
            }
        }
        if self.content_key == self.metadata_key
            || self.content_key == self.id_key
            || self.metadata_key == self.id_key
        {
            return bad("payload keys must differ".into());
        }
        Ok(())
    }

    pub(crate) fn build_client(&self) -> reqwest::Client {
        self.http_client.clone().unwrap_or_else(|| {
            reqwest::Client::builder()
                .connect_timeout(self.connect_timeout)
                // Never follow redirects: the API key header would follow
                // the redirect to another origin.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default()
        })
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Names that go into a URL path: no escaping needed, no traversal.
fn is_plain_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(c: &QdrantConfig) -> bool {
        c.validate().is_ok()
    }

    #[test]
    fn urls() {
        assert!(ok(&QdrantConfig::new("http://qdrant:6333", "c")));
        assert!(ok(&QdrantConfig::new(
            "https://x.cloud.qdrant.io:6333/",
            "c"
        )
        .api_key("k")));
        assert!(ok(
            &QdrantConfig::new("http://127.0.0.1:6333", "c").api_key("k")
        ));
        assert!(ok(&QdrantConfig::new("http://[::1]:6333", "c").api_key("k")));
        assert!(ok(
            &QdrantConfig::new("http://localhost:6333", "c").api_key("k")
        ));
        assert!(!ok(
            &QdrantConfig::new("http://qdrant:6333", "c").api_key("k")
        ));
        assert!(ok(&QdrantConfig::new("http://qdrant:6333", "c")
            .api_key("k")
            .allow_insecure_http(true)));
        assert!(!ok(&QdrantConfig::new("https://u:p@host", "c")));
        assert!(!ok(&QdrantConfig::new("https://host?x=1", "c")));
        assert!(!ok(&QdrantConfig::new("ftp://host", "c")));
        assert!(!ok(&QdrantConfig::new("not a url", "c")));
        assert_eq!(QdrantConfig::new("http://h:1///", "c").url, "http://h:1");
    }

    #[test]
    fn names_and_keys() {
        let base = || QdrantConfig::new("http://localhost:6333", "docs");
        assert!(ok(&base()));
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a?b",
            "a b",
            "%2e%2e",
            &"x".repeat(256),
        ] {
            assert!(!ok(&QdrantConfig::new("http://localhost", bad)), "{bad}");
        }
        assert!(!ok(&base().vector_name("a/b")));
        assert!(ok(&base().vector_name("dense-v1")));
        assert!(!ok(&base().dimension(0)));
        assert!(!ok(&base().payload_keys("a.b", "m", "i")));
        assert!(!ok(&base().payload_keys("x", "x", "i")));
        assert!(!ok(&base().payload_keys("c", "", "i")));
        assert_eq!(base().batch_size(0).batch_size, 1);
    }

    #[test]
    fn debug_hides_the_key() {
        let c = QdrantConfig::new("http://localhost:6333", "docs").api_key("very-secret-key");
        let d = format!("{c:?}");
        assert!(!d.contains("very-secret-key"), "{d}");
        assert!(d.contains("[REDACTED]"));
    }
}

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{RerankError, Reranker};
use crate::scored::ScoredDocument;

/// Default whole-request timeout for [`ApiReranker`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default connect timeout for the client [`ApiReranker`] builds.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on a rerank response body (4 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Most documents sent in one request (the lowest provider limit, Cohere's).
const MAX_DOCUMENTS: usize = 1_000;
/// Characters of an error body kept in [`RerankError::Status`].
const ERROR_BODY_CHARS: usize = 512;

/// A hosted rerank API.
///
/// | Provider | Endpoint | Default model | Env var |
/// |---|---|---|---|
/// | Cohere | `POST https://api.cohere.com/v2/rerank` | `rerank-v3.5` | `COHERE_API_KEY` |
/// | Jina | `POST https://api.jina.ai/v1/rerank` | `jina-reranker-v2-base-multilingual` | `JINA_API_KEY` |
/// | Voyage | `POST https://api.voyageai.com/v1/rerank` | `rerank-2.5` | `VOYAGE_API_KEY` |
///
/// All three take a bearer token and a JSON body with `model`, `query` and
/// `documents` (plain strings), and answer with `(index, relevance_score)`
/// pairs (`results` for Cohere and Jina, `data` for Voyage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RerankProvider {
    /// Cohere Rerank (v2 API).
    Cohere,
    /// Jina AI Reranker.
    Jina,
    /// Voyage AI Reranker.
    Voyage,
}

impl RerankProvider {
    /// API base URL (the request goes to `<base>/rerank`).
    #[must_use]
    pub const fn default_base_url(self) -> &'static str {
        match self {
            Self::Cohere => "https://api.cohere.com/v2",
            Self::Jina => "https://api.jina.ai/v1",
            Self::Voyage => "https://api.voyageai.com/v1",
        }
    }

    /// Default model name.
    #[must_use]
    pub const fn default_model(self) -> &'static str {
        match self {
            Self::Cohere => "rerank-v3.5",
            Self::Jina => "jina-reranker-v2-base-multilingual",
            Self::Voyage => "rerank-2.5",
        }
    }

    /// Environment variable read by [`ApiReranker::from_env`].
    #[must_use]
    pub const fn api_key_env(self) -> &'static str {
        match self {
            Self::Cohere => "COHERE_API_KEY",
            Self::Jina => "JINA_API_KEY",
            Self::Voyage => "VOYAGE_API_KEY",
        }
    }
}

/// JSON request body for `provider` (sans-I/O; used by [`ApiReranker`]).
///
/// ```rust
/// use rune_chain_retrieval::{RerankProvider, build_request_body};
///
/// let body = build_request_body(RerankProvider::Voyage, "rerank-2.5", "q", &["a", "b"], 1);
/// assert_eq!(body["top_k"], 1); // Voyage names it top_k; Cohere and Jina top_n
/// ```
#[must_use]
pub fn build_request_body(
    provider: RerankProvider,
    model: &str,
    query: &str,
    documents: &[&str],
    top_n: usize,
) -> Value {
    match provider {
        RerankProvider::Cohere => json!({
            "model": model, "query": query, "documents": documents, "top_n": top_n,
        }),
        RerankProvider::Jina => json!({
            "model": model, "query": query, "documents": documents, "top_n": top_n,
            "return_documents": false,
        }),
        RerankProvider::Voyage => json!({
            "model": model, "query": query, "documents": documents, "top_k": top_n,
            "truncation": true,
        }),
    }
}

#[derive(Deserialize)]
struct RerankResponse {
    #[serde(alias = "data")]
    results: Vec<RerankItem>,
}

#[derive(Deserialize)]
struct RerankItem {
    index: usize,
    relevance_score: f64,
}

/// Parse a rerank response body into `(document index, relevance score)`
/// pairs, best first (sans-I/O; used by [`ApiReranker`]).
///
/// Accepts the `results` (Cohere, Jina) and `data` (Voyage) shapes.
///
/// # Errors
///
/// [`RerankError::InvalidResponse`] on malformed JSON, an index outside
/// `0..document_count`, a repeated index, or a non-finite score.
///
/// ```rust
/// use rune_chain_retrieval::parse_response;
///
/// let body = br#"{"results":[{"index":1,"relevance_score":0.9},{"index":0,"relevance_score":0.2}]}"#;
/// assert_eq!(parse_response(body, 2)?, [(1, 0.9), (0, 0.2)]);
/// # Ok::<(), rune_chain_retrieval::RerankError>(())
/// ```
pub fn parse_response(
    body: &[u8],
    document_count: usize,
) -> Result<Vec<(usize, f32)>, RerankError> {
    let parsed: RerankResponse =
        serde_json::from_slice(body).map_err(|e| RerankError::InvalidResponse(e.to_string()))?;
    let mut seen = vec![false; document_count];
    let mut out = Vec::with_capacity(parsed.results.len());
    for item in parsed.results {
        let slot = seen.get_mut(item.index).ok_or_else(|| {
            RerankError::InvalidResponse(format!(
                "index {} out of range for {document_count} documents",
                item.index
            ))
        })?;
        if *slot {
            return Err(RerankError::InvalidResponse(format!(
                "index {} repeated",
                item.index
            )));
        }
        *slot = true;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "relevance scores are small; f32 precision is plenty"
        )]
        let score = item.relevance_score as f32;
        if !score.is_finite() {
            return Err(RerankError::InvalidResponse(format!(
                "non-finite score for index {}",
                item.index
            )));
        }
        out.push((item.index, score));
    }
    out.sort_by(|a, b| b.1.total_cmp(&a.1));
    Ok(out)
}

/// [`Reranker`] backed by the Cohere, Jina or Voyage rerank API.
///
/// Hardened by default: the base URL must be `https://`, the built-in
/// client refuses plain-HTTP and redirects, every request has a 30 s
/// timeout (10 s to connect), responses over 4 MiB are rejected while
/// streaming, at most 1 000 documents go in one request, and the API key
/// is shown as `[REDACTED]` in `Debug` output.
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rune_chain_retrieval::{ApiReranker, Bm25Retriever, Document, RerankingRetriever};
///
/// let reranker = ApiReranker::cohere(std::env::var("COHERE_API_KEY")?)?
///     .with_model("rerank-v3.5");
/// let base = Arc::new(Bm25Retriever::from_documents(vec![Document::new("…")]));
/// let retriever = RerankingRetriever::new(base, Arc::new(reranker)).with_fetch_k(50);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct ApiReranker {
    provider: RerankProvider,
    api_key: String,
    base_url: String,
    model: String,
    timeout: Duration,
    max_response_bytes: usize,
    client: reqwest::Client,
}

impl std::fmt::Debug for ApiReranker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiReranker")
            .field("provider", &self.provider)
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

fn check_https(url: &str) -> Result<(), RerankError> {
    let has_scheme = url
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
    if has_scheme && url.len() > 8 {
        Ok(())
    } else {
        Err(RerankError::InvalidConfig(format!(
            "base URL must use https://, got {url:?}"
        )))
    }
}

impl ApiReranker {
    /// Reranker for `provider` with its default endpoint and model.
    ///
    /// # Errors
    ///
    /// [`RerankError::InvalidConfig`] if `api_key` is blank or the HTTP
    /// client cannot be built.
    pub fn new(provider: RerankProvider, api_key: impl Into<String>) -> Result<Self, RerankError> {
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(RerankError::InvalidConfig("API key is empty".into()));
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| RerankError::InvalidConfig(e.to_string()))?;
        Ok(Self {
            provider,
            api_key,
            base_url: provider.default_base_url().to_owned(),
            model: provider.default_model().to_owned(),
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            client,
        })
    }

    /// Cohere Rerank.
    ///
    /// # Errors
    ///
    /// See [`new`](Self::new).
    pub fn cohere(api_key: impl Into<String>) -> Result<Self, RerankError> {
        Self::new(RerankProvider::Cohere, api_key)
    }

    /// Jina Reranker.
    ///
    /// # Errors
    ///
    /// See [`new`](Self::new).
    pub fn jina(api_key: impl Into<String>) -> Result<Self, RerankError> {
        Self::new(RerankProvider::Jina, api_key)
    }

    /// Voyage Reranker.
    ///
    /// # Errors
    ///
    /// See [`new`](Self::new).
    pub fn voyage(api_key: impl Into<String>) -> Result<Self, RerankError> {
        Self::new(RerankProvider::Voyage, api_key)
    }

    /// Read the key from the provider's environment variable
    /// ([`RerankProvider::api_key_env`]).
    ///
    /// # Errors
    ///
    /// [`RerankError::InvalidConfig`] if the variable is unset or blank.
    pub fn from_env(provider: RerankProvider) -> Result<Self, RerankError> {
        let var = provider.api_key_env();
        let key = std::env::var(var)
            .map_err(|_| RerankError::InvalidConfig(format!("{var} is not set")))?;
        Self::new(provider, key)
    }

    /// Use another model.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Use another endpoint base (a proxy or regional host). The request
    /// goes to `<base_url>/rerank`.
    ///
    /// # Errors
    ///
    /// [`RerankError::InvalidConfig`] unless `base_url` starts with `https://`.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Result<Self, RerankError> {
        let base_url = base_url.into();
        check_https(&base_url)?;
        base_url
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        Ok(self)
    }

    /// Whole-request timeout (default 30 s). Applied per request, so it also
    /// holds for a client passed to [`with_client`](Self::with_client).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Reject responses larger than `bytes` (default 4 MiB).
    #[must_use]
    pub const fn with_max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Use a preconfigured client (proxy, TLS roots). The HTTPS-only base
    /// URL check, per-request timeout and size cap still apply; redirect
    /// and `https_only` policy are the client's own.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// The provider.
    #[must_use]
    pub const fn provider(&self) -> RerankProvider {
        self.provider
    }

    /// The model name.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    async fn post(&self, body: &Value) -> Result<Vec<u8>, RerankError> {
        let mut response = self
            .client
            .post(format!("{}/rerank", self.base_url))
            .bearer_auth(&self.api_key)
            .timeout(self.timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| RerankError::Request(e.without_url().to_string()))?;
        let status = response.status();
        let limit = self.max_response_bytes;
        if response
            .content_length()
            .is_some_and(|len| len > limit as u64)
        {
            return Err(RerankError::ResponseTooLarge { limit });
        }
        let mut buf = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| RerankError::Request(e.without_url().to_string()))?
        {
            if buf.len().saturating_add(chunk.len()) > limit {
                return Err(RerankError::ResponseTooLarge { limit });
            }
            buf.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(RerankError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&buf)
                    .chars()
                    .take(ERROR_BODY_CHARS)
                    .collect(),
            });
        }
        Ok(buf)
    }
}

#[async_trait]
impl Reranker for ApiReranker {
    async fn rerank(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
        top_n: usize,
    ) -> Result<Vec<ScoredDocument>, RerankError> {
        if top_n == 0 || documents.is_empty() {
            return Ok(Vec::new());
        }
        if documents.len() > MAX_DOCUMENTS {
            return Err(RerankError::InvalidConfig(format!(
                "{} documents exceed the {MAX_DOCUMENTS}-document request limit",
                documents.len()
            )));
        }
        let top_n = top_n.min(documents.len());
        let texts: Vec<&str> = documents
            .iter()
            .map(|d| d.document.content.as_str())
            .collect();
        let body = build_request_body(self.provider, &self.model, query, &texts, top_n);
        let bytes = self.post(&body).await?;
        let ranking = parse_response(&bytes, documents.len())?;
        let mut slots: Vec<Option<ScoredDocument>> = documents.into_iter().map(Some).collect();
        Ok(ranking
            .into_iter()
            .filter_map(|(index, score)| {
                let mut doc = slots.get_mut(index)?.take()?;
                doc.score = score;
                Some(doc)
            })
            .take(top_n)
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;
    use crate::document::Document;

    const COHERE_FIXTURE: &[u8] = br#"{
        "id": "07734bd2-2473-4f07-94e1-0d9f0e6843cf",
        "results": [
            {"index": 3, "relevance_score": 0.999071},
            {"index": 0, "relevance_score": 0.32713068}
        ],
        "meta": {"api_version": {"version": "2"}, "billed_units": {"search_units": 1}}
    }"#;

    const JINA_FIXTURE: &[u8] = br#"{
        "model": "jina-reranker-v2-base-multilingual",
        "usage": {"total_tokens": 815},
        "results": [
            {"index": 1, "relevance_score": 0.8},
            {"index": 2, "relevance_score": 0.1}
        ]
    }"#;

    const VOYAGE_FIXTURE: &[u8] = br#"{
        "object": "list",
        "data": [
            {"relevance_score": 0.4375, "index": 0},
            {"relevance_score": 0.84765625, "index": 1}
        ],
        "model": "rerank-2.5",
        "usage": {"total_tokens": 26}
    }"#;

    #[test]
    fn parses_provider_fixtures() {
        assert_eq!(
            parse_response(COHERE_FIXTURE, 4).unwrap(),
            [(3, 0.999_071), (0, 0.327_130_68)]
        );
        assert_eq!(
            parse_response(JINA_FIXTURE, 3).unwrap(),
            [(1, 0.8), (2, 0.1)]
        );
        // Voyage data is re-sorted best first.
        assert_eq!(
            parse_response(VOYAGE_FIXTURE, 2).unwrap(),
            [(1, 0.847_656_25), (0, 0.4375)]
        );
    }

    #[test]
    fn rejects_bad_responses() {
        assert!(matches!(
            parse_response(COHERE_FIXTURE, 3),
            Err(RerankError::InvalidResponse(_))
        ));
        let dup =
            br#"{"results":[{"index":0,"relevance_score":1},{"index":0,"relevance_score":0.5}]}"#;
        assert!(parse_response(dup, 1).is_err());
        assert!(parse_response(b"not json", 1).is_err());
        assert!(parse_response(br#"{"results":[{"index":-1,"relevance_score":1}]}"#, 1).is_err());
        let huge = br#"{"results":[{"index":0,"relevance_score":1e300}]}"#;
        assert!(parse_response(huge, 1).is_err());
        assert!(parse_response(br#"{"results":[]}"#, 0).unwrap().is_empty());
    }

    #[test]
    fn request_bodies_follow_each_api() {
        let docs = ["a", "b"];
        let c = build_request_body(RerankProvider::Cohere, "m", "q", &docs, 2);
        assert_eq!(
            c,
            json!({"model":"m","query":"q","documents":["a","b"],"top_n":2})
        );
        let j = build_request_body(RerankProvider::Jina, "m", "q", &docs, 1);
        assert_eq!(j["top_n"], 1);
        assert_eq!(j["return_documents"], false);
        let v = build_request_body(RerankProvider::Voyage, "m", "q", &docs, 1);
        assert_eq!(v["top_k"], 1);
        assert!(v.get("top_n").is_none());
    }

    #[test]
    fn debug_redacts_api_key() {
        let r = ApiReranker::cohere("sk-super-secret-123").unwrap();
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("sk-super-secret-123"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn https_is_enforced() {
        let r = ApiReranker::jina("k").unwrap();
        assert!(r.clone().with_base_url("http://api.jina.ai/v1").is_err());
        assert!(r.clone().with_base_url("ftp://x").is_err());
        assert!(r.clone().with_base_url("https://").is_err());
        let ok = r.with_base_url("HTTPS://proxy.example.com/v1/").unwrap();
        assert_eq!(ok.base_url, "HTTPS://proxy.example.com/v1");
        for p in [
            RerankProvider::Cohere,
            RerankProvider::Jina,
            RerankProvider::Voyage,
        ] {
            assert!(check_https(p.default_base_url()).is_ok());
        }
    }

    #[test]
    fn blank_key_is_rejected() {
        assert!(ApiReranker::voyage("  ").is_err());
    }

    #[tokio::test]
    async fn trivial_calls_skip_the_network() {
        // An unroutable base URL proves no request is made.
        let r = ApiReranker::cohere("k")
            .unwrap()
            .with_base_url("https://invalid.invalid")
            .unwrap();
        let docs = vec![ScoredDocument::new(Document::new("a"), 1.0)];
        assert!(r.rerank("q", docs, 0).await.unwrap().is_empty());
        assert!(r.rerank("q", Vec::new(), 5).await.unwrap().is_empty());
        let many = vec![ScoredDocument::new(Document::new("a"), 1.0); MAX_DOCUMENTS + 1];
        assert!(matches!(
            r.rerank("q", many, 1).await,
            Err(RerankError::InvalidConfig(_))
        ));
    }
}

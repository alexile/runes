//! Model management: list (`/api/tags`), inspect (`/api/show`) and pull
//! (`/api/pull`) models.

use std::pin::Pin;

use futures::{Stream, StreamExt};
use rune_chain_core::LlmError;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::Ollama;
use crate::client::encode;
use crate::ndjson::{self, Limits};
use crate::types::{ModelRequest, error_message};

/// Longest model name accepted by the helpers here.
const MAX_MODEL_NAME: usize = 512;

/// A locally available model, from [`Ollama::list_models`].
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct ModelSummary {
    /// Name to pass to [`Ollama::model`], e.g. `llama3.2:latest`.
    pub name: String,
    /// Model identifier (usually equal to `name`).
    #[serde(default)]
    pub model: String,
    /// Last modification time (RFC 3339), as reported.
    #[serde(default)]
    pub modified_at: Option<String>,
    /// Size on disk in bytes.
    #[serde(default)]
    pub size: u64,
    /// Content digest.
    #[serde(default)]
    pub digest: String,
    /// Format, family, size and quantization.
    #[serde(default)]
    pub details: ModelDetails,
}

/// Format, family, parameter count and quantization of a model.
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct ModelDetails {
    /// File format, e.g. `gguf`.
    #[serde(default)]
    pub format: String,
    /// Model family, e.g. `llama`.
    #[serde(default)]
    pub family: String,
    /// All families the model belongs to.
    #[serde(default)]
    pub families: Option<Vec<String>>,
    /// Parameter count, e.g. `8.0B`.
    #[serde(default)]
    pub parameter_size: String,
    /// Quantization, e.g. `Q4_K_M`.
    #[serde(default)]
    pub quantization_level: String,
    /// Base model, for derived models.
    #[serde(default)]
    pub parent_model: String,
}

/// Detailed model information, from [`Ollama::show_model`].
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct ModelInfo {
    /// Format, family, size and quantization.
    #[serde(default)]
    pub details: ModelDetails,
    /// Capabilities such as `completion`, `tools`, `vision`, `thinking`,
    /// `embedding` (reported by Ollama 0.6+; empty on older servers).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Default parameters from the Modelfile, one per line.
    #[serde(default)]
    pub parameters: String,
    /// The prompt template.
    #[serde(default)]
    pub template: String,
    /// Architecture metadata (context length, embedding size, …).
    #[serde(default)]
    pub model_info: Map<String, Value>,
}

impl ModelInfo {
    /// Whether the server lists `capability` (e.g. `"tools"`, `"vision"`).
    ///
    /// ```rust
    /// let info: rune_chain_ollama::ModelInfo =
    ///     serde_json::from_str(r#"{"capabilities":["completion","tools"]}"#).unwrap();
    /// assert!(info.supports("tools"));
    /// assert!(!info.supports("vision"));
    /// ```
    #[must_use]
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// The model's trained context length, from `<arch>.context_length` in
    /// [`model_info`](Self::model_info), if reported.
    #[must_use]
    pub fn context_length(&self) -> Option<u64> {
        self.model_info
            .iter()
            .find(|(k, _)| k.ends_with(".context_length"))
            .and_then(|(_, v)| v.as_u64())
    }
}

/// One progress update of [`Ollama::pull_model`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct PullProgress {
    /// Status text: `pulling manifest`, `pulling <digest>`,
    /// `verifying sha256 digest`, `writing manifest`, `success`, …
    pub status: String,
    /// Layer being downloaded.
    #[serde(default)]
    pub digest: Option<String>,
    /// Layer size in bytes.
    #[serde(default)]
    pub total: Option<u64>,
    /// Bytes of the layer downloaded so far.
    #[serde(default)]
    pub completed: Option<u64>,
}

impl PullProgress {
    /// Whether this is the final `success` update.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == "success"
    }

    /// Download progress of the current layer in `0.0..=1.0`, when known.
    #[must_use]
    #[allow(clippy::cast_precision_loss, reason = "progress display only")]
    pub fn fraction(&self) -> Option<f64> {
        match (self.completed, self.total) {
            (Some(done), Some(total)) if total > 0 => Some((done as f64 / total as f64).min(1.0)),
            _ => None,
        }
    }
}

/// A boxed stream of [`PullProgress`] updates.
pub type PullStream = Pin<Box<dyn Stream<Item = Result<PullProgress, LlmError>> + Send>>;

#[derive(Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<ModelSummary>,
}

fn check_model_name(name: &str) -> Result<(), LlmError> {
    if name.trim().is_empty() || name.len() > MAX_MODEL_NAME || name.chars().any(char::is_control) {
        return Err(LlmError::other(format!(
            "invalid model name `{}`",
            crate::http::truncate(name, 80)
        )));
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, LlmError> {
    serde_json::from_slice(body).map_err(|e| LlmError::invalid_response(e.to_string()))
}

/// Decode one `/api/pull` line.
fn decode_pull_line(line: &[u8]) -> Result<PullProgress, LlmError> {
    let value: Value = serde_json::from_slice(line)
        .map_err(|e| LlmError::invalid_response(format!("undecodable pull line: {e}")))?;
    if let Some(msg) = error_message(&value) {
        return Err(LlmError::provider(crate::http::truncate(
            &msg,
            crate::http::MAX_ERROR_CHARS,
        )));
    }
    serde_json::from_value(value)
        .map_err(|e| LlmError::invalid_response(format!("undecodable pull line: {e}")))
}

/// Turn an `/api/pull` NDJSON byte stream into progress updates. Ends after
/// `success`; a stream that ends before it is an error.
pub(crate) fn pull_events<S, B, E>(body: S, max_line: usize) -> PullStream
where
    S: Stream<Item = Result<B, E>> + Send + Unpin + 'static,
    B: AsRef<[u8]> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let limits = Limits {
        max_line,
        // Progress lines are small but a large pull emits many of them.
        max_total: usize::MAX,
    };
    let mut lines = Box::pin(ndjson::lines(body, limits));
    Box::pin(async_stream::stream! {
        while let Some(line) = lines.next().await {
            match line.and_then(|l| decode_pull_line(&l)) {
                Ok(p) => {
                    let done = p.is_success();
                    yield Ok(p);
                    if done {
                        return;
                    }
                }
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
        yield Err(LlmError::invalid_response("pull ended before `success`"));
    })
}

impl Ollama {
    /// List the models available on the server (`GET /api/tags`).
    ///
    /// ```rust,no_run
    /// # tokio_test::block_on(async {
    /// for m in rune_chain_ollama::Ollama::new().list_models().await.unwrap() {
    ///     println!("{} ({} bytes)", m.name, m.size);
    /// }
    /// # });
    /// ```
    pub async fn list_models(&self) -> Result<Vec<ModelSummary>, LlmError> {
        let response = self.send("/api/tags", None, self.request_timeout()).await?;
        let body = crate::http::read_body(response, self.max_response(), false).await?;
        Ok(decode::<TagsResponse>(&body)?.models)
    }

    /// Show details and capabilities of `model` (`POST /api/show`).
    pub async fn show_model(&self, model: &str) -> Result<ModelInfo, LlmError> {
        check_model_name(model)?;
        let body = self
            .post_json(
                "/api/show",
                &ModelRequest {
                    model,
                    stream: None,
                },
            )
            .await?;
        decode(&body)
    }

    /// Download `model` from the registry (`POST /api/pull`), streaming
    /// progress. The stream ends after the `success` update. The
    /// whole-request [`timeout`](Self::timeout) does not apply (pulls can
    /// take hours); drop the stream to stop waiting (the server may keep
    /// downloading).
    ///
    /// ```rust,no_run
    /// use futures::StreamExt;
    ///
    /// # tokio_test::block_on(async {
    /// let mut pull = rune_chain_ollama::Ollama::new().pull_model("llama3.2").await.unwrap();
    /// while let Some(p) = pull.next().await {
    ///     let p = p.unwrap();
    ///     println!("{} {:?}", p.status, p.fraction());
    /// }
    /// # });
    /// ```
    pub async fn pull_model(&self, model: &str) -> Result<PullStream, LlmError> {
        check_model_name(model)?;
        let payload = encode(&ModelRequest {
            model,
            stream: Some(true),
        })?;
        let response = self.send("/api/pull", Some(payload), None).await?;
        Ok(pull_events(
            Box::pin(response.bytes_stream()),
            self.limits().max_line,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::LlmErrorKind;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
        };
    }

    #[test]
    fn decodes_tags_fixture() {
        let tags: TagsResponse = decode(fixture!("tags.json").as_bytes()).unwrap();
        assert_eq!(tags.models.len(), 2);
        let m = &tags.models[0];
        assert_eq!(m.name, "llama3.2:latest");
        assert_eq!(m.size, 2_019_393_189);
        assert_eq!(m.details.quantization_level, "Q4_K_M");
        assert_eq!(tags.models[1].details.family, "nomic-bert");
    }

    #[test]
    fn decodes_show_fixture() {
        let info: ModelInfo = decode(fixture!("show.json").as_bytes()).unwrap();
        assert!(info.supports("tools"));
        assert!(!info.supports("vision"));
        assert_eq!(info.context_length(), Some(131_072));
        assert_eq!(info.details.parameter_size, "3.2B");
    }

    fn pull(body: &[u8], size: usize) -> Vec<Result<PullProgress, LlmError>> {
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            body.chunks(size).map(|c| Ok(c.to_vec())).collect();
        futures::executor::block_on(pull_events(futures::stream::iter(chunks), 1024).collect())
    }

    #[test]
    fn pull_stream_reports_progress_and_ends_at_success() {
        let body = fixture!("pull.ndjson").as_bytes();
        for size in [1, 5, body.len()] {
            let items: Vec<PullProgress> = pull(body, size)
                .into_iter()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(items.first().unwrap().status, "pulling manifest");
            assert_eq!(items[1].fraction(), Some(0.5));
            assert!(items.last().unwrap().is_success());
        }
    }

    #[test]
    fn pull_errors_and_truncation() {
        let items = pull(
            b"{\"status\":\"pulling manifest\"}\n{\"error\":\"file does not exist\"}\n",
            7,
        );
        assert!(
            matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Provider && m.message() == "file does not exist")
        );
        let items = pull(b"{\"status\":\"pulling manifest\"}\n", 7);
        assert!(
            matches!(items.last(), Some(Err(m)) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("success"))
        );
        let items = pull(b"not json\n", 3);
        assert!(matches!(&items[0], Err(e) if e.kind() == LlmErrorKind::InvalidResponse));
        let long = format!("{{\"status\":\"{}\"}}\n", "x".repeat(2000));
        assert!(
            matches!(&pull(long.as_bytes(), 64)[0], Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("line"))
        );
    }

    #[test]
    fn model_names_are_checked() {
        assert!(check_model_name("llama3.2:8b").is_ok());
        assert!(check_model_name("").is_err());
        assert!(check_model_name("a\nb").is_err());
        assert!(check_model_name(&"x".repeat(MAX_MODEL_NAME + 1)).is_err());
    }
}

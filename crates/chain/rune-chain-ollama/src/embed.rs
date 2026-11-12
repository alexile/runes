//! Embeddings via `/api/embed` (batch input), and the
//! [`Embedder`](rune_chain_embed::Embedder) implementation.

use async_trait::async_trait;
use rune_chain_core::{LlmError, LlmErrorKind, TokenUsage};
use rune_chain_embed::{EmbedError, Embedder};

use crate::Ollama;
use crate::types::{EmbedRequest, EmbedResponse};

/// The result of [`Ollama::embed_texts`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Embeddings {
    /// One vector per input, in input order.
    pub vectors: Vec<Vec<f32>>,
    /// Prompt tokens evaluated, when reported.
    pub usage: Option<TokenUsage>,
}

impl Ollama {
    /// Ask the server for embeddings of this many dimensions (`dimensions`;
    /// only for models that support truncating their output, e.g.
    /// Matryoshka-trained ones).
    #[must_use]
    pub const fn embed_dimensions(mut self, dimensions: u32) -> Self {
        self.embed_dimensions = Some(dimensions);
        self
    }

    /// Whether the server may truncate inputs longer than the context
    /// window (`truncate`, server default `true`). With `false`, an
    /// over-long input is an error instead of a silently partial embedding.
    #[must_use]
    pub const fn embed_truncate(mut self, truncate: bool) -> Self {
        self.embed_truncate = Some(truncate);
        self
    }

    /// Embed `inputs` in one `/api/embed` request with the configured
    /// [`model`](Self::model) (use an embedding model such as
    /// `nomic-embed-text` or `mxbai-embed-large`). An empty slice returns no
    /// vectors without contacting the server.
    ///
    /// ```rust,no_run
    /// use rune_chain_ollama::Ollama;
    ///
    /// # tokio_test::block_on(async {
    /// let embedder = Ollama::new().model("nomic-embed-text");
    /// let out = embedder.embed_texts(&["first", "second"]).await.unwrap();
    /// assert_eq!(out.vectors.len(), 2);
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Transport and server errors, and [`LlmError::invalid_response`] when
    /// the server returns a different number of vectors than inputs.
    pub async fn embed_texts(&self, inputs: &[&str]) -> Result<Embeddings, LlmError> {
        if inputs.is_empty() {
            return Ok(Embeddings::default());
        }
        let body = self.embed_request(inputs)?;
        let bytes = self.post_json("/api/embed", &body).await?;
        decode_embeddings(&bytes, inputs.len())
    }

    fn embed_request<'a>(&'a self, inputs: &'a [&'a str]) -> Result<EmbedRequest<'a>, LlmError> {
        Ok(EmbedRequest {
            model: self.model_id(),
            input: inputs,
            truncate: self.embed_truncate,
            dimensions: self.embed_dimensions,
            keep_alive: self.keep_alive_value(),
            options: self.options_map()?,
        })
    }
}

fn decode_embeddings(body: &[u8], expected: usize) -> Result<Embeddings, LlmError> {
    let response: EmbedResponse =
        serde_json::from_slice(body).map_err(|e| LlmError::invalid_response(e.to_string()))?;
    if response.embeddings.len() != expected {
        return Err(LlmError::invalid_response(format!(
            "expected {expected} embeddings, got {}",
            response.embeddings.len()
        )));
    }
    Ok(Embeddings {
        vectors: response.embeddings,
        usage: response.prompt_eval_count.map(|p| TokenUsage::new(p, 0)),
    })
}

fn to_embed_error(err: &LlmError) -> EmbedError {
    let message = err.message().to_string();
    match err.kind() {
        LlmErrorKind::Network | LlmErrorKind::Timeout => EmbedError::RequestFailed(message),
        LlmErrorKind::InvalidResponse => EmbedError::InvalidResponse(message),
        LlmErrorKind::Unsupported | LlmErrorKind::Other => EmbedError::Other(message),
        _ => EmbedError::ProviderError(message),
    }
}

#[async_trait]
impl Embedder for Ollama {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.embed_texts(texts)
            .await
            .map(|e| e.vectors)
            .map_err(|e| to_embed_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::KeepAlive;

    #[test]
    fn request_shape() {
        let llm = Ollama::new().model("nomic-embed-text");
        let inputs = ["a", "b"];
        let v = serde_json::to_value(llm.embed_request(&inputs).unwrap()).unwrap();
        assert_eq!(
            v,
            json!({ "model": "nomic-embed-text", "input": ["a", "b"] })
        );

        let llm = llm
            .embed_dimensions(256)
            .embed_truncate(false)
            .keep_alive(KeepAlive::Forever)
            .num_ctx(8192);
        let v = serde_json::to_value(llm.embed_request(&inputs).unwrap()).unwrap();
        assert_eq!(v["dimensions"], 256);
        assert_eq!(v["truncate"], false);
        assert_eq!(v["keep_alive"], -1);
        assert_eq!(v["options"], json!({ "num_ctx": 8192 }));
    }

    #[test]
    fn decodes_fixture_and_checks_count() {
        let body = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/embed.json"));
        let out = decode_embeddings(body, 2).unwrap();
        assert_eq!(out.vectors, [vec![0.1, -0.2, 0.3], vec![0.0, 0.5, -0.5]]);
        assert_eq!(out.usage.map(|u| u.prompt_tokens), Some(4));
        assert!(matches!(
            decode_embeddings(body, 3),
            Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("expected 3")
        ));
        assert!(decode_embeddings(b"{}", 1).is_err());
    }

    #[test]
    fn empty_batch_needs_no_server() {
        let llm = Ollama::new().base_url("http://127.0.0.1:9");
        let out = futures::executor::block_on(llm.embed_batch(&[])).unwrap();
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn errors_map_to_embed_errors() {
        assert!(matches!(
            to_embed_error(&LlmError::provider("x")),
            EmbedError::ProviderError(_)
        ));
        assert!(matches!(
            to_embed_error(&LlmError::other("x")),
            EmbedError::Other(_)
        ));
    }
}

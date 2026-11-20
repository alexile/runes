//! The provider-neutral client traits: pick a model by name, then build an
//! agent or an extractor on it.

use rune_chain_core::Llm;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;

use crate::builder::AgentBuilder;
use crate::extractor::ExtractorBuilder;

/// A chat model whose sampling settings can be changed before use.
///
/// Implemented for the provider models ([`OpenAi`](crate::openai::OpenAi),
/// [`Anthropic`](crate::anthropic::Anthropic),
/// [`Ollama`](crate::ollama::Ollama)). It is what makes
/// [`AgentBuilder::temperature`] and [`AgentBuilder::max_tokens`]
/// available; agents also work on any other [`Llm`], just without those two
/// methods.
pub trait CompletionModel: Llm + Sized + 'static {
    /// The same model with this sampling temperature.
    #[must_use]
    fn with_temperature(self, temperature: f32) -> Self;

    /// The same model with this cap on generated tokens.
    #[must_use]
    fn with_max_tokens(self, max_tokens: u32) -> Self;
}

/// A provider client that hands out chat models by name.
///
/// ```rust,no_run
/// use rune_chain::prelude::*;
/// use rune_chain::openai;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = openai::Client::from_env()?;
/// let agent = client.agent("gpt-4o-mini").preamble("Be terse.").build();
/// println!("{}", agent.prompt("Name a prime above 100.").await?);
/// # Ok(())
/// # }
/// ```
pub trait CompletionClient {
    /// The model type this client creates.
    type Model: CompletionModel;

    /// A chat model by provider model id, e.g. `"gpt-4o-mini"`.
    fn completion_model(&self, name: &str) -> Self::Model;

    /// Start building an [`Agent`](crate::Agent) on the model `name`.
    fn agent(&self, name: &str) -> AgentBuilder<Self::Model> {
        AgentBuilder::new(self.completion_model(name))
    }

    /// Start building an [`Extractor`](crate::Extractor) that pulls a `T`
    /// out of free text with the model `name`.
    fn extractor<T>(&self, name: &str) -> ExtractorBuilder<Self::Model, T>
    where
        T: JsonSchema + DeserializeOwned + Send + Sync + 'static,
    {
        ExtractorBuilder::new(self.completion_model(name))
    }
}

/// A provider client that hands out embedding models by name.
#[cfg(feature = "embed")]
pub trait EmbeddingsClient {
    /// The embedder type this client creates.
    type Embedder: rune_chain_embed::Embedder + 'static;

    /// An embedding model by provider model id, e.g.
    /// `"text-embedding-3-small"`.
    fn embedding_model(&self, name: &str) -> Self::Embedder;
}

/// A provider client that hands out speech-to-text models by name.
///
/// ```rust
/// use rune_chain::openai;
/// use rune_chain::prelude::*;
///
/// let client = openai::Client::new("sk-example");
/// let whisper = client.transcription_model("whisper-1");
/// assert_eq!(whisper.model_id(), "whisper-1");
/// ```
pub trait TranscriptionClient {
    /// The model type this client creates.
    type TranscriptionModel: rune_chain_core::TranscriptionModel + 'static;

    /// A transcription model by provider model id, e.g. `"whisper-1"`.
    fn transcription_model(&self, name: &str) -> Self::TranscriptionModel;
}

/// A provider client that hands out image generation models by name.
pub trait ImageGenerationClient {
    /// The model type this client creates.
    type ImageGenerationModel: rune_chain_core::ImageGenerationModel + 'static;

    /// An image model by provider model id, e.g. `"gpt-image-1"`.
    fn image_generation_model(&self, name: &str) -> Self::ImageGenerationModel;
}

/// A provider client that hands out text-to-speech models by name.
pub trait SpeechClient {
    /// The model type this client creates.
    type SpeechModel: rune_chain_core::SpeechModel + 'static;

    /// A speech model by provider model id, e.g. `"gpt-4o-mini-tts"`.
    fn speech_model(&self, name: &str) -> Self::SpeechModel;
}

//! The traits and builders most programs need: `use rune_chain::prelude::*;`.

pub use crate::{
    Agent, AgentBuilder, AgentResponse, CompletionClient, CompletionModel, Extractor,
    ExtractorBuilder, ImageGenerationClient, SpeechClient, TranscriptionClient, Typed, TypedTool,
};
pub use rune_chain_core::{
    Chain, ChainError, ChainExt, GenerateResult, ImageGenerationModel, ImageGenerationRequest, Llm,
    LlmError, LlmExt, Memory, Message, PromptArgs, Role, SpeechModel, SpeechRequest, StreamData,
    Tool, ToolError, ToolExt, TranscriptionModel, TranscriptionRequest, prompt_args,
};
pub use schemars::JsonSchema;

#[cfg(feature = "macros")]
pub use rune_chain_core::tool;

#[cfg(feature = "embed")]
pub use crate::EmbeddingsClient;
#[cfg(feature = "embed")]
pub use rune_chain_embed::Embedder;

#[cfg(feature = "retrieval")]
pub use crate::EmbeddingIndex;
#[cfg(feature = "retrieval")]
pub use rune_chain_retrieval::Retriever;

#[cfg(feature = "vectorstore")]
pub use rune_vectorstore::VectorStore;

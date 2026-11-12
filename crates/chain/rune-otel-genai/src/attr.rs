//! Attribute keys, metric names and well-known values.
//!
//! Keys under `gen_ai.*`, `error.*`, `http.*` and `server.*` follow the
//! [OpenTelemetry GenAI semantic conventions] as published in semantic
//! conventions **v1.40.0** (status: Development). From v1.41.0 the `GenAI`
//! conventions live in their own repository with the same names. Notably:
//!
//! - the provider is `gen_ai.provider.name`; the older `gen_ai.system` is
//!   deprecated and only emitted on request
//!   ([`GenAiConfig::with_legacy_system`](crate::GenAiConfig::with_legacy_system));
//! - cache and reasoning counts are `gen_ai.usage.cache_read.input_tokens`,
//!   `gen_ai.usage.cache_creation.input_tokens` and
//!   `gen_ai.usage.reasoning.output_tokens`, each a subset of the
//!   input/output total.
//!
//! Keys under `rune.gen_ai.*` are this crate's extensions for values the
//! conventions do not define, such as cost.
//!
//! [OpenTelemetry GenAI semantic conventions]: https://opentelemetry.io/docs/specs/semconv/gen-ai/

/// The operation being performed, such as `chat` or `execute_tool`.
pub const GEN_AI_OPERATION_NAME: &str = "gen_ai.operation.name";
/// The `GenAI` provider, such as `openai` or `anthropic`.
pub const GEN_AI_PROVIDER_NAME: &str = "gen_ai.provider.name";
/// Deprecated predecessor of [`GEN_AI_PROVIDER_NAME`], for backends that
/// still expect it.
pub const GEN_AI_SYSTEM: &str = "gen_ai.system";
/// The model a request asked for.
pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";
/// The maximum number of output tokens requested.
pub const GEN_AI_REQUEST_MAX_TOKENS: &str = "gen_ai.request.max_tokens";
/// The sampling temperature requested.
pub const GEN_AI_REQUEST_TEMPERATURE: &str = "gen_ai.request.temperature";
/// The nucleus sampling (`top_p`) setting requested.
pub const GEN_AI_REQUEST_TOP_P: &str = "gen_ai.request.top_p";
/// The conversation (session, thread) the operation belongs to.
pub const GEN_AI_CONVERSATION_ID: &str = "gen_ai.conversation.id";
/// The requested output type, such as `text` or `json`.
pub const GEN_AI_OUTPUT_TYPE: &str = "gen_ai.output.type";
/// Tokens in the prompt.
pub const GEN_AI_USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
/// Tokens in the response.
pub const GEN_AI_USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
/// Prompt tokens served from the provider's prompt cache (part of
/// `gen_ai.usage.input_tokens`).
pub const GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS: &str = "gen_ai.usage.cache_read.input_tokens";
/// Prompt tokens written to the provider's prompt cache (part of
/// `gen_ai.usage.input_tokens`).
pub const GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS: &str =
    "gen_ai.usage.cache_creation.input_tokens";
/// Output tokens spent on reasoning (part of `gen_ai.usage.output_tokens`).
pub const GEN_AI_USAGE_REASONING_OUTPUT_TOKENS: &str = "gen_ai.usage.reasoning.output_tokens";
/// Which side a `gen_ai.client.token.usage` measurement counts: `input` or
/// `output`.
pub const GEN_AI_TOKEN_TYPE: &str = "gen_ai.token.type";
/// Why the model stopped. The conventions define a string array; tracing
/// fields cannot hold arrays, so the single reason is recorded as a string.
pub const GEN_AI_RESPONSE_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";
/// The chat history sent to the model (opt-in, JSON).
pub const GEN_AI_INPUT_MESSAGES: &str = "gen_ai.input.messages";
/// The messages the model returned (opt-in, JSON).
pub const GEN_AI_OUTPUT_MESSAGES: &str = "gen_ai.output.messages";
/// The tool's name.
pub const GEN_AI_TOOL_NAME: &str = "gen_ai.tool.name";
/// The tool's description.
pub const GEN_AI_TOOL_DESCRIPTION: &str = "gen_ai.tool.description";
/// The tool's type; this crate reports `function`.
pub const GEN_AI_TOOL_TYPE: &str = "gen_ai.tool.type";
/// The tool call identifier issued by the model.
pub const GEN_AI_TOOL_CALL_ID: &str = "gen_ai.tool.call.id";
/// The arguments passed to a tool (opt-in).
pub const GEN_AI_TOOL_CALL_ARGUMENTS: &str = "gen_ai.tool.call.arguments";
/// The result a tool returned (opt-in).
pub const GEN_AI_TOOL_CALL_RESULT: &str = "gen_ai.tool.call.result";
/// The agent's human-readable name.
pub const GEN_AI_AGENT_NAME: &str = "gen_ai.agent.name";
/// The agent's unique identifier.
pub const GEN_AI_AGENT_ID: &str = "gen_ai.agent.id";
/// A free-form description of the agent.
pub const GEN_AI_AGENT_DESCRIPTION: &str = "gen_ai.agent.description";
/// The class of error the operation ended with.
pub const ERROR_TYPE: &str = "error.type";
/// The HTTP status of a failed provider response, when there was one.
pub const HTTP_RESPONSE_STATUS_CODE: &str = "http.response.status_code";
/// The `GenAI` server's host name.
pub const SERVER_ADDRESS: &str = "server.address";
/// The `GenAI` server's port.
pub const SERVER_PORT: &str = "server.port";

/// Extension: cost of the call in US dollars, from the configured pricing.
pub const RUNE_USAGE_COST_USD: &str = "rune.gen_ai.usage.cost_usd";
/// Extension: `true` when the token counts are local estimates because the
/// provider reported none (always the case for streams).
pub const RUNE_USAGE_ESTIMATED: &str = "rune.gen_ai.usage.estimated";
/// Extension: number of tool calls the model requested in its response.
pub const RUNE_RESPONSE_TOOL_CALLS: &str = "rune.gen_ai.response.tool_calls";

/// Histogram of model call durations, in seconds.
pub const METRIC_OPERATION_DURATION: &str = "gen_ai.client.operation.duration";
/// Histogram of input and output tokens per call.
pub const METRIC_TOKEN_USAGE: &str = "gen_ai.client.token.usage";

/// Name of the span event recorded for each tool call a model requests.
pub const EVENT_TOOL_CALL: &str = "gen_ai.tool.call";

/// Well-known `gen_ai.operation.name` values.
pub mod operation {
    /// A chat completion.
    pub const CHAT: &str = "chat";
    /// A plain text completion.
    pub const TEXT_COMPLETION: &str = "text_completion";
    /// An embeddings request.
    pub const EMBEDDINGS: &str = "embeddings";
    /// A tool execution.
    pub const EXECUTE_TOOL: &str = "execute_tool";
    /// An agent invocation.
    pub const INVOKE_AGENT: &str = "invoke_agent";
}

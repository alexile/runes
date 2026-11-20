//! Presets for OpenAI-compatible providers and the wire-format quirks that
//! tell them apart.
//!
//! Many hosted and self-hosted servers speak the `/chat/completions` dialect
//! but differ in details: how the API key is sent, whether `max_tokens` or
//! `max_completion_tokens` is accepted, whether `stream_options` is allowed,
//! and which `response_format` types exist. Each [`Provider`] carries a
//! [`Quirks`] record with those differences, a default base URL, the
//! conventional API-key environment variable and a default model. All of it is
//! data in one table, so adding a provider is one entry.
//!
//! ```rust
//! use rune_chain_openai::{OpenAi, Provider};
//!
//! let llm = OpenAi::for_provider(Provider::Mistral, "key");
//! assert_eq!(llm.provider(), Provider::Mistral);
//! assert_eq!(llm.model_id(), "mistral-small-latest");
//! assert!(!llm.active_quirks().stream_usage_option);
//!
//! for p in Provider::ALL {
//!     println!("{:<12} {:?} {:?}", p.name(), p.default_base_url(), p.api_key_env());
//! }
//! ```

/// An OpenAI-compatible API this crate has a preset for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Provider {
    /// `OpenAI` itself (`api.openai.com`).
    OpenAi,
    /// Azure `OpenAI`: deployment-scoped URLs, an `api-version` query
    /// parameter and an `api-key` header. Build with
    /// [`OpenAi::azure`](crate::OpenAi::azure).
    AzureOpenAi,
    /// Mistral La Plateforme (`api.mistral.ai`).
    Mistral,
    /// Groq (`api.groq.com/openai`).
    Groq,
    /// Together AI (`api.together.xyz`).
    Together,
    /// `DeepSeek` (`api.deepseek.com`).
    DeepSeek,
    /// `OpenRouter` (`openrouter.ai/api`).
    OpenRouter,
    /// A self-hosted vLLM server (default `http://localhost:8000/v1`).
    Vllm,
    /// LM Studio's local server (default `http://localhost:1234/v1`).
    LmStudio,
    /// xAI Grok (`api.x.ai`).
    Xai,
    /// Fireworks AI (`api.fireworks.ai/inference`).
    Fireworks,
    /// Cerebras Inference (`api.cerebras.ai`).
    Cerebras,
    /// Moonshot AI Kimi (`api.moonshot.ai`). Temperatures above 1 are
    /// rejected by the server.
    Moonshot,
    /// Hyperbolic (`api.hyperbolic.ai/inference`).
    Hyperbolic,
    /// Hugging Face Inference Providers router (`router.huggingface.co`).
    /// Models are Hub ids, optionally with a `:provider`, `:fastest` or
    /// `:cheapest` suffix.
    HuggingFace,
    /// NVIDIA NIM on the hosted API catalog (`integrate.api.nvidia.com`).
    /// Point [`base_url`](crate::OpenAi::base_url) at a self-hosted NIM to
    /// use one.
    NvidiaNim,
    /// `SambaNova` Cloud (`api.sambanova.ai`).
    SambaNova,
    /// Cohere's `OpenAI` compatibility API (`api.cohere.ai/compatibility`).
    Cohere,
}

/// How the API key is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthStyle {
    /// `Authorization: Bearer <key>` (`OpenAI` and most compatible servers).
    Bearer,
    /// `api-key: <key>` (Azure `OpenAI`).
    ApiKeyHeader,
}

/// Which request field carries the output-token limit set with
/// [`OpenAi::max_tokens`](crate::OpenAi::max_tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaxTokensField {
    /// `max_completion_tokens` — required by `OpenAI` reasoning models.
    MaxCompletionTokens,
    /// The legacy `max_tokens`, which most compatible servers expect.
    MaxTokens,
}

/// Wire-format differences between OpenAI-compatible servers.
///
/// Start from a provider's record ([`Provider::quirks`]) and adjust it with
/// the `with_*` methods, then apply it with
/// [`OpenAi::quirks`](crate::OpenAi::quirks) — e.g. to turn off native JSON
/// Schema for a model on `OpenRouter` that lacks it.
///
/// ```rust
/// use rune_chain_openai::{OpenAi, Provider};
///
/// let quirks = Provider::OpenRouter.quirks().with_json_schema(false);
/// let llm = OpenAi::for_provider(Provider::OpenRouter, "key").quirks(quirks);
/// assert!(!llm.active_quirks().json_schema);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent per-server capability flags"
)]
pub struct Quirks {
    /// How the API key is sent. An empty key sends no auth header at all.
    pub auth: AuthStyle,
    /// The field used for the output-token limit.
    pub max_tokens_field: MaxTokensField,
    /// Whether streaming requests made with
    /// [`OpenAi::stream_events`](crate::OpenAi::stream_events) send
    /// `stream_options: {"include_usage": true}`. Servers that reject the
    /// field but report usage anyway (Groq, Mistral, `OpenRouter`) have it off;
    /// usage found in any chunk is reported either way.
    pub stream_usage_option: bool,
    /// Whether `response_format: {"type": "json_schema"}` is supported.
    pub json_schema: bool,
    /// Whether `response_format: {"type": "json_object"}` is supported.
    pub json_object: bool,
    /// Whether `tool_choice` is accepted. When off, the field is left out
    /// and the server picks (`auto`); tools are still sent.
    pub tool_choice: bool,
}

impl Quirks {
    /// The `OpenAI` API's own behaviour.
    pub const OPENAI: Self = Self {
        auth: AuthStyle::Bearer,
        max_tokens_field: MaxTokensField::MaxCompletionTokens,
        stream_usage_option: true,
        json_schema: true,
        json_object: true,
        tool_choice: true,
    };

    /// A conservative default for unknown compatible servers: bearer auth,
    /// `max_tokens`, no `stream_options`, JSON-object mode only.
    pub const GENERIC: Self = Self {
        auth: AuthStyle::Bearer,
        max_tokens_field: MaxTokensField::MaxTokens,
        stream_usage_option: false,
        json_schema: false,
        json_object: true,
        tool_choice: true,
    };

    /// Set [`auth`](Self::auth).
    #[must_use]
    pub const fn with_auth(mut self, auth: AuthStyle) -> Self {
        self.auth = auth;
        self
    }

    /// Set [`max_tokens_field`](Self::max_tokens_field).
    #[must_use]
    pub const fn with_max_tokens_field(mut self, field: MaxTokensField) -> Self {
        self.max_tokens_field = field;
        self
    }

    /// Set [`stream_usage_option`](Self::stream_usage_option).
    #[must_use]
    pub const fn with_stream_usage_option(mut self, on: bool) -> Self {
        self.stream_usage_option = on;
        self
    }

    /// Set [`json_schema`](Self::json_schema).
    #[must_use]
    pub const fn with_json_schema(mut self, on: bool) -> Self {
        self.json_schema = on;
        self
    }

    /// Set [`json_object`](Self::json_object).
    #[must_use]
    pub const fn with_json_object(mut self, on: bool) -> Self {
        self.json_object = on;
        self
    }

    /// Set [`tool_choice`](Self::tool_choice).
    #[must_use]
    pub const fn with_tool_choice(mut self, on: bool) -> Self {
        self.tool_choice = on;
        self
    }
}

/// One row of the preset table.
struct Spec {
    provider: Provider,
    name: &'static str,
    base_url: Option<&'static str>,
    api_key_env: Option<&'static str>,
    default_model: Option<&'static str>,
    quirks: Quirks,
}

const fn quirks(
    max_tokens_field: MaxTokensField,
    stream_usage_option: bool,
    json_schema: bool,
    json_object: bool,
) -> Quirks {
    Quirks {
        auth: AuthStyle::Bearer,
        max_tokens_field,
        stream_usage_option,
        json_schema,
        json_object,
        tool_choice: true,
    }
}

use MaxTokensField::{MaxCompletionTokens, MaxTokens};

/// The preset table. Model ids are each provider's long-lived aliases.
const SPECS: &[Spec] = &[
    Spec {
        provider: Provider::OpenAi,
        name: "openai",
        base_url: Some(crate::DEFAULT_BASE_URL),
        api_key_env: Some("OPENAI_API_KEY"),
        default_model: Some(crate::models::DEFAULT_MODEL),
        quirks: Quirks::OPENAI,
    },
    Spec {
        provider: Provider::AzureOpenAi,
        name: "azure-openai",
        base_url: None,
        api_key_env: Some("AZURE_OPENAI_API_KEY"),
        default_model: None,
        quirks: Quirks::OPENAI.with_auth(AuthStyle::ApiKeyHeader),
    },
    Spec {
        provider: Provider::Mistral,
        name: "mistral",
        base_url: Some("https://api.mistral.ai/v1"),
        api_key_env: Some("MISTRAL_API_KEY"),
        default_model: Some("mistral-small-latest"),
        quirks: quirks(MaxTokens, false, true, true),
    },
    Spec {
        provider: Provider::Groq,
        name: "groq",
        base_url: Some("https://api.groq.com/openai/v1"),
        api_key_env: Some("GROQ_API_KEY"),
        default_model: Some("llama-3.3-70b-versatile"),
        quirks: quirks(MaxCompletionTokens, false, true, true),
    },
    Spec {
        provider: Provider::Together,
        name: "together",
        base_url: Some("https://api.together.xyz/v1"),
        api_key_env: Some("TOGETHER_API_KEY"),
        default_model: Some("meta-llama/Llama-3.3-70B-Instruct-Turbo"),
        quirks: quirks(MaxTokens, false, false, true),
    },
    Spec {
        provider: Provider::DeepSeek,
        name: "deepseek",
        base_url: Some("https://api.deepseek.com/v1"),
        api_key_env: Some("DEEPSEEK_API_KEY"),
        default_model: Some("deepseek-chat"),
        quirks: quirks(MaxTokens, true, false, true),
    },
    Spec {
        provider: Provider::OpenRouter,
        name: "openrouter",
        base_url: Some("https://openrouter.ai/api/v1"),
        api_key_env: Some("OPENROUTER_API_KEY"),
        default_model: Some("openrouter/auto"),
        quirks: quirks(MaxTokens, false, true, true),
    },
    Spec {
        provider: Provider::Vllm,
        name: "vllm",
        base_url: Some("http://localhost:8000/v1"),
        api_key_env: Some("VLLM_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, true, true, true),
    },
    Spec {
        provider: Provider::LmStudio,
        name: "lm-studio",
        base_url: Some("http://localhost:1234/v1"),
        api_key_env: None,
        default_model: None,
        quirks: quirks(MaxTokens, false, true, false),
    },
    // https://docs.x.ai/docs/guides/chat (base URL) and
    // https://docs.x.ai/developers/rest-api-reference/inference/chat-completions:
    // `max_tokens` is deprecated for `max_completion_tokens`; `stream_options`
    // and `json_schema` are supported.
    Spec {
        provider: Provider::Xai,
        name: "xai",
        base_url: Some("https://api.x.ai/v1"),
        api_key_env: Some("XAI_API_KEY"),
        default_model: None,
        quirks: quirks(MaxCompletionTokens, true, true, true),
    },
    // https://docs.fireworks.ai/tools-sdks/openai-compatibility and
    // https://docs.fireworks.ai/api-reference/post-chatcompletions:
    // `max_completion_tokens` is only an alias of `max_tokens`.
    Spec {
        provider: Provider::Fireworks,
        name: "fireworks",
        base_url: Some("https://api.fireworks.ai/inference/v1"),
        api_key_env: Some("FIREWORKS_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, true, true, true),
    },
    // https://inference-docs.cerebras.ai/resources/openai and
    // https://inference-docs.cerebras.ai/api-reference/chat-completions:
    // `stream_options` is not documented, so it is not sent.
    Spec {
        provider: Provider::Cerebras,
        name: "cerebras",
        base_url: Some("https://api.cerebras.ai/v1"),
        api_key_env: Some("CEREBRAS_API_KEY"),
        default_model: None,
        quirks: quirks(MaxCompletionTokens, false, true, true),
    },
    // https://platform.kimi.ai/docs/guide/migrating-from-openai-to-kimi and
    // https://platform.kimi.ai/docs/api/chat: `max_tokens` is deprecated for
    // `max_completion_tokens`; temperature range is [0, 1].
    Spec {
        provider: Provider::Moonshot,
        name: "moonshot",
        base_url: Some("https://api.moonshot.ai/v1"),
        api_key_env: Some("MOONSHOT_API_KEY"),
        default_model: None,
        quirks: quirks(MaxCompletionTokens, true, true, true),
    },
    // https://hyperbolic.ai/docs/inference/text-apis.md
    Spec {
        provider: Provider::Hyperbolic,
        name: "hyperbolic",
        base_url: Some("https://api.hyperbolic.ai/inference/v1"),
        api_key_env: Some("HYPERBOLIC_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, true, true, true),
    },
    // https://huggingface.co/docs/inference-providers/index: chat only; the
    // backend varies per request, so the conservative defaults apply.
    Spec {
        provider: Provider::HuggingFace,
        name: "huggingface",
        base_url: Some("https://router.huggingface.co/v1"),
        api_key_env: Some("HF_TOKEN"),
        default_model: None,
        quirks: Quirks::GENERIC,
    },
    // https://docs.api.nvidia.com/nim/reference/llm-apis: the request schema
    // has no `response_format`, `stream_options` or `tool_choice` and
    // rejects unknown fields.
    Spec {
        provider: Provider::NvidiaNim,
        name: "nvidia-nim",
        base_url: Some("https://integrate.api.nvidia.com/v1"),
        api_key_env: Some("NVIDIA_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, false, false, false).with_tool_choice(false),
    },
    // https://docs.sambanova.ai/docs/api-reference/chat-completions/create-chat-based-completion.md
    Spec {
        provider: Provider::SambaNova,
        name: "sambanova",
        base_url: Some("https://api.sambanova.ai/v1"),
        api_key_env: Some("SAMBANOVA_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, true, true, true),
    },
    // https://docs.cohere.com/docs/compatibility-api: `max_tokens` only; no
    // `stream_options` or `tool_choice`; JSON mode, not `json_schema`.
    Spec {
        provider: Provider::Cohere,
        name: "cohere",
        base_url: Some("https://api.cohere.ai/compatibility/v1"),
        api_key_env: Some("COHERE_API_KEY"),
        default_model: None,
        quirks: quirks(MaxTokens, false, false, true).with_tool_choice(false),
    },
];

impl Provider {
    /// Every preset, in a stable order.
    pub const ALL: [Self; 18] = [
        Self::OpenAi,
        Self::AzureOpenAi,
        Self::Mistral,
        Self::Groq,
        Self::Together,
        Self::DeepSeek,
        Self::OpenRouter,
        Self::Vllm,
        Self::LmStudio,
        Self::Xai,
        Self::Fireworks,
        Self::Cerebras,
        Self::Moonshot,
        Self::Hyperbolic,
        Self::HuggingFace,
        Self::NvidiaNim,
        Self::SambaNova,
        Self::Cohere,
    ];

    fn spec(self) -> &'static Spec {
        SPECS
            .iter()
            .find(|s| s.provider == self)
            .unwrap_or(&SPECS[0])
    }

    /// A short lowercase name, e.g. `"openrouter"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.spec().name
    }

    /// The API base URL (`…/v1`), or `None` for Azure, whose URL depends on
    /// the resource and deployment.
    #[must_use]
    pub fn default_base_url(self) -> Option<&'static str> {
        self.spec().base_url
    }

    /// The environment variable conventionally holding the API key.
    #[must_use]
    pub fn api_key_env(self) -> Option<&'static str> {
        self.spec().api_key_env
    }

    /// The model a preset client starts with, if the provider has a
    /// well-known default. Self-hosted servers (vLLM, LM Studio), Azure
    /// deployments and providers with fast-moving catalogs have none; set
    /// one with [`OpenAi::model`](crate::OpenAi::model).
    #[must_use]
    pub fn default_model(self) -> Option<&'static str> {
        self.spec().default_model
    }

    /// The provider's wire-format quirks.
    #[must_use]
    pub fn quirks(self) -> Quirks {
        self.spec().quirks
    }

    /// Whether an empty API key is acceptable (local servers run without
    /// authentication by default).
    #[must_use]
    pub const fn key_optional(self) -> bool {
        matches!(self, Self::Vllm | Self::LmStudio)
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_provider_has_exactly_one_spec() {
        assert_eq!(SPECS.len(), Provider::ALL.len());
        for p in Provider::ALL {
            assert_eq!(SPECS.iter().filter(|s| s.provider == p).count(), 1, "{p}");
            assert_eq!(p.spec().provider, p);
        }
    }

    #[test]
    fn remote_presets_use_https() {
        for p in Provider::ALL {
            match p.default_base_url() {
                Some(url) if !p.key_optional() => assert!(url.starts_with("https://"), "{p}"),
                Some(url) => assert!(url.starts_with("http://localhost:"), "{p}"),
                None => assert_eq!(p, Provider::AzureOpenAi),
            }
            assert_ne!(p.name(), "");
        }
    }

    #[test]
    fn quirk_highlights() {
        assert_eq!(Provider::OpenAi.quirks(), Quirks::OPENAI);
        assert_eq!(Provider::AzureOpenAi.quirks().auth, AuthStyle::ApiKeyHeader);
        assert!(!Provider::DeepSeek.quirks().json_schema);
        assert!(!Provider::LmStudio.quirks().json_object);
        assert!(!Provider::Cohere.quirks().tool_choice);
        assert!(!Provider::NvidiaNim.quirks().tool_choice);
        assert!(Provider::Xai.quirks().tool_choice);
        assert_eq!(
            Provider::Mistral.quirks().max_tokens_field,
            MaxTokensField::MaxTokens
        );
    }
}

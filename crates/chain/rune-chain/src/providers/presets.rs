//! One module per OpenAI-compatible provider, all on
//! [`compat::Client`](crate::compat::Client).

preset_module! {
    /// Groq: OpenAI-compatible chat. No embeddings.
    groq, Groq, "groq", Groq,
    keys: ["GROQ_API_KEY"], embeddings: false, model: "llama-3.3-70b-versatile",
}

preset_module! {
    /// Mistral La Plateforme: chat and embeddings (`mistral-embed`).
    mistral, Mistral, "mistral", Mistral,
    keys: ["MISTRAL_API_KEY"], embeddings: true, model: "mistral-large-latest",
}

preset_module! {
    /// `DeepSeek`: chat. No embeddings.
    deepseek, DeepSeek, "deepseek", DeepSeek,
    keys: ["DEEPSEEK_API_KEY"], embeddings: false, model: "deepseek-chat",
}

preset_module! {
    /// xAI Grok over the chat completions API. No embeddings.
    xai, Xai, "xai", Xai,
    keys: ["XAI_API_KEY"], embeddings: false, model: "grok-4",
}

preset_module! {
    /// `OpenRouter`: one key for many vendors; models are `vendor/model` ids.
    openrouter, OpenRouter, "openrouter", OpenRouter,
    keys: ["OPENROUTER_API_KEY"], embeddings: false, model: "anthropic/claude-sonnet-4",
}

preset_module! {
    /// Together AI: chat.
    together, Together, "together", Together,
    keys: ["TOGETHER_API_KEY"], embeddings: false, model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
}

preset_module! {
    /// Fireworks AI: chat and embeddings.
    fireworks, Fireworks, "fireworks", Fireworks,
    keys: ["FIREWORKS_API_KEY"], embeddings: true, model: "accounts/fireworks/models/llama-v3p3-70b-instruct",
}

preset_module! {
    /// Cerebras Inference: chat. No embeddings.
    cerebras, Cerebras, "cerebras", Cerebras,
    keys: ["CEREBRAS_API_KEY"], embeddings: false, model: "gpt-oss-120b",
}

preset_module! {
    /// Moonshot AI (Kimi): chat. Temperatures must be in `[0, 1]`.
    moonshot, Moonshot, "moonshot", Moonshot,
    keys: ["MOONSHOT_API_KEY"], embeddings: false, model: "kimi-k2-0905-preview",
}

preset_module! {
    /// Hyperbolic: chat. No embeddings.
    hyperbolic, Hyperbolic, "hyperbolic", Hyperbolic,
    keys: ["HYPERBOLIC_API_KEY"], embeddings: false, model: "deepseek-ai/DeepSeek-V3",
}

preset_module! {
    /// Hugging Face Inference Providers router: chat with Hub model ids,
    /// optionally suffixed `:provider`, `:fastest` or `:cheapest`. The
    /// router has no embeddings endpoint.
    huggingface, HuggingFace, "huggingface", HuggingFace,
    keys: ["HF_TOKEN"], embeddings: false, model: "deepseek-ai/DeepSeek-R1:fastest",
}

preset_module! {
    /// NVIDIA NIM (hosted API catalog, or a self-hosted NIM with
    /// [`Client::with_base_url`](crate::compat::Client::with_base_url)):
    /// chat. `tool_choice` is not sent.
    nvidia, NvidiaNim, "nvidia", NvidiaNim,
    keys: ["NVIDIA_API_KEY"], embeddings: false, model: "meta/llama-3.3-70b-instruct",
}

preset_module! {
    /// `SambaNova` Cloud: chat. No embeddings.
    sambanova, SambaNova, "sambanova", SambaNova,
    keys: ["SAMBANOVA_API_KEY"], embeddings: false, model: "Meta-Llama-3.3-70B-Instruct",
}

preset_module! {
    /// Cohere's `OpenAI` compatibility API: chat and embeddings.
    /// `tool_choice` is not sent. The key comes from `COHERE_API_KEY` or
    /// `CO_API_KEY`.
    cohere, Cohere, "cohere", Cohere,
    keys: ["COHERE_API_KEY", "CO_API_KEY"], embeddings: true, model: "command-a-03-2025",
}

preset_module! {
    /// A self-hosted vLLM server (default `http://localhost:8000/v1`, change
    /// it with [`Client::with_base_url`](crate::compat::Client::with_base_url)):
    /// chat and embeddings. The key is optional.
    vllm, Vllm, "vllm", Vllm,
    keys: ["VLLM_API_KEY"], embeddings: true, model: "Qwen/Qwen2.5-7B-Instruct",
}

preset_module! {
    /// LM Studio's local server (`http://localhost:1234/v1`): chat and
    /// embeddings, no key.
    lmstudio, LmStudio, "lmstudio", LmStudio,
    keys: [], embeddings: true, model: "qwen2.5-7b-instruct",
}

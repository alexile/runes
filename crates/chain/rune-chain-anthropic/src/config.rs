//! Request options beyond the portable [`Llm`](rune_chain_core::Llm)
//! surface: prompt caching, extended thinking, effort, the structured
//! output strategy, beta flags and server-side refusal fallbacks.

use serde::Serialize;

/// Lifetime of a prompt-cache entry written at a `cache_control` breakpoint.
///
/// A cache read refreshes the entry's timer. Writes cost 1.25× the base
/// input price for [`FiveMinutes`](Self::FiveMinutes) and 2× for
/// [`OneHour`](Self::OneHour); reads cost a fraction of it (see
/// [`ModelInfo::pricing`](crate::ModelInfo::pricing)).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CacheTtl {
    /// The default five-minute lifetime.
    #[default]
    FiveMinutes,
    /// The one-hour lifetime, for prefixes reused across longer gaps.
    OneHour,
}

impl CacheTtl {
    pub(crate) const fn to_wire(self) -> CacheControl {
        CacheControl {
            kind: "ephemeral",
            ttl: match self {
                Self::FiveMinutes => None,
                Self::OneHour => Some("1h"),
            },
        }
    }
}

/// Wire form of a `cache_control` breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CacheControl {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'static str>,
}

/// Where the client places `cache_control` breakpoints.
///
/// The API renders a request as `tools` → `system` → `messages` and caches
/// the prefix up to each breakpoint. Put stable content (tool definitions,
/// a frozen system prompt) first; anything that changes per request
/// invalidates every breakpoint after it. Entries with a longer TTL must come
/// before shorter ones, which the client checks before sending.
///
/// Prefixes below the model's minimum cacheable length are silently not
/// cached; check [`Usage::cache_creation_input_tokens`](crate::Usage) and
/// [`Usage::cache_read_input_tokens`](crate::Usage) to confirm hits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CachePolicy {
    /// Breakpoint on the last tool definition (caches every tool).
    pub tools: Option<CacheTtl>,
    /// Breakpoint on the system prompt (caches tools + system).
    pub system: Option<CacheTtl>,
    /// Breakpoint on the last content block of the last message (caches the
    /// whole conversation so far; the next turn reads it).
    pub messages: Option<CacheTtl>,
}

impl CachePolicy {
    /// No breakpoints (the default).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            tools: None,
            system: None,
            messages: None,
        }
    }

    /// Breakpoints on tools, system prompt and conversation tail, all with
    /// `ttl` — the usual setup for multi-turn agents.
    #[must_use]
    pub const fn all(ttl: CacheTtl) -> Self {
        Self {
            tools: Some(ttl),
            system: Some(ttl),
            messages: Some(ttl),
        }
    }

    /// Set the tools breakpoint.
    #[must_use]
    pub const fn with_tools(mut self, ttl: CacheTtl) -> Self {
        self.tools = Some(ttl);
        self
    }

    /// Set the system-prompt breakpoint.
    #[must_use]
    pub const fn with_system(mut self, ttl: CacheTtl) -> Self {
        self.system = Some(ttl);
        self
    }

    /// Set the conversation-tail breakpoint.
    #[must_use]
    pub const fn with_messages(mut self, ttl: CacheTtl) -> Self {
        self.messages = Some(ttl);
        self
    }

    /// `true` when no breakpoint is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tools.is_none() && self.system.is_none() && self.messages.is_none()
    }

    /// Check the API's ordering rule: a one-hour entry may not follow a
    /// five-minute one in render order (tools → system → messages).
    pub(crate) fn check_order(self) -> Result<(), &'static str> {
        let mut seen_short = false;
        for ttl in [self.tools, self.system, self.messages]
            .into_iter()
            .flatten()
        {
            match ttl {
                CacheTtl::FiveMinutes => seen_short = true,
                CacheTtl::OneHour if seen_short => {
                    return Err(
                        "a one-hour cache breakpoint may not follow a five-minute one \
                         (render order is tools, system, messages)",
                    );
                }
                CacheTtl::OneHour => {}
            }
        }
        Ok(())
    }
}

/// Visibility of thinking content in responses.
///
/// Thinking is billed the same under every setting; this only controls what
/// comes back. The raw chain of thought is never returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ThinkingDisplay {
    /// A readable summary of the reasoning.
    Summarized,
    /// Thinking blocks with empty text (the default on current models).
    Omitted,
}

/// Extended-thinking configuration (the request's `thinking` field).
///
/// Which modes a model accepts differs by generation; for a known model the
/// client rejects an unsupported mode locally (see
/// [`ModelInfo`](crate::ModelInfo)'s thinking flags):
///
/// - [`Adaptive`](Self::Adaptive) — the model decides how much to think.
///   The recommended mode on every current model except Claude Haiku 4.5.
///   Steer depth with [`Effort`].
/// - [`Budget`](Self::Budget) — a fixed thinking budget (`budget_tokens`).
///   Only older models accept it (Claude Opus 4.6, Sonnet 4.6, Haiku 4.5);
///   newer ones reject it with HTTP 400. The budget must be at least 1024
///   and below `max_tokens`.
/// - [`Disabled`](Self::Disabled) — no thinking. Rejected by models whose
///   thinking is always on.
///
/// Thinking blocks are parsed from responses (see
/// [`MessageResponse::thinking`](crate::MessageResponse::thinking)) and never
/// mixed into the response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Thinking {
    /// Adaptive thinking.
    Adaptive {
        /// Optional display setting.
        #[serde(skip_serializing_if = "Option::is_none")]
        display: Option<ThinkingDisplay>,
    },
    /// Fixed thinking budget (older models only).
    #[serde(rename = "enabled")]
    Budget {
        /// Thinking tokens the model may use; counts against `max_tokens`.
        budget_tokens: u32,
        /// Optional display setting.
        #[serde(skip_serializing_if = "Option::is_none")]
        display: Option<ThinkingDisplay>,
    },
    /// Thinking off.
    Disabled,
}

impl Thinking {
    /// Smallest budget the API accepts for [`Budget`](Self::Budget).
    pub const MIN_BUDGET_TOKENS: u32 = 1024;

    /// Adaptive thinking with the model's default display.
    #[must_use]
    pub const fn adaptive() -> Self {
        Self::Adaptive { display: None }
    }

    /// A fixed thinking budget, for models that still accept one.
    #[must_use]
    pub const fn budget(budget_tokens: u32) -> Self {
        Self::Budget {
            budget_tokens,
            display: None,
        }
    }

    /// Set the display; no effect on [`Disabled`](Self::Disabled).
    #[must_use]
    pub const fn with_display(self, display: ThinkingDisplay) -> Self {
        match self {
            Self::Adaptive { .. } => Self::Adaptive {
                display: Some(display),
            },
            Self::Budget { budget_tokens, .. } => Self::Budget {
                budget_tokens,
                display: Some(display),
            },
            Self::Disabled => Self::Disabled,
        }
    }

    /// `true` unless [`Disabled`](Self::Disabled).
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// How much effort the model spends (thinking depth and overall token
/// spend), sent as `output_config.effort`.
///
/// Defaults differ per model (e.g. `medium` on Claude Opus 5.5, `high` on
/// Claude Sonnet 5.5). [`Xhigh`](Self::Xhigh) and [`Max`](Self::Max) are not
/// accepted by every model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Effort {
    /// Least effort: fast, terse; good for simple tasks and sub-agents.
    Low,
    /// Medium effort.
    Medium,
    /// High effort.
    High,
    /// Extra-high effort (coding and agentic work on models that accept it).
    Xhigh,
    /// Maximum effort.
    Max,
}

/// Strategy [`Llm::generate_structured`](rune_chain_core::Llm::generate_structured)
/// uses for the JSON response formats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StructuredOutput {
    /// Pick per request (the default):
    ///
    /// - a [`JsonSchema`](rune_chain_core::ResponseFormat::JsonSchema) uses
    ///   [`Native`](Self::Native) unless the model is known not to support it,
    ///   then [`ForcedTool`](Self::ForcedTool) where forced tool choice is
    ///   accepted and thinking is off, else [`Prompt`](Self::Prompt);
    /// - a [`JsonObject`](rune_chain_core::ResponseFormat::JsonObject) uses
    ///   [`ForcedTool`](Self::ForcedTool) where accepted, else
    ///   [`Prompt`](Self::Prompt).
    #[default]
    Auto,
    /// Constrained decoding with `output_config.format` (`json_schema`). The
    /// response text is guaranteed to match the schema. The schema must
    /// follow the API's subset (every object needs
    /// `"additionalProperties": false`).
    Native,
    /// Forced tool use: the schema becomes the input schema of a single tool
    /// the model is required to call, and the tool input is returned as the
    /// generation. Rejected by models that accept only an automatic tool
    /// choice (Claude Fable 5.1/5.2, Opus 5.5, Sonnet 5.5) and when thinking
    /// is on.
    ForcedTool,
    /// No API-level constraint: the format's instructions are added as a
    /// system message (the [`Llm`](rune_chain_core::Llm) default).
    Prompt,
}

/// Beta flag for server-side refusal fallbacks; sent automatically when
/// [`Anthropic::fallbacks`](crate::Anthropic::fallbacks) is set.
pub const SERVER_SIDE_FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

/// Server-side refusal fallbacks (the request's `fallbacks` field).
///
/// On models with safety classifiers (Claude Opus 5.5, Opus 5, Fable 5.1,
/// Fable 5.2, Sonnet 5.5) a request can be declined with
/// `stop_reason: "refusal"`. With fallbacks set, the API re-runs a declined
/// request on another model inside the same call; the response then reports
/// the switch (see [`MessageResponse::served_by_fallback`](crate::MessageResponse::served_by_fallback)
/// and [`MessageResponse::fallback_switches`](crate::MessageResponse::fallback_switches)).
/// A refusal on the final response means every model in the chain declined.
///
/// Setting fallbacks adds the [`SERVER_SIDE_FALLBACK_BETA`] header. Not
/// accepted by the Batches API or on Bedrock, Vertex AI and Foundry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fallbacks {
    /// `"default"`: the API picks the fallback model by refusal category.
    /// The preferred form; no model list to maintain.
    Default,
    /// An explicit chain of 1–3 distinct fallback models, tried in order.
    Models(Vec<FallbackModel>),
}

impl Fallbacks {
    /// Most entries the [`Models`](Self::Models) form may hold.
    pub const MAX_MODELS: usize = 3;

    /// An explicit fallback chain.
    #[must_use]
    pub fn models(models: impl IntoIterator<Item = FallbackModel>) -> Self {
        Self::Models(models.into_iter().collect())
    }

    /// Check what can be checked locally: the [`Models`](Self::Models) form
    /// needs 1–3 entries, each with a model id, and no entry twice.
    ///
    /// # Errors
    ///
    /// [`LlmError::other`](rune_chain_core::LlmError::other) describing the
    /// first problem found.
    pub fn validate(&self) -> Result<(), rune_chain_core::LlmError> {
        let Self::Models(models) = self else {
            return Ok(());
        };
        let err = |msg: String| Err(rune_chain_core::LlmError::other(msg));
        if models.is_empty() || models.len() > Self::MAX_MODELS {
            return err(format!(
                "fallbacks need 1 to {} models, got {}",
                Self::MAX_MODELS,
                models.len()
            ));
        }
        for (i, entry) in models.iter().enumerate() {
            if entry.model.trim().is_empty() {
                return err(format!("fallback entry {i} has an empty model id"));
            }
            if models[..i].contains(entry) {
                return err(format!(
                    "fallback entry {i} (`{}`) repeats an earlier entry",
                    entry.model
                ));
            }
        }
        Ok(())
    }
}

impl Serialize for Fallbacks {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Default => serializer.serialize_str("default"),
            Self::Models(models) => models.serialize(serializer),
        }
    }
}

/// One entry of [`Fallbacks::Models`]: a fallback model and optional
/// settings that apply to that attempt only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FallbackModel {
    /// Model id, e.g. `claude-opus-4-8`.
    pub model: String,
    /// `max_tokens` for this attempt.
    pub max_tokens: Option<u32>,
    /// `thinking` for this attempt.
    pub thinking: Option<Thinking>,
    /// `output_config.effort` for this attempt.
    pub effort: Option<Effort>,
    /// `speed` for this attempt (e.g. `"fast"` where the model offers it).
    pub speed: Option<String>,
}

impl FallbackModel {
    /// A fallback to `model` with the request's own settings.
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            max_tokens: None,
            thinking: None,
            effort: None,
            speed: None,
        }
    }

    /// Override `max_tokens` for this attempt.
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Override `thinking` for this attempt.
    #[must_use]
    pub const fn with_thinking(mut self, thinking: Thinking) -> Self {
        self.thinking = Some(thinking);
        self
    }

    /// Override the effort (`output_config.effort`) for this attempt.
    #[must_use]
    pub const fn with_effort(mut self, effort: Effort) -> Self {
        self.effort = Some(effort);
        self
    }

    /// Override `speed` for this attempt.
    #[must_use]
    pub fn with_speed(mut self, speed: impl Into<String>) -> Self {
        self.speed = Some(speed.into());
        self
    }
}

impl Serialize for FallbackModel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct EntryOutput {
            effort: Effort,
        }
        #[derive(Serialize)]
        struct Entry<'a> {
            model: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            max_tokens: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            thinking: Option<Thinking>,
            #[serde(skip_serializing_if = "Option::is_none")]
            output_config: Option<EntryOutput>,
            #[serde(skip_serializing_if = "Option::is_none")]
            speed: Option<&'a str>,
        }
        Entry {
            model: &self.model,
            max_tokens: self.max_tokens,
            thinking: self.thinking,
            output_config: self.effort.map(|effort| EntryOutput { effort }),
            speed: self.speed.as_deref(),
        }
        .serialize(serializer)
    }
}

//! Claude model identifiers and per-model capability notes.
//!
//! The model a client talks to is a free-form string — pass any id the
//! Messages API accepts to [`Anthropic::model`](crate::Anthropic::model),
//! including ids released after this crate. The constants here are the ids
//! that were current when the crate was published, and [`lookup`] returns a
//! [`ModelInfo`] capability note for each of them.
//!
//! The client uses these notes for a cheap pre-flight check: a request that a
//! *known* model is documented to reject (a sampling `temperature` on a model
//! that no longer accepts one, or a forced tool choice on a model that only
//! accepts `auto`) fails locally with [`LlmError::other`](rune_chain_core::LlmError::other)
//! instead of a round trip ending in HTTP 400. Unknown ids are never checked.
//!
//! Each note also carries the model's list [`Pricing`], so a token count
//! turns into a cost with [`Pricing::cost`].
//!
//! ```rust
//! use rune_chain_anthropic::{Anthropic, models};
//!
//! let llm = Anthropic::new("sk-ant-example").model(models::CLAUDE_OPUS_5_5);
//!
//! let info = models::lookup(models::CLAUDE_OPUS_5_5).unwrap();
//! assert_eq!(info.context_window, 1_000_000);
//! assert!(!info.sampling_params);
//! assert_eq!(info.pricing.input, 4_000_000); // $4 / MTok
//!
//! // Ids the table does not know are still usable.
//! assert!(models::lookup("claude-next").is_none());
//! let _llm = Anthropic::new("sk-ant-example").model("claude-next");
//! ```

use rune_chain_core::Pricing;

/// Claude Fable 5.2 — the most capable widely released Claude model.
pub const CLAUDE_FABLE_5_2: &str = "claude-fable-5-2";
/// Claude Fable 5.1 — previous Fable release, still served.
pub const CLAUDE_FABLE_5_1: &str = "claude-fable-5-1";
/// Claude Fable 5 — first Fable release, still served.
pub const CLAUDE_FABLE_5: &str = "claude-fable-5";
/// Claude Opus 5.5 — the current Opus.
pub const CLAUDE_OPUS_5_5: &str = "claude-opus-5-5";
/// Claude Opus 5.
pub const CLAUDE_OPUS_5: &str = "claude-opus-5";
/// Claude Opus 4.8.
pub const CLAUDE_OPUS_4_8: &str = "claude-opus-4-8";
/// Claude Opus 4.7.
pub const CLAUDE_OPUS_4_7: &str = "claude-opus-4-7";
/// Claude Opus 4.6.
pub const CLAUDE_OPUS_4_6: &str = "claude-opus-4-6";
/// Claude Sonnet 5.5 — the current Sonnet, and this crate's default.
pub const CLAUDE_SONNET_5_5: &str = "claude-sonnet-5-5";
/// Claude Sonnet 5.
pub const CLAUDE_SONNET_5: &str = "claude-sonnet-5";
/// Claude Sonnet 4.6.
pub const CLAUDE_SONNET_4_6: &str = "claude-sonnet-4-6";
/// Claude Haiku 5.5 — the current Haiku.
pub const CLAUDE_HAIKU_5_5: &str = "claude-haiku-5-5";
/// Claude Haiku 4.5.
pub const CLAUDE_HAIKU_4_5: &str = "claude-haiku-4-5";

/// The model a freshly built [`Anthropic`](crate::Anthropic) client uses.
pub const DEFAULT_MODEL: &str = CLAUDE_SONNET_5_5;

/// Model tier within the Claude family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Tier {
    /// Fable — the most capable tier.
    Fable,
    /// Opus — frontier capability at a lower price than Fable.
    Opus,
    /// Sonnet — balance of speed and capability.
    Sonnet,
    /// Haiku — fastest and cheapest.
    Haiku,
}

/// Capability note for one Claude model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags, mirrored from provider docs"
)]
pub struct ModelInfo {
    /// The API model id, e.g. `"claude-opus-5-5"`.
    pub id: &'static str,
    /// Human-readable name, e.g. `"Claude Opus 5.5"`.
    pub display_name: &'static str,
    /// Model tier.
    pub tier: Tier,
    /// Context window in tokens.
    pub context_window: u32,
    /// Maximum `max_tokens` the model accepts (large values need streaming).
    pub max_output_tokens: u32,
    /// Whether the model accepts image input.
    pub vision: bool,
    /// Whether the model accepts native tool use.
    pub tools: bool,
    /// Whether a non-default sampling `temperature` is accepted. Newer models
    /// reject sampling parameters with HTTP 400.
    pub sampling_params: bool,
    /// Whether a forced tool choice ([`ToolChoice::Required`] or
    /// [`ToolChoice::Tool`]) is accepted; models without it accept only
    /// `auto`.
    ///
    /// [`ToolChoice::Required`]: rune_chain_core::ToolChoice::Required
    /// [`ToolChoice::Tool`]: rune_chain_core::ToolChoice::Tool
    pub forced_tool_choice: bool,
    /// Whether extended thinking is always on (it cannot be disabled, and
    /// counts against `max_tokens`).
    pub thinking_always_on: bool,
    /// Whether adaptive thinking (`{"type": "adaptive"}`) is accepted.
    pub adaptive_thinking: bool,
    /// Whether a fixed thinking budget (`budget_tokens`) is accepted. Newer
    /// models reject it with HTTP 400.
    pub thinking_budget: bool,
    /// Whether thinking can be turned off with `{"type": "disabled"}`.
    pub thinking_can_disable: bool,
    /// Whether native structured output (`output_config.format`) is
    /// supported.
    pub native_structured_output: bool,
    /// Short free-text note on what the model is for.
    pub note: &'static str,
    /// First-party Claude API list prices at the time this crate was
    /// published (Amazon Bedrock and Vertex AI bill separately). Use it with
    /// `rune-chain-usage` or [`Pricing::cost`] to estimate spend. Claude
    /// Haiku 5.5 charges more for prompts over 100K tokens; the table holds
    /// its base tier.
    pub pricing: Pricing,
}

const M: u32 = 1_000_000;
const K128: u32 = 128_000;

#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "positional table rows keep KNOWN_MODELS compact"
)]
const fn info(
    id: &'static str,
    display_name: &'static str,
    tier: Tier,
    context_window: u32,
    max_output_tokens: u32,
    sampling_params: bool,
    forced_tool_choice: bool,
    thinking_always_on: bool,
    note: &'static str,
    pricing: Pricing,
) -> ModelInfo {
    ModelInfo {
        id,
        display_name,
        tier,
        context_window,
        max_output_tokens,
        vision: true,
        tools: true,
        sampling_params,
        forced_tool_choice,
        thinking_always_on,
        adaptive_thinking: true,
        thinking_budget: false,
        thinking_can_disable: !thinking_always_on,
        native_structured_output: true,
        note,
        pricing,
    }
}

impl ModelInfo {
    /// Override the thinking modes (table helper).
    const fn thinking_modes(mut self, adaptive: bool, budget: bool, can_disable: bool) -> Self {
        self.adaptive_thinking = adaptive;
        self.thinking_budget = budget;
        self.thinking_can_disable = can_disable;
        self
    }

    /// Mark native structured output unsupported (table helper).
    const fn without_native_structured_output(mut self) -> Self {
        self.native_structured_output = false;
        self
    }
}

/// List prices: input, output and cache-read in micro-dollars per million
/// tokens. Cache writes (5-minute TTL) cost 1.25× the input price.
const fn usd(input: u64, output: u64, cache_read: u64) -> Pricing {
    Pricing::per_mtok(input, output).with_cache(cache_read, input / 4 * 5)
}

/// Every model this crate has a capability note for, newest first per tier.
pub const KNOWN_MODELS: &[ModelInfo] = &[
    info(
        CLAUDE_FABLE_5_2,
        "Claude Fable 5.2",
        Tier::Fable,
        M,
        K128,
        false,
        false,
        true,
        "Most capable widely released model; demanding reasoning and long-horizon agentic work.",
        usd(8_000_000, 40_000_000, 200_000),
    ),
    info(
        CLAUDE_FABLE_5_1,
        "Claude Fable 5.1",
        Tier::Fable,
        M,
        K128,
        false,
        false,
        true,
        "Previous Fable; superseded by Fable 5.2 at a lower price.",
        usd(10_000_000, 50_000_000, 250_000),
    ),
    info(
        CLAUDE_FABLE_5,
        "Claude Fable 5",
        Tier::Fable,
        M,
        K128,
        false,
        true,
        true,
        "First Fable release.",
        usd(10_000_000, 50_000_000, 1_000_000),
    ),
    info(
        CLAUDE_OPUS_5_5,
        "Claude Opus 5.5",
        Tier::Opus,
        M,
        K128,
        false,
        false,
        true,
        "Current Opus; strong general and agentic model, effort defaults to medium.",
        usd(4_000_000, 20_000_000, 200_000),
    ),
    info(
        CLAUDE_OPUS_5,
        "Claude Opus 5",
        Tier::Opus,
        M,
        K128,
        false,
        true,
        false,
        "Previous Opus; adaptive thinking on by default.",
        usd(5_000_000, 25_000_000, 500_000),
    ),
    info(
        CLAUDE_OPUS_4_8,
        "Claude Opus 4.8",
        Tier::Opus,
        M,
        K128,
        false,
        true,
        false,
        "Opus 4 generation; thinking off unless requested.",
        usd(5_000_000, 25_000_000, 500_000),
    ),
    info(
        CLAUDE_OPUS_4_7,
        "Claude Opus 4.7",
        Tier::Opus,
        M,
        K128,
        false,
        true,
        false,
        "Opus 4 generation; thinking off unless requested.",
        usd(5_000_000, 25_000_000, 500_000),
    )
    .without_native_structured_output(),
    info(
        CLAUDE_OPUS_4_6,
        "Claude Opus 4.6",
        Tier::Opus,
        M,
        K128,
        true,
        true,
        false,
        "Oldest current Opus; still accepts sampling parameters.",
        usd(5_000_000, 25_000_000, 500_000),
    )
    .thinking_modes(true, true, true)
    .without_native_structured_output(),
    info(
        CLAUDE_SONNET_5_5,
        "Claude Sonnet 5.5",
        Tier::Sonnet,
        M,
        K128,
        false,
        false,
        false,
        "Current Sonnet; speed and capability for everyday coding and agent work.",
        usd(2_000_000, 10_000_000, 100_000),
    )
    .thinking_modes(true, false, false),
    info(
        CLAUDE_SONNET_5,
        "Claude Sonnet 5",
        Tier::Sonnet,
        M,
        K128,
        false,
        true,
        false,
        "Previous Sonnet; still accepts forced tool choice.",
        usd(2_000_000, 10_000_000, 200_000),
    ),
    info(
        CLAUDE_SONNET_4_6,
        "Claude Sonnet 4.6",
        Tier::Sonnet,
        M,
        K128,
        true,
        true,
        false,
        "Sonnet 4 generation; still accepts sampling parameters.",
        usd(3_000_000, 15_000_000, 300_000),
    )
    .thinking_modes(true, true, true)
    .without_native_structured_output(),
    info(
        CLAUDE_HAIKU_5_5,
        "Claude Haiku 5.5",
        Tier::Haiku,
        M,
        K128,
        false,
        true,
        false,
        "Current Haiku; cheapest and fastest, good for sub-tasks and classification.",
        usd(100_000, 500_000, 10_000),
    ),
    info(
        CLAUDE_HAIKU_4_5,
        "Claude Haiku 4.5",
        Tier::Haiku,
        200_000,
        64_000,
        true,
        true,
        false,
        "Previous Haiku; 200K context.",
        usd(1_000_000, 5_000_000, 100_000),
    )
    .thinking_modes(false, true, true),
];

/// Return the capability note for a known model id, or `None` for an id this
/// crate does not know (which is still a valid model to use).
#[must_use]
pub fn lookup(id: &str) -> Option<&'static ModelInfo> {
    KNOWN_MODELS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for m in KNOWN_MODELS {
            assert!(seen.insert(m.id), "duplicate id {}", m.id);
            assert!(m.id.starts_with("claude-"), "{}", m.id);
            assert!(
                m.id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}",
                m.id
            );
            assert!(m.max_output_tokens < m.context_window, "{}", m.id);
            assert_ne!(m.note, "");
            assert!(m.display_name.starts_with("Claude "));
        }
    }

    #[test]
    fn every_constant_has_a_note() {
        for id in [
            CLAUDE_FABLE_5_2,
            CLAUDE_FABLE_5_1,
            CLAUDE_FABLE_5,
            CLAUDE_OPUS_5_5,
            CLAUDE_OPUS_5,
            CLAUDE_OPUS_4_8,
            CLAUDE_OPUS_4_7,
            CLAUDE_OPUS_4_6,
            CLAUDE_SONNET_5_5,
            CLAUDE_SONNET_5,
            CLAUDE_SONNET_4_6,
            CLAUDE_HAIKU_5_5,
            CLAUDE_HAIKU_4_5,
        ] {
            assert_eq!(lookup(id).map(|m| m.id), Some(id));
        }
        assert_eq!(KNOWN_MODELS.len(), 13);
        assert!(lookup(DEFAULT_MODEL).is_some());
    }

    #[test]
    fn pricing_is_consistent() {
        for m in KNOWN_MODELS {
            let p = m.pricing;
            assert!(p.input > 0 && p.output > p.input, "{}", m.id);
            assert!(p.cache_read < p.input, "{}", m.id);
            assert_eq!(p.cache_write * 4, p.input * 5, "{}", m.id);
        }
        let opus = lookup(CLAUDE_OPUS_5_5).unwrap().pricing;
        assert_eq!(
            (opus.input, opus.output, opus.cache_read),
            (4_000_000, 20_000_000, 200_000)
        );
        let haiku = lookup(CLAUDE_HAIKU_5_5).unwrap().pricing;
        assert_eq!((haiku.input, haiku.output), (100_000, 500_000));
    }

    #[test]
    fn thinking_and_structured_output_flags_are_consistent() {
        for m in KNOWN_MODELS {
            if m.thinking_always_on {
                assert!(!m.thinking_can_disable, "{}", m.id);
            }
            assert!(m.adaptive_thinking || m.thinking_budget, "{}", m.id);
        }
        // Fixed budgets only on the older models that still take them.
        let budget: Vec<_> = KNOWN_MODELS
            .iter()
            .filter(|m| m.thinking_budget)
            .map(|m| m.id)
            .collect();
        assert_eq!(
            budget,
            [CLAUDE_OPUS_4_6, CLAUDE_SONNET_4_6, CLAUDE_HAIKU_4_5]
        );
        assert!(!lookup(CLAUDE_SONNET_5_5).unwrap().thinking_can_disable);
        for id in [
            CLAUDE_FABLE_5_2,
            CLAUDE_OPUS_5_5,
            CLAUDE_SONNET_5_5,
            CLAUDE_HAIKU_5_5,
        ] {
            assert!(lookup(id).unwrap().native_structured_output, "{id}");
        }
    }

    #[test]
    fn unknown_ids_have_no_note() {
        assert!(lookup("claude-test").is_none());
        assert!(lookup("").is_none());
        assert!(lookup("CLAUDE-OPUS-5-5").is_none());
    }
}

//! `OpenAI` chat model identifiers and per-model capability notes.
//!
//! The model a client talks to is a free-form string — pass any id
//! `/v1/chat/completions` accepts to [`OpenAi::model`](crate::OpenAi::model),
//! including ids released after this crate. The constants here are ids that
//! were current when the crate was published, and [`lookup`] returns a
//! [`ModelInfo`] capability note for each of them.
//!
//! The client uses these notes for a cheap pre-flight check: a sampling
//! `temperature` on a known reasoning model (which only accepts the default)
//! fails locally with [`LlmError::other`](rune_chain_core::LlmError::other)
//! instead of a round trip ending in HTTP 400. Unknown ids are never checked.
//!
//! Each note also carries the model's list [`Pricing`], so a token count
//! turns into a cost with [`Pricing::cost`].
//!
//! ```rust
//! use rune_chain_openai::{OpenAi, models};
//!
//! let _llm = OpenAi::new("sk-example").model(models::GPT_4_1_MINI);
//!
//! let info = models::lookup(models::GPT_5).unwrap();
//! assert!(info.reasoning && !info.sampling_params);
//! assert_eq!(info.pricing.output, 10_000_000); // $10 / MTok
//!
//! // Ids the table does not know are still usable.
//! assert!(models::lookup("gpt-next").is_none());
//! let _llm = OpenAi::new("sk-example").model("gpt-next");
//! ```

use rune_chain_core::Pricing;

/// GPT-5.2 — current flagship reasoning model (December 2025).
pub const GPT_5_2: &str = "gpt-5.2";
/// GPT-5.1 — reasoning model (November 2025).
pub const GPT_5_1: &str = "gpt-5.1";
/// GPT-5 — reasoning model (August 2025).
pub const GPT_5: &str = "gpt-5";
/// GPT-5 mini — smaller, cheaper GPT-5; this crate's default.
pub const GPT_5_MINI: &str = "gpt-5-mini";
/// GPT-5 nano — smallest, fastest GPT-5.
pub const GPT_5_NANO: &str = "gpt-5-nano";
/// GPT-4.1 — non-reasoning model with a 1M-token context window.
pub const GPT_4_1: &str = "gpt-4.1";
/// GPT-4.1 mini.
pub const GPT_4_1_MINI: &str = "gpt-4.1-mini";
/// GPT-4.1 nano.
pub const GPT_4_1_NANO: &str = "gpt-4.1-nano";
/// GPT-4o — earlier multimodal non-reasoning model.
pub const GPT_4O: &str = "gpt-4o";
/// GPT-4o mini.
pub const GPT_4O_MINI: &str = "gpt-4o-mini";
/// o3 — reasoning model.
pub const O3: &str = "o3";
/// o4-mini — small reasoning model.
pub const O4_MINI: &str = "o4-mini";

/// The model a freshly built [`OpenAi`](crate::OpenAi) client uses.
pub const DEFAULT_MODEL: &str = GPT_5_MINI;

/// Capability note for one `OpenAI` chat model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent capability flags, mirrored from provider docs"
)]
pub struct ModelInfo {
    /// The API model id, e.g. `"gpt-5"`.
    pub id: &'static str,
    /// Context window in tokens.
    pub context_window: u32,
    /// Maximum completion tokens (including hidden reasoning tokens).
    pub max_output_tokens: u32,
    /// Whether the model accepts image input.
    pub vision: bool,
    /// Whether the model accepts native tool calling.
    pub tools: bool,
    /// Whether this is a reasoning model: hidden reasoning tokens count
    /// against `max_tokens`, so leave generous headroom.
    pub reasoning: bool,
    /// Whether a non-default sampling `temperature` is accepted.
    pub sampling_params: bool,
    /// Short free-text note on what the model is for.
    pub note: &'static str,
    /// Standard-tier list prices at the time this crate was published (batch
    /// and flex tiers are cheaper, priority dearer). Use it with
    /// `rune-chain-usage` or [`Pricing::cost`] to estimate spend.
    pub pricing: Pricing,
}

const fn info(
    id: &'static str,
    context_window: u32,
    max_output_tokens: u32,
    reasoning: bool,
    note: &'static str,
    pricing: Pricing,
) -> ModelInfo {
    ModelInfo {
        id,
        context_window,
        max_output_tokens,
        vision: true,
        tools: true,
        reasoning,
        sampling_params: !reasoning,
        note,
        pricing,
    }
}

/// List prices: input, output and cached-input in micro-dollars per million
/// tokens. `OpenAI` does not charge extra for cache writes.
const fn usd(input: u64, output: u64, cache_read: u64) -> Pricing {
    Pricing::per_mtok(input, output).with_cache(cache_read, input)
}

/// Every model this crate has a capability note for.
pub const KNOWN_MODELS: &[ModelInfo] = &[
    info(
        GPT_5_2,
        400_000,
        128_000,
        true,
        "Flagship reasoning model for coding and agentic tasks.",
        usd(1_750_000, 14_000_000, 175_000),
    ),
    info(
        GPT_5_1,
        400_000,
        128_000,
        true,
        "GPT-5 refresh with adaptive reasoning.",
        usd(1_250_000, 10_000_000, 125_000),
    ),
    info(
        GPT_5,
        400_000,
        128_000,
        true,
        "Original GPT-5 reasoning model.",
        usd(1_250_000, 10_000_000, 125_000),
    ),
    info(
        GPT_5_MINI,
        400_000,
        128_000,
        true,
        "Cheaper GPT-5 for well-defined tasks.",
        usd(250_000, 2_000_000, 25_000),
    ),
    info(
        GPT_5_NANO,
        400_000,
        128_000,
        true,
        "Fastest, cheapest GPT-5; classification and extraction.",
        usd(50_000, 400_000, 5_000),
    ),
    info(
        GPT_4_1,
        1_047_576,
        32_768,
        false,
        "Non-reasoning; long context, strong instruction following.",
        usd(2_000_000, 8_000_000, 500_000),
    ),
    info(
        GPT_4_1_MINI,
        1_047_576,
        32_768,
        false,
        "Smaller GPT-4.1.",
        usd(400_000, 1_600_000, 100_000),
    ),
    info(
        GPT_4_1_NANO,
        1_047_576,
        32_768,
        false,
        "Smallest GPT-4.1.",
        usd(100_000, 400_000, 25_000),
    ),
    info(
        GPT_4O,
        128_000,
        16_384,
        false,
        "Earlier multimodal non-reasoning model.",
        usd(2_500_000, 10_000_000, 1_250_000),
    ),
    info(
        GPT_4O_MINI,
        128_000,
        16_384,
        false,
        "Smaller GPT-4o.",
        usd(150_000, 600_000, 75_000),
    ),
    info(
        O3,
        200_000,
        100_000,
        true,
        "o-series reasoning model.",
        usd(2_000_000, 8_000_000, 500_000),
    ),
    info(
        O4_MINI,
        200_000,
        100_000,
        true,
        "Small o-series reasoning model.",
        usd(1_100_000, 4_400_000, 275_000),
    ),
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
    fn ids_are_unique_and_consistent() {
        let mut seen = HashSet::new();
        for m in KNOWN_MODELS {
            assert!(seen.insert(m.id), "duplicate id {}", m.id);
            assert!(m.max_output_tokens < m.context_window, "{}", m.id);
            assert_eq!(m.sampling_params, !m.reasoning, "{}", m.id);
            assert_ne!(m.note, "");
        }
    }

    #[test]
    fn every_constant_has_a_note() {
        for id in [
            GPT_5_2,
            GPT_5_1,
            GPT_5,
            GPT_5_MINI,
            GPT_5_NANO,
            GPT_4_1,
            GPT_4_1_MINI,
            GPT_4_1_NANO,
            GPT_4O,
            GPT_4O_MINI,
            O3,
            O4_MINI,
        ] {
            assert_eq!(lookup(id).map(|m| m.id), Some(id));
        }
        assert_eq!(KNOWN_MODELS.len(), 12);
        for m in KNOWN_MODELS {
            let p = m.pricing;
            assert!(p.input > 0 && p.output > p.input, "{}", m.id);
            assert!(
                p.cache_read < p.input && p.cache_write == p.input,
                "{}",
                m.id
            );
        }
        assert_eq!(lookup(GPT_5_NANO).unwrap().pricing.cache_read, 5_000);
        assert!(lookup(DEFAULT_MODEL).is_some());
        assert!(lookup("gpt-3.5-turbo").is_none());
    }
}

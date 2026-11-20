//! Gemini model identifiers, per-model capability notes and list prices.
//!
//! The model a client talks to is a free-form string — pass any id the
//! Gemini API accepts to [`Gemini::model`](crate::Gemini::model), including
//! ids released after this crate. The constants here are ids this crate
//! knows, and [`lookup`] returns a [`ModelInfo`] for each.
//!
//! The client uses the notes for cheap pre-flight checks: a thinking setting
//! a known model is documented to reject fails locally instead of in a round
//! trip ending in HTTP 400. Unknown ids are never checked.
//!
//! Prices are the Gemini API paid tier list prices as of
//! [`PRICES_AS_OF`], for text, image and video input. Pro models charge more
//! for prompts above [`LONG_CONTEXT_THRESHOLD`] tokens; [`ModelInfo::cost`]
//! picks the tier. Context caching storage (billed per hour) is not
//! included. Check the provider's price list before relying on them.
//!
//! ```rust
//! use rune_chain_core::TokenUsage;
//! use rune_chain_gemini::models;
//!
//! let info = models::lookup(models::GEMINI_2_5_PRO).unwrap();
//! assert_eq!(info.pricing.output, 10_000_000); // $10 / MTok
//!
//! // 300k prompt tokens: the long-context tier applies.
//! let usage = TokenUsage::new(300_000, 1_000);
//! assert_eq!(info.cost(&usage).micros(), 300_000 * 2_500_000 / 1_000_000 + 15_000);
//!
//! assert!(models::lookup("gemini-next").is_none());
//! ```

use rune_chain_core::{Cost, Pricing, TokenUsage};

use crate::config::ThinkingLevel;

/// Date of the prices in [`KNOWN_MODELS`].
pub const PRICES_AS_OF: &str = "2026-01";
/// Prompt size above which [`ModelInfo::long_context_pricing`] applies.
pub const LONG_CONTEXT_THRESHOLD: u32 = 200_000;

/// Gemini 3 Pro (preview) — most capable reasoning model.
pub const GEMINI_3_PRO_PREVIEW: &str = "gemini-3-pro-preview";
/// Gemini 3 Flash (preview) — fast frontier-class model.
pub const GEMINI_3_FLASH_PREVIEW: &str = "gemini-3-flash-preview";
/// Gemini 2.5 Pro — thinking model for complex tasks.
pub const GEMINI_2_5_PRO: &str = "gemini-2.5-pro";
/// Gemini 2.5 Flash — price-performance thinking model; this crate's default.
pub const GEMINI_2_5_FLASH: &str = "gemini-2.5-flash";
/// Gemini 2.5 Flash-Lite — cheapest 2.5 model.
pub const GEMINI_2_5_FLASH_LITE: &str = "gemini-2.5-flash-lite";
/// Gemini 2.0 Flash — earlier non-thinking workhorse.
pub const GEMINI_2_0_FLASH: &str = "gemini-2.0-flash";
/// Gemini 2.0 Flash-Lite.
pub const GEMINI_2_0_FLASH_LITE: &str = "gemini-2.0-flash-lite";

/// Gemini embedding model (`gemini-embedding-001`), $0.15 per million input tokens.
pub const GEMINI_EMBEDDING_001: &str = "gemini-embedding-001";

/// The model a freshly built [`Gemini`](crate::Gemini) client uses.
pub const DEFAULT_MODEL: &str = GEMINI_2_5_FLASH;

/// What thinking settings a model accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ThinkingSupport {
    /// Documented range of fixed budgets, inclusive (`None`: not checked
    /// locally).
    pub budget_range: Option<(u32, u32)>,
    /// Whether thinking can be turned off.
    pub can_disable: bool,
    /// Accepted [`ThinkingLevel`]s (empty: levels not accepted).
    pub levels: &'static [ThinkingLevel],
}

/// Capability note for one Gemini model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ModelInfo {
    /// The API model id, e.g. `"gemini-2.5-flash"`.
    pub id: &'static str,
    /// Input context window in tokens.
    pub context_window: u32,
    /// Maximum output tokens (thinking included).
    pub max_output_tokens: u32,
    /// Thinking support; `None` for models that do not think.
    pub thinking: Option<ThinkingSupport>,
    /// Short free-text note on what the model is for.
    pub note: &'static str,
    /// List prices for prompts up to [`LONG_CONTEXT_THRESHOLD`] tokens
    /// (thinking tokens are billed as output).
    pub pricing: Pricing,
    /// List prices for longer prompts, where they differ.
    pub long_context_pricing: Option<Pricing>,
}

impl ModelInfo {
    /// The price tier for a prompt of `prompt_tokens`.
    #[must_use]
    pub const fn pricing_for(&self, prompt_tokens: u32) -> Pricing {
        match self.long_context_pricing {
            Some(long) if prompt_tokens > LONG_CONTEXT_THRESHOLD => long,
            _ => self.pricing,
        }
    }

    /// Cost of a reported [`TokenUsage`] at the matching tier.
    #[must_use]
    pub const fn cost(&self, usage: &TokenUsage) -> Cost {
        self.pricing_for(usage.prompt_tokens).cost(usage)
    }
}

/// List prices in micro-dollars per million tokens: input, output and
/// cached input. Gemini bills cache storage by the hour rather than per
/// write, so cache writes are priced as plain input.
const fn usd(input: u64, output: u64, cache_read: u64) -> Pricing {
    Pricing::per_mtok(input, output).with_cache(cache_read, input)
}

const ALL_LEVELS: &[ThinkingLevel] = &[
    ThinkingLevel::Minimal,
    ThinkingLevel::Low,
    ThinkingLevel::Medium,
    ThinkingLevel::High,
];

const fn model(
    id: &'static str,
    max_output_tokens: u32,
    thinking: Option<ThinkingSupport>,
    note: &'static str,
    pricing: Pricing,
    long_context_pricing: Option<Pricing>,
) -> ModelInfo {
    ModelInfo {
        id,
        context_window: 1_048_576,
        max_output_tokens,
        thinking,
        note,
        pricing,
        long_context_pricing,
    }
}

/// Every model this crate has a capability note for.
pub const KNOWN_MODELS: &[ModelInfo] = &[
    model(
        GEMINI_3_PRO_PREVIEW,
        65_536,
        Some(ThinkingSupport {
            budget_range: None,
            can_disable: false,
            levels: &[ThinkingLevel::Low, ThinkingLevel::High],
        }),
        "Most capable reasoning and agentic model; thinking always on.",
        usd(2_000_000, 12_000_000, 200_000),
        Some(usd(4_000_000, 18_000_000, 400_000)),
    ),
    model(
        GEMINI_3_FLASH_PREVIEW,
        65_536,
        Some(ThinkingSupport {
            budget_range: None,
            can_disable: false,
            levels: ALL_LEVELS,
        }),
        "Fast Gemini 3 model; `minimal` thinking for the lowest latency.",
        usd(500_000, 3_000_000, 50_000),
        None,
    ),
    model(
        GEMINI_2_5_PRO,
        65_536,
        Some(ThinkingSupport {
            budget_range: Some((128, 32_768)),
            can_disable: false,
            levels: &[],
        }),
        "Thinking model for coding and complex reasoning; thinking always on.",
        usd(1_250_000, 10_000_000, 125_000),
        Some(usd(2_500_000, 15_000_000, 250_000)),
    ),
    model(
        GEMINI_2_5_FLASH,
        65_536,
        Some(ThinkingSupport {
            budget_range: Some((1, 24_576)),
            can_disable: true,
            levels: &[],
        }),
        "Price-performance thinking model; thinking can be turned off.",
        usd(300_000, 2_500_000, 30_000),
        None,
    ),
    model(
        GEMINI_2_5_FLASH_LITE,
        65_536,
        Some(ThinkingSupport {
            budget_range: Some((512, 24_576)),
            can_disable: true,
            levels: &[],
        }),
        "Cheapest 2.5 model; thinking off unless a budget is set.",
        usd(100_000, 400_000, 10_000),
        None,
    ),
    model(
        GEMINI_2_0_FLASH,
        8_192,
        None,
        "Earlier non-thinking model.",
        usd(100_000, 400_000, 25_000),
        None,
    ),
    model(
        GEMINI_2_0_FLASH_LITE,
        8_192,
        None,
        "Smallest 2.0 model; no context caching.",
        usd(75_000, 300_000, 75_000),
        None,
    ),
];

/// Return the capability note for a known model id (a `models/` prefix is
/// ignored), or `None` for an id this crate does not know (which is still a
/// valid model to use).
#[must_use]
pub fn lookup(id: &str) -> Option<&'static ModelInfo> {
    let id = id.strip_prefix("models/").unwrap_or(id);
    KNOWN_MODELS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use std::collections::HashSet;

    use super::*;

    #[test]
    fn table_is_consistent() {
        let mut seen = HashSet::new();
        for m in KNOWN_MODELS {
            assert!(seen.insert(m.id), "duplicate id {}", m.id);
            assert!(m.max_output_tokens < m.context_window, "{}", m.id);
            assert_ne!(m.note, "");
            let p = m.pricing;
            assert!(p.input > 0 && p.output > p.input, "{}", m.id);
            assert!(
                p.cache_read <= p.input && p.cache_write == p.input,
                "{}",
                m.id
            );
            if let Some(long) = m.long_context_pricing {
                assert!(long.input > p.input && long.output > p.output, "{}", m.id);
            }
            if let Some(t) = m.thinking
                && let Some((lo, hi)) = t.budget_range
            {
                assert!(lo >= 1 && lo < hi && hi <= m.max_output_tokens, "{}", m.id);
            }
        }
        for id in [
            GEMINI_3_PRO_PREVIEW,
            GEMINI_3_FLASH_PREVIEW,
            GEMINI_2_5_PRO,
            GEMINI_2_5_FLASH,
            GEMINI_2_5_FLASH_LITE,
            GEMINI_2_0_FLASH,
            GEMINI_2_0_FLASH_LITE,
        ] {
            assert_eq!(lookup(id).map(|m| m.id), Some(id));
        }
        assert_eq!(KNOWN_MODELS.len(), 7);
        assert!(lookup(DEFAULT_MODEL).is_some());
        assert_eq!(
            lookup("models/gemini-2.5-flash").map(|m| m.id),
            Some(GEMINI_2_5_FLASH)
        );
        assert!(lookup("gemini-1.0-pro").is_none());
    }

    #[test]
    fn tiered_cost() {
        let pro = lookup(GEMINI_2_5_PRO).unwrap();
        // 1000 in + 100 out at $1.25 / $10.
        let usage = TokenUsage::new(1_000, 100);
        assert_eq!(
            pro.cost(&usage).picodollars(),
            1_000 * 1_250_000 + 100 * 10_000_000
        );
        // Exactly at the threshold stays on the base tier.
        let usage = TokenUsage::new(LONG_CONTEXT_THRESHOLD, 0);
        assert_eq!(pro.pricing_for(usage.prompt_tokens), pro.pricing);
        let usage = TokenUsage::new(LONG_CONTEXT_THRESHOLD + 1, 0);
        assert_eq!(
            pro.pricing_for(usage.prompt_tokens),
            pro.long_context_pricing.unwrap()
        );
        // Cached tokens at the cache rate.
        let flash = lookup(GEMINI_2_5_FLASH).unwrap();
        let usage = TokenUsage::new(1_000, 0).with_cache_read_tokens(800);
        assert_eq!(
            flash.cost(&usage).picodollars(),
            200 * 300_000 + 800 * 30_000
        );
    }
}

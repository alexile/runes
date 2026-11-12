//! Per-model token prices and exact, integer cost arithmetic.
//!
//! Provider crates attach a [`Pricing`] to each model they know about (see
//! `ModelInfo::pricing` in `rune-chain-anthropic` and `rune-chain-openai`), and
//! accounting layers turn token counts into a [`Cost`].
//!
//! Prices are stored as integer **micro-dollars per million tokens**
//! (`$3.00 / MTok` is `3_000_000`), so multiplying by a token count yields
//! **picodollars** exactly — no floating-point rounding accumulates over a
//! long run.

use std::fmt;
use std::ops::{Add, AddAssign};

use serde::{Deserialize, Serialize};

use crate::TokenUsage;

/// Picodollars in one US dollar.
const PICO_PER_USD: u64 = 1_000_000_000_000;

/// An amount of money in US dollars, held as an integer number of
/// picodollars (10⁻¹² USD).
///
/// Arithmetic saturates at [`u64::MAX`] (about 18.4 million dollars) rather
/// than overflowing.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::Cost;
///
/// let c = Cost::from_micros(1_500); // $0.0015
/// assert_eq!(c.to_string(), "$0.001500");
/// assert_eq!((c + c).micros(), 3_000);
/// ```
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Cost(u64);

impl Cost {
    /// Zero dollars.
    pub const ZERO: Self = Self(0);

    /// A cost of `picodollars` × 10⁻¹² USD.
    #[must_use]
    pub const fn from_picodollars(picodollars: u64) -> Self {
        Self(picodollars)
    }

    /// A cost of `micros` × 10⁻⁶ USD (saturating).
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros.saturating_mul(1_000_000))
    }

    /// A cost of whole cents (saturating).
    #[must_use]
    pub const fn from_cents(cents: u64) -> Self {
        Self(cents.saturating_mul(10_000_000_000))
    }

    /// The exact amount in picodollars.
    #[must_use]
    pub const fn picodollars(self) -> u64 {
        self.0
    }

    /// The amount in micro-dollars, rounded down.
    #[must_use]
    pub const fn micros(self) -> u64 {
        self.0 / 1_000_000
    }

    /// The amount in US dollars as a float, for display or export.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "f64 is only used for presentation; the exact value stays integral"
    )]
    pub fn as_usd(self) -> f64 {
        self.0 as f64 / PICO_PER_USD as f64
    }

    /// Sum of two costs, saturating at the maximum.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Difference of two costs, saturating at zero.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl Add for Cost {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.saturating_add(rhs)
    }
}

impl AddAssign for Cost {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.saturating_add(rhs);
    }
}

impl std::iter::Sum for Cost {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl fmt::Display for Cost {
    /// Formats as dollars with six decimals (micro-dollar precision, rounded
    /// down), e.g. `$0.000198`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dollars = self.0 / PICO_PER_USD;
        let micros = (self.0 % PICO_PER_USD) / 1_000_000;
        write!(f, "${dollars}.{micros:06}")
    }
}

/// List prices for one model, in micro-dollars per million tokens.
///
/// `$3.00 / MTok` is written `3_000_000`; `$0.075 / MTok` is `75_000`.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{Cost, Pricing, TokenUsage};
///
/// // $3 / MTok in, $15 / MTok out.
/// let p = Pricing::per_mtok(3_000_000, 15_000_000);
/// let usage = TokenUsage::new(21, 9);
/// assert_eq!(p.cost(&usage), Cost::from_micros(198)); // 21·3 + 9·15 µ$
///
/// // Cache reads at $0.30 / MTok: 20 of the 21 prompt tokens were cached.
/// let p = p.with_cache(300_000, 3_750_000);
/// let usage = TokenUsage::new(21, 9).with_cache_read_tokens(20);
/// assert_eq!(p.cost(&usage), Cost::from_micros(3 + 6 + 135));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Pricing {
    /// Price of uncached input (prompt) tokens.
    pub input: u64,
    /// Price of output (completion) tokens, including hidden reasoning tokens.
    pub output: u64,
    /// Price of input tokens served from the prompt cache.
    pub cache_read: u64,
    /// Price of input tokens written to the prompt cache.
    pub cache_write: u64,
}

impl Pricing {
    /// Prices for input and output tokens; cache reads and writes are priced
    /// like ordinary input until set with [`with_cache`](Self::with_cache).
    #[must_use]
    pub const fn per_mtok(input: u64, output: u64) -> Self {
        Self {
            input,
            output,
            cache_read: input,
            cache_write: input,
        }
    }

    /// Set the cache-read and cache-write prices.
    #[must_use]
    pub const fn with_cache(mut self, cache_read: u64, cache_write: u64) -> Self {
        self.cache_read = cache_read;
        self.cache_write = cache_write;
        self
    }

    /// Cost of `input` uncached prompt tokens and `output` completion tokens.
    #[must_use]
    pub const fn cost_of(&self, input: u64, output: u64) -> Cost {
        Cost(
            input
                .saturating_mul(self.input)
                .saturating_add(output.saturating_mul(self.output)),
        )
    }

    /// Cost of a full token breakdown, including prompt-cache traffic.
    ///
    /// `input` counts only uncached prompt tokens, as providers report them.
    #[must_use]
    pub const fn cost_detailed(
        &self,
        input: u64,
        output: u64,
        cache_read: u64,
        cache_write: u64,
    ) -> Cost {
        self.cost_of(input, output)
            .saturating_add(Cost(cache_read.saturating_mul(self.cache_read)))
            .saturating_add(Cost(cache_write.saturating_mul(self.cache_write)))
    }

    /// Cost of a provider-reported [`TokenUsage`].
    ///
    /// Cache reads and writes are priced at their own rates and the rest of
    /// the prompt ([`TokenUsage::uncached_prompt_tokens`]) at the input rate.
    /// `total_tokens` is ignored.
    #[must_use]
    pub const fn cost(&self, usage: &TokenUsage) -> Cost {
        self.cost_detailed(
            usage.uncached_prompt_tokens() as u64,
            usage.completion_tokens as u64,
            usage.cache_read_tokens as u64,
            usage.cache_creation_tokens as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_exact_in_picodollars() {
        // $0.075 / MTok × 1 token = 0.075 µ$ = 75_000 p$.
        let p = Pricing::per_mtok(75_000, 300_000);
        assert_eq!(p.cost_of(1, 0).picodollars(), 75_000);
        assert_eq!(p.cost_of(1_000_000, 0), Cost::from_micros(75_000));
        assert_eq!(p.cost_of(0, 1_000_000).to_string(), "$0.300000");
    }

    #[test]
    fn cache_defaults_to_input_price() {
        let p = Pricing::per_mtok(3, 15);
        assert_eq!((p.cache_read, p.cache_write), (3, 3));
        let p = p.with_cache(1, 4);
        assert_eq!(
            p.cost_detailed(10, 10, 10, 10).picodollars(),
            30 + 150 + 10 + 40
        );
    }

    #[test]
    fn arithmetic_saturates() {
        let p = Pricing::per_mtok(u64::MAX, u64::MAX);
        assert_eq!(p.cost_of(2, 2).picodollars(), u64::MAX);
        assert_eq!(Cost(u64::MAX) + Cost(1), Cost(u64::MAX));
        assert_eq!(Cost(1).saturating_sub(Cost(2)), Cost::ZERO);
        assert_eq!(Cost::from_micros(u64::MAX).picodollars(), u64::MAX);
    }

    #[test]
    fn display_and_conversions() {
        assert_eq!(Cost::ZERO.to_string(), "$0.000000");
        assert_eq!(Cost::from_cents(1_234).to_string(), "$12.340000");
        assert_eq!(Cost::from_cents(150).micros(), 1_500_000);
        assert!((Cost::from_cents(150).as_usd() - 1.5).abs() < 1e-12);
        let total: Cost = [Cost::from_micros(1), Cost::from_micros(2)]
            .into_iter()
            .sum();
        assert_eq!(total, Cost::from_micros(3));
        let mut c = Cost::ZERO;
        c += Cost::from_micros(5);
        assert_eq!(c.micros(), 5);
    }

    #[test]
    fn token_usage_cost_ignores_total_field() {
        let p = Pricing::per_mtok(1_000_000, 2_000_000);
        let usage = TokenUsage::new(3, 4).with_total_tokens(999);
        assert_eq!(p.cost(&usage), Cost::from_micros(11));
    }

    #[test]
    fn token_usage_cost_prices_cache_traffic() {
        let p = Pricing::per_mtok(1_000_000, 2_000_000).with_cache(100_000, 1_250_000);
        // 10 prompt tokens: 6 read from cache, 2 written, 2 uncached.
        let usage = TokenUsage::new(10, 1)
            .with_cache_read_tokens(6)
            .with_cache_creation_tokens(2)
            .with_reasoning_tokens(1);
        assert_eq!(
            p.cost(&usage).picodollars(),
            2 * 1_000_000 + 2_000_000 + 6 * 100_000 + 2 * 1_250_000
        );
        // Inconsistent reports never underflow.
        let odd = TokenUsage::new(1, 0).with_cache_read_tokens(5);
        assert_eq!(p.cost(&odd).picodollars(), 5 * 100_000);
    }
}

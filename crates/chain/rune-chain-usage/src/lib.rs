//! Per-provider token and cost accounting, with budget caps, for
//! [`rune-chain`](rune_chain_core) LLMs.
//!
//! - [`UsageMeter`] — a cloneable, thread-safe ledger of calls, tokens
//!   (cache reads/writes and reasoning included) and cost, broken down by
//!   provider/model and by tag. Memory is bounded: aggregates, capped
//!   breakdowns and an optional ring buffer of recent calls, never an
//!   unbounded per-request log. [`UsageMeter::report`] gives a serde
//!   snapshot ([`UsageReport`]).
//! - [`Budget`] — cost and/or token caps, a warning threshold and an alert
//!   callback. Once a cap is reached the meter refuses further calls, which
//!   stops an agent loop or chain run; [`Budget::with_warn_only`] makes the
//!   caps alert-only.
//! - [`MeteredLlm`] — wraps any [`Llm`](rune_chain_core::Llm): checks the
//!   budget before each call (from a local token estimate) and records the
//!   provider-reported usage after it, falling back to an estimate when the
//!   provider reports none.
//! - [`estimate_messages`] and friends — local token estimates built on
//!   [`rune_tokenize`].
//!
//! Prices come from [`Pricing`](rune_chain_core::Pricing): provider crates
//! attach list prices to their model notes
//! (`rune_chain_anthropic::models::lookup(id).map(|m| m.pricing)`), and you
//! can build your own for any other model. Costs are exact integer
//! picodollars ([`Cost`](rune_chain_core::Cost)).
//!
//! # Example
//!
//! ```rust
//! use rune_chain_core::{Cost, Pricing};
//! use rune_chain_usage::{Budget, BudgetAlert, Usage, UsageMeter};
//!
//! let meter = UsageMeter::new(
//!     Budget::default()
//!         .with_max_cost(Cost::from_cents(1))
//!         .with_warn_at_percent(80)
//!         .on_alert(|a| if let BudgetAlert::Warning { spent, .. } = a {
//!             eprintln!("80% of budget used: {}", spent.cost);
//!         }),
//! );
//! let sonnet = Pricing::per_mtok(3_000_000, 15_000_000); // $3 / $15 per MTok
//!
//! // Record what the provider reported for a call: 21 in, 9 out.
//! let cost = meter.record("anthropic", "claude-sonnet-4-6", &sonnet, Usage::reported(21, 9)).unwrap();
//! assert_eq!(cost, Cost::from_micros(198));
//!
//! // Before the next call, check that the budget allows it.
//! assert!(meter.check(Cost::from_micros(5_000), 2_000).is_ok());
//! assert!(meter.check(Cost::from_cents(1), 0).is_err());
//!
//! let (provider, totals) = &meter.by_provider()[0];
//! assert_eq!((provider.as_str(), totals.total_tokens()), ("anthropic", 30));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod budget;
mod error;
pub mod estimate;
mod meter;
mod metered;

pub use budget::{AlertFn, Budget, BudgetAlert, Limit};
pub use error::UsageError;
pub use estimate::{estimate_messages, estimate_text};
pub use meter::{
    CallRecord, DEFAULT_MAX_KEYS, ModelKey, ModelTotals, NamedTotals, OVERFLOW_KEY, Totals, Usage,
    UsageMeter, UsageReport, UsageSource,
};
pub use metered::MeteredLlm;

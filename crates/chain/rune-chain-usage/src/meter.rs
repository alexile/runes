//! The shared, thread-safe usage ledger.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use rune_chain_core::{Cost, Pricing, TokenUsage};
use serde::{Deserialize, Serialize};

use crate::{Budget, BudgetAlert, Limit, UsageError};

/// Default cap on distinct provider/model pairs and on distinct tags a
/// [`UsageMeter`] breaks totals down by.
pub const DEFAULT_MAX_KEYS: usize = 256;

/// The provider, model and tag name that usage is filed under once a
/// breakdown is full (see [`UsageMeter::with_max_keys`]).
pub const OVERFLOW_KEY: &str = "_other";

/// Where a [`Usage`] record's token counts came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UsageSource {
    /// Counts reported by the provider in its response.
    Reported,
    /// Counts estimated locally (the provider reported none, e.g. on a stream).
    Estimated,
}

/// Token counts for one LLM call.
///
/// As in [`TokenUsage`], the breakdown fields are subsets: `input_tokens`
/// includes the cache reads and writes, `output_tokens` the reasoning
/// tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Usage {
    /// Prompt (input) tokens, cached ones included.
    pub input_tokens: u64,
    /// Completion (output) tokens, reasoning included.
    pub output_tokens: u64,
    /// Input tokens read from the provider's prompt cache.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// Input tokens written to the provider's prompt cache.
    #[serde(default)]
    pub cache_creation_tokens: u64,
    /// Output tokens spent on reasoning.
    #[serde(default)]
    pub reasoning_tokens: u64,
    /// Whether the counts were reported or estimated.
    pub source: UsageSource,
}

impl Usage {
    /// Provider-reported counts.
    #[must_use]
    pub const fn reported(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            reasoning_tokens: 0,
            source: UsageSource::Reported,
        }
    }

    /// Locally estimated counts.
    #[must_use]
    pub const fn estimated(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            source: UsageSource::Estimated,
            ..Self::reported(input_tokens, output_tokens)
        }
    }

    /// Set the prompt-cache reads and writes (builder style). Both are part
    /// of `input_tokens`.
    #[must_use]
    pub const fn with_cache(mut self, read: u64, creation: u64) -> Self {
        self.cache_read_tokens = read;
        self.cache_creation_tokens = creation;
        self
    }

    /// Set the reasoning tokens (builder style), part of `output_tokens`.
    #[must_use]
    pub const fn with_reasoning_tokens(mut self, tokens: u64) -> Self {
        self.reasoning_tokens = tokens;
        self
    }

    /// Input tokens billed at the ordinary input rate: `input_tokens` minus
    /// cache reads and writes (saturating).
    #[must_use]
    pub const fn uncached_input_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_sub(self.cache_read_tokens)
            .saturating_sub(self.cache_creation_tokens)
    }

    /// The cost of these tokens at `pricing`, cache traffic at its own rates.
    #[must_use]
    pub const fn cost(&self, pricing: &Pricing) -> Cost {
        pricing.cost_detailed(
            self.uncached_input_tokens(),
            self.output_tokens,
            self.cache_read_tokens,
            self.cache_creation_tokens,
        )
    }

    /// Provider-reported counts from a [`TokenUsage`], including its cache
    /// and reasoning breakdown.
    #[must_use]
    pub const fn from_token_usage(usage: &TokenUsage) -> Self {
        Self::reported(usage.prompt_tokens as u64, usage.completion_tokens as u64)
            .with_cache(
                usage.cache_read_tokens as u64,
                usage.cache_creation_tokens as u64,
            )
            .with_reasoning_tokens(usage.reasoning_tokens as u64)
    }
}

/// Running totals for a meter, a provider, a model or a tag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Totals {
    /// Number of calls recorded.
    pub calls: u64,
    /// How many of those calls were estimated rather than reported.
    pub estimated_calls: u64,
    /// Prompt (input) tokens.
    pub input_tokens: u64,
    /// Completion (output) tokens.
    pub output_tokens: u64,
    /// Input tokens read from prompt caches (part of `input_tokens`).
    pub cache_read_tokens: u64,
    /// Input tokens written to prompt caches (part of `input_tokens`).
    pub cache_creation_tokens: u64,
    /// Reasoning tokens (part of `output_tokens`).
    pub reasoning_tokens: u64,
    /// Accumulated cost.
    pub cost: Cost,
}

impl Totals {
    /// Input plus output tokens.
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    /// Add `other` into `self` (saturating).
    pub fn merge(&mut self, other: &Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.estimated_calls = self.estimated_calls.saturating_add(other.estimated_calls);
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(other.cache_read_tokens);
        self.cache_creation_tokens = self
            .cache_creation_tokens
            .saturating_add(other.cache_creation_tokens);
        self.reasoning_tokens = self.reasoning_tokens.saturating_add(other.reasoning_tokens);
        self.cost += other.cost;
    }

    fn add(&mut self, usage: &Usage, cost: Cost) {
        self.merge(&Self {
            calls: 1,
            estimated_calls: u64::from(usage.source == UsageSource::Estimated),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            reasoning_tokens: usage.reasoning_tokens,
            cost,
        });
    }
}

/// Identifies a provider and model in a [`UsageMeter`] breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModelKey {
    /// Provider name, e.g. `"anthropic"`.
    pub provider: String,
    /// Model id, e.g. `"claude-opus-5-5"`.
    pub model: String,
}

impl ModelKey {
    /// The key for `model` served by `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
        }
    }
}

/// One recorded call, kept in the meter's bounded history (see
/// [`UsageMeter::with_history`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CallRecord {
    /// Position of the call in the meter's lifetime, from 1.
    pub seq: u64,
    /// Wall-clock time of recording, in milliseconds since the Unix epoch.
    pub unix_ms: u64,
    /// Provider the call went to.
    pub provider: String,
    /// Model the call used.
    pub model: String,
    /// Tag the call was recorded under, if any.
    pub tag: Option<String>,
    /// Its token counts.
    pub usage: Usage,
    /// Its cost.
    pub cost: Cost,
}

/// Totals for one provider/model pair in a [`UsageReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ModelTotals {
    /// Provider name.
    pub provider: String,
    /// Model id.
    pub model: String,
    /// Totals for the pair.
    #[serde(flatten)]
    pub totals: Totals,
}

/// Totals for one provider or tag in a [`UsageReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NamedTotals {
    /// Provider or tag name.
    pub name: String,
    /// Totals under that name.
    #[serde(flatten)]
    pub totals: Totals,
}

/// A serialisable snapshot of a [`UsageMeter`], from
/// [`UsageMeter::report`].
///
/// Costs serialise as integer picodollars, so the snapshot round-trips
/// exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UsageReport {
    /// Totals across everything.
    pub totals: Totals,
    /// Per provider/model pair, sorted.
    pub by_model: Vec<ModelTotals>,
    /// Per provider, sorted.
    pub by_provider: Vec<NamedTotals>,
    /// Per tag, sorted. Untagged calls are not listed.
    pub by_tag: Vec<NamedTotals>,
    /// The most recent calls, oldest first (empty without a history).
    pub recent: Vec<CallRecord>,
    /// The budget's cost cap.
    pub max_cost: Option<Cost>,
    /// The budget's token cap.
    pub max_tokens: Option<u64>,
    /// The cap that has been reached, if any.
    pub exhausted: Option<Limit>,
}

#[derive(Debug, Clone, Copy)]
struct Settings {
    history: usize,
    max_keys: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            history: 0,
            max_keys: DEFAULT_MAX_KEYS,
        }
    }
}

#[derive(Debug, Default)]
struct State {
    totals: Totals,
    by_model: BTreeMap<ModelKey, Totals>,
    by_tag: BTreeMap<String, Totals>,
    recent: VecDeque<CallRecord>,
    seq: u64,
    warned: Vec<Limit>,
    exhausted: Option<Limit>,
}

/// A cloneable, thread-safe ledger of token usage and cost, broken down by
/// provider/model and by tag, enforcing a [`Budget`].
///
/// Clones share one ledger, so a meter can be handed to several
/// [`MeteredLlm`](crate::MeteredLlm)s (one per provider or model) to enforce
/// a single budget across all of them.
///
/// Memory stays bounded however many calls are recorded: the meter keeps
/// aggregates, at most [`with_max_keys`](Self::with_max_keys) breakdown
/// entries each (further keys are filed under [`OVERFLOW_KEY`]), and an
/// optional ring buffer of the last [`with_history`](Self::with_history)
/// calls.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{Cost, Pricing};
/// use rune_chain_usage::{Budget, Usage, UsageMeter};
///
/// let meter = UsageMeter::new(Budget::default().with_max_cost(Cost::from_micros(100)));
/// let price = Pricing::per_mtok(1_000_000, 2_000_000); // $1 in, $2 out per MTok
///
/// meter.record("acme", "small", &price, Usage::reported(20, 10)).unwrap(); // 40 µ$
/// assert_eq!(meter.totals().cost, Cost::from_micros(40));
///
/// // The next call crosses the cap: it is still recorded, and reported.
/// assert!(meter.record("acme", "small", &price, Usage::reported(40, 20)).is_err());
/// assert!(meter.is_exhausted());
/// assert!(meter.check(Cost::ZERO, 0).is_err());
/// ```
#[derive(Debug, Clone, Default)]
pub struct UsageMeter {
    state: Arc<Mutex<State>>,
    budget: Arc<Budget>,
    settings: Settings,
}

impl UsageMeter {
    /// A meter enforcing `budget`.
    #[must_use]
    pub fn new(budget: Budget) -> Self {
        Self {
            budget: Arc::new(budget),
            ..Self::default()
        }
    }

    /// A meter that only counts.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Keep the last `calls` recorded calls (default 0: aggregates only).
    /// Configure before cloning; clones made earlier keep their setting.
    #[must_use]
    pub fn with_history(mut self, calls: usize) -> Self {
        self.settings.history = calls;
        let mut state = self.lock();
        while state.recent.len() > calls {
            state.recent.pop_front();
        }
        drop(state);
        self
    }

    /// Cap the per-model and per-tag breakdowns at `keys` entries each
    /// (default [`DEFAULT_MAX_KEYS`]). Usage under a new key once a
    /// breakdown is full is filed under [`OVERFLOW_KEY`]; totals stay exact.
    #[must_use]
    pub const fn with_max_keys(mut self, keys: usize) -> Self {
        self.settings.max_keys = keys;
        self
    }

    /// The budget this meter enforces.
    #[must_use]
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The state is plain counters, valid after any panic mid-update.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record one untagged call and return its cost. See
    /// [`record_tagged`](Self::record_tagged).
    ///
    /// # Errors
    ///
    /// [`UsageError::BudgetExhausted`] when spending has reached a cap.
    pub fn record(
        &self,
        provider: &str,
        model: &str,
        pricing: &Pricing,
        usage: Usage,
    ) -> Result<Cost, UsageError> {
        self.record_tagged(provider, model, None, pricing, usage)
    }

    /// Record one call under `tag` (a feature, tenant, agent or run name)
    /// and return its cost.
    ///
    /// The usage is always added to the ledger, because the provider has
    /// already billed it. If this call makes spending reach a cap, the meter
    /// becomes exhausted and, unless the budget is
    /// [warn-only](Budget::with_warn_only), the call returns
    /// [`UsageError::BudgetExhausted`]; later [`check`](Self::check)s fail.
    ///
    /// # Errors
    ///
    /// [`UsageError::BudgetExhausted`] when spending has reached a cap.
    pub fn record_tagged(
        &self,
        provider: &str,
        model: &str,
        tag: Option<&str>,
        pricing: &Pricing,
        usage: Usage,
    ) -> Result<Cost, UsageError> {
        let cost = usage.cost(pricing);
        let mut alerts = Vec::new();
        let result = {
            let mut state = self.lock();
            state.totals.add(&usage, cost);
            let key = ModelKey::new(provider, model);
            let key = if state.by_model.contains_key(&key)
                || state.by_model.len() < self.settings.max_keys
            {
                key
            } else {
                ModelKey::new(OVERFLOW_KEY, OVERFLOW_KEY)
            };
            state.by_model.entry(key).or_default().add(&usage, cost);
            if let Some(tag) = tag {
                let tag = if state.by_tag.contains_key(tag)
                    || state.by_tag.len() < self.settings.max_keys
                {
                    tag
                } else {
                    OVERFLOW_KEY
                };
                state
                    .by_tag
                    .entry(tag.to_owned())
                    .or_default()
                    .add(&usage, cost);
            }
            let seq = state.seq.saturating_add(1);
            state.seq = seq;
            if self.settings.history > 0 {
                if state.recent.len() >= self.settings.history {
                    state.recent.pop_front();
                }
                state.recent.push_back(CallRecord {
                    seq,
                    unix_ms: now_ms(),
                    provider: provider.to_owned(),
                    model: model.to_owned(),
                    tag: tag.map(str::to_owned),
                    usage,
                    cost,
                });
            }
            let spent = state.totals;
            for (limit, used, max) in self.budget.caps(&spent) {
                if let Some(pct) = self.budget.warn_at_percent() {
                    let threshold = u128::from(max) * u128::from(pct);
                    if u128::from(used) * 100 >= threshold && !state.warned.contains(&limit) {
                        state.warned.push(limit);
                        alerts.push(BudgetAlert::Warning { limit, spent });
                    }
                }
                if used >= max && state.exhausted.is_none() {
                    state.exhausted = Some(limit);
                    alerts.push(BudgetAlert::Exhausted { limit, spent });
                }
            }
            match state.exhausted {
                Some(limit) if !self.budget.is_warn_only() => {
                    Err(UsageError::BudgetExhausted { limit, spent })
                }
                _ => Ok(cost),
            }
        };
        for alert in &alerts {
            self.budget.alert(alert);
        }
        result
    }

    /// Check, before sending a call, that the budget allows it: the meter is
    /// not exhausted, and spending plus the call's `projected_cost` and
    /// `projected_tokens` stays within every cap. A
    /// [warn-only](Budget::with_warn_only) budget allows every call.
    ///
    /// # Errors
    ///
    /// [`UsageError::BudgetExhausted`] if a cap has already been reached, or
    /// [`UsageError::WouldExceed`] if this call would pass one. Either raises
    /// [`BudgetAlert::Refused`].
    pub fn check(&self, projected_cost: Cost, projected_tokens: u64) -> Result<(), UsageError> {
        if self.budget.is_warn_only() {
            return Ok(());
        }
        let result = {
            let state = self.lock();
            let spent = state.totals;
            let exceeded = || {
                self.budget.caps(&spent).find(|(limit, used, max)| {
                    let extra = match limit {
                        Limit::Cost(_) => projected_cost.picodollars(),
                        Limit::Tokens(_) => projected_tokens,
                    };
                    used.saturating_add(extra) > *max
                })
            };
            match (state.exhausted, exceeded()) {
                (Some(limit), _) => Err(UsageError::BudgetExhausted { limit, spent }),
                (None, Some((limit, ..))) => Err(UsageError::WouldExceed {
                    limit,
                    spent,
                    projected_cost,
                    projected_tokens,
                }),
                (None, None) => Ok(()),
            }
        };
        if let Err(e) = &result {
            let (limit, spent) = e.parts();
            self.budget.alert(&BudgetAlert::Refused { limit, spent });
        }
        result
    }

    /// Totals across every provider and model.
    #[must_use]
    pub fn totals(&self) -> Totals {
        self.lock().totals
    }

    /// Totals per provider and model, sorted by provider then model.
    #[must_use]
    pub fn by_model(&self) -> Vec<(ModelKey, Totals)> {
        self.lock()
            .by_model
            .iter()
            .map(|(k, t)| (k.clone(), *t))
            .collect()
    }

    /// Totals per provider, sorted by provider name.
    #[must_use]
    pub fn by_provider(&self) -> Vec<(String, Totals)> {
        provider_totals(&self.lock().by_model)
    }

    /// Totals per tag, sorted by tag. Untagged calls are not listed.
    #[must_use]
    pub fn by_tag(&self) -> Vec<(String, Totals)> {
        self.lock()
            .by_tag
            .iter()
            .map(|(k, t)| (k.clone(), *t))
            .collect()
    }

    /// The most recent calls, oldest first (empty unless
    /// [`with_history`](Self::with_history) is set).
    #[must_use]
    pub fn recent(&self) -> Vec<CallRecord> {
        self.lock().recent.iter().cloned().collect()
    }

    /// A consistent, serialisable snapshot of everything the meter holds.
    ///
    /// ```rust
    /// use rune_chain_core::Pricing;
    /// use rune_chain_usage::{Usage, UsageMeter};
    ///
    /// let meter = UsageMeter::unlimited().with_history(10);
    /// let price = Pricing::per_mtok(1_000_000, 2_000_000);
    /// meter.record_tagged("acme", "small", Some("search"), &price, Usage::reported(5, 5)).unwrap();
    /// let report = meter.report();
    /// assert_eq!(report.by_tag[0].name, "search");
    /// assert_eq!(report.recent.len(), 1);
    /// ```
    #[must_use]
    pub fn report(&self) -> UsageReport {
        let state = self.lock();
        UsageReport {
            totals: state.totals,
            by_model: state
                .by_model
                .iter()
                .map(|(k, t)| ModelTotals {
                    provider: k.provider.clone(),
                    model: k.model.clone(),
                    totals: *t,
                })
                .collect(),
            by_provider: provider_totals(&state.by_model)
                .into_iter()
                .map(|(name, totals)| NamedTotals { name, totals })
                .collect(),
            by_tag: state
                .by_tag
                .iter()
                .map(|(name, t)| NamedTotals {
                    name: name.clone(),
                    totals: *t,
                })
                .collect(),
            recent: state.recent.iter().cloned().collect(),
            max_cost: self.budget.max_cost(),
            max_tokens: self.budget.max_tokens(),
            exhausted: state.exhausted,
        }
    }

    /// Money left under the cost cap, or `None` without one.
    #[must_use]
    pub fn remaining_cost(&self) -> Option<Cost> {
        let spent = self.lock().totals.cost;
        self.budget.max_cost().map(|m| m.saturating_sub(spent))
    }

    /// Tokens left under the token cap, or `None` without one.
    #[must_use]
    pub fn remaining_tokens(&self) -> Option<u64> {
        let spent = self.lock().totals.total_tokens();
        self.budget.max_tokens().map(|m| m.saturating_sub(spent))
    }

    /// Whether a cap has been reached. Unless the budget is warn-only,
    /// every further call is then refused.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.lock().exhausted.is_some()
    }

    /// Clear the ledger and history and re-arm every alert, keeping the
    /// budget and settings.
    pub fn reset(&self) {
        *self.lock() = State::default();
    }
}

fn provider_totals(by_model: &BTreeMap<ModelKey, Totals>) -> Vec<(String, Totals)> {
    let mut out: Vec<(String, Totals)> = Vec::new();
    for (key, t) in by_model {
        match out.last_mut() {
            Some((p, acc)) if *p == key.provider => acc.merge(t),
            _ => out.push((key.provider.clone(), *t)),
        }
    }
    out
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {

    use std::sync::Mutex as StdMutex;

    use super::*;

    const PRICE: Pricing = Pricing::per_mtok(1_000_000, 2_000_000);

    #[test]
    fn records_per_provider_and_model() {
        let meter = UsageMeter::unlimited();
        meter
            .record("b", "m2", &PRICE, Usage::reported(10, 5))
            .unwrap();
        meter
            .record("a", "m1", &PRICE, Usage::estimated(1, 1))
            .unwrap();
        meter
            .record("b", "m1", &PRICE, Usage::reported(10, 5))
            .unwrap();
        let t = meter.totals();
        assert_eq!((t.calls, t.estimated_calls), (3, 1));
        assert_eq!(
            (t.input_tokens, t.output_tokens, t.total_tokens()),
            (21, 11, 32)
        );
        assert_eq!(t.cost, Cost::from_micros(21 + 22));

        let models: Vec<_> = meter
            .by_model()
            .into_iter()
            .map(|(k, t)| (k.provider, k.model, t.calls))
            .collect();
        assert_eq!(
            models,
            [
                ("a".into(), "m1".into(), 1),
                ("b".into(), "m1".into(), 1),
                ("b".into(), "m2".into(), 1)
            ]
        );
        let providers = meter.by_provider();
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[1].0, "b");
        assert_eq!(providers[1].1.input_tokens, 20);
        assert_eq!(providers[1].1.cost, Cost::from_micros(40));
        assert_eq!(meter.remaining_cost(), None);
        assert!(!meter.is_exhausted());
    }

    #[test]
    fn token_cap_exhausts_and_refuses() {
        let meter = UsageMeter::new(Budget::default().with_max_tokens(100));
        assert!(
            meter
                .record("p", "m", &PRICE, Usage::reported(50, 10))
                .is_ok()
        );
        assert_eq!(meter.remaining_tokens(), Some(40));
        assert!(meter.check(Cost::ZERO, 40).is_ok());
        assert!(matches!(
            meter.check(Cost::ZERO, 41),
            Err(UsageError::WouldExceed {
                limit: Limit::Tokens(100),
                ..
            })
        ));
        let err = meter
            .record("p", "m", &PRICE, Usage::reported(40, 0))
            .unwrap_err();
        assert!(matches!(
            err,
            UsageError::BudgetExhausted {
                limit: Limit::Tokens(100),
                ..
            }
        ));
        assert!(meter.is_exhausted());
        assert!(meter.check(Cost::ZERO, 0).is_err());
        // Over-cap usage is still counted: the provider billed it.
        assert_eq!(meter.totals().total_tokens(), 100);

        meter.reset();
        assert!(!meter.is_exhausted());
        assert_eq!(meter.totals(), Totals::default());
    }

    #[test]
    fn alerts_fire_once_and_outside_the_lock() {
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let meter_slot: Arc<StdMutex<Option<UsageMeter>>> = Arc::default();
        let (s, slot) = (seen.clone(), meter_slot.clone());
        let budget = Budget::default()
            .with_max_cost(Cost::from_micros(100))
            .with_warn_at_percent(50)
            .on_alert(move |a| {
                // Reading the meter from the callback must not deadlock.
                if let Some(m) = slot.lock().unwrap().as_ref() {
                    let _ = m.totals();
                }
                s.lock().unwrap().push(a.clone());
            });
        let meter = UsageMeter::new(budget);
        *meter_slot.lock().unwrap() = Some(meter.clone());

        meter
            .record("p", "m", &PRICE, Usage::reported(30, 0))
            .unwrap(); // 30 µ$
        meter
            .record("p", "m", &PRICE, Usage::reported(30, 0))
            .unwrap(); // 60 µ$ → warn
        meter
            .record("p", "m", &PRICE, Usage::reported(10, 0))
            .unwrap(); // 70 µ$
        assert!(meter.check(Cost::from_micros(31), 0).is_err()); // refused
        assert!(
            meter
                .record("p", "m", &PRICE, Usage::reported(40, 0))
                .is_err()
        ); // exhausted
        assert!(
            meter
                .record("p", "m", &PRICE, Usage::reported(1, 0))
                .is_err()
        );

        let kinds: Vec<&str> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|a| match a {
                BudgetAlert::Warning { .. } => "warn",
                BudgetAlert::Exhausted { .. } => "exhausted",
                BudgetAlert::Refused { .. } => "refused",
            })
            .collect();
        assert_eq!(kinds, ["warn", "refused", "exhausted"]);
        assert_eq!(meter.remaining_cost(), Some(Cost::ZERO));
    }

    #[test]
    fn usage_from_token_usage() {
        let u = Usage::from_token_usage(&TokenUsage::new(7, 3).with_total_tokens(10));
        assert_eq!(u, Usage::reported(7, 3));
        let u = Usage::from_token_usage(
            &TokenUsage::new(100, 30)
                .with_cache_read_tokens(60)
                .with_cache_creation_tokens(20)
                .with_reasoning_tokens(10),
        );
        assert_eq!(
            u,
            Usage::reported(100, 30)
                .with_cache(60, 20)
                .with_reasoning_tokens(10)
        );
        assert_eq!(u.uncached_input_tokens(), 20);
    }

    #[test]
    fn cache_traffic_is_priced_and_totalled() {
        // $1 in, $2 out, $0.10 cache read, $1.25 cache write per MTok.
        let price = Pricing::per_mtok(1_000_000, 2_000_000).with_cache(100_000, 1_250_000);
        let meter = UsageMeter::unlimited();
        let usage = Usage::reported(100, 30)
            .with_cache(60, 20)
            .with_reasoning_tokens(10);
        let cost = meter.record("p", "m", &price, usage).unwrap();
        // 20 uncached · 1 + 30 · 2 + 60 · 0.1 + 20 · 1.25 µ$ = 111 µ$.
        assert_eq!(cost, Cost::from_micros(111));
        meter.record("p", "m", &price, usage).unwrap();
        let t = meter.totals();
        assert_eq!(
            (
                t.input_tokens,
                t.cache_read_tokens,
                t.cache_creation_tokens,
                t.reasoning_tokens
            ),
            (200, 120, 40, 20)
        );
        assert_eq!(t.cost, Cost::from_micros(222));
    }

    #[test]
    fn tags_overflow_and_provider_rollup() {
        let meter = UsageMeter::unlimited().with_max_keys(2);
        let u = Usage::reported(10, 0)
            .with_cache(4, 0)
            .with_reasoning_tokens(0);
        for (p, m, tag) in [
            ("a", "x", Some("t1")),
            ("a", "y", Some("t2")),
            ("b", "z", Some("t3")),
            ("a", "x", None),
        ] {
            meter.record_tagged(p, m, tag, &PRICE, u).unwrap();
        }
        let models: Vec<_> = meter
            .by_model()
            .into_iter()
            .map(|(k, t)| (k.provider, k.model, t.calls))
            .collect();
        assert_eq!(
            models,
            [
                (OVERFLOW_KEY.into(), OVERFLOW_KEY.into(), 1),
                ("a".into(), "x".into(), 2),
                ("a".into(), "y".into(), 1),
            ]
        );
        let tags: Vec<_> = meter
            .by_tag()
            .into_iter()
            .map(|(t, totals)| (t, totals.calls))
            .collect();
        assert_eq!(
            tags,
            [(OVERFLOW_KEY.into(), 1), ("t1".into(), 1), ("t2".into(), 1)]
        );
        // Provider roll-up keeps the cache breakdown.
        let a = &meter.by_provider()[1];
        assert_eq!(
            (a.0.as_str(), a.1.calls, a.1.cache_read_tokens),
            ("a", 3, 12)
        );
        assert_eq!(meter.totals().calls, 4);
    }

    #[test]
    fn history_is_a_bounded_ring() {
        let meter = UsageMeter::unlimited().with_history(2);
        for i in 1..=5 {
            meter
                .record("p", "m", &PRICE, Usage::reported(i, 0))
                .unwrap();
        }
        let recent = meter.recent();
        assert_eq!(
            recent
                .iter()
                .map(|r| (r.seq, r.usage.input_tokens))
                .collect::<Vec<_>>(),
            [(4, 4), (5, 5)]
        );
        assert_eq!(UsageMeter::unlimited().recent().len(), 0);
        meter.reset();
        assert_eq!(meter.recent().len(), 0);
    }

    #[test]
    fn warn_only_budget_alerts_but_never_refuses() {
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let s = seen.clone();
        let meter = UsageMeter::new(
            Budget::default()
                .with_max_tokens(10)
                .with_warn_at_percent(50)
                .with_warn_only(true)
                .on_alert(move |a| s.lock().unwrap().push(a.clone())),
        );
        assert!(
            meter
                .record("p", "m", &PRICE, Usage::reported(20, 0))
                .is_ok()
        );
        assert!(meter.is_exhausted());
        assert!(meter.check(Cost::from_cents(1), 1_000).is_ok());
        let alerts = seen.lock().unwrap();
        assert!(matches!(alerts[0], BudgetAlert::Warning { .. }));
        assert!(matches!(alerts[1], BudgetAlert::Exhausted { .. }));
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn known_prices_are_exact() {
        // Sonnet-class list prices: $3 in, $15 out, $0.30 cache read,
        // $3.75 cache write per MTok.
        let sonnet = Pricing::per_mtok(3_000_000, 15_000_000).with_cache(300_000, 3_750_000);
        let usage = Usage::reported(10_000, 2_000).with_cache(6_000, 1_000);
        // 3000·3 + 2000·15 + 6000·0.3 + 1000·3.75 µ$ = 44_550 µ$.
        assert_eq!(usage.cost(&sonnet), Cost::from_micros(44_550));

        // Sub-micro prices accumulate without drift: 1 token at
        // $0.075 / MTok is 75_000 p$; a million such calls is $0.075.
        let cheap = Pricing::per_mtok(75_000, 0);
        let meter = UsageMeter::unlimited();
        for _ in 0..1_000 {
            meter
                .record("p", "m", &cheap, Usage::reported(1, 0))
                .unwrap();
        }
        assert_eq!(meter.totals().cost, Cost::from_picodollars(75_000_000));
        assert_eq!(meter.totals().cost, Cost::from_micros(75));
    }

    #[test]
    fn report_round_trips_through_json() {
        let meter =
            UsageMeter::new(Budget::default().with_max_cost(Cost::from_cents(1))).with_history(4);
        meter
            .record_tagged(
                "p",
                "m",
                Some("chat"),
                &PRICE,
                Usage::estimated(3, 4).with_reasoning_tokens(2),
            )
            .unwrap();
        let report = meter.report();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["totals"]["cost"], 11_000_000);
        assert_eq!(json["by_model"][0]["provider"], "p");
        assert_eq!(json["by_model"][0]["calls"], 1);
        assert_eq!(json["recent"][0]["usage"]["source"], "estimated");
        let back: UsageReport = serde_json::from_value(json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn concurrent_recording_is_exact() {
        let meter = UsageMeter::unlimited();
        std::thread::scope(|s| {
            for t in 0..8 {
                let meter = meter.clone();
                s.spawn(move || {
                    for _ in 0..500 {
                        meter
                            .record_tagged(
                                "p",
                                "m",
                                Some(["a", "b"][t % 2]),
                                &PRICE,
                                Usage::reported(1, 1),
                            )
                            .unwrap();
                    }
                });
            }
        });
        let t = meter.totals();
        assert_eq!((t.calls, t.total_tokens()), (4_000, 8_000));
        assert_eq!(t.cost, Cost::from_micros(4_000 * 3));
        assert_eq!(meter.by_tag()[0].1.calls, 2_000);
    }
}

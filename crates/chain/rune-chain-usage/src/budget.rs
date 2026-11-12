//! Spending caps and the alerts they raise.

use std::fmt;
use std::sync::Arc;

use rune_chain_core::Cost;
use serde::{Deserialize, Serialize};

use crate::Totals;

/// Which cap a [`BudgetAlert`] or [`UsageError`](crate::UsageError) refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Limit {
    /// The [`Budget::with_max_cost`] cap.
    Cost(Cost),
    /// The [`Budget::with_max_tokens`] cap (input plus output tokens).
    Tokens(u64),
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cost(c) => write!(f, "cost cap {c}"),
            Self::Tokens(t) => write!(f, "token cap {t}"),
        }
    }
}

/// An event delivered to the [`Budget::on_alert`] callback.
///
/// Each of `Warning` and `Exhausted` fires at most once per limit for the
/// lifetime of a [`UsageMeter`](crate::UsageMeter) (until
/// [`reset`](crate::UsageMeter::reset)); `Refused` fires on every call the
/// meter turns away.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetAlert {
    /// Spending crossed the warning threshold of `limit`.
    Warning {
        /// The cap being approached.
        limit: Limit,
        /// Running totals after the call that crossed the threshold.
        spent: Totals,
    },
    /// Spending reached or passed `limit`; later calls are refused.
    Exhausted {
        /// The cap that was reached.
        limit: Limit,
        /// Running totals after the call that reached it.
        spent: Totals,
    },
    /// A call was refused before it was sent, because the budget is
    /// exhausted or the call's estimated cost would exceed `limit`.
    Refused {
        /// The cap that would be exceeded.
        limit: Limit,
        /// Running totals at the time of the refusal.
        spent: Totals,
    },
}

/// Callback type for [`Budget::on_alert`].
pub type AlertFn = Arc<dyn Fn(&BudgetAlert) + Send + Sync>;

/// Spending caps for a [`UsageMeter`](crate::UsageMeter).
///
/// The default budget has no caps: the meter only counts.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::Cost;
/// use rune_chain_usage::Budget;
///
/// let budget = Budget::default()
///     .with_max_cost(Cost::from_cents(50))
///     .with_max_tokens(200_000)
///     .with_warn_at_percent(80)
///     .on_alert(|alert| eprintln!("budget: {alert:?}"));
/// assert_eq!(budget.max_cost(), Some(Cost::from_cents(50)));
/// ```
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Budget {
    max_cost: Option<Cost>,
    max_tokens: Option<u64>,
    warn_at_percent: Option<u8>,
    warn_only: bool,
    on_alert: Option<AlertFn>,
}

impl Budget {
    /// A budget with no caps.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Stop once the accumulated cost reaches `max`.
    #[must_use]
    pub const fn with_max_cost(mut self, max: Cost) -> Self {
        self.max_cost = Some(max);
        self
    }

    /// Stop once accumulated input plus output tokens reach `max`.
    #[must_use]
    pub const fn with_max_tokens(mut self, max: u64) -> Self {
        self.max_tokens = Some(max);
        self
    }

    /// Raise a [`BudgetAlert::Warning`] once spending reaches `percent` of a
    /// cap. Values above 100 are clamped to 100.
    #[must_use]
    pub fn with_warn_at_percent(mut self, percent: u8) -> Self {
        self.warn_at_percent = Some(percent.min(100));
        self
    }

    /// Make the caps soft: reaching one raises [`BudgetAlert::Exhausted`]
    /// (and the warning before it) but never refuses or fails a call.
    /// Off by default, so caps are hard stops.
    #[must_use]
    pub const fn with_warn_only(mut self, warn_only: bool) -> Self {
        self.warn_only = warn_only;
        self
    }

    /// Whether the caps only alert (see [`with_warn_only`](Self::with_warn_only)).
    #[must_use]
    pub const fn is_warn_only(&self) -> bool {
        self.warn_only
    }

    /// Call `f` for every [`BudgetAlert`]. The callback runs after the meter's
    /// lock is released, so it may read the meter.
    #[must_use]
    pub fn on_alert(mut self, f: impl Fn(&BudgetAlert) + Send + Sync + 'static) -> Self {
        self.on_alert = Some(Arc::new(f));
        self
    }

    /// The cost cap, if any.
    #[must_use]
    pub const fn max_cost(&self) -> Option<Cost> {
        self.max_cost
    }

    /// The token cap, if any.
    #[must_use]
    pub const fn max_tokens(&self) -> Option<u64> {
        self.max_tokens
    }

    /// The warning threshold in percent, if any.
    #[must_use]
    pub const fn warn_at_percent(&self) -> Option<u8> {
        self.warn_at_percent
    }

    pub(crate) fn alert(&self, alert: &BudgetAlert) {
        if let Some(f) = &self.on_alert {
            f(alert);
        }
    }

    /// The caps paired with the amount spent against each, as
    /// `(limit, spent, max)` in a common unit.
    pub(crate) fn caps(&self, totals: &Totals) -> impl Iterator<Item = (Limit, u64, u64)> {
        let cost = self
            .max_cost
            .map(|m| (Limit::Cost(m), totals.cost.picodollars(), m.picodollars()));
        let tokens = self
            .max_tokens
            .map(|m| (Limit::Tokens(m), totals.total_tokens(), m));
        cost.into_iter().chain(tokens)
    }
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Budget")
            .field("max_cost", &self.max_cost)
            .field("max_tokens", &self.max_tokens)
            .field("warn_at_percent", &self.warn_at_percent)
            .field("warn_only", &self.warn_only)
            .field("on_alert", &self.on_alert.as_ref().map(|_| "Fn"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_and_debug() {
        let b = Budget::unlimited()
            .with_max_tokens(10)
            .with_warn_at_percent(250)
            .on_alert(|_| {});
        assert_eq!(b.max_tokens(), Some(10));
        assert_eq!(b.max_cost(), None);
        assert_eq!(b.warn_at_percent(), Some(100));
        let dbg = format!("{b:?}");
        assert!(dbg.contains("max_tokens: Some(10)") && dbg.contains("\"Fn\""));
    }

    #[test]
    fn limit_display() {
        assert_eq!(Limit::Tokens(5).to_string(), "token cap 5");
        assert_eq!(
            Limit::Cost(Cost::from_cents(1)).to_string(),
            "cost cap $0.010000"
        );
    }
}

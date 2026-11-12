//! The crate's error type.

use rune_chain_core::{Cost, LlmError};
use thiserror::Error;

use crate::{Limit, Totals};

/// Why a [`UsageMeter`](crate::UsageMeter) stopped a call.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UsageError {
    /// Spending has reached `limit`; no further calls are allowed.
    #[error("budget exhausted: {limit} reached (spent {} over {} tokens)", spent.cost, spent.total_tokens())]
    BudgetExhausted {
        /// The cap that was reached.
        limit: Limit,
        /// Totals when the cap was reached or the call was refused.
        spent: Totals,
    },
    /// The call's estimated cost or token count would pass `limit`.
    #[error(
        "budget would be exceeded: {limit} (spent {}, call estimated at {projected_cost} / {projected_tokens} tokens)",
        spent.cost
    )]
    WouldExceed {
        /// The cap that would be passed.
        limit: Limit,
        /// Totals at the time of the check.
        spent: Totals,
        /// Estimated cost of the refused call.
        projected_cost: Cost,
        /// Estimated tokens of the refused call.
        projected_tokens: u64,
    },
}

impl UsageError {
    /// The cap involved and the totals at the time.
    #[must_use]
    pub const fn parts(&self) -> (Limit, Totals) {
        match self {
            Self::BudgetExhausted { limit, spent } | Self::WouldExceed { limit, spent, .. } => {
                (*limit, *spent)
            }
        }
    }
}

impl From<UsageError> for LlmError {
    fn from(e: UsageError) -> Self {
        Self::other(e.to_string())
    }
}

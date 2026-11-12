use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rune_chain_core::ChainError;

type RetryPredicate = Arc<dyn Fn(&ChainError, u32) -> bool + Send + Sync>;

/// When and how often a failing [`Step`](crate::Step) is run again.
///
/// The delay before attempt `n + 1` is `initial_delay * 2^(n - 1)`, capped at
/// `max_delay`. When the error is an [`LlmError`](rune_chain_core::LlmError)
/// with a provider [`retry_after`](rune_chain_core::LlmError::retry_after),
/// the delay is at least that long (still capped at `max_delay`). There is
/// no jitter, so runs are reproducible.
///
/// By default only [transient errors](is_transient) are retried; replace the
/// test with [`retry_if`](Self::retry_if).
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_core::{ChainError, LlmError};
/// use rune_chain_sequential::RetryPolicy;
///
/// let policy = RetryPolicy::new(3).backoff(Duration::from_millis(100), Duration::from_secs(1));
/// let flaky: ChainError = LlmError::from_status(503, "overloaded").into();
/// assert!(policy.should_retry(&flaky, 1));
/// assert!(policy.should_retry(&flaky, 2));
/// assert!(!policy.should_retry(&flaky, 3)); // three attempts in total
/// assert_eq!(policy.delay(&flaky, 2), Duration::from_millis(200));
///
/// let fatal = ChainError::MissingVariable("topic".into());
/// assert!(!policy.should_retry(&fatal, 1));
/// ```
#[derive(Clone)]
pub struct RetryPolicy {
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
    retry_if: RetryPredicate,
}

impl RetryPolicy {
    /// Default first delay.
    pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(200);
    /// Default delay cap.
    pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(10);

    /// Up to `max_attempts` attempts in total (values below 1 count as 1),
    /// retrying [transient errors](is_transient) with the default backoff.
    #[must_use]
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_delay: Self::DEFAULT_INITIAL_DELAY,
            max_delay: Self::DEFAULT_MAX_DELAY,
            retry_if: Arc::new(|e, _| is_transient(e)),
        }
    }

    /// Set the first delay and the cap.
    #[must_use]
    pub const fn backoff(mut self, initial_delay: Duration, max_delay: Duration) -> Self {
        self.initial_delay = initial_delay;
        self.max_delay = max_delay;
        self
    }

    /// Decide which errors are worth another attempt. The closure gets the
    /// error and the number of the attempt that just failed (from 1).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::ChainError;
    /// use rune_chain_sequential::RetryPolicy;
    ///
    /// // Re-ask when the model's output did not parse.
    /// let policy = RetryPolicy::new(2).retry_if(|e, _| matches!(e, ChainError::ParseError(_)));
    /// assert!(policy.should_retry(&ChainError::ParseError("bad json".into()), 1));
    /// ```
    #[must_use]
    pub fn retry_if(
        mut self,
        predicate: impl Fn(&ChainError, u32) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.retry_if = Arc::new(predicate);
        self
    }

    /// The total number of attempts allowed.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// `true` if attempt number `attempt` (from 1) failed with `error` and
    /// another attempt should follow.
    #[must_use]
    pub fn should_retry(&self, error: &ChainError, attempt: u32) -> bool {
        attempt < self.max_attempts && (self.retry_if)(error, attempt)
    }

    /// How long to wait after attempt number `attempt` failed with `error`.
    #[must_use]
    pub fn delay(&self, error: &ChainError, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        let backoff = self.initial_delay.saturating_mul(factor);
        let wanted = match error {
            ChainError::LlmError(e) => e.retry_after().map_or(backoff, |r| r.max(backoff)),
            _ => backoff,
        };
        wanted.min(self.max_delay)
    }
}

impl fmt::Debug for RetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryPolicy")
            .field("max_attempts", &self.max_attempts)
            .field("initial_delay", &self.initial_delay)
            .field("max_delay", &self.max_delay)
            .finish_non_exhaustive()
    }
}

/// `true` for errors that may go away on their own: LLM rate limits,
/// overload, timeouts (including step timeouts), network and server faults.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{ChainError, LlmError};
/// use rune_chain_sequential::is_transient;
///
/// assert!(is_transient(&LlmError::timeout("slow").into()));
/// assert!(!is_transient(&LlmError::from_status(401, "bad key").into()));
/// assert!(!is_transient(&ChainError::ParseError("x".into())));
/// ```
#[must_use]
pub const fn is_transient(error: &ChainError) -> bool {
    matches!(error, ChainError::LlmError(e) if e.is_retryable())
}

#[cfg(test)]
mod tests {
    use rune_chain_core::LlmError;

    use super::*;

    #[test]
    fn delays_grow_and_respect_retry_after_and_the_cap() {
        let p = RetryPolicy::new(10).backoff(Duration::from_millis(100), Duration::from_secs(1));
        let e: ChainError = LlmError::from_status(500, "x").into();
        let delays: Vec<u128> = (1..=6).map(|a| p.delay(&e, a).as_millis()).collect();
        assert_eq!(delays, [100, 200, 400, 800, 1000, 1000]);

        let limited: ChainError = LlmError::from_status(429, "slow down")
            .with_retry_after(Duration::from_millis(700))
            .into();
        assert_eq!(p.delay(&limited, 1), Duration::from_millis(700));
        assert_eq!(p.delay(&limited, 4), Duration::from_millis(800));
        let huge: ChainError = LlmError::from_status(429, "x")
            .with_retry_after(Duration::from_secs(60))
            .into();
        assert_eq!(p.delay(&huge, 1), Duration::from_secs(1));
        assert_eq!(p.delay(&e, u32::MAX), Duration::from_secs(1));
    }

    #[test]
    fn zero_attempts_means_one() {
        let p = RetryPolicy::new(0);
        assert_eq!(p.max_attempts(), 1);
        assert!(!p.should_retry(&LlmError::timeout("x").into(), 1));
        assert!(format!("{p:?}").contains("max_attempts"));
    }
}

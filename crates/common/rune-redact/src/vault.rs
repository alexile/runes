//! The token map behind [`Replacement::Tokenize`](crate::Replacement::Tokenize).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use regex::Regex;

use crate::category::Category;

#[derive(Default)]
struct State {
    by_value: HashMap<(Category, String), String>,
    by_token: HashMap<String, String>,
    counters: HashMap<&'static str, u64>,
}

/// A thread-safe, bounded map between sensitive values and the numbered
/// tokens (`[EMAIL_1]`) that replace them.
///
/// Every [`Redactor`](crate::Redactor) owns one, shared by its clones, its
/// stream redactors and writers. The vault keeps the original values in
/// memory: treat it like the secrets themselves. Its `Debug` output shows
/// only the number of entries.
///
/// # Example
///
/// ```rust
/// use rune_redact::{Policy, Redactor, Replacement};
///
/// let redactor = Redactor::new(Policy::default().with_replacement(Replacement::Tokenize))?;
/// let prompt = redactor.redact("Summarise mail from bob@example.com to amy@example.com");
/// assert_eq!(prompt, "Summarise mail from [EMAIL_1] to [EMAIL_2]");
/// assert_eq!(redactor.vault().len(), 2);
/// assert_eq!(redactor.vault().original("[EMAIL_2]").as_deref(), Some("amy@example.com"));
/// # Ok::<(), rune_redact::Error>(())
/// ```
pub struct TokenVault {
    state: Mutex<State>,
    capacity: usize,
}

impl fmt::Debug for TokenVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenVault")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl TokenVault {
    /// An empty vault that remembers at most `capacity` values.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            capacity,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The state is a plain map; a panic elsewhere cannot leave it torn.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The token for `value`, allocating the next number for a new value.
    /// `None` when the vault is full and `value` is not already in it.
    pub(crate) fn token_for(&self, category: Category, value: &str) -> Option<String> {
        let mut state = self.lock();
        let key = (category, value.to_owned());
        if let Some(token) = state.by_value.get(&key) {
            return Some(token.clone());
        }
        if state.by_token.len() >= self.capacity {
            return None;
        }
        let label = category.label();
        let n = state.counters.entry(label).or_insert(0);
        *n += 1;
        let token = format!("[{label}_{n}]");
        state.by_token.insert(token.clone(), key.1.clone());
        state.by_value.insert(key, token.clone());
        drop(state);
        Some(token)
    }

    /// The original value behind `token` (`"[EMAIL_1]"`), if known.
    #[must_use]
    pub fn original(&self, token: &str) -> Option<String> {
        self.lock().by_token.get(token).cloned()
    }

    /// Replaces every known token in `text` with its original value. Unknown
    /// tokens are left as they are.
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        let Some(re) = token_re() else {
            return text.to_owned();
        };
        let state = self.lock();
        re.replace_all(text, |caps: &regex::Captures<'_>| {
            let token = &caps[0];
            state
                .by_token
                .get(token)
                .map_or_else(|| token.to_owned(), Clone::clone)
        })
        .into_owned()
    }

    /// Number of values held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().by_token.len()
    }

    /// Whether the vault is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The maximum number of values held.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Forgets every value and restarts numbering. Tokens issued before
    /// can no longer be restored, and later values reuse their numbers.
    pub fn clear(&self) {
        *self.lock() = State::default();
    }
}

fn token_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[A-Z][A-Z_]*_[0-9]+\]").ok())
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_same_token() {
        let v = TokenVault::new(10);
        let a = v.token_for(Category::Email, "a@x.io");
        let b = v.token_for(Category::Email, "b@x.io");
        assert_eq!(a.as_deref(), Some("[EMAIL_1]"));
        assert_eq!(b.as_deref(), Some("[EMAIL_2]"));
        assert_eq!(v.token_for(Category::Email, "a@x.io"), a);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn ipv4_and_ipv6_share_label_numbering() {
        let v = TokenVault::new(10);
        assert_eq!(
            v.token_for(Category::Ipv4, "1.2.3.4").as_deref(),
            Some("[IP_1]")
        );
        assert_eq!(
            v.token_for(Category::Ipv6, "::1").as_deref(),
            Some("[IP_2]")
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let v = TokenVault::new(1);
        assert!(v.token_for(Category::Ssn, "1").is_some());
        assert!(v.token_for(Category::Ssn, "2").is_none());
        assert!(v.token_for(Category::Ssn, "1").is_some());
    }

    #[test]
    fn restore_and_clear() {
        let v = TokenVault::new(10);
        let t = v
            .token_for(Category::Phone, "555-123-4567")
            .unwrap_or_default();
        assert_eq!(
            v.restore(&format!("call {t} not [PHONE_9]")),
            "call 555-123-4567 not [PHONE_9]"
        );
        v.clear();
        assert!(v.is_empty());
        assert_eq!(v.restore(&t), t);
    }

    #[test]
    fn debug_hides_values() {
        let v = TokenVault::new(10);
        let _ = v.token_for(Category::Email, "secret@x.io");
        assert!(!format!("{v:?}").contains("secret"));
    }
}

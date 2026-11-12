//! Redaction policy: which categories to redact and how to replace them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rune_leak::SecretRule;

use crate::category::Category;

/// Default entropy threshold, bits per byte, of [`Category::HighEntropy`].
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Default minimum token length of [`Category::HighEntropy`].
pub const DEFAULT_MIN_ENTROPY_LEN: usize = 16;

/// Default number of distinct values a [`TokenVault`](crate::TokenVault)
/// remembers before [`Replacement::Tokenize`] falls back to
/// [`Replacement::Label`].
pub const DEFAULT_VAULT_CAPACITY: usize = 100_000;

/// How a detected value is rewritten.
///
/// # Example
///
/// ```rust
/// use rune_redact::{Category, Policy, Redactor, Replacement};
///
/// let policy = Policy::none()
///     .with_category(Category::CreditCard)
///     .with_replacement(Replacement::Mask { fill: '*', keep_last: 4 });
/// let redactor = Redactor::new(policy)?;
/// assert_eq!(redactor.redact("card 4111 1111 1111 1234"), "card ***************1234");
/// # Ok::<(), rune_redact::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Replacement {
    /// A fixed placeholder naming the category: `[EMAIL]`.
    Label,
    /// Every character replaced by `fill`, except the last `keep_last`
    /// characters. At most half of the value is ever kept visible, so a short
    /// value is never shown in full. `4111 1111 1111 1234` → `***************1234`.
    Mask {
        /// The fill character.
        fill: char,
        /// How many trailing characters to keep (capped at half the value).
        keep_last: usize,
    },
    /// A keyed hash of the value: `[EMAIL:3f2a9c1b04d7e6a8]`, the first 8
    /// bytes of HMAC-SHA256 under the policy's
    /// [hash key](Policy::with_hash_key), in hex. Equal values give equal
    /// output across processes that share the key, so redacted logs can still
    /// be correlated, and without the key the hash cannot be brute-forced back
    /// to a low-entropy value such as a phone number.
    Hash,
    /// A numbered token, `[EMAIL_1]`, `[EMAIL_2]`, …: the same value always
    /// maps to the same token within one [`Redactor`](crate::Redactor) (and its
    /// clones), and [`Redactor::restore`](crate::Redactor::restore) maps tokens
    /// back. Use it to send redacted prompts to an LLM and restore the reply.
    Tokenize,
}

impl Replacement {
    /// [`Replacement::Mask`] with `*` and nothing kept.
    #[must_use]
    pub const fn mask() -> Self {
        Self::Mask {
            fill: '*',
            keep_last: 0,
        }
    }
}

/// Which categories to redact, how, and the detector settings.
///
/// Start from [`Policy::default()`] (every category, `[LABEL]` placeholders)
/// or [`Policy::none()`] (nothing) and adjust with the builder methods.
///
/// # Example
///
/// ```rust
/// use rune_redact::{Category, Policy, Replacement};
///
/// let policy = Policy::default()
///     .without_category(Category::Ipv4)
///     .with_replacement(Replacement::Tokenize)
///     .with_override(Category::CreditCard, Replacement::mask());
/// assert!(!policy.categories.contains(&Category::Ipv4));
/// assert_eq!(policy.replacement_for(Category::Email), &Replacement::Tokenize);
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct Policy {
    /// The categories to detect and redact.
    pub categories: BTreeSet<Category>,
    /// The replacement used for categories without an override.
    pub replacement: Replacement,
    /// Per-category replacements.
    pub overrides: BTreeMap<Category, Replacement>,
    /// Minimum Shannon entropy, bits per byte, for [`Category::HighEntropy`].
    pub entropy_threshold: f64,
    /// Tokens shorter than this (in bytes) are never flagged as
    /// [`Category::HighEntropy`].
    pub min_entropy_len: usize,
    /// Extra `rune-leak` rules, reported as [`Category::Credential`] after the
    /// built-in ones.
    pub extra_rules: Vec<SecretRule>,
    /// Distinct values remembered for [`Replacement::Tokenize`]; past this,
    /// new values get a [`Replacement::Label`] placeholder instead.
    pub vault_capacity: usize,
    hash_key: Vec<u8>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("categories", &self.categories)
            .field("replacement", &self.replacement)
            .field("overrides", &self.overrides)
            .field("entropy_threshold", &self.entropy_threshold)
            .field("min_entropy_len", &self.min_entropy_len)
            .field(
                "extra_rules",
                &self.extra_rules.iter().map(|r| &r.id).collect::<Vec<_>>(),
            )
            .field("vault_capacity", &self.vault_capacity)
            .field("hash_key", &format_args!("<{} bytes>", self.hash_key.len()))
            .finish()
    }
}

impl Default for Policy {
    /// Every category, [`Replacement::Label`].
    fn default() -> Self {
        Self::none().with_categories(Category::ALL)
    }
}

impl Policy {
    /// No categories: redacts nothing until some are added.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            categories: BTreeSet::new(),
            replacement: Replacement::Label,
            overrides: BTreeMap::new(),
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            min_entropy_len: DEFAULT_MIN_ENTROPY_LEN,
            extra_rules: Vec::new(),
            vault_capacity: DEFAULT_VAULT_CAPACITY,
            hash_key: Vec::new(),
        }
    }

    /// Adds a category.
    #[must_use]
    pub fn with_category(mut self, category: Category) -> Self {
        self.categories.insert(category);
        self
    }

    /// Adds several categories.
    #[must_use]
    pub fn with_categories(mut self, categories: impl IntoIterator<Item = Category>) -> Self {
        self.categories.extend(categories);
        self
    }

    /// Removes a category.
    #[must_use]
    pub fn without_category(mut self, category: Category) -> Self {
        self.categories.remove(&category);
        self
    }

    /// Sets the default replacement.
    #[must_use]
    pub const fn with_replacement(mut self, replacement: Replacement) -> Self {
        self.replacement = replacement;
        self
    }

    /// Sets the replacement for one category.
    #[must_use]
    pub fn with_override(mut self, category: Category, replacement: Replacement) -> Self {
        self.overrides.insert(category, replacement);
        self
    }

    /// Sets the [`Category::HighEntropy`] threshold, bits per byte.
    #[must_use]
    pub const fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Sets the [`Category::HighEntropy`] minimum token length.
    #[must_use]
    pub const fn with_min_entropy_len(mut self, len: usize) -> Self {
        self.min_entropy_len = len;
        self
    }

    /// Adds `rune-leak` rules for organisation-specific credentials.
    #[must_use]
    pub fn with_rules(mut self, rules: impl IntoIterator<Item = SecretRule>) -> Self {
        self.extra_rules.extend(rules);
        self
    }

    /// Sets the key for [`Replacement::Hash`]. Keep it secret: anyone holding
    /// it can confirm guesses of redacted values.
    #[must_use]
    pub fn with_hash_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.hash_key = key.into();
        self
    }

    /// Sets the [`Replacement::Tokenize`] vault capacity.
    #[must_use]
    pub const fn with_vault_capacity(mut self, capacity: usize) -> Self {
        self.vault_capacity = capacity;
        self
    }

    /// The replacement used for `category`.
    #[must_use]
    pub fn replacement_for(&self, category: Category) -> &Replacement {
        self.overrides.get(&category).unwrap_or(&self.replacement)
    }

    /// Whether `category` is redacted.
    #[must_use]
    pub fn contains(&self, category: Category) -> bool {
        self.categories.contains(&category)
    }

    pub(crate) fn hash_key(&self) -> &[u8] {
        &self.hash_key
    }

    pub(crate) fn uses(&self, replacement: &Replacement) -> bool {
        self.categories
            .iter()
            .any(|&c| self.replacement_for(c) == replacement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_every_category() {
        let p = Policy::default();
        assert!(Category::ALL.iter().all(|&c| p.contains(c)));
        assert!(Policy::none().categories.is_empty());
    }

    #[test]
    fn overrides_take_precedence() {
        let p = Policy::default()
            .with_replacement(Replacement::Hash)
            .with_override(Category::Phone, Replacement::mask());
        assert_eq!(p.replacement_for(Category::Phone), &Replacement::mask());
        assert_eq!(p.replacement_for(Category::Email), &Replacement::Hash);
        assert!(p.uses(&Replacement::Hash));
        assert!(!p.uses(&Replacement::Tokenize));
    }

    #[test]
    fn debug_hides_the_hash_key() {
        let p = Policy::default().with_hash_key("hunter2-very-secret");
        let s = format!("{p:?}");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("<19 bytes>"));
    }
}

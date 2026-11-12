//! Budgets for whole prompts and chat conversations.

use crate::counter::TokenCounter;

/// Fixed tokens a chat template adds around the message text.
///
/// The total for a conversation is
/// `reply_priming + Σ (per_message + tokens(role) + tokens(content) [+ per_name + tokens(name)])`,
/// the accounting `OpenAI` documents for its chat models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChatOverhead {
    /// Tokens added to every message (role markers, separators).
    pub per_message: usize,
    /// Extra tokens when a message carries a `name`.
    pub per_name: usize,
    /// Tokens that prime the assistant's reply, counted once.
    pub reply_priming: usize,
}

impl ChatOverhead {
    /// No overhead: count only the text.
    pub const NONE: Self = Self::new(0, 0, 0);
    /// `OpenAI` chat models (GPT-3.5 / GPT-4 / GPT-4o): 3 per message, 1 per
    /// name, 3 for reply priming.
    pub const OPENAI: Self = Self::new(3, 1, 3);

    /// Build an overhead description.
    #[must_use]
    pub const fn new(per_message: usize, per_name: usize, reply_priming: usize) -> Self {
        Self {
            per_message,
            per_name,
            reply_priming,
        }
    }
}

impl Default for ChatOverhead {
    fn default() -> Self {
        Self::OPENAI
    }
}

/// One chat message, borrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChatMessage<'a> {
    /// `system`, `user`, `assistant`, `tool`, …
    pub role: &'a str,
    /// Message text.
    pub content: &'a str,
    /// Optional participant name.
    pub name: Option<&'a str>,
}

impl<'a> ChatMessage<'a> {
    /// A message without a name.
    #[must_use]
    pub const fn new(role: &'a str, content: &'a str) -> Self {
        Self {
            role,
            content,
            name: None,
        }
    }

    /// Attach a participant name.
    #[must_use]
    pub const fn with_name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }

    /// Tokens this message costs, overhead included (reply priming excluded).
    #[must_use]
    pub fn tokens<C: TokenCounter + ?Sized>(&self, counter: &C, overhead: ChatOverhead) -> usize {
        let name = self.name.map_or(0, |n| {
            overhead.per_name.saturating_add(counter.count_tokens(n))
        });
        overhead
            .per_message
            .saturating_add(counter.count_tokens(self.role))
            .saturating_add(counter.count_tokens(self.content))
            .saturating_add(name)
    }
}

/// Tokens a whole conversation costs, reply priming included.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{count_chat, ChatMessage, ChatOverhead, TokenizerProfile};
///
/// let chat = [
///     ChatMessage::new("system", "You are terse."),
///     ChatMessage::new("user", "Hi!"),
/// ];
/// let p = TokenizerProfile::O200k;
/// let n = count_chat(&chat, &p, p.chat_overhead());
/// assert!(n > count_chat(&chat, &p, ChatOverhead::NONE));
/// ```
#[must_use]
pub fn count_chat<C: TokenCounter + ?Sized>(
    messages: &[ChatMessage<'_>],
    counter: &C,
    overhead: ChatOverhead,
) -> usize {
    messages.iter().fold(overhead.reply_priming, |acc, m| {
        acc.saturating_add(m.tokens(counter, overhead))
    })
}

/// Sliding-window history trimming: keep the first `pinned` messages (e.g. the
/// system prompt) and as many of the most recent messages as fit in
/// `max_tokens`.
///
/// Returns the index `start` such that `messages[..pinned]` followed by
/// `messages[start..]` fits (`start == messages.len()` means only the pinned
/// messages fit), or `None` if even the pinned messages exceed the budget.
/// `pinned` is clamped to `messages.len()`.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{fit_recent_messages, ChatMessage, ChatOverhead, TokenizerProfile};
///
/// let history = [
///     ChatMessage::new("system", "Be brief."),
///     ChatMessage::new("user", "a long, long question about many things"),
///     ChatMessage::new("assistant", "a long, long answer about many things"),
///     ChatMessage::new("user", "thanks"),
/// ];
/// let p = TokenizerProfile::Simple;
/// let start = fit_recent_messages(&history, 20, 1, &p, ChatOverhead::NONE).unwrap();
/// assert!(start > 1); // the oldest turns were dropped
/// assert!(start < history.len()); // the latest one survived
/// ```
#[must_use]
pub fn fit_recent_messages<C: TokenCounter + ?Sized>(
    messages: &[ChatMessage<'_>],
    max_tokens: usize,
    pinned: usize,
    counter: &C,
    overhead: ChatOverhead,
) -> Option<usize> {
    let pinned = pinned.min(messages.len());
    let mut used = count_chat(&messages[..pinned], counter, overhead);
    if used > max_tokens {
        return None;
    }
    let mut start = messages.len();
    while start > pinned {
        let next = used.saturating_add(messages[start - 1].tokens(counter, overhead));
        if next > max_tokens {
            break;
        }
        used = next;
        start -= 1;
    }
    Some(start)
}

/// A context window split between the prompt and the reserved completion.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{Budget, TokenizerProfile};
///
/// let budget = Budget::new(8192, 1024);
/// assert_eq!(budget.input_limit(), 7168);
/// assert_eq!(budget.remaining(7000), 168);
/// assert!(budget.fits("short prompt", &TokenizerProfile::Cl100k));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Budget {
    /// Total context window of the model, in tokens.
    pub context_window: usize,
    /// Tokens kept free for the model's reply.
    pub reserved_output: usize,
}

impl Budget {
    /// A budget for `context_window` tokens with `reserved_output` kept for the reply.
    #[must_use]
    pub const fn new(context_window: usize, reserved_output: usize) -> Self {
        Self {
            context_window,
            reserved_output,
        }
    }

    /// Tokens available for the prompt (never underflows).
    #[must_use]
    pub const fn input_limit(&self) -> usize {
        self.context_window.saturating_sub(self.reserved_output)
    }

    /// Prompt tokens still free after `used` (never underflows).
    #[must_use]
    pub const fn remaining(&self, used: usize) -> usize {
        self.input_limit().saturating_sub(used)
    }

    /// `true` if `text` fits in the prompt budget.
    #[must_use]
    pub fn fits<C: TokenCounter + ?Sized>(&self, text: &str, counter: &C) -> bool {
        counter.count_tokens(text) <= self.input_limit()
    }

    /// `true` if the conversation fits in the prompt budget.
    #[must_use]
    pub fn fits_chat<C: TokenCounter + ?Sized>(
        &self,
        messages: &[ChatMessage<'_>],
        counter: &C,
        overhead: ChatOverhead,
    ) -> bool {
        count_chat(messages, counter, overhead) <= self.input_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenizerProfile;

    #[test]
    fn openai_overhead_accounting() {
        let words = |s: &str| s.split_whitespace().count();
        let chat = [
            ChatMessage::new("system", "a b"),
            ChatMessage::new("user", "c").with_name("bob"),
        ];
        // priming 3 + (3 + 1 + 2) + (3 + 1 + 1 + 1 + 1)
        assert_eq!(count_chat(&chat, &words, ChatOverhead::OPENAI), 16);
        assert_eq!(count_chat(&[], &words, ChatOverhead::OPENAI), 3);
    }

    #[test]
    fn fit_recent_keeps_pinned_and_latest() {
        let words = |s: &str| s.split_whitespace().count();
        let chat = [
            ChatMessage::new("s", "x"),
            ChatMessage::new("u", "one two three"),
            ChatMessage::new("a", "four five"),
            ChatMessage::new("u", "six"),
        ];
        let none = ChatOverhead::NONE;
        assert_eq!(fit_recent_messages(&chat, 100, 1, &words, none), Some(1));
        assert_eq!(fit_recent_messages(&chat, 5, 1, &words, none), Some(3));
        assert_eq!(fit_recent_messages(&chat, 2, 1, &words, none), Some(4));
        assert_eq!(fit_recent_messages(&chat, 1, 1, &words, none), None);
        assert_eq!(fit_recent_messages(&chat, 0, 99, &words, none), None);
        assert_eq!(fit_recent_messages(&[], 0, 99, &words, none), Some(0));
    }

    #[test]
    fn budget_saturates() {
        let b = Budget::new(10, 20);
        assert_eq!(b.input_limit(), 0);
        assert_eq!(b.remaining(5), 0);
        assert!(b.fits("", &TokenizerProfile::Simple));
        assert!(!b.fits("x", &TokenizerProfile::Simple));
    }
}

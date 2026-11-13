use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rune_chain_core::{ChainError, ContentPart, Memory, Message, MessageContent};

use crate::budget::Buffer;
use crate::util::lock;
use crate::{DEFAULT_MAX_MESSAGES, MemorySnapshot};

/// Counts how many tokens a [`Message`] costs in the model's context window.
///
/// Implemented for any `Fn(&Message) -> usize + Send + Sync`, so a real
/// tokenizer (tiktoken, a `HuggingFace` tokenizer, …) can be plugged in with a
/// closure. [`CharEstimator`] is a dependency-free heuristic default.
///
/// Counters are always called *outside* the memory's internal lock, so they
/// may be slow or even call back into the memory without deadlocking.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::TokenCounter;
/// use rune_chain_core::Message;
///
/// let words = |m: &Message| m.content.text_content().split_whitespace().count();
/// assert_eq!(words.count(&Message::human("one two three")), 3);
/// ```
pub trait TokenCounter: Send + Sync {
    /// The token cost of `message`, including any per-message overhead.
    fn count(&self, message: &Message) -> usize;
}

impl<F> TokenCounter for F
where
    F: Fn(&Message) -> usize + Send + Sync,
{
    fn count(&self, message: &Message) -> usize {
        self(message)
    }
}

/// Heuristic token counter: roughly one token per `chars_per_token`
/// characters, plus a fixed per-message and per-image overhead.
///
/// The defaults (4 chars/token, 4 tokens/message, 85 tokens/image) are a
/// reasonable approximation for English text on GPT- and Claude-family
/// tokenizers. Use a real tokenizer when exact budgets matter.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::{CharEstimator, TokenCounter};
/// use rune_chain_core::Message;
///
/// let est = CharEstimator::default();
/// // 8 chars -> 2 tokens, + 4 overhead
/// assert_eq!(est.count(&Message::human("abcdefgh")), 6);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharEstimator {
    /// Characters per token (values below 1 are treated as 1).
    pub chars_per_token: usize,
    /// Fixed cost added to every message (role markers, separators).
    pub per_message: usize,
    /// Cost of each image part.
    pub per_image: usize,
}

impl Default for CharEstimator {
    fn default() -> Self {
        Self {
            chars_per_token: 4,
            per_message: 4,
            per_image: 85,
        }
    }
}

impl TokenCounter for CharEstimator {
    fn count(&self, message: &Message) -> usize {
        let (chars, images) = match &message.content {
            MessageContent::Text(s) => (s.chars().count(), 0),
            MessageContent::Parts(parts) => {
                parts.iter().fold((0usize, 0usize), |(c, i), p| match p {
                    ContentPart::Text { text } => (c.saturating_add(text.chars().count()), i),
                    ContentPart::Image { .. } => (c, i.saturating_add(1)),
                })
            }
        };
        let tool_chars = message.tool_calls.iter().fold(0usize, |acc, c| {
            acc.saturating_add(c.name.chars().count())
                .saturating_add(c.arguments.chars().count())
        });
        chars
            .saturating_add(tool_chars)
            .div_ceil(self.chars_per_token.max(1))
            .saturating_add(self.per_message)
            .saturating_add(images.saturating_mul(self.per_image))
    }
}

/// Conversation memory that keeps the newest messages fitting a token budget.
///
/// After every [`add`](Memory::add) the oldest messages are evicted until the
/// stored history costs at most `max_tokens` according to the configured
/// [`TokenCounter`]. Eviction also drops tool-result messages whose
/// originating tool-call turn was evicted, so the history stays valid for
/// providers that require call/result pairing.
///
/// - The first system message is **pinned** by default (never evicted by the
///   budget, always returned first); disable with
///   [`pin_system(false)`](Self::pin_system).
/// - A hard cap of [`DEFAULT_MAX_MESSAGES`] messages bounds storage even if
///   the counter returns `0`; change it with [`max_messages`](Self::max_messages).
/// - A single message larger than the whole budget is evicted immediately.
/// - The pinned system message counts against the budget. If it alone is
///   larger than `max_tokens`, every other message is evicted as soon as it
///   is added and [`messages`](Memory::messages) returns only the system
///   message. Size the budget above the prompt, or disable pinning.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::TokenBufferMemory;
/// use rune_chain_core::{Memory, Message, Role};
///
/// # tokio_test::block_on(async {
/// // Count one token per word.
/// let mem = TokenBufferMemory::new(5, |m: &Message| {
///     m.content.text_content().split_whitespace().count()
/// });
/// mem.add(Message::system("be brief")).await.unwrap();       // 2, pinned
/// mem.add(Message::human("what is two plus two")).await.unwrap(); // 5, over budget
/// mem.add(Message::ai("four")).await.unwrap();               // 1
///
/// let visible = mem.messages().await.unwrap();
/// assert_eq!(visible.len(), 2);
/// assert_eq!(visible[0].role, Role::System);
/// assert_eq!(visible[1].content, "four");
/// assert!(mem.token_count() <= 5);
/// # });
/// ```
pub struct TokenBufferMemory {
    max_tokens: usize,
    max_messages: usize,
    pin_system: bool,
    counter: Arc<dyn TokenCounter>,
    state: Mutex<Buffer>,
}

impl TokenBufferMemory {
    /// Create a memory holding at most `max_tokens` tokens as measured by
    /// `counter`.
    #[must_use]
    pub fn new(max_tokens: usize, counter: impl TokenCounter + 'static) -> Self {
        Self {
            max_tokens,
            max_messages: DEFAULT_MAX_MESSAGES,
            pin_system: true,
            counter: Arc::new(counter),
            state: Mutex::new(Buffer::default()),
        }
    }

    /// Create a memory using the [`CharEstimator`] heuristic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::TokenBufferMemory;
    ///
    /// let mem = TokenBufferMemory::with_char_estimate(4_000);
    /// assert_eq!(mem.max_tokens(), 4_000);
    /// ```
    #[must_use]
    pub fn with_char_estimate(max_tokens: usize) -> Self {
        Self::new(max_tokens, CharEstimator::default())
    }

    /// Pin the first system message (default: on). A pinned message larger
    /// than the whole budget leaves no room for any other message.
    #[must_use]
    pub const fn pin_system(mut self, pin: bool) -> Self {
        self.pin_system = pin;
        self
    }

    /// Hard cap on stored messages, pinned one included
    /// (default: [`DEFAULT_MAX_MESSAGES`]).
    #[must_use]
    pub const fn max_messages(mut self, max: usize) -> Self {
        self.max_messages = max;
        self
    }

    /// The token budget.
    #[must_use]
    pub const fn max_tokens(&self) -> usize {
        self.max_tokens
    }

    /// Tokens currently held (always `<= max_tokens`, unless the pinned
    /// system message alone exceeds the budget).
    #[must_use]
    pub fn token_count(&self) -> usize {
        lock(&self.state).total_tokens()
    }

    /// Number of stored messages.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.state).len()
    }

    /// `true` when no messages are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take a serializable copy of the stored history.
    #[must_use]
    pub fn snapshot(&self) -> MemorySnapshot {
        MemorySnapshot::new(lock(&self.state).messages(), None)
    }

    /// Replace the stored history with `snapshot`, re-applying pinning, the
    /// token budget and the message cap.
    ///
    /// # Errors
    ///
    /// [`ChainError::MemoryError`] if the snapshot format version is unsupported.
    pub fn restore(&self, snapshot: MemorySnapshot) -> Result<(), ChainError> {
        snapshot.check_version()?;
        let mut buf = Buffer::default();
        for m in snapshot.messages {
            let t = self.counter.count(&m);
            buf.push(self.pin_system, m, t);
            buf.trim(self.max_tokens, 0, self.max_messages);
        }
        *lock(&self.state) = buf;
        Ok(())
    }
}

/// Redacted: prints sizes only, never message contents.
impl std::fmt::Debug for TokenBufferMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = lock(&self.state);
        f.debug_struct("TokenBufferMemory")
            .field("max_tokens", &self.max_tokens)
            .field("max_messages", &self.max_messages)
            .field("pin_system", &self.pin_system)
            .field("len", &s.len())
            .field("tokens", &s.total_tokens())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Memory for TokenBufferMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        Ok(lock(&self.state).messages())
    }

    async fn add(&self, message: Message) -> Result<(), ChainError> {
        // Count before locking: user code never runs under the lock.
        let tokens = self.counter.count(&message);
        let mut s = lock(&self.state);
        s.push(self.pin_system, message, tokens);
        s.trim(self.max_tokens, 0, self.max_messages);
        drop(s);
        Ok(())
    }

    async fn clear(&self) -> Result<(), ChainError> {
        *lock(&self.state) = Buffer::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rune_chain_core::{Role, ToolCall};

    use super::*;

    fn one_each(_: &Message) -> usize {
        1
    }

    #[test]
    fn char_estimator_counts_parts_and_tool_calls() {
        let est = CharEstimator {
            chars_per_token: 0,
            per_message: 0,
            per_image: 10,
        };
        let m = Message::human(MessageContent::Parts(vec![
            ContentPart::text("abc"),
            ContentPart::image_url("https://example.com/x.png"),
        ]));
        assert_eq!(est.count(&m), 13);
        let m = Message::ai_with_tool_calls("", vec![ToolCall::new("1", "ab", "cd")]);
        assert_eq!(est.count(&m), 4);
    }

    #[tokio::test]
    async fn evicts_oldest_to_fit_budget() {
        let mem = TokenBufferMemory::new(3, one_each);
        for i in 0..10 {
            mem.add(Message::human(format!("{i}"))).await.unwrap();
        }
        let texts: Vec<_> = mem
            .messages()
            .await
            .unwrap()
            .iter()
            .map(|m| m.content.text_content())
            .collect();
        assert_eq!(texts, ["7", "8", "9"]);
        assert_eq!(mem.token_count(), 3);
    }

    #[tokio::test]
    async fn pins_system_unless_disabled() {
        let mem = TokenBufferMemory::new(2, one_each);
        mem.add(Message::system("s")).await.unwrap();
        for _ in 0..5 {
            mem.add(Message::human("h")).await.unwrap();
        }
        let v = mem.messages().await.unwrap();
        assert_eq!(v[0].role, Role::System);
        assert_eq!(v.len(), 2);

        let mem = TokenBufferMemory::new(2, one_each).pin_system(false);
        mem.add(Message::system("s")).await.unwrap();
        for _ in 0..5 {
            mem.add(Message::human("h")).await.unwrap();
        }
        assert!(
            mem.messages()
                .await
                .unwrap()
                .iter()
                .all(|m| m.role == Role::Human)
        );
    }

    #[tokio::test]
    async fn oversized_message_is_dropped() {
        let mem = TokenBufferMemory::new(5, |m: &Message| m.content.text_content().len());
        mem.add(Message::human("ok")).await.unwrap();
        mem.add(Message::human("way too long")).await.unwrap();
        assert!(mem.is_empty());
    }

    #[tokio::test]
    async fn zero_cost_counter_is_still_bounded() {
        let mem = TokenBufferMemory::new(10, |_: &Message| 0).max_messages(5);
        for _ in 0..100 {
            mem.add(Message::human("x")).await.unwrap();
        }
        assert_eq!(mem.len(), 5);
    }

    #[tokio::test]
    async fn orphaned_tool_results_are_dropped() {
        let mem = TokenBufferMemory::new(2, one_each).pin_system(false);
        mem.add(Message::ai_with_tool_calls(
            "",
            vec![ToolCall::new("1", "t", "{}")],
        ))
        .await
        .unwrap();
        mem.add(Message::tool_result("1", "r")).await.unwrap();
        mem.add(Message::ai("done")).await.unwrap();
        // Budget 2 evicts the call, so its result goes too.
        assert_eq!(mem.messages().await.unwrap(), [Message::ai("done")]);
    }

    #[tokio::test]
    async fn restore_reapplies_budget() {
        let mem = TokenBufferMemory::new(2, one_each);
        let snap = MemorySnapshot::new(
            vec![
                Message::system("s"),
                Message::human("a"),
                Message::human("b"),
            ],
            None,
        );
        mem.restore(snap).unwrap();
        assert_eq!(
            mem.messages().await.unwrap(),
            [Message::system("s"), Message::human("b")]
        );
        assert!(format!("{mem:?}").contains("TokenBufferMemory"));
    }

    #[tokio::test]
    async fn oversized_pinned_prompt_leaves_room_for_nothing() {
        use rune_chain_core::Memory;
        let mem = TokenBufferMemory::new(5, |m: &Message| m.text().len());
        mem.add(Message::system("0123456789")).await.unwrap();
        mem.add(Message::human("hi")).await.unwrap();
        assert_eq!(
            mem.messages().await.unwrap(),
            [Message::system("0123456789")]
        );
    }
}

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use rune_chain_core::{ChainError, Memory, Message};

use crate::MemorySnapshot;
use crate::util::{drop_orphan_tool_results, lock};

/// In-process conversation memory that returns the full stored history.
///
/// Stores every message that has been [`add`](Memory::add)ed and returns the
/// whole history from [`messages`](Memory::messages). Backed by a `Mutex`, so
/// it is safe to share across threads via `Arc`.
///
/// By default the history is **unbounded**. When the conversation is driven by
/// untrusted input (a public chat endpoint, say), cap it with
/// [`with_max_messages`](Self::with_max_messages) so a single session cannot
/// grow process memory without limit; the oldest messages are evicted first,
/// along with any tool results left at the front without their call.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::SimpleMemory;
/// use rune_chain_core::{Memory, Message};
///
/// # tokio_test::block_on(async {
/// let mem = SimpleMemory::new();
/// mem.add(Message::human("Hello")).await.unwrap();
/// mem.add(Message::ai("Hi there!")).await.unwrap();
///
/// let history = mem.messages().await.unwrap();
/// assert_eq!(history.len(), 2);
/// # });
/// ```
pub struct SimpleMemory {
    max_messages: Option<usize>,
    messages: Mutex<VecDeque<Message>>,
}

impl SimpleMemory {
    /// Create an empty, unbounded memory store.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::SimpleMemory;
    /// use rune_chain_core::Memory;
    ///
    /// # tokio_test::block_on(async {
    /// let mem = SimpleMemory::new();
    /// assert!(mem.messages().await.unwrap().is_empty());
    /// # });
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_messages: None,
            messages: Mutex::new(VecDeque::new()),
        }
    }

    /// Create an empty memory that keeps at most `max_messages` messages,
    /// evicting the oldest first (FIFO).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::SimpleMemory;
    /// use rune_chain_core::{Memory, Message};
    ///
    /// # tokio_test::block_on(async {
    /// let mem = SimpleMemory::with_max_messages(2);
    /// for t in ["a", "b", "c"] {
    ///     mem.add(Message::human(t)).await.unwrap();
    /// }
    /// let texts: Vec<_> = mem.messages().await.unwrap()
    ///     .into_iter().map(|m| m.content.text_content()).collect();
    /// assert_eq!(texts, ["b", "c"]);
    /// # });
    /// ```
    #[must_use]
    pub const fn with_max_messages(max_messages: usize) -> Self {
        Self {
            max_messages: Some(max_messages),
            messages: Mutex::new(VecDeque::new()),
        }
    }

    /// The capacity limit, if any.
    #[must_use]
    pub const fn max_messages(&self) -> Option<usize> {
        self.max_messages
    }

    /// Number of stored messages.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.messages).len()
    }

    /// `true` when no messages are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.messages).is_empty()
    }

    /// Take a serializable copy of the stored history.
    #[must_use]
    pub fn snapshot(&self) -> MemorySnapshot {
        MemorySnapshot::new(lock(&self.messages).iter().cloned().collect(), None)
    }

    /// Replace the stored history with `snapshot`, applying the capacity limit
    /// (the newest messages are kept).
    ///
    /// # Errors
    ///
    /// [`ChainError::MemoryError`] if the snapshot format version is unsupported.
    pub fn restore(&self, snapshot: MemorySnapshot) -> Result<(), ChainError> {
        snapshot.check_version()?;
        let mut restored: VecDeque<Message> = snapshot.messages.into();
        self.enforce_cap(&mut restored);
        *lock(&self.messages) = restored;
        Ok(())
    }

    fn enforce_cap(&self, messages: &mut VecDeque<Message>) {
        if let Some(max) = self.max_messages {
            let excess = messages.len().saturating_sub(max);
            if excess > 0 {
                messages.drain(..excess);
                drop_orphan_tool_results(messages);
            }
        }
    }
}

impl Default for SimpleMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Redacted: prints sizes only, never message contents.
impl std::fmt::Debug for SimpleMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleMemory")
            .field("max_messages", &self.max_messages)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Memory for SimpleMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        Ok(lock(&self.messages).iter().cloned().collect())
    }

    async fn add(&self, message: Message) -> Result<(), ChainError> {
        let mut stored = lock(&self.messages);
        stored.push_back(message);
        self.enforce_cap(&mut stored);
        drop(stored);
        Ok(())
    }

    async fn clear(&self) -> Result<(), ChainError> {
        lock(&self.messages).clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn starts_empty() {
        let mem = SimpleMemory::new();
        assert_eq!(mem.messages().await.unwrap(), [] as [Message; 0]);
        assert!(mem.is_empty());
    }

    #[tokio::test]
    async fn add_and_retrieve() {
        let mem = SimpleMemory::new();
        mem.add(Message::human("Hello")).await.unwrap();
        mem.add(Message::ai("Hi")).await.unwrap();

        let history = mem.messages().await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content, "Hello");
        assert_eq!(history[1].content, "Hi");
    }

    #[tokio::test]
    async fn clear_resets_history() {
        let mem = SimpleMemory::new();
        mem.add(Message::human("Hello")).await.unwrap();
        mem.clear().await.unwrap();
        assert_eq!(mem.messages().await.unwrap(), [] as [Message; 0]);
    }

    #[tokio::test]
    async fn retains_all_messages() {
        let mem = SimpleMemory::new();
        for i in 0..20 {
            mem.add(Message::human(format!("msg {i}"))).await.unwrap();
        }
        assert_eq!(mem.messages().await.unwrap().len(), 20);
        assert_eq!(mem.max_messages(), None);
    }

    #[tokio::test]
    async fn cap_evicts_oldest() {
        let mem = SimpleMemory::with_max_messages(3);
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
        assert_eq!(mem.len(), 3);
    }

    #[tokio::test]
    async fn restore_applies_cap() {
        let mem = SimpleMemory::with_max_messages(2);
        let snap = MemorySnapshot::new(
            (0..5).map(|i| Message::human(format!("{i}"))).collect(),
            None,
        );
        mem.restore(snap).unwrap();
        let texts: Vec<_> = mem
            .messages()
            .await
            .unwrap()
            .iter()
            .map(|m| m.content.text_content())
            .collect();
        assert_eq!(texts, ["3", "4"]);
    }

    #[test]
    fn debug_is_redacted() {
        let mem = SimpleMemory::new();
        tokio_test::block_on(mem.add(Message::human("password123"))).unwrap();
        assert!(!format!("{mem:?}").contains("password123"));
    }

    #[tokio::test]
    async fn cap_drops_orphan_tool_results() {
        use rune_chain_core::ToolCall;
        let mem = SimpleMemory::with_max_messages(2);
        mem.add(Message::ai_with_tool_calls(
            "",
            vec![ToolCall::new("1", "t", "{}")],
        ))
        .await
        .unwrap();
        mem.add(Message::tool_result("1", "r")).await.unwrap();
        mem.add(Message::human("next")).await.unwrap();
        assert_eq!(mem.messages().await.unwrap(), [Message::human("next")]);
    }
}

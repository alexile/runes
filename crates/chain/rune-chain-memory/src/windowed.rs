use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use rune_chain_core::{ChainError, Memory, Message, Role};

use crate::MemorySnapshot;
use crate::util::lock;

#[derive(Default)]
struct State {
    /// The first system message, when pinning is enabled.
    pinned: Option<Message>,
    /// The most recent turns, never more than `window`.
    turns: VecDeque<Message>,
}

/// Sliding-window conversation memory that exposes only the last `N` turns.
///
/// [`messages`](Memory::messages) returns the most recent `window` messages.
/// Messages that slide out of the window are dropped, so storage is bounded
/// by the window size no matter how long the conversation runs.
///
/// With [`pin_system`](Self::pin_system) enabled, the first [`Role::System`]
/// message added (since the last [`clear`](Memory::clear)) is kept outside
/// the window and always returned first, so the model never loses its
/// instructions. It does not count against `window`.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::WindowedMemory;
/// use rune_chain_core::{Memory, Message};
///
/// # tokio_test::block_on(async {
/// let mem = WindowedMemory::new(2);
///
/// mem.add(Message::human("turn 1")).await.unwrap();
/// mem.add(Message::ai("reply 1")).await.unwrap();
/// mem.add(Message::human("turn 2")).await.unwrap();
/// mem.add(Message::ai("reply 2")).await.unwrap();
///
/// // Only the last 2 messages are visible
/// let visible = mem.messages().await.unwrap();
/// assert_eq!(visible.len(), 2);
/// assert_eq!(visible[0].content, "turn 2");
/// assert_eq!(visible[1].content, "reply 2");
/// # });
/// ```
///
/// Keeping the system prompt:
///
/// ```rust
/// use rune_chain_memory::WindowedMemory;
/// use rune_chain_core::{Memory, Message, Role};
///
/// # tokio_test::block_on(async {
/// let mem = WindowedMemory::new(1).pin_system(true);
/// mem.add(Message::system("Answer in French.")).await.unwrap();
/// mem.add(Message::human("hello")).await.unwrap();
/// mem.add(Message::human("goodbye")).await.unwrap();
///
/// let visible = mem.messages().await.unwrap();
/// assert_eq!(visible.len(), 2);
/// assert_eq!(visible[0].role, Role::System);
/// assert_eq!(visible[1].content, "goodbye");
/// # });
/// ```
pub struct WindowedMemory {
    window: usize,
    pin_system: bool,
    state: Mutex<State>,
}

impl WindowedMemory {
    /// Create a windowed memory that returns at most `window` messages.
    ///
    /// A `window` of `0` means [`messages`](Memory::messages) always returns
    /// an empty slice (useful for stateless testing), unless a system message
    /// is pinned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::WindowedMemory;
    ///
    /// let mem = WindowedMemory::new(4);
    /// assert_eq!(mem.window(), 4);
    /// ```
    #[must_use]
    pub const fn new(window: usize) -> Self {
        Self {
            window,
            pin_system: false,
            state: Mutex::new(State {
                pinned: None,
                turns: VecDeque::new(),
            }),
        }
    }

    /// Pin the first system message outside the window (default: off).
    #[must_use]
    pub const fn pin_system(mut self, pin: bool) -> Self {
        self.pin_system = pin;
        self
    }

    /// The maximum number of (non-pinned) messages returned by
    /// [`messages`](Memory::messages).
    #[must_use]
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Whether the first system message is pinned.
    #[must_use]
    pub const fn pins_system(&self) -> bool {
        self.pin_system
    }

    /// Number of stored messages (including a pinned system message).
    #[must_use]
    pub fn len(&self) -> usize {
        let s = lock(&self.state);
        s.turns.len() + usize::from(s.pinned.is_some())
    }

    /// `true` when no messages are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take a serializable copy of the visible history.
    #[must_use]
    pub fn snapshot(&self) -> MemorySnapshot {
        MemorySnapshot::new(Self::collect(&lock(&self.state)), None)
    }

    /// Replace the stored history with `snapshot`, re-applying the window
    /// and system pinning exactly as if each message had been added in order.
    ///
    /// # Errors
    ///
    /// [`ChainError::MemoryError`] if the snapshot format version is unsupported.
    pub fn restore(&self, snapshot: MemorySnapshot) -> Result<(), ChainError> {
        snapshot.check_version()?;
        let mut state = State::default();
        for m in snapshot.messages {
            self.push(&mut state, m);
        }
        *lock(&self.state) = state;
        Ok(())
    }

    fn push(&self, state: &mut State, message: Message) {
        if self.pin_system && state.pinned.is_none() && message.role == Role::System {
            state.pinned = Some(message);
            return;
        }
        state.turns.push_back(message);
        let excess = state.turns.len().saturating_sub(self.window);
        state.turns.drain(..excess);
    }

    fn collect(state: &State) -> Vec<Message> {
        state
            .pinned
            .iter()
            .chain(state.turns.iter())
            .cloned()
            .collect()
    }
}

/// Redacted: prints sizes only, never message contents.
impl std::fmt::Debug for WindowedMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowedMemory")
            .field("window", &self.window)
            .field("pin_system", &self.pin_system)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Memory for WindowedMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        Ok(Self::collect(&lock(&self.state)))
    }

    async fn add(&self, message: Message) -> Result<(), ChainError> {
        let mut state = lock(&self.state);
        self.push(&mut state, message);
        Ok(())
    }

    async fn clear(&self) -> Result<(), ChainError> {
        *lock(&self.state) = State::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_last_n_messages() {
        let mem = WindowedMemory::new(3);
        for i in 0..6 {
            mem.add(Message::human(format!("msg {i}"))).await.unwrap();
        }

        let visible = mem.messages().await.unwrap();
        assert_eq!(visible.len(), 3);
        assert_eq!(visible[0].content, "msg 3");
        assert_eq!(visible[2].content, "msg 5");
    }

    #[tokio::test]
    async fn fewer_messages_than_window() {
        let mem = WindowedMemory::new(10);
        mem.add(Message::human("only one")).await.unwrap();

        let visible = mem.messages().await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].content, "only one");
    }

    #[tokio::test]
    async fn window_zero_returns_empty() {
        let mem = WindowedMemory::new(0);
        mem.add(Message::human("ignored")).await.unwrap();
        assert_eq!(mem.messages().await.unwrap(), [] as [Message; 0]);
    }

    #[tokio::test]
    async fn clear_resets_history() {
        let mem = WindowedMemory::new(5).pin_system(true);
        mem.add(Message::system("sys")).await.unwrap();
        mem.add(Message::human("hello")).await.unwrap();
        mem.clear().await.unwrap();
        assert_eq!(mem.messages().await.unwrap(), [] as [Message; 0]);
        assert!(mem.is_empty());
    }

    #[tokio::test]
    async fn window_slides_as_messages_added() {
        let mem = WindowedMemory::new(2);

        mem.add(Message::human("a")).await.unwrap();
        assert_eq!(mem.messages().await.unwrap().len(), 1);

        mem.add(Message::human("b")).await.unwrap();
        assert_eq!(mem.messages().await.unwrap().len(), 2);

        mem.add(Message::human("c")).await.unwrap();
        let visible = mem.messages().await.unwrap();
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].content, "b");
        assert_eq!(visible[1].content, "c");
    }

    #[tokio::test]
    async fn storage_is_bounded_by_window() {
        let mem = WindowedMemory::new(4);
        for i in 0..10_000 {
            mem.add(Message::human(format!("{i}"))).await.unwrap();
        }
        assert_eq!(mem.len(), 4);
    }

    #[tokio::test]
    async fn only_first_system_message_is_pinned() {
        let mem = WindowedMemory::new(1).pin_system(true);
        mem.add(Message::system("first")).await.unwrap();
        mem.add(Message::system("second")).await.unwrap();
        mem.add(Message::human("h")).await.unwrap();
        let visible = mem.messages().await.unwrap();
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].content, "first");
        assert_eq!(visible[1].content, "h");
    }

    #[tokio::test]
    async fn without_pinning_system_slides_out() {
        let mem = WindowedMemory::new(1);
        mem.add(Message::system("sys")).await.unwrap();
        mem.add(Message::human("h")).await.unwrap();
        assert_eq!(mem.messages().await.unwrap(), [Message::human("h")]);
    }

    #[tokio::test]
    async fn snapshot_roundtrip_reapplies_window() {
        let mem = WindowedMemory::new(2).pin_system(true);
        mem.add(Message::system("s")).await.unwrap();
        for i in 0..5 {
            mem.add(Message::human(format!("{i}"))).await.unwrap();
        }
        let snap = mem.snapshot();
        let other = WindowedMemory::new(1).pin_system(true);
        other.restore(snap).unwrap();
        let visible = other.messages().await.unwrap();
        assert_eq!(visible, [Message::system("s"), Message::human("4")]);
    }
}

use async_trait::async_trait;

use crate::{ChainError, Message};

/// Persistent conversation history attached to a [`Chain`](crate::Chain).
///
/// A memory implementation stores and retrieves [`Message`] turns so that
/// subsequent chain calls have access to prior context. Implementations may
/// keep history in process memory, a database, or a vector store.
///
/// # Example
///
/// ```rust
/// use std::sync::Mutex;
///
/// use async_trait::async_trait;
/// use rune_chain_core::{ChainError, Memory, Message};
///
/// #[derive(Default)]
/// struct InMemory(Mutex<Vec<Message>>);
///
/// #[async_trait]
/// impl Memory for InMemory {
///     async fn messages(&self) -> Result<Vec<Message>, ChainError> {
///         let guard = self.0.lock().map_err(|e| ChainError::MemoryError(e.to_string()))?;
///         Ok(guard.clone())
///     }
///     async fn add(&self, message: Message) -> Result<(), ChainError> {
///         let mut guard = self.0.lock().map_err(|e| ChainError::MemoryError(e.to_string()))?;
///         guard.push(message);
///         Ok(())
///     }
///     async fn clear(&self) -> Result<(), ChainError> {
///         let mut guard = self.0.lock().map_err(|e| ChainError::MemoryError(e.to_string()))?;
///         guard.clear();
///         Ok(())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let memory = InMemory::default();
/// memory.add(Message::human("What is 2 + 2?")).await?;
/// memory.add(Message::ai("4")).await?;
///
/// let history = memory.messages().await?;
/// assert_eq!(history.len(), 2);
/// # Ok::<(), ChainError>(())
/// # }).unwrap();
/// ```
#[async_trait]
pub trait Memory: Sync + Send {
    /// Return all messages currently stored in this memory.
    async fn messages(&self) -> Result<Vec<Message>, ChainError>;

    /// Append a single message to the stored history.
    async fn add(&self, message: Message) -> Result<(), ChainError>;

    /// Clear all stored messages, resetting the conversation to zero turns.
    async fn clear(&self) -> Result<(), ChainError>;
}

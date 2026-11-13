//! Serializable snapshots of conversation history.

use rune_chain_core::{ChainError, Message};
use serde::{Deserialize, Serialize};

/// A serializable, point-in-time copy of a memory's stored history.
///
/// Every memory type in this crate offers `snapshot()` and `restore()`, so a
/// conversation can be persisted (to JSON, a database row, a session cookie
/// store, …) and resumed later, possibly in a different memory type.
///
/// Restoring re-applies the target memory's limits (window, token budget,
/// capacity), so a snapshot from an untrusted source cannot be used to grow a
/// memory beyond its configured bounds.
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::{MemorySnapshot, SimpleMemory};
/// use rune_chain_core::{Memory, Message};
///
/// # tokio_test::block_on(async {
/// let mem = SimpleMemory::new();
/// mem.add(Message::human("hi")).await.unwrap();
///
/// let json = serde_json::to_string(&mem.snapshot()).unwrap();
///
/// let restored = SimpleMemory::new();
/// let snap: MemorySnapshot = serde_json::from_str(&json).unwrap();
/// restored.restore(snap).unwrap();
/// assert_eq!(restored.messages().await.unwrap(), mem.messages().await.unwrap());
/// # });
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemorySnapshot {
    /// Snapshot format version; see [`MemorySnapshot::FORMAT_VERSION`].
    pub version: u32,
    /// Stored messages, oldest first (a pinned system message comes first).
    pub messages: Vec<Message>,
    /// Running summary of compacted turns (only set by
    /// [`SummaryBufferMemory`](crate::SummaryBufferMemory)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Per-entity notes, least recently used first (only set by
    /// `EntityMemory`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EntitySummary>,
}

/// One entity and its running summary, as stored in a [`MemorySnapshot`].
///
/// # Example
///
/// ```rust
/// use rune_chain_memory::EntitySummary;
///
/// let e = EntitySummary::new("Alice", "Works on the billing team.");
/// assert_eq!(e.name, "Alice");
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EntitySummary {
    /// The entity's name as first seen.
    pub name: String,
    /// What the conversation has established about it.
    pub summary: String,
}

impl EntitySummary {
    /// Pair a name with its summary.
    #[must_use]
    pub fn new(name: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            summary: summary.into(),
        }
    }
}

/// Redacted: prints nothing but the type name (summaries may hold PII).
impl std::fmt::Debug for EntitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntitySummary").finish_non_exhaustive()
    }
}

impl MemorySnapshot {
    /// The snapshot format version written by this crate.
    pub const FORMAT_VERSION: u32 = 1;

    /// Build a snapshot from messages (and an optional running summary).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::MemorySnapshot;
    /// use rune_chain_core::Message;
    ///
    /// let snap = MemorySnapshot::new(vec![Message::human("hi")], None);
    /// assert_eq!(snap.version, MemorySnapshot::FORMAT_VERSION);
    /// ```
    #[must_use]
    pub const fn new(messages: Vec<Message>, summary: Option<String>) -> Self {
        Self {
            version: Self::FORMAT_VERSION,
            messages,
            summary,
            entities: Vec::new(),
        }
    }

    /// Attach entity notes, least recently used first.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_memory::{EntitySummary, MemorySnapshot};
    ///
    /// let snap = MemorySnapshot::new(Vec::new(), None)
    ///     .with_entities(vec![EntitySummary::new("Paris", "Where the user lives.")]);
    /// assert_eq!(snap.entities.len(), 1);
    /// ```
    #[must_use]
    pub fn with_entities(mut self, entities: Vec<EntitySummary>) -> Self {
        self.entities = entities;
        self
    }

    /// Reject snapshots written by a newer, incompatible format.
    pub(crate) fn check_version(&self) -> Result<(), ChainError> {
        if self.version == 0 || self.version > Self::FORMAT_VERSION {
            return Err(ChainError::MemoryError(format!(
                "unsupported memory snapshot version {} (supported: 1..={})",
                self.version,
                Self::FORMAT_VERSION
            )));
        }
        Ok(())
    }
}

/// Redacted: prints counts only, never message contents (which may hold PII).
impl std::fmt::Debug for MemorySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySnapshot")
            .field("version", &self.version)
            .field("messages", &self.messages.len())
            .field("has_summary", &self.summary.is_some())
            .field("entities", &self.entities.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_versions() {
        let mut s = MemorySnapshot::new(Vec::new(), None);
        assert!(s.check_version().is_ok());
        s.version = 0;
        assert!(s.check_version().is_err());
        s.version = MemorySnapshot::FORMAT_VERSION + 1;
        assert!(s.check_version().is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let s = MemorySnapshot::new(vec![Message::human("secret")], Some("s3cret".into()))
            .with_entities(vec![EntitySummary::new("Bob", "sekret")]);
        let d = format!("{s:?}");
        assert!(
            !d.contains("secret") && !d.contains("s3cret") && !d.contains("Bob"),
            "{d}"
        );
    }
}

//! In-process conversation memory for the `rune-chain` LLM orchestration framework.
//!
//! Provides [`Memory`](rune_chain_core::Memory) implementations that store
//! conversation history in process memory behind a `Mutex`, making them safe
//! to share across threads and tasks via `Arc`.
//!
//! # Implementations
//!
//! | Type | Keeps | Bounded by |
//! |------|-------|------------|
//! | [`SimpleMemory`] | everything | optional [`with_max_messages`](SimpleMemory::with_max_messages) |
//! | [`WindowedMemory`] | last `N` messages (+ optional pinned system prompt) | window |
//! | [`TokenBufferMemory`] | newest messages fitting a token budget, system prompt pinned | tokens + message cap |
//! | [`SummaryBufferMemory`] | recent turns verbatim + an LLM-written summary of older ones | tokens + message cap + summary length |
//! | `VectorMemory` (feature `vector`) | past exchanges in a vector store; injects the most relevant ones | stored exchanges + exchange length + injected length |
//! | `EntityMemory` (feature `entity`) | LLM-written notes per entity; injects those the input mentions | entity count (LRU) + name/summary length + injected length |
//!
//! The two retrieval memories inject their context as one [`Role::Human`]
//! message fenced as untrusted data, never into the system prompt. Because
//! [`Memory::messages`] does not receive the new input, both offer a
//! `prepare(input)` method to call before reading history; without it they
//! use the last human message.
//!
//! [`Role::Human`]: rune_chain_core::Role::Human
//! [`Memory::messages`]: rune_chain_core::Memory::messages
//!
//! # Features
//!
//! - `vector`: `VectorMemory`, backed by `rune-vectorstore` and
//!   `rune-chain-embed`.
//! - `entity`: `EntityMemory`, using any `Llm` with structured output.
//!
//! Both are off by default so the core stays dependency-light.
//!
//! Every type also offers `snapshot()` / `restore()` with a serde-serializable
//! [`MemorySnapshot`] for persisting conversations.
//!
//! # Safety properties
//!
//! - No lock is ever held across an `.await`, and user callbacks
//!   ([`TokenCounter`], [`Summarizer`], LLMs, embedders, stores, error hooks)
//!   never run while a lock is held.
//! - Lock poisoning is recovered from instead of propagating panics.
//! - All types except an unconfigured [`SimpleMemory`] have bounded storage,
//!   and `restore` re-applies bounds, so untrusted input cannot grow memory
//!   without limit.
//! - `Debug` output is redacted: it never prints message contents.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_memory::SimpleMemory;
//! use rune_chain_core::{Memory, Message};
//!
//! # tokio_test::block_on(async {
//! let mem = SimpleMemory::new();
//!
//! mem.add(Message::human("What is 2 + 2?")).await.unwrap();
//! mem.add(Message::ai("4")).await.unwrap();
//!
//! let history = mem.messages().await.unwrap();
//! assert_eq!(history.len(), 2);
//! # });
//! ```
//!
//! Limit context with a sliding window:
//!
//! ```rust
//! use rune_chain_memory::WindowedMemory;
//! use rune_chain_core::{Memory, Message};
//!
//! # tokio_test::block_on(async {
//! let mem = WindowedMemory::new(2);
//!
//! for i in 0..5 {
//!     mem.add(Message::human(format!("turn {i}"))).await.unwrap();
//! }
//!
//! // Only the last 2 are visible to the LLM
//! let visible = mem.messages().await.unwrap();
//! assert_eq!(visible.len(), 2);
//! assert_eq!(visible[0].content, "turn 3");
//! # });
//! ```
//!
//! Fit a token budget, keeping the system prompt:
//!
//! ```rust
//! use rune_chain_memory::TokenBufferMemory;
//! use rune_chain_core::{Memory, Message, Role};
//!
//! # tokio_test::block_on(async {
//! let mem = TokenBufferMemory::with_char_estimate(30);
//! mem.add(Message::system("You are terse.")).await.unwrap();
//! for i in 0..50 {
//!     mem.add(Message::human(format!("message number {i}"))).await.unwrap();
//! }
//! assert!(mem.token_count() <= 30);
//! assert_eq!(mem.messages().await.unwrap()[0].role, Role::System);
//! # });
//! ```

mod budget;
#[cfg(feature = "entity")]
mod entity;
#[cfg(any(feature = "vector", feature = "entity"))]
mod recent;
mod simple;
mod snapshot;
mod summary;
mod token;
mod util;
#[cfg(feature = "vector")]
mod vector;
mod windowed;

#[cfg(feature = "entity")]
pub use entity::{
    DEFAULT_ENTITY_HEADER, DEFAULT_ENTITY_RECENT, DEFAULT_EXTRACT_INSTRUCTIONS,
    DEFAULT_MAX_ENTITIES, DEFAULT_MAX_ENTITIES_PER_TURN, DEFAULT_MAX_ENTITY_CONTEXT_CHARS,
    DEFAULT_MAX_ENTITY_SUMMARY_CHARS, DEFAULT_MAX_NAME_CHARS, DEFAULT_UPDATE_INSTRUCTIONS,
    EntityMemory,
};
pub use simple::SimpleMemory;
pub use snapshot::{EntitySummary, MemorySnapshot};
pub use summary::{
    DEFAULT_MAX_SUMMARY_CHARS, DEFAULT_SUMMARY_PREFIX, LlmSummarizer, Summarizer,
    SummaryBufferMemory,
};
pub use token::{CharEstimator, TokenBufferMemory, TokenCounter};
#[cfg(feature = "vector")]
pub use vector::{
    DEFAULT_MAX_CONTEXT_CHARS, DEFAULT_MAX_EXCHANGE_CHARS, DEFAULT_MAX_TURNS,
    DEFAULT_VECTOR_HEADER, DEFAULT_VECTOR_TOP_K, NAMESPACE_KEY, VectorMemory,
};
pub use windowed::WindowedMemory;

/// Default hard cap on stored messages for [`TokenBufferMemory`] and
/// [`SummaryBufferMemory`], independent of the token budget.
pub const DEFAULT_MAX_MESSAGES: usize = 10_000;

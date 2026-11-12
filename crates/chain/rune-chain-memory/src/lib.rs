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
//!
//! Every type also offers `snapshot()` / `restore()` with a serde-serializable
//! [`MemorySnapshot`] for persisting conversations.
//!
//! # Safety properties
//!
//! - No lock is ever held across an `.await`, and user callbacks
//!   ([`TokenCounter`], [`Summarizer`]) never run while a lock is held.
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
mod simple;
mod snapshot;
mod summary;
mod token;
mod util;
mod windowed;

pub use simple::SimpleMemory;
pub use snapshot::MemorySnapshot;
pub use summary::{
    DEFAULT_MAX_SUMMARY_CHARS, DEFAULT_SUMMARY_PREFIX, LlmSummarizer, Summarizer,
    SummaryBufferMemory,
};
pub use token::{CharEstimator, TokenBufferMemory, TokenCounter};
pub use windowed::WindowedMemory;

/// Default hard cap on stored messages for [`TokenBufferMemory`] and
/// [`SummaryBufferMemory`], independent of the token budget.
pub const DEFAULT_MAX_MESSAGES: usize = 10_000;

# rune-chain-memory

> In-process conversation memory for the rune-chain LLM orchestration framework.

[![crates.io](https://img.shields.io/crates/v/rune-chain-memory)](https://crates.io/crates/rune-chain-memory)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-memory)](https://docs.rs/rune-chain-memory)
[![license](https://img.shields.io/crates/l/rune-chain-memory)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-memory` provides [`Memory`](https://docs.rs/rune-chain-core/latest/rune_chain_core/trait.Memory.html)
implementations that keep conversation history in process memory, from a plain
unbounded log to a token-budgeted buffer that summarizes old turns with an LLM,
plus two optional retrieval memories: one that recalls relevant past exchanges
from a vector store, and one that keeps LLM-written notes about the entities a
conversation mentions. All of them are `Send + Sync` and can be shared across
tasks with `Arc`.

## Installation

```toml
[dependencies]
rune-chain-memory = "0.2"
# or, with the retrieval memories:
# rune-chain-memory = { version = "0.2", features = ["vector", "entity"] }
```

| Feature | Adds | Extra dependencies |
|---------|------|--------------------|
| `vector` | `VectorMemory` | `rune-vectorstore`, `rune-chain-embed` |
| `entity` | `EntityMemory` | `serde_json` |

Both are off by default so the core stays light.

## Implementations

| Type | Keeps | Bounded by |
|------|-------|------------|
| `SimpleMemory` | everything | optional `with_max_messages(n)` (FIFO eviction) |
| `WindowedMemory` | the last `N` messages, optionally plus the pinned system prompt | window |
| `TokenBufferMemory` | the newest messages that fit a token budget; system prompt pinned | tokens + message cap |
| `SummaryBufferMemory` | recent turns verbatim + a running summary of older ones | tokens + message cap + summary length |
| `VectorMemory` | past exchanges in a vector store; injects the top-k relevant ones | stored exchanges (oldest evicted) + exchange length + injected length |
| `EntityMemory` | an LLM-maintained note per entity; injects notes for entities in the input | entity count (LRU) + name/summary length + injected length |

## Usage

Unbounded history:

```rust
use rune_chain_memory::SimpleMemory;
use rune_chain_core::{Memory, Message};

let mem = SimpleMemory::new();
mem.add(Message::human("What is 2 + 2?")).await?;
mem.add(Message::ai("4")).await?;
assert_eq!(mem.messages().await?.len(), 2);
```

Sliding window that keeps the system prompt:

```rust
use rune_chain_memory::WindowedMemory;

let mem = WindowedMemory::new(4).pin_system(true);
```

Token budget with a pluggable counter (any `Fn(&Message) -> usize`, or the
built-in `CharEstimator` heuristic):

```rust
use rune_chain_memory::TokenBufferMemory;
use rune_chain_core::Message;

let mem = TokenBufferMemory::new(4_000, |m: &Message| my_tokenizer.count(&m.content.text_content()));
// or: TokenBufferMemory::with_char_estimate(4_000)
```

Summarize old turns with any `Llm`:

```rust
use std::sync::Arc;
use rune_chain_memory::{LlmSummarizer, SummaryBufferMemory};

let mem = SummaryBufferMemory::new(LlmSummarizer::new(Arc::new(llm)), 2_000);
```

Log failures that `add` swallows (summarizer, extractor, embedder, store):

```rust
let mem = SummaryBufferMemory::new(summarizer, 2_000)
    .on_error(|e| tracing::warn!(error = %e, "memory compaction failed"));
```

### Retrieval memories

`Memory::messages` does not receive the new input, and chains read history
before recording the turn. Call `prepare(input)` first so retrieval uses the
input; otherwise the last human message is the query. Retrieved context comes
back as one human-role message fenced as untrusted past conversation, after
the pinned system prompt and never merged into it.

Recall relevant past exchanges (like LangChain's `VectorStoreRetrieverMemory`):

```rust
use std::sync::Arc;
use rune_chain_memory::VectorMemory;
use rune_vectorstore::InMemoryVectorStore;

let mem = VectorMemory::new(InMemoryVectorStore::default(), embedder)
    .top_k(4)
    .min_score(0.3)
    .with_mmr(20, 0.5)       // diversify near-duplicates
    .max_turns(1_000)        // oldest exchanges are deleted from the store
    .max_context_chars(4_000)
    .recent(4);              // also keep the last 4 messages verbatim

mem.prepare(&user_input).await;
let history = mem.messages().await?;
```

Keep notes about people, places and things (like LangChain's
`ConversationEntityMemory`):

```rust
use rune_chain_memory::EntityMemory;

let mem = EntityMemory::new(Arc::new(llm))
    .max_entities(200)       // least recently mentioned evicted first
    .max_summary_chars(600)
    .on_error(|e| tracing::warn!(error = %e, "entity update failed"));

mem.prepare(&user_input).await; // extracts entities from the input
let history = mem.messages().await?;
```

Extraction and updates use `Llm::generate_structured` with a JSON schema; the
number of entities per message, name and summary lengths are capped, and the
model can only update entities it was asked about. Failures never fail the
conversation: notes stay as they were and known names are still matched
literally.

Persist and resume a conversation:

```rust
let json = serde_json::to_string(&mem.snapshot())?;
mem.restore(serde_json::from_str(&json)?)?;
```

`EntityMemory` snapshots carry the entity notes. `VectorMemory` snapshots
carry the stored exchanges as plain messages, and its `restore` is async
because it re-embeds them.

## Safety properties

- No lock is held across `.await`; token counters and summarizers never run under a lock.
- Lock poisoning is recovered from rather than turned into panics.
- Every type except an unconfigured `SimpleMemory` has bounded storage, and
  `restore` re-applies the bounds to untrusted snapshots.
- Budget trimming drops tool results whose tool-call turn was evicted, so the
  history stays valid for providers that require call/result pairing.
- `SummaryBufferMemory` runs one compaction at a time, is cancellation-safe,
  discards summaries invalidated by a concurrent `clear`/`restore`, and caps the
  summary length. `LlmSummarizer` fences the transcript as untrusted data.
- `VectorMemory` and `EntityMemory` fence everything they inject or send to a
  model as untrusted data, neutralize closing delimiters, scope store records
  to a namespace, and discard in-flight writes after a `clear`/`restore`.
- `Debug` output is redacted and never prints message contents.

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change. Stored messages may now carry `reasoning`; it is not part of their text.

## License

MIT

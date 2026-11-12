# rune-tokenize

> Approximate token counting, budget checking, text truncation, and overlapping chunk splitting for LLM context windows.

[![crates.io](https://img.shields.io/crates/v/rune-tokenize)](https://crates.io/crates/rune-tokenize)
[![docs.rs](https://img.shields.io/docsrs/rune-tokenize)](https://docs.rs/rune-tokenize)
[![license](https://img.shields.io/crates/l/rune-tokenize)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-tokenize` covers what every LLM application needs before sending text to
a model: estimate the token count, check it against a budget, truncate to a
limit without cutting mid-word (or mid-character, or mid-emoji), and split a
long document into overlapping chunks for retrieval-augmented generation (RAG).

- **No dependencies, no vocabulary files**, `no_std` + `alloc`.
- **Model-aware heuristics**: `TokenizerProfile` for GPT-4 (`cl100k`), GPT-4o /
  GPT-5 (`o200k`), Claude, Llama 3/4 and Llama 2 / Mistral, accounting for CJK,
  other scripts, digit grouping, punctuation, indentation and emoji. The
  default `Simple` profile is the classic **4 characters ≈ 1 token**.
- **Pluggable exact counting**: every helper takes a `TokenCounter`; closures
  `Fn(&str) -> usize` qualify, so tiktoken or a HF tokenizer drops straight in.
- **Unicode-safe**: cuts never split a UTF-8 sequence, a combining sequence, a
  ZWJ emoji or a flag; nothing panics on any input (property-tested).
- **Truncation strategies**: keep the start, the end, or both ends with an ellipsis.
- **Structure-aware chunking**: paragraph → sentence → word → grapheme
  fallback, overlap, zero-copy slices with byte offsets; invalid sizes are
  errors, never infinite loops.
- **Chat budgets**: per-message overhead (`OpenAI` accounting and per-family
  presets), sliding-window history trimming, context-window `Budget`.

The heuristics are tuned to land close to (and usually slightly above) the real
tokenizers, which is what you want for budgeting. For exact numbers plug a real
tokenizer in through `TokenCounter`.

## Installation

```toml
[dependencies]
rune-tokenize = "0.1"
```

Without the standard library: `default-features = false`.

The `rune-tokenize` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-tokenize --features cli
```

## Usage

The original `⌈chars / 4⌉` API:

```rust
use rune_tokenize::{estimate, fits, truncate, chunk};

assert_eq!(estimate("hello world"), 3);
assert!(fits("hello world", 4096));

// Truncate to fit, snapping to a word boundary
let safe = truncate("The quick brown fox jumps over the lazy dog", 4);
assert_eq!(safe, "The quick brown");

// 500-token chunks with 50-token overlap (panics on invalid sizes; see try_chunk)
let chunks = chunk("one two three four five", 500, 50);
assert_eq!(chunks.len(), 1);
```

Model profiles, truncation strategies and structure-aware chunking:

```rust
use rune_tokenize::{
    chunk_with, truncate_with, Boundary, ChunkConfig, TokenCounter, TokenizerProfile, Truncation,
};

let p = TokenizerProfile::for_model("gpt-4o").unwrap_or_default();
assert_eq!(p, TokenizerProfile::O200k);
let n = p.count_tokens("Hello, world!");

// Keep the end of a long log, or both ends with " … " in between.
let log = "boot ok; disk ok; net ok; ERROR: database unreachable";
let tail = truncate_with(log, 6, &p, Truncation::KeepEnd);
let both = truncate_with(log, 10, &p, Truncation::Middle);

// Chunks borrow from the input and carry byte offsets and token counts.
let doc = "First paragraph.\n\nSecond paragraph. It has two sentences.";
let config = ChunkConfig::new(8).overlap(2).boundary(Boundary::Sentence);
for c in chunk_with(doc, &config, &p).expect("valid config") {
    assert_eq!(&doc[c.start..c.end], c.text);
    assert!(c.tokens <= 8);
}
```

Plug in an exact tokenizer and budget a chat:

```rust
use rune_tokenize::{count_chat, fit_recent_messages, Budget, ChatMessage, ChatOverhead};

// Any `Fn(&str) -> usize` is a TokenCounter, e.g. a tiktoken-rs closure:
// let bpe = tiktoken_rs::o200k_base()?;
// let exact = |s: &str| bpe.encode_ordinary(s).len();
let exact = |s: &str| s.split_whitespace().count(); // stand-in

let history = [
    ChatMessage::new("system", "You are terse."),
    ChatMessage::new("user", "first question"),
    ChatMessage::new("assistant", "first answer"),
    ChatMessage::new("user", "follow-up"),
];
let total = count_chat(&history, &exact, ChatOverhead::OPENAI);

// Keep the system prompt plus as many recent turns as fit in 20 tokens.
let start = fit_recent_messages(&history, 20, 1, &exact, ChatOverhead::OPENAI);
assert_eq!(start, Some(3));

let budget = Budget::new(128_000, 4_096);
assert!(budget.fits_chat(&history, &exact, ChatOverhead::OPENAI));
```

## CLI

```bash
cat document.txt | rune-tokenize             # estimated token count (simple profile)
rune-tokenize -m gpt-4o document.txt         # o200k heuristics
rune-tokenize -m claude -b 200000 prompt.md  # exit status 1 if over budget
```

## API

| Item | Description |
|------|-------------|
| `estimate(text)` | Approximate token count: `⌈chars / 4⌉` |
| `fits(text, max)` / `fits_with(text, max, &counter)` | Budget check |
| `truncate(text, max)` | Cut to `max` tokens, snap to word boundary |
| `chunk(text, size, overlap)` / `try_chunk(…)` | Word-joined overlapping windows (panicking / `Result`) |
| `TokenCounter` | Trait for any counter; implemented by closures and profiles |
| `TokenizerProfile` | `Simple`, `Cl100k`, `O200k`, `Claude`, `Llama3`, `Llama2`; `for_model`, `FromStr` |
| `truncate_with(text, max, &counter, Truncation)` | `KeepStart`, `KeepEnd`, `Middle` |
| `truncate_middle(text, max, &counter, ellipsis)` | Middle truncation with a custom marker |
| `chunk_with(text, &ChunkConfig, &counter)` | Paragraph/sentence/word/grapheme chunks with overlap and offsets |
| `count_chat`, `fit_recent_messages`, `ChatOverhead` | Chat-message budgeting |
| `Budget` | Context window minus reserved output |

## When to use this in rune-chain

| Chain crate | Usage |
|-------------|-------|
| `rune-chain-conversational` | Check if history fits before each call |
| `rune-chain-memory` | Enforce a token budget on `WindowedMemory` |
| `rune-chain-retrieval` | Size document chunks for embedding |
| `rune-chain-splitter` | Back this crate's chunking with word-level splitting |
| Any provider crate | Guard against context-window overflow |

## License

MIT

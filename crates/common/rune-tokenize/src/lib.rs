//! Approximate token counting, budget checking, truncation, and overlapping chunk
//! splitting for LLM context windows. No dependencies, no vocabulary files,
//! `no_std` + `alloc`.
//!
//! The original free functions use the classic rule of thumb, **4 characters ≈
//! 1 token**. For better numbers pick a [`TokenizerProfile`] tuned for a model
//! family (GPT-4 `cl100k`, GPT-4o `o200k`, Claude, Llama 3, Llama 2 / Mistral),
//! which accounts for CJK, other scripts, digits, punctuation, code
//! indentation and emoji. For exact numbers, implement [`TokenCounter`] (or
//! pass a closure) around a real tokenizer: every helper accepts one.
//!
//! # Features
//!
//! - [`estimate`], [`fits`], [`truncate`], [`chunk`] — the original `⌈chars/4⌉` API
//! - [`TokenCounter`] / [`TokenizerProfile`] — pluggable and per-model counting
//! - [`truncate_with`] — keep the start, the end, or both ends with an ellipsis
//! - [`chunk_with`] — paragraph / sentence / word / grapheme-aware chunks with
//!   overlap, borrowed from the input with byte offsets
//! - [`count_chat`], [`fit_recent_messages`], [`Budget`] — chat-message
//!   overhead and context-window budgeting
//!
//! Every cut lands on a character *and* (approximate) grapheme-cluster
//! boundary, nothing panics on any input, and invalid chunk settings are
//! errors ([`try_chunk`], [`chunk_with`]) rather than infinite loops.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_tokenize::{estimate, fits, truncate, chunk};
//!
//! let text = "The quick brown fox jumps over the lazy dog.";
//!
//! println!("{} tokens", estimate(text)); // ~11
//! assert!(fits(text, 50));
//!
//! let short = truncate(text, 5);
//! assert!(estimate(short) <= 5);
//! ```
//!
//! Model-aware counting and structure-aware chunking:
//!
//! ```rust
//! use rune_tokenize::{chunk_with, truncate_with, ChunkConfig, Truncation, TokenCounter, TokenizerProfile};
//!
//! let p = TokenizerProfile::for_model("gpt-4o").unwrap_or_default();
//! let doc = "Intro paragraph.\n\nA second paragraph. With two sentences.";
//!
//! assert!(p.count_tokens(doc) < 20);
//!
//! let chunks = chunk_with(doc, &ChunkConfig::new(6).overlap(1), &p)?;
//! assert_eq!(chunks[0].text, "Intro paragraph.");
//!
//! let tail = truncate_with(doc, 4, &p, Truncation::KeepEnd);
//! assert!(tail.ends_with("sentences."));
//! # Ok::<(), rune_tokenize::ChunkError>(())
//! ```
//!
//! Split a long document into overlapping chunks for retrieval-augmented generation:
//!
//! ```rust
//! use rune_tokenize::chunk;
//!
//! let doc = "one two three four five six seven eight nine ten";
//! let chunks = chunk(doc, 4, 3); // 4-token chunks, 1-token step
//! assert!(chunks.len() > 1);
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

mod chat;
mod counter;
mod grapheme;
mod split;
mod truncate;

use alloc::string::String;
use alloc::vec::Vec;

pub use chat::{Budget, ChatMessage, ChatOverhead, count_chat, fit_recent_messages};
pub use counter::{ParseProfileError, TokenCounter, TokenizerProfile};
pub use split::{Boundary, Chunk, ChunkConfig, ChunkError, chunk_with};
pub use truncate::{DEFAULT_ELLIPSIS, Truncation, truncate_middle, truncate_with};

/// Approximate number of tokens in `text` (4 UTF-8 characters ≈ 1 token).
///
/// Returns 0 for an empty string. The result is a ceiling so budget comparisons
/// are conservative — you will never undercount.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::estimate;
///
/// assert_eq!(estimate(""), 0);
/// assert_eq!(estimate("hello world"), 3); // 11 chars → ⌈11/4⌉ = 3
/// ```
#[must_use]
pub fn estimate(text: &str) -> usize {
    let chars = text.chars().count();
    chars.div_ceil(4)
}

/// Return `true` if `text` fits within `max_tokens`.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::fits;
///
/// assert!(fits("hello", 2));
/// assert!(!fits("hello world how are you today", 2));
/// ```
#[must_use]
pub fn fits(text: &str, max_tokens: usize) -> bool {
    estimate(text) <= max_tokens
}

/// Return `true` if `text` fits within `max_tokens` according to `counter`.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{fits_with, TokenizerProfile};
///
/// assert!(fits_with("hello world", 2, &TokenizerProfile::Cl100k));
/// assert!(!fits_with("你好世界", 2, &TokenizerProfile::Cl100k));
/// ```
#[must_use]
pub fn fits_with<C: TokenCounter + ?Sized>(text: &str, max_tokens: usize, counter: &C) -> bool {
    counter.count_tokens(text) <= max_tokens
}

/// Truncate `text` to at most `max_tokens` tokens, snapping back to the nearest
/// word boundary so the result is always a clean, readable substring.
///
/// Returns the full string unchanged if it already fits. Returns an empty string
/// if `max_tokens` is 0. If not even one word fits, the first word is cut at a
/// grapheme-cluster boundary. For other counters or strategies see
/// [`truncate_with`].
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{truncate, estimate};
///
/// let text = "The quick brown fox jumps over the lazy dog";
/// let short = truncate(text, 4);
/// assert!(estimate(short) <= 4);
/// // always ends on a complete word
/// assert!(!short.ends_with(' '));
/// ```
#[must_use]
pub fn truncate(text: &str, max_tokens: usize) -> &str {
    if max_tokens == 0 {
        return "";
    }
    if fits(text, max_tokens) {
        return text;
    }
    let max_chars = max_tokens.saturating_mul(4);
    let byte_end = text
        .char_indices()
        .nth(max_chars)
        .map_or(text.len(), |(i, _)| i);
    // Never leave a combining mark, ZWJ sequence or flag half-cut.
    let candidate = &text[..grapheme::floor(text, byte_end)];
    candidate
        .rfind(|c: char| c.is_whitespace())
        .map_or(candidate, |i| text[..i].trim_end())
}

/// Split `text` into overlapping chunks of approximately `chunk_tokens` tokens,
/// advancing `chunk_tokens − overlap_tokens` tokens between chunks.
///
/// Chunks are split on word boundaries, so each chunk is a clean, readable
/// string. Consecutive chunks share `overlap_tokens` worth of content, providing
/// retrieval context that spans chunk edges.
///
/// Chunks are re-joined with single spaces. To keep the original formatting,
/// get byte offsets, or cut at sentence / paragraph boundaries, use
/// [`chunk_with`].
///
/// # Panics
///
/// Panics if `overlap_tokens >= chunk_tokens` or `chunk_tokens == 0`. Use
/// [`try_chunk`] to get an error instead.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::chunk;
///
/// let text = "one two three four five six seven eight nine ten";
/// // step = chunk - overlap = 4 - 3 = 1 token → guaranteed word overlap
/// let chunks = chunk(text, 4, 3);
///
/// assert!(chunks.len() >= 2);
///
/// // consecutive chunks share at least one word
/// let words_0: Vec<&str> = chunks[0].split_whitespace().collect();
/// let words_1: Vec<&str> = chunks[1].split_whitespace().collect();
/// assert!(words_0.iter().any(|w| words_1.contains(w)));
/// ```
#[must_use]
#[allow(
    clippy::panic,
    reason = "documented legacy contract; try_chunk is the non-panicking form"
)]
pub fn chunk(text: &str, chunk_tokens: usize, overlap_tokens: usize) -> Vec<String> {
    match try_chunk(text, chunk_tokens, overlap_tokens) {
        Ok(chunks) => chunks,
        Err(e) => panic!("{e}"),
    }
}

/// Like [`chunk`], but returns a [`ChunkError`] instead of panicking when
/// `chunk_tokens == 0` or `overlap_tokens >= chunk_tokens`.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{try_chunk, ChunkError};
///
/// assert_eq!(try_chunk("a b c", 0, 0), Err(ChunkError::ZeroChunkSize));
/// assert!(try_chunk("a b c", 2, 2).is_err());
/// assert_eq!(try_chunk("a b c", 100, 0), Ok(vec!["a b c".to_string()]));
/// ```
pub fn try_chunk(
    text: &str,
    chunk_tokens: usize,
    overlap_tokens: usize,
) -> Result<Vec<String>, ChunkError> {
    ChunkConfig::new(chunk_tokens)
        .overlap(overlap_tokens)
        .validate()?;

    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return Ok(Vec::new());
    }

    let chunk_chars = chunk_tokens.saturating_mul(4);
    let step_chars = (chunk_tokens - overlap_tokens).saturating_mul(4);

    let mut result: Vec<String> = Vec::new();
    let mut word_start = 0;

    loop {
        let word_end = fill_chunk(&words, word_start, chunk_chars);
        if word_end <= word_start {
            break;
        }

        result.push(words[word_start..word_end].join(" "));

        if word_end >= words.len() {
            break;
        }

        word_start = advance(&words, word_start, word_end, step_chars);
    }

    Ok(result)
}

fn fill_chunk(words: &[&str], start: usize, max_chars: usize) -> usize {
    let mut char_count: usize = 0;
    let mut end = start;
    for (i, word) in words[start..].iter().enumerate() {
        let word_chars = word.chars().count() + usize::from(i > 0);
        if char_count.saturating_add(word_chars) > max_chars && i > 0 {
            break;
        }
        char_count = char_count.saturating_add(word_chars);
        end = start + i + 1;
    }
    end
}

fn advance(words: &[&str], start: usize, end: usize, step_chars: usize) -> usize {
    let mut advanced = 0;
    let mut next = start;
    while next < end && advanced < step_chars {
        let word_chars = words[next].chars().count() + usize::from(next > start);
        advanced += word_chars;
        next += 1;
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_empty() {
        assert_eq!(estimate(""), 0);
    }

    #[test]
    fn estimate_ceiling() {
        assert_eq!(estimate("hello"), 2); // 5 chars → ⌈5/4⌉ = 2
        assert_eq!(estimate("hell"), 1); // 4 chars → ⌈4/4⌉ = 1
        assert_eq!(estimate("hello world"), 3); // 11 chars → ⌈11/4⌉ = 3
    }

    #[test]
    fn fits_under_budget() {
        assert!(fits("hello", 10));
        assert!(fits("", 0));
    }

    #[test]
    fn fits_exactly_at_budget() {
        // "hell" = 4 chars = 1 token
        assert!(fits("hell", 1));
    }

    #[test]
    fn fits_over_budget() {
        assert!(!fits("hello world how are you", 2));
    }

    #[test]
    fn truncate_already_fits() {
        let text = "hi";
        assert_eq!(truncate(text, 100), text);
    }

    #[test]
    fn truncate_zero_budget() {
        assert_eq!(truncate("hello world", 0), "");
    }

    #[test]
    fn truncate_snaps_to_word_boundary() {
        let text = "The quick brown fox";
        let result = truncate(text, 3); // 3 tokens = 12 chars
        assert!(estimate(result) <= 3);
        assert!(!result.ends_with(' '));
        // Should end on a complete word
        assert!(text.starts_with(result));
    }

    #[test]
    fn chunk_no_overlap_covers_full_text() {
        let text = "one two three four five six seven eight";
        let chunks = chunk(text, 4, 0);
        let reconstructed = chunks.join(" ");
        // Every word from the original appears somewhere in the chunks
        for word in text.split_whitespace() {
            assert!(reconstructed.contains(word), "missing word: {word}");
        }
    }

    #[test]
    fn chunk_with_overlap_shares_content() {
        let text = "the quick brown fox jumps over the lazy dog";
        let chunks = chunk(text, 4, 2);
        assert!(chunks.len() >= 2);
        let words_0: Vec<&str> = chunks[0].split_whitespace().collect();
        let words_1: Vec<&str> = chunks[1].split_whitespace().collect();
        assert!(
            words_0.iter().any(|w| words_1.contains(w)),
            "no shared words between chunk 0 and chunk 1: {:?} / {:?}",
            chunks[0],
            chunks[1]
        );
    }

    #[test]
    fn chunk_single_chunk_when_text_is_short() {
        let chunks = chunk("hello world", 100, 0);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "hello world");
    }

    #[test]
    fn chunk_empty_text() {
        assert_eq!(chunk("   ", 10, 0), [] as [String; 0]);
    }

    #[test]
    fn chunk_long_single_word_gets_its_own_chunk() {
        let chunks = chunk("superlongwordthatexceedsbudget next", 1, 0);
        assert_ne!(chunks, [] as [String; 0]);
        assert!(chunks[0].starts_with("superlongword"));
    }
}

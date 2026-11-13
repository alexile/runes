//! Property tests: no panics, UTF-8 / grapheme-safe cuts, budgets respected,
//! full coverage, termination, on arbitrary input.

use proptest::prelude::*;
use rune_tokenize::{
    Boundary, ChatMessage, ChunkConfig, TokenCounter, TokenizerProfile, Truncation, chunk,
    chunk_with, count_chat, estimate, fit_recent_messages, fits, truncate, truncate_with,
    try_chunk,
};

/// Pieces that stress segmentation: combining marks, ZWJ emoji, flags, CR LF,
/// CJK punctuation, Indic, RTL, digits, code.
const PIECES: &[&str] = &[
    "a",
    "word",
    "The",
    "quick",
    " ",
    "  ",
    "\n",
    "\n\n",
    "\r\n",
    "\t",
    ".",
    "!",
    "?",
    "…",
    "\"",
    "e\u{301}",
    "\u{0915}\u{093F}",
    "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
    "\u{1F1EB}\u{1F1F7}",
    "\u{1F1E9}",
    "\u{1F44D}\u{1F3FD}",
    "日本語",
    "。",
    "！",
    "한국어",
    "مرحبا",
    "Привет",
    "12345",
    "fn main() {",
    "}",
    "    ",
    "\u{200D}",
    "\u{301}",
    "\u{FE0F}",
    "\0",
    "ß",
    "İ",
];

fn tricky() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        prop::collection::vec(prop::sample::select(PIECES), 0..60).prop_map(|v| v.concat()),
    ]
}

fn profile() -> impl Strategy<Value = TokenizerProfile> {
    prop::sample::select(TokenizerProfile::ALL.to_vec())
}

fn boundary() -> impl Strategy<Value = Boundary> {
    prop::sample::select(vec![
        Boundary::Grapheme,
        Boundary::Word,
        Boundary::Sentence,
        Boundary::Paragraph,
    ])
}

/// Extend characters used in `PIECES`.
const fn is_extend(c: char) -> bool {
    matches!(
        c,
        '\u{301}' | '\u{200D}' | '\u{FE0F}' | '\u{1F3FD}' | '\u{93F}'
    )
}

/// A cut of `text` at byte `at` is clean: on a char boundary, and either at a
/// word break or not splitting a combining sequence / ZWJ sequence.
fn cut_ok(text: &str, at: usize) -> bool {
    if !text.is_char_boundary(at) {
        return false;
    }
    let (before, after) = text.split_at(at);
    match (before.chars().next_back(), after.chars().next()) {
        (Some(p), Some(n)) => {
            p.is_whitespace()
                || n.is_whitespace()
                || p.is_control()
                || n.is_control()
                || !(is_extend(n) || (p == '\u{200D}' && u32::from(n) >= 0x1F000))
        }
        _ => true,
    }
}

fn non_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn legacy_truncate_is_safe(text in tricky(), max in 0usize..40) {
        let out = truncate(&text, max);
        prop_assert!(text.starts_with(out));
        prop_assert!(fits(out, max));
        prop_assert!(cut_ok(&text, out.len()));
    }

    #[test]
    fn legacy_chunk_covers_all_words(text in tricky(), size in 1usize..30, overlap in 0usize..30) {
        let overlap = overlap % size;
        let chunks = chunk(&text, size, overlap);
        let joined = chunks.join(" ");
        for w in text.split_whitespace() {
            prop_assert!(joined.contains(w));
        }
    }

    #[test]
    fn try_chunk_never_panics(text in tricky(), size in 0usize..10, overlap in 0usize..12) {
        let r = try_chunk(&text, size, overlap);
        prop_assert_eq!(r.is_ok(), size > 0 && overlap < size);
    }

    #[test]
    fn huge_sizes_do_not_overflow(text in tricky()) {
        let chunks = chunk(&text, usize::MAX, usize::MAX - 1);
        prop_assert!(chunks.len() <= 1);
        prop_assert_eq!(truncate(&text, usize::MAX), text.as_str());
    }

    #[test]
    fn profiles_never_panic_and_are_monotone(text in tricky(), p in profile()) {
        let n = p.count_tokens(&text);
        if text.is_empty() {
            prop_assert_eq!(n, 0);
        }
        if n == 0 {
            prop_assert!(text.trim().is_empty());
        }
        // Removing the last char never increases the count.
        let mut shorter = text;
        shorter.pop();
        prop_assert!(p.count_tokens(&shorter) <= n);
    }

    #[test]
    fn simple_profile_is_estimate(text in tricky()) {
        prop_assert_eq!(TokenizerProfile::Simple.count_tokens(&text), estimate(&text));
    }

    #[test]
    fn truncate_with_fits_and_is_clean(text in tricky(), max in 0usize..30, p in profile()) {
        for strategy in [Truncation::KeepStart, Truncation::KeepEnd, Truncation::Middle] {
            let out = truncate_with(&text, max, &p, strategy);
            prop_assert!(p.count_tokens(&out) <= max, "{strategy:?}: {out:?}");
            match strategy {
                Truncation::KeepStart => {
                    prop_assert!(text.starts_with(&*out));
                    prop_assert!(cut_ok(&text, out.len()));
                }
                Truncation::KeepEnd => {
                    prop_assert!(text.ends_with(&*out));
                    prop_assert!(cut_ok(&text, text.len() - out.len()));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn chunk_with_is_complete_and_bounded(
        text in tricky(),
        max in 1usize..25,
        overlap in 0usize..25,
        b in boundary(),
        p in profile(),
    ) {
        let overlap = overlap % max;
        let config = ChunkConfig::new(max).overlap(overlap).boundary(b);
        let chunks = chunk_with(&text, &config, &p).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let mut last_start = None;
        let mut covered = 0usize; // bytes of `text` covered so far
        for c in &chunks {
            prop_assert_eq!(&text[c.start..c.end], c.text);
            prop_assert!(!c.text.is_empty());
            prop_assert_eq!(c.text, c.text.trim());
            prop_assert_eq!(c.tokens, p.count_tokens(c.text));
            // Over budget only for a single grapheme cluster.
            if c.tokens > max {
                // (a lone CR LF is one cluster too)
                prop_assert!(c.text == "\r\n" || !c.text.chars().skip(1).any(char::is_whitespace));
            }
            prop_assert!(cut_ok(&text, c.start) && cut_ok(&text, c.end));
            // Strictly advancing, nothing but whitespace skipped.
            prop_assert!(last_start.is_none_or(|s| c.start > s));
            if c.start > covered {
                prop_assert!(non_ws(&text[covered..c.start]).is_empty());
            }
            covered = covered.max(c.end);
            last_start = Some(c.start);
        }
        prop_assert!(non_ws(&text[covered..]).is_empty());
        if non_ws(&text).is_empty() {
            prop_assert!(chunks.is_empty());
        }
    }

    #[test]
    fn chat_window_fits(
        contents in prop::collection::vec(tricky(), 0..8),
        max in 0usize..120,
        pinned in 0usize..3,
        p in profile(),
    ) {
        let msgs: Vec<ChatMessage<'_>> =
            contents.iter().map(|c| ChatMessage::new("user", c)).collect();
        let overhead = p.chat_overhead();
        if let Some(start) = fit_recent_messages(&msgs, max, pinned, &p, overhead) {
            let pinned = pinned.min(msgs.len());
            prop_assert!(start >= pinned && start <= msgs.len());
            let mut kept = msgs[..pinned].to_vec();
            kept.extend_from_slice(&msgs[start..]);
            prop_assert!(count_chat(&kept, &p, overhead) <= max);
        }
    }
}

#[test]
fn large_inputs_stay_fast() {
    let p = TokenizerProfile::Cl100k;
    let word = "x".repeat(400_000);
    let chunks = chunk_with(&word, &ChunkConfig::new(64), &p).unwrap_or_default();
    assert!(chunks.len() > 100);
    assert!(chunks.iter().all(|c| c.tokens <= 64));

    let prose = "Lorem ipsum dolor sit amet. ".repeat(20_000);
    let config = ChunkConfig::new(256)
        .overlap(32)
        .boundary(Boundary::Sentence);
    let chunks = chunk_with(&prose, &config, &p).unwrap_or_default();
    assert!(chunks.len() > 100);

    let flags = "\u{1F1EB}".repeat(50_001);
    let cut = truncate_with(&flags, 1000, &p, Truncation::KeepStart);
    assert!(p.count_tokens(&cut) <= 1000);
}

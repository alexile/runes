//! Property tests: no splitter panics on any text or any size settings,
//! chunks are verbatim slices with correct offsets, and without overlap they
//! reassemble to the original text.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use proptest::prelude::*;
use rune_chain_splitter::{
    BreakpointThreshold, CharacterSplitter, Chunk, MarkdownSplitter, RecursiveSplitter,
    SemanticChunker, TextSplitter, TokenSplitter, sentence_spans,
};

/// Prose and markdown with the separators the splitters look for.
const PROSE: &str = "([a-zé日 ]{0,12}(\n|\n\n|# |## |```\n|\\. |。|! )){0,20}";

fn text() -> impl Strategy<Value = String> {
    prop_oneof![any::<String>(), PROSE]
}

fn splitters(size: usize, overlap: usize) -> Vec<(&'static str, Box<dyn TextSplitter>)> {
    vec![
        (
            "character",
            Box::new(
                CharacterSplitter::new()
                    .chunk_size(size)
                    .chunk_overlap(overlap),
            ),
        ),
        (
            "character-space",
            Box::new(
                CharacterSplitter::new()
                    .separator(" ")
                    .chunk_size(size)
                    .chunk_overlap(overlap),
            ),
        ),
        (
            "recursive",
            Box::new(
                RecursiveSplitter::new()
                    .chunk_size(size)
                    .chunk_overlap(overlap),
            ),
        ),
        (
            "token",
            Box::new(
                TokenSplitter::new()
                    .chunk_tokens(size)
                    .overlap_tokens(overlap),
            ),
        ),
        (
            "markdown",
            Box::new(MarkdownSplitter::new().max_chunk_size(size)),
        ),
    ]
}

/// Offsets are exact: text matches the byte span, char spans match, indices count up.
fn check_offsets(name: &str, text: &str, chunks: &[Chunk]) -> Result<(), TestCaseError> {
    for (i, c) in chunks.iter().enumerate() {
        prop_assert_eq!(c.index, i, "{}", name);
        prop_assert_eq!(
            text.get(c.byte_range.clone()),
            Some(c.text.as_str()),
            "{}",
            name
        );
        let char_start = text[..c.byte_range.start].chars().count();
        prop_assert_eq!(
            c.char_range.clone(),
            char_start..char_start + c.text.chars().count(),
            "{}",
            name
        );
        prop_assert!(!c.text.is_empty(), "{} produced an empty chunk", name);
    }
    Ok(())
}

proptest! {
    #[test]
    fn recursive_is_lossless_and_char_bounded(text in text(), size in 1usize..48) {
        let chunks = RecursiveSplitter::new().chunk_size(size).chunk_overlap(0).split(&text);
        prop_assert_eq!(chunks.concat(), text);
        for c in &chunks {
            prop_assert!(c.chars().count() <= size, "{c:?} over {size} chars");
        }
    }

    #[test]
    fn recursive_overlap_keeps_chunks_char_bounded(text in text(), size in 1usize..48, overlap in 0usize..64) {
        for c in RecursiveSplitter::new().chunk_size(size).chunk_overlap(overlap).split(&text) {
            prop_assert!(c.chars().count() <= size, "{c:?} over {size} chars");
        }
    }

    #[test]
    fn splitters_never_panic_and_offsets_are_exact(text in text(), size in 0usize..64, overlap in 0usize..80) {
        for (name, s) in splitters(size, overlap) {
            check_offsets(name, &text, &s.chunks(&text))?;
            let valid = s.validate().is_ok();
            prop_assert_eq!(s.try_chunks(&text).is_ok(), valid, "{}", name);
        }
    }

    #[test]
    fn chunks_reassemble_without_overlap(text in text(), size in 0usize..64) {
        for (name, s) in splitters(size, 0) {
            let joined: String = s.split(&text).concat();
            prop_assert_eq!(&joined, &text, "{}", name);
        }
    }

    #[test]
    fn output_size_stays_proportional(text in text(), size in 1usize..32, overlap in 0usize..64) {
        // Even an overlap larger than the chunk must not make chunks snowball.
        for (name, s) in splitters(size, overlap) {
            let total: usize = s.split(&text).iter().map(String::len).sum();
            let bound = (text.len() + 1) * (size + 4) * 4;
            prop_assert!(total <= bound, "{name}: {total} bytes from {}", text.len());
        }
    }

    #[test]
    fn sentence_spans_tile_the_text(text in text()) {
        let spans = sentence_spans(&text);
        let mut pos = 0;
        for s in &spans {
            prop_assert_eq!(s.start, pos);
            prop_assert!(s.end > s.start);
            prop_assert!(text.get(s.clone()).is_some());
            pos = s.end;
        }
        prop_assert_eq!(pos, text.len());
    }

    #[test]
    fn semantic_chunks_reassemble(
        text in text(),
        seed in any::<u64>(),
        which in 0usize..5,
        min in 0usize..20,
        max in prop::option::of(1usize..40),
    ) {
        let spans = sentence_spans(&text);
        // Deterministic pseudo-random 3-d embeddings, sometimes zero vectors.
        let mut state = seed | 1;
        let embeddings: Vec<Vec<f32>> = spans.iter().map(|_| {
            (0..3).map(|_| {
                state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                f32::from(u8::try_from(state % 5).unwrap()) - 2.0
            }).collect()
        }).collect();
        let threshold = [
            BreakpointThreshold::Percentile(90.0),
            BreakpointThreshold::StandardDeviation(1.0),
            BreakpointThreshold::Interquartile(0.5),
            BreakpointThreshold::Gradient(80.0),
            BreakpointThreshold::ChunkCount(3),
        ][which];
        let max = max.map(|m| m.max(min));
        let chunker = SemanticChunker::new().threshold(threshold).min_chunk_chars(min).max_chunk_chars(max);
        let chunks = chunker.chunk_with_embeddings(&text, &spans, &embeddings).unwrap();
        check_offsets("semantic", &text, &chunks)?;
        prop_assert_eq!(chunks.iter().map(|c| c.text.as_str()).collect::<String>(), text);
        if let Some(max) = max {
            prop_assert!(chunks.iter().all(|c| c.text.chars().count() <= max));
        }
    }
}

#[test]
fn empty_text_has_no_chunks() {
    for (name, s) in splitters(16, 4) {
        assert!(s.split("").is_empty(), "{name}");
        assert!(s.chunks("").is_empty(), "{name}");
    }
}

#[test]
fn default_chunks_locates_custom_splitter_output() {
    struct Words;
    impl TextSplitter for Words {
        fn split(&self, text: &str) -> Vec<String> {
            text.split_whitespace().map(String::from).collect()
        }
    }
    let text = "ab ab  ünï ab";
    let chunks = Words.chunks(text);
    let starts: Vec<usize> = chunks.iter().map(|c| c.byte_range.start).collect();
    assert_eq!(starts, [0, 3, 7, 13]);
    assert_eq!(chunks[2].char_range, 7..10);
    assert!(Words.try_chunks(text).is_ok());
}

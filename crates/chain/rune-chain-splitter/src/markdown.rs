use std::ops::Range;

use crate::chunk::{Chunk, chunks_from_ranges};
use crate::error::SplitError;
use crate::recursive::{RecursiveSplitter, split_recursive};
use crate::splitter::TextSplitter;

const DEFAULT_MAX_CHUNK_SIZE: usize = 1000;

/// Metadata key holding the full header path, joined with `" > "`.
pub const HEADER_PATH_KEY: &str = "header_path";

/// Split Markdown at heading boundaries, recording the header path of every chunk.
///
/// Each ATX heading (`#` … `######` followed by a space, up to three spaces
/// of indentation) starts a new section; `#` lines inside fenced code blocks
/// (```` ``` ```` / `~~~`) and `#hashtags` are not headings. A heading that
/// is directly followed by another heading stays with it, so no chunk is a
/// bare heading. Sections longer than `max_chunk_size` characters are split
/// further like [`RecursiveSplitter`] (paragraphs, lines, sentences, words).
///
/// Every chunk from [`chunks`](TextSplitter::chunks) carries the headings
/// that enclose it as metadata: `"h1"` … `"h6"` for each active level, and
/// [`HEADER_PATH_KEY`] (`"header_path"`) with the whole path, e.g.
/// `"Guide > Install > Linux"`. Chunks are verbatim slices of the input and
/// concatenate back to it.
///
/// # Examples
///
/// ```rust
/// use rune_chain_splitter::{TextSplitter, MarkdownSplitter};
///
/// let md = "# Guide\n\nIntro.\n\n## Install\n\nRun it.";
/// let chunks = MarkdownSplitter::new().max_chunk_size(200).chunks(md);
/// assert_eq!(chunks.len(), 2);
/// assert_eq!(chunks[1].metadata["header_path"], "Guide > Install");
/// assert_eq!(chunks[1].metadata["h2"], "Install");
/// ```
#[derive(Debug, Clone)]
pub struct MarkdownSplitter {
    max_chunk_size: usize,
}

impl Default for MarkdownSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkdownSplitter {
    /// Create a splitter with default settings.
    ///
    /// Default: `max_chunk_size = 1000`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::MarkdownSplitter;
    ///
    /// let splitter = MarkdownSplitter::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
        }
    }

    /// Set the maximum character count before a section is further split.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::MarkdownSplitter;
    ///
    /// let splitter = MarkdownSplitter::new().max_chunk_size(500);
    /// ```
    #[must_use]
    pub const fn max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }
}

impl TextSplitter for MarkdownSplitter {
    fn split(&self, text: &str) -> Vec<String> {
        self.chunks(text).into_iter().map(|c| c.text).collect()
    }

    fn chunks(&self, text: &str) -> Vec<Chunk> {
        if text.is_empty() {
            return Vec::new();
        }
        let max = self.max_chunk_size.max(1);
        let separators = RecursiveSplitter::default_separators();
        let mut ranges = Vec::new();
        let mut owners = Vec::new();
        let sections = sections(text);
        for (i, section) in sections.iter().enumerate() {
            let before = ranges.len();
            split_recursive(
                text,
                section.range.clone(),
                &separators,
                max,
                0,
                &mut ranges,
            );
            owners.extend(std::iter::repeat_n(i, ranges.len() - before));
        }
        let mut chunks = chunks_from_ranges(text, &ranges);
        for (chunk, owner) in chunks.iter_mut().zip(owners) {
            let headers = &sections[owner].headers;
            if headers.is_empty() {
                continue;
            }
            for (level, title) in headers {
                chunk.metadata.insert(format!("h{level}"), title.clone());
            }
            let path: Vec<&str> = headers.iter().map(|(_, t)| t.as_str()).collect();
            chunk
                .metadata
                .insert(HEADER_PATH_KEY.to_owned(), path.join(" > "));
        }
        chunks
    }

    fn validate(&self) -> Result<(), SplitError> {
        if self.max_chunk_size == 0 {
            return Err(SplitError::ZeroChunkSize);
        }
        Ok(())
    }
}

struct Section {
    range: Range<usize>,
    /// `(level, title)` of the enclosing headings, outermost first.
    headers: Vec<(usize, String)>,
}

/// Cut `text` into sections that tile it, one per heading (plus any preamble).
fn sections(text: &str) -> Vec<Section> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut start = 0;
    let mut has_body = false;
    let mut fence: Option<(char, usize)> = None;
    let mut pos = 0;

    for line in text.split_inclusive('\n') {
        let line_start = pos;
        pos += line.len();
        if let Some(marker) = fence_marker(line) {
            match fence {
                None => fence = Some(marker),
                Some((c, n)) if marker.0 == c && marker.1 >= n => fence = None,
                Some(_) => {}
            }
            has_body = true;
            continue;
        }
        if fence.is_some() {
            has_body = true;
            continue;
        }
        if let Some((level, title)) = atx_heading(line) {
            if has_body {
                out.push(Section {
                    range: start..line_start,
                    headers: stack.clone(),
                });
                start = line_start;
                has_body = false;
            }
            stack.retain(|(l, _)| *l < level);
            stack.push((level, title));
        } else if !line.trim().is_empty() {
            has_body = true;
        }
    }
    if start < text.len() {
        out.push(Section {
            range: start..text.len(),
            headers: stack,
        });
    }
    out
}

/// `(level, title)` if `line` is an ATX heading.
fn atx_heading(line: &str) -> Option<(usize, String)> {
    let line = line.trim_end_matches(['\n', '\r']);
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let level = rest.len() - rest.trim_start_matches('#').len();
    if !(1..=6).contains(&level) {
        return None;
    }
    let after = &rest[level..];
    if !(after.is_empty() || after.starts_with([' ', '\t'])) {
        return None;
    }
    let mut title = after.trim();
    // Optional closing sequence: ` ##`.
    let without_hashes = title.trim_end_matches('#');
    if without_hashes.is_empty() || without_hashes.ends_with([' ', '\t']) {
        title = without_hashes.trim_end();
    }
    Some((level, title.to_owned()))
}

/// `(char, run length)` if `line` opens or closes a fenced code block.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let c = rest.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = rest.len() - rest.trim_start_matches(c).len();
    (run >= 3).then_some((c, run))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::char_len as chars;

    #[test]
    fn splits_at_heading_boundaries() {
        let md = "# One\n\nFirst.\n\n## Two\n\nSecond.";
        let chunks = MarkdownSplitter::new().max_chunk_size(200).split(md);
        assert_eq!(chunks, ["# One\n\nFirst.\n\n", "## Two\n\nSecond."]);
    }

    #[test]
    fn no_headings_returns_one_chunk() {
        let md = "Just plain text.\n\nNo headings here.";
        let chunks = MarkdownSplitter::new().max_chunk_size(200).chunks(md);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].metadata.is_empty());
    }

    #[test]
    fn oversized_section_is_further_split() {
        let body = "paragraph text\n\n".repeat(40);
        let md = format!("# Title\n\n{body}");
        let chunks = MarkdownSplitter::new().max_chunk_size(100).chunks(&md);
        assert!(chunks.len() > 1);
        for c in &chunks {
            assert!(chars(&c.text) <= 100);
            assert_eq!(c.metadata["header_path"], "Title");
        }
    }

    #[test]
    fn oversized_paragraph_is_bounded() {
        // Regression: sections were re-split on "\n\n" only, so a long
        // paragraph stayed oversized; the size was also measured in bytes.
        let md = format!("# T\n\n{}", "wörd ".repeat(100));
        for c in MarkdownSplitter::new().max_chunk_size(30).split(&md) {
            assert!(chars(&c) <= 30, "{c:?}");
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(MarkdownSplitter::new().split(""), [] as [String; 0]);
    }

    #[test]
    fn header_path_tracks_nesting() {
        let md = "# A\n\na\n\n## B\n\nb\n\n### C\n\nc\n\n## D\n\nd\n\n# E\n\ne";
        let chunks = MarkdownSplitter::new().chunks(md);
        let paths: Vec<&str> = chunks
            .iter()
            .map(|c| c.metadata[HEADER_PATH_KEY].as_str())
            .collect();
        assert_eq!(paths, ["A", "A > B", "A > B > C", "A > D", "E"]);
        assert_eq!(chunks[3].metadata.get("h3"), None);
        assert_eq!(chunks[3].metadata["h2"], "D");
    }

    #[test]
    fn code_fences_and_hashtags_are_not_headings() {
        let md = "# Real\n\n```sh\n# a comment\n```\n\n#hashtag text\n";
        let chunks = MarkdownSplitter::new().chunks(md);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].metadata[HEADER_PATH_KEY], "Real");
    }

    #[test]
    fn consecutive_headings_stay_with_their_body() {
        let md = "# Guide\n## Install\n\nSteps.\n";
        let chunks = MarkdownSplitter::new().chunks(md);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].metadata[HEADER_PATH_KEY], "Guide > Install");
    }

    #[test]
    fn closing_hashes_and_crlf_are_stripped_from_titles() {
        assert_eq!(atx_heading("## Title ##\r\n"), Some((2, "Title".into())));
        assert_eq!(atx_heading("#\n"), Some((1, String::new())));
        assert_eq!(atx_heading("####### seven"), None);
        assert_eq!(atx_heading("    # code"), None);
        assert_eq!(atx_heading("# C#"), Some((1, "C#".into())));
    }

    #[test]
    fn preamble_has_no_header_metadata() {
        let md = "intro\n\n# H\n\nbody";
        let chunks = MarkdownSplitter::new().chunks(md);
        assert_eq!(chunks.len(), 2);
        assert!(!chunks[0].metadata.contains_key(HEADER_PATH_KEY));
        assert_eq!(chunks[1].metadata[HEADER_PATH_KEY], "H");
    }
}

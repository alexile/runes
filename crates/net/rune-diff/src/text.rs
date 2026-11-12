//! Line, word and character diffs of text, and unified diff output.

use std::fmt::{self, Write as _};

use crate::{DiffOp, DiffOptions, EditScript, diff_slices};

/// How text is split into tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Granularity {
    /// Lines, each keeping its `\n` (the last line may lack one).
    #[default]
    Line,
    /// Words: runs of alphanumerics (and `_`), runs of whitespace, and
    /// single other characters. Joining the tokens gives the text back.
    Word,
    /// Unicode scalar values.
    Char,
}

impl Granularity {
    /// Splits `text` into tokens; concatenating them yields `text`.
    #[must_use]
    pub fn tokenize(self, text: &str) -> Vec<&str> {
        match self {
            Self::Line => text.split_inclusive('\n').collect(),
            Self::Word => words(text),
            Self::Char => text
                .char_indices()
                .map(|(i, c)| &text[i..i + c.len_utf8()])
                .collect(),
        }
    }
}

fn words(text: &str) -> Vec<&str> {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Class {
        Word,
        Space,
        Other,
    }
    let class = |c: char| {
        if c.is_alphanumeric() || c == '_' {
            Class::Word
        } else if c.is_whitespace() {
            Class::Space
        } else {
            Class::Other
        }
    };
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev: Option<Class> = None;
    for (i, c) in text.char_indices() {
        let cl = class(c);
        if let Some(p) = prev
            && (p != cl || cl == Class::Other)
        {
            out.push(&text[start..i]);
            start = i;
        }
        prev = Some(cl);
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// What a [`Change`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChangeTag {
    /// In both texts.
    Equal,
    /// Only in the old text.
    Delete,
    /// Only in the new text.
    Insert,
}

/// One token of a [`TextDiff`], tagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change<'a> {
    /// Equal, deleted or inserted.
    pub tag: ChangeTag,
    /// Index in the old tokens (for equal and deleted tokens).
    pub old_index: Option<usize>,
    /// Index in the new tokens (for equal and inserted tokens).
    pub new_index: Option<usize>,
    /// The token text.
    pub value: &'a str,
}

/// The diff of two texts at some [`Granularity`].
///
/// ```
/// use rune_diff::{Granularity, TextDiff};
///
/// let diff = TextDiff::new("a\nb\nc\n", "a\nB\nc\n", Granularity::Line);
/// assert_eq!(diff.unified(1).to_string(), "\
/// @@ -1,3 +1,3 @@
///  a
/// -b
/// +B
///  c
/// ");
/// assert!((diff.ratio() - 2.0 / 3.0).abs() < 1e-9);
/// ```
#[derive(Debug, Clone)]
pub struct TextDiff<'a> {
    old: Vec<&'a str>,
    new: Vec<&'a str>,
    script: EditScript,
}

impl<'a> TextDiff<'a> {
    /// Diffs `old` and `new` with default [`DiffOptions`].
    #[must_use]
    pub fn new(old: &'a str, new: &'a str, granularity: Granularity) -> Self {
        Self::with_options(old, new, granularity, &DiffOptions::default())
    }

    /// Diffs `old` and `new`.
    #[must_use]
    pub fn with_options(
        old: &'a str,
        new: &'a str,
        granularity: Granularity,
        options: &DiffOptions,
    ) -> Self {
        let old = granularity.tokenize(old);
        let new = granularity.tokenize(new);
        let script = diff_slices(&old, &new, options);
        Self { old, new, script }
    }

    /// A diff from tokens and a script computed over them.
    pub(crate) const fn from_parts(
        old: Vec<&'a str>,
        new: Vec<&'a str>,
        script: EditScript,
    ) -> Self {
        Self { old, new, script }
    }

    /// The old tokens.
    #[must_use]
    pub fn old_tokens(&self) -> &[&'a str] {
        &self.old
    }

    /// The new tokens.
    #[must_use]
    pub fn new_tokens(&self) -> &[&'a str] {
        &self.new
    }

    /// The edit script.
    #[must_use]
    pub const fn script(&self) -> &EditScript {
        &self.script
    }

    /// The ops of the edit script.
    #[must_use]
    pub fn ops(&self) -> &[DiffOp] {
        &self.script.ops
    }

    /// Whether the texts are identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.script.is_identity()
    }

    /// Similarity in `[0, 1]`: `2 · equal tokens / all tokens`.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        self.script.ratio(self.old.len(), self.new.len())
    }

    /// Every token, tagged, in order.
    pub fn changes(&self) -> impl Iterator<Item = Change<'a>> + '_ {
        self.script
            .ops
            .iter()
            .flat_map(move |op| self.op_changes(*op))
    }

    fn op_changes(&self, op: DiffOp) -> Vec<Change<'a>> {
        match op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => (0..len)
                .map(|i| Change {
                    tag: ChangeTag::Equal,
                    old_index: Some(old_index + i),
                    new_index: Some(new_index + i),
                    value: self.old[old_index + i],
                })
                .collect(),
            DiffOp::Delete {
                old_index, old_len, ..
            } => (old_index..old_index + old_len)
                .map(|i| Change {
                    tag: ChangeTag::Delete,
                    old_index: Some(i),
                    new_index: None,
                    value: self.old[i],
                })
                .collect(),
            DiffOp::Insert {
                new_index, new_len, ..
            } => (new_index..new_index + new_len)
                .map(|i| Change {
                    tag: ChangeTag::Insert,
                    old_index: None,
                    new_index: Some(i),
                    value: self.new[i],
                })
                .collect(),
        }
    }

    /// Unified-diff hunks with `context` lines around each change; its
    /// `Display` is the body of `diff -u` (no `---`/`+++` header). Meant for
    /// [`Granularity::Line`]; other granularities print one token per line.
    #[must_use]
    pub const fn unified(&self, context: usize) -> Unified<'_, 'a> {
        Unified {
            diff: self,
            context,
            header: None,
        }
    }

    /// Groups ops into hunks: runs of changes with at most `2 * context`
    /// equal tokens between them, plus `context` on each side.
    fn hunks(&self, context: usize) -> Vec<Vec<DiffOp>> {
        let ops = &self.script.ops;
        let mut hunks = Vec::new();
        let mut current: Vec<DiffOp> = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            let DiffOp::Equal {
                old_index,
                new_index,
                len,
            } = *op
            else {
                current.push(*op);
                continue;
            };
            let first = i == 0;
            let last = i + 1 == ops.len();
            if current.is_empty() {
                // Leading context for the next hunk.
                if !last {
                    let take = len.min(context);
                    if take > 0 {
                        current.push(DiffOp::Equal {
                            old_index: old_index + len - take,
                            new_index: new_index + len - take,
                            len: take,
                        });
                    }
                }
                continue;
            }
            if !last && !first && len <= 2 * context {
                current.push(*op);
                continue;
            }
            // Close the hunk with trailing context.
            let take = len.min(context);
            if take > 0 {
                current.push(DiffOp::Equal {
                    old_index,
                    new_index,
                    len: take,
                });
            }
            hunks.push(std::mem::take(&mut current));
            if !last {
                let take = len.min(context);
                if take > 0 {
                    current.push(DiffOp::Equal {
                        old_index: old_index + len - take,
                        new_index: new_index + len - take,
                        len: take,
                    });
                }
            }
        }
        if current.iter().any(|op| !matches!(op, DiffOp::Equal { .. })) {
            hunks.push(current);
        }
        hunks
    }
}

/// Unified diff output; see [`TextDiff::unified`].
#[derive(Debug, Clone, Copy)]
pub struct Unified<'d, 'a> {
    diff: &'d TextDiff<'a>,
    context: usize,
    header: Option<(&'d str, &'d str)>,
}

impl<'d> Unified<'d, '_> {
    /// Adds the `--- old` / `+++ new` file header.
    #[must_use]
    pub const fn with_header(mut self, old: &'d str, new: &'d str) -> Self {
        self.header = Some((old, new));
        self
    }
}

impl fmt::Display for Unified<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hunks = self.diff.hunks(self.context);
        if hunks.is_empty() {
            return Ok(());
        }
        if let Some((old, new)) = self.header {
            writeln!(f, "--- {old}\n+++ {new}")?;
        }
        for hunk in hunks {
            let old_start = hunk.first().map_or(0, |op| op.old_range().start);
            let new_start = hunk.first().map_or(0, |op| op.new_range().start);
            let old_len: usize = hunk.iter().map(|op| op.old_range().len()).sum();
            let new_len: usize = hunk.iter().map(|op| op.new_range().len()).sum();
            writeln!(
                f,
                "@@ -{} +{} @@",
                range(old_start, old_len),
                range(new_start, new_len)
            )?;
            for op in hunk {
                for c in self.diff.op_changes(op) {
                    let sign = match c.tag {
                        ChangeTag::Equal => ' ',
                        ChangeTag::Delete => '-',
                        ChangeTag::Insert => '+',
                    };
                    f.write_char(sign)?;
                    f.write_str(c.value)?;
                    if !c.value.ends_with('\n') {
                        f.write_str("\n\\ No newline at end of file\n")?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// `start,len` in unified-diff form: 1-based, `start` is the line before
/// an empty range, and `,1` is omitted.
fn range(start: usize, len: usize) -> String {
    match len {
        0 => format!("{start},0"),
        1 => format!("{}", start + 1),
        _ => format!("{},{len}", start + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizers_round_trip() {
        let text = "Hello, wörld!  foo_bar=42\r\nnext line\n";
        for g in [Granularity::Line, Granularity::Word, Granularity::Char] {
            assert_eq!(g.tokenize(text).concat(), text);
        }
        assert_eq!(
            Granularity::Word.tokenize("a+b  c"),
            ["a", "+", "b", "  ", "c"]
        );
        assert_eq!(Granularity::Line.tokenize("a\nb"), ["a\n", "b"]);
        assert_eq!(Granularity::Line.tokenize(""), Vec::<&str>::new());
    }

    #[test]
    fn word_diff() {
        let d = TextDiff::new("the quick fox", "the slow fox", Granularity::Word);
        let changed: Vec<_> = d
            .changes()
            .filter(|c| c.tag != ChangeTag::Equal)
            .map(|c| (c.tag, c.value))
            .collect();
        assert_eq!(
            changed,
            [(ChangeTag::Delete, "quick"), (ChangeTag::Insert, "slow")]
        );
    }

    #[test]
    fn unified_matches_gnu_diff() {
        // Expected output produced by `diff -u` (GNU diffutils 3.10).
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n";
        let new = "1\n2\nthree\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n";
        let d = TextDiff::new(old, new, Granularity::Line);
        assert_eq!(
            d.unified(3).with_header("a", "b").to_string(),
            "--- a\n+++ b\n@@ -1,6 +1,6 @@\n 1\n 2\n-3\n+three\n 4\n 5\n 6\n@@ -10,3 +10,4 @@\n 10\n 11\n 12\n+13\n"
        );
        // Close changes merge into one hunk.
        let new = "1\nII\n3\n4\n5\n6\n7\n8\nIX\n10\n11\n12\n";
        let d = TextDiff::new(old, new, Granularity::Line);
        assert_eq!(
            d.unified(3).to_string(),
            "@@ -1,12 +1,12 @@\n 1\n-2\n+II\n 3\n 4\n 5\n 6\n 7\n 8\n-9\n+IX\n 10\n 11\n 12\n"
        );
    }

    #[test]
    fn unified_edge_cases() {
        let d = TextDiff::new("", "a\n", Granularity::Line);
        assert_eq!(d.unified(3).to_string(), "@@ -0,0 +1 @@\n+a\n");
        let d = TextDiff::new("a\n", "", Granularity::Line);
        assert_eq!(d.unified(3).to_string(), "@@ -1 +0,0 @@\n-a\n");
        let d = TextDiff::new("a", "b", Granularity::Line);
        assert_eq!(
            d.unified(0).to_string(),
            "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n"
        );
        assert_eq!(
            TextDiff::new("x\n", "x\n", Granularity::Line)
                .unified(3)
                .to_string(),
            ""
        );
    }
}

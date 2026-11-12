//! Myers' O(ND) difference algorithm, linear-space variant.
//!
//! Eugene W. Myers, "An O(ND) Difference Algorithm and Its Variations",
//! Algorithmica 1(2), 1986, section 4b: the "middle snake" divide and
//! conquer, which needs O(N + M) memory. Common prefixes and suffixes are
//! stripped first. Above [`DiffOptions::max_cost`] edit steps a subproblem
//! is emitted as a plain delete + insert, which keeps the script valid but
//! no longer minimal; [`EditScript::exact`] records whether that happened.

use std::collections::HashMap;
use std::hash::Hash;

/// One run of an edit script, with indices into the old and new sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "op", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DiffOp {
    /// `len` tokens are equal: `old[old_index..][..len] == new[new_index..][..len]`.
    Equal {
        /// Start in the old sequence.
        old_index: usize,
        /// Start in the new sequence.
        new_index: usize,
        /// Number of tokens.
        len: usize,
    },
    /// `old[old_index..][..old_len]` is removed; it sat before `new[new_index]`.
    Delete {
        /// Start in the old sequence.
        old_index: usize,
        /// Number of removed tokens.
        old_len: usize,
        /// Position in the new sequence.
        new_index: usize,
    },
    /// `new[new_index..][..new_len]` is added before `old[old_index]`.
    Insert {
        /// Position in the old sequence.
        old_index: usize,
        /// Start in the new sequence.
        new_index: usize,
        /// Number of added tokens.
        new_len: usize,
    },
}

impl DiffOp {
    /// The old-sequence range this op covers (empty for inserts).
    #[must_use]
    pub const fn old_range(&self) -> std::ops::Range<usize> {
        match *self {
            Self::Equal { old_index, len, .. } => old_index..old_index + len,
            Self::Delete {
                old_index, old_len, ..
            } => old_index..old_index + old_len,
            Self::Insert { old_index, .. } => old_index..old_index,
        }
    }

    /// The new-sequence range this op covers (empty for deletes).
    #[must_use]
    pub const fn new_range(&self) -> std::ops::Range<usize> {
        match *self {
            Self::Equal { new_index, len, .. } => new_index..new_index + len,
            Self::Insert {
                new_index, new_len, ..
            } => new_index..new_index + new_len,
            Self::Delete { new_index, .. } => new_index..new_index,
        }
    }
}

/// Settings for [`diff_slices`] and the text diffs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiffOptions {
    /// Largest number of edit steps searched per subproblem before falling
    /// back to delete + insert. Bounds the worst case at roughly
    /// `O((N + M) · max_cost)` per level for hostile inputs. Default 4096.
    pub max_cost: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self { max_cost: 4096 }
    }
}

impl DiffOptions {
    /// Sets [`max_cost`](Self::max_cost).
    #[must_use]
    pub const fn with_max_cost(mut self, max_cost: usize) -> Self {
        self.max_cost = max_cost;
        self
    }
}

/// The result of a diff: ops in order, covering both sequences exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EditScript {
    /// The ops, in order. Adjacent ops of the same kind are merged, and a
    /// delete always comes before an insert at the same position.
    pub ops: Vec<DiffOp>,
    /// `false` if [`DiffOptions::max_cost`] was hit somewhere, so the script
    /// is valid but may not be minimal.
    pub exact: bool,
}

impl EditScript {
    /// Number of equal tokens.
    #[must_use]
    pub fn matched(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match op {
                DiffOp::Equal { len, .. } => *len,
                _ => 0,
            })
            .sum()
    }

    /// Whether the sequences are equal (no deletes or inserts).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.ops.iter().all(|op| matches!(op, DiffOp::Equal { .. }))
    }

    /// Similarity `2 · matched / (old_len + new_len)` in `[0, 1]`, 1 when both are empty.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "token counts are far below 2^52"
    )]
    pub fn ratio(&self, old_len: usize, new_len: usize) -> f64 {
        let total = old_len + new_len;
        if total == 0 {
            1.0
        } else {
            (2 * self.matched()) as f64 / total as f64
        }
    }
}

/// Diffs two slices with Myers' algorithm. Tokens are interned first, so
/// comparisons in the inner loop are integer compares.
///
/// ```
/// use rune_diff::{DiffOp, DiffOptions, diff_slices};
///
/// let script = diff_slices(&["a", "b", "c"], &["a", "x", "c"], &DiffOptions::default());
/// assert_eq!(script.ops, [
///     DiffOp::Equal { old_index: 0, new_index: 0, len: 1 },
///     DiffOp::Delete { old_index: 1, old_len: 1, new_index: 1 },
///     DiffOp::Insert { old_index: 2, new_index: 1, new_len: 1 },
///     DiffOp::Equal { old_index: 2, new_index: 2, len: 1 },
/// ]);
/// ```
#[must_use]
pub fn diff_slices<T: Eq + Hash>(old: &[T], new: &[T], options: &DiffOptions) -> EditScript {
    let mut ids: HashMap<&T, u32> = HashMap::new();
    let mut intern = |t| {
        let next = u32::try_from(ids.len()).unwrap_or(u32::MAX);
        *ids.entry(t).or_insert(next)
    };
    let a: Vec<u32> = old.iter().map(&mut intern).collect();
    let b: Vec<u32> = new.iter().map(&mut intern).collect();
    let mut state = State {
        a: &a,
        b: &b,
        vf: Vec::new(),
        vb: Vec::new(),
        max_cost: options.max_cost,
        exact: true,
        out: Builder::default(),
    };
    state.conquer(0, a.len(), 0, b.len());
    EditScript {
        ops: state.out.ops,
        exact: state.exact,
    }
}

/// Appends ops, merging adjacent runs of the same kind and ordering a
/// delete before an insert at the same spot.
#[derive(Default)]
struct Builder {
    ops: Vec<DiffOp>,
}

impl Builder {
    fn equal(&mut self, old_index: usize, new_index: usize, len: usize) {
        if len == 0 {
            return;
        }
        if let Some(DiffOp::Equal { len: l, .. }) = self.ops.last_mut() {
            *l += len;
        } else {
            self.ops.push(DiffOp::Equal {
                old_index,
                new_index,
                len,
            });
        }
    }

    fn delete(&mut self, old_index: usize, old_len: usize, new_index: usize) {
        if old_len == 0 {
            return;
        }
        let at = self.ops.len();
        if let Some(DiffOp::Insert {
            old_index: ins_old,
            new_index: ins_new,
            ..
        }) = self.ops.last_mut()
        {
            // Keep deletes before inserts: the delete moves in front of the
            // trailing insert, which now sits after the deleted run.
            *ins_old += old_len;
            let ins_new = *ins_new;
            if at >= 2
                && let DiffOp::Delete { old_len: l, .. } = &mut self.ops[at - 2]
            {
                *l += old_len;
            } else {
                self.ops.insert(
                    at - 1,
                    DiffOp::Delete {
                        old_index,
                        old_len,
                        new_index: ins_new,
                    },
                );
            }
        } else if let Some(DiffOp::Delete { old_len: l, .. }) = self.ops.last_mut() {
            *l += old_len;
        } else {
            self.ops.push(DiffOp::Delete {
                old_index,
                old_len,
                new_index,
            });
        }
    }

    fn insert(&mut self, old_index: usize, new_index: usize, new_len: usize) {
        if new_len == 0 {
            return;
        }
        if let Some(DiffOp::Insert { new_len: l, .. }) = self.ops.last_mut() {
            *l += new_len;
        } else {
            self.ops.push(DiffOp::Insert {
                old_index,
                new_index,
                new_len,
            });
        }
    }
}

struct State<'a> {
    a: &'a [u32],
    b: &'a [u32],
    vf: Vec<usize>,
    vb: Vec<usize>,
    max_cost: usize,
    exact: bool,
    out: Builder,
}

impl State<'_> {
    /// Diffs `a[a_lo..a_hi]` against `b[b_lo..b_hi]`.
    fn conquer(&mut self, mut a_lo: usize, mut a_hi: usize, mut b_lo: usize, mut b_hi: usize) {
        let prefix = common_prefix(&self.a[a_lo..a_hi], &self.b[b_lo..b_hi]);
        self.out.equal(a_lo, b_lo, prefix);
        a_lo += prefix;
        b_lo += prefix;
        let suffix = common_suffix(&self.a[a_lo..a_hi], &self.b[b_lo..b_hi]);
        a_hi -= suffix;
        b_hi -= suffix;

        if a_lo == a_hi {
            self.out.insert(a_lo, b_lo, b_hi - b_lo);
        } else if b_lo == b_hi {
            self.out.delete(a_lo, a_hi - a_lo, b_lo);
        } else if let Some((x, y)) = self.middle_snake(a_lo, a_hi, b_lo, b_hi) {
            self.conquer(a_lo, a_lo + x, b_lo, b_lo + y);
            self.conquer(a_lo + x, a_hi, b_lo + y, b_hi);
        } else {
            self.exact = false;
            self.out.delete(a_lo, a_hi - a_lo, b_lo);
            self.out.insert(a_hi, b_lo, b_hi - b_lo);
        }

        self.out.equal(a_hi, b_hi, suffix);
    }

    /// Finds a point `(x, y)` (relative to the subproblem) on an optimal
    /// edit path that splits it into two strictly smaller subproblems, or
    /// `None` when the edit distance exceeds `max_cost`.
    #[allow(
        clippy::many_single_char_names,
        reason = "a, b, n, m, d, k, x, y follow the paper's notation"
    )]
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "lengths are slice lengths, far below isize::MAX; signs are checked"
    )]
    fn middle_snake(
        &mut self,
        a_lo: usize,
        a_hi: usize,
        b_lo: usize,
        b_hi: usize,
    ) -> Option<(usize, usize)> {
        let a = &self.a[a_lo..a_hi];
        let b = &self.b[b_lo..b_hi];
        let (n, m) = (a.len() as isize, b.len() as isize);
        let delta = n - m;
        let odd = delta & 1 == 1;
        let d_max = ((n + m + 1) / 2).min(self.max_cost as isize);
        // Diagonals k range over [-(d_max+1), d_max+1]; delta shifts the
        // backward diagonals, so leave room for both.
        let offset = d_max + 1 + delta.abs();
        let size = (2 * offset + 1) as usize;
        self.vf.clear();
        self.vf.resize(size, 0);
        self.vb.clear();
        self.vb.resize(size, 0);
        let idx = |k: isize| (k + offset) as usize;

        for d in 0..=d_max {
            // Forward search from the top-left.
            let mut k = -d;
            while k <= d {
                let mut x = if k == -d || (k != d && self.vf[idx(k - 1)] < self.vf[idx(k + 1)]) {
                    self.vf[idx(k + 1)] as isize
                } else {
                    self.vf[idx(k - 1)] as isize + 1
                };
                let y = x - k;
                let (x0, y0) = (x, y);
                if x < n && y < m && y >= 0 {
                    x += common_prefix(&a[x as usize..], &b[y as usize..]) as isize;
                }
                self.vf[idx(k)] = x.max(0) as usize;
                if odd && (k - delta).abs() < d {
                    let back = self.vb[idx(delta - k)] as isize;
                    if x + back >= n {
                        return Some((x0 as usize, y0 as usize));
                    }
                }
                k += 2;
            }
            // Backward search from the bottom-right, in reversed coordinates.
            let mut k = -d;
            while k <= d {
                let mut x = if k == -d || (k != d && self.vb[idx(k - 1)] < self.vb[idx(k + 1)]) {
                    self.vb[idx(k + 1)] as isize
                } else {
                    self.vb[idx(k - 1)] as isize + 1
                };
                let mut y = x - k;
                if x < n && y < m && y >= 0 {
                    let run =
                        common_suffix(&a[..(n - x) as usize], &b[..(m - y) as usize]) as isize;
                    x += run;
                    y += run;
                }
                self.vb[idx(k)] = x.max(0) as usize;
                if !odd && (k - delta).abs() <= d {
                    let fwd = self.vf[idx(delta - k)] as isize;
                    if x + fwd >= n {
                        return Some(((n - x) as usize, (m - y) as usize));
                    }
                }
                k += 2;
            }
        }
        None
    }
}

fn common_prefix(a: &[u32], b: &[u32]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn common_suffix(a: &[u32], b: &[u32]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuilds `new` from `old` and the script, checking every index.
    fn apply<T: Clone + PartialEq + std::fmt::Debug>(
        old: &[T],
        new: &[T],
        s: &EditScript,
    ) -> Vec<T> {
        let (mut oi, mut ni) = (0, 0);
        let mut out = Vec::new();
        for op in &s.ops {
            assert_eq!(op.old_range().start, oi, "{op:?}");
            assert_eq!(op.new_range().start, ni, "{op:?}");
            match *op {
                DiffOp::Equal {
                    old_index,
                    new_index,
                    len,
                } => {
                    assert_eq!(
                        old[old_index..old_index + len],
                        new[new_index..new_index + len]
                    );
                    out.extend_from_slice(&old[old_index..old_index + len]);
                }
                DiffOp::Insert {
                    new_index, new_len, ..
                } => {
                    out.extend_from_slice(&new[new_index..new_index + new_len]);
                }
                DiffOp::Delete { .. } => {}
            }
            oi = op.old_range().end;
            ni = op.new_range().end;
        }
        assert_eq!((oi, ni), (old.len(), new.len()));
        out
    }

    fn lcs_len(a: &[u8], b: &[u8]) -> usize {
        let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in 0..a.len() {
            for j in 0..b.len() {
                dp[i + 1][j + 1] = if a[i] == b[j] {
                    dp[i][j] + 1
                } else {
                    dp[i][j + 1].max(dp[i + 1][j])
                };
            }
        }
        dp[a.len()][b.len()]
    }

    #[test]
    fn classic_example() {
        // Myers' paper: ABCABBA -> CBABAC has edit distance 5 (LCS 4).
        let (a, b) = (b"ABCABBA", b"CBABAC");
        let s = diff_slices(a, b, &DiffOptions::default());
        assert_eq!(apply(a, b, &s), b);
        assert_eq!(s.matched(), 4);
        assert!(s.exact);
    }

    #[test]
    fn edge_cases() {
        let empty: [u8; 0] = [];
        for (a, b) in [
            (&empty[..], &empty[..]),
            (b"abc", &empty[..]),
            (&empty[..], b"abc"),
            (b"abc", b"abc"),
            (b"a", b"b"),
        ] {
            let s = diff_slices(a, b, &DiffOptions::default());
            assert_eq!(apply(a, b, &s), b);
            assert_eq!(s.matched(), lcs_len(a, b));
        }
        assert!(diff_slices(b"same", b"same", &DiffOptions::default()).is_identity());
    }

    #[test]
    fn minimal_on_small_inputs() {
        let words: [&[u8]; 8] = [
            b"", b"a", b"ab", b"ba", b"abcabba", b"cbabac", b"xaxbxcx", b"abcdefg",
        ];
        for a in words {
            for b in words {
                let s = diff_slices(a, b, &DiffOptions::default());
                assert_eq!(apply(a, b, &s), b);
                assert_eq!(s.matched(), lcs_len(a, b), "{a:?} {b:?}");
            }
        }
    }

    #[test]
    fn cost_cap_stays_valid() {
        let a: Vec<u32> = (0..500).collect();
        let b: Vec<u32> = (0..500).rev().collect();
        let s = diff_slices(&a, &b, &DiffOptions::default().with_max_cost(3));
        assert_eq!(apply(&a, &b, &s), b);
        assert!(!s.exact);
    }

    #[test]
    fn ratio() {
        let s = diff_slices(b"abcd", b"abxd", &DiffOptions::default());
        assert!((s.ratio(4, 4) - 0.75).abs() < 1e-9);
        assert!((EditScript::default().ratio(0, 0) - 1.0).abs() < f64::EPSILON);
    }
}

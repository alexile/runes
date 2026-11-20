//! Which keys a query row may see, and tile classification.

/// Saturating `usize -> i64`.
pub fn to_i64(x: usize) -> i64 {
    i64::try_from(x).unwrap_or(i64::MAX)
}

/// Clamp an `i64` into `0..=max` and return it as `usize`.
pub fn clamp_usize(x: i64, max: usize) -> usize {
    usize::try_from(x.max(0)).map_or(max, |v| v.min(max))
}

/// The visible key interval of every query row of one sequence.
///
/// Query `i` sits at key position `i + shift`, `shift = seq_k - seq_q`
/// (bottom-right alignment), and sees keys `j` with
/// `lo <= j < hi`, where `lo = max(key_lo, i + shift - left)` and
/// `hi = min(key_hi, i + shift + right + 1)` (a missing window side is
/// unbounded).
#[derive(Debug, Clone, Copy)]
pub struct RowMask {
    pub shift: i64,
    left: Option<i64>,
    right: Option<i64>,
    key_lo: i64,
    key_hi: i64,
}

/// How a `rows × cols` tile intersects the mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileKind {
    /// Nothing visible: skip the tile.
    Empty,
    /// Everything visible: no per-element masking needed.
    Full,
    /// Mixed: mask element by element.
    Partial,
}

impl RowMask {
    pub fn new(
        seq_q: usize,
        seq_k: usize,
        left: Option<usize>,
        right: Option<usize>,
        keys: (usize, usize),
    ) -> Self {
        Self {
            shift: to_i64(seq_k) - to_i64(seq_q),
            left: left.map(to_i64),
            right: right.map(to_i64),
            key_lo: to_i64(keys.0.min(seq_k)),
            key_hi: to_i64(keys.1.min(seq_k)),
        }
    }

    /// Visible keys `[lo, hi)` of row `i`; empty when `lo >= hi`.
    pub fn row(&self, i: usize) -> (i64, i64) {
        let center = to_i64(i).saturating_add(self.shift);
        let lo = self
            .left
            .map_or(self.key_lo, |w| self.key_lo.max(center.saturating_sub(w)));
        let hi = self.right.map_or(self.key_hi, |w| {
            self.key_hi.min(center.saturating_add(w).saturating_add(1))
        });
        (lo, hi)
    }

    /// Classify the tile of rows `i0..i1` and keys `j0..j1`.
    pub fn tile(&self, i0: usize, i1: usize, j0: usize, j1: usize) -> TileKind {
        let (j0, j1) = (to_i64(j0), to_i64(j1));
        let mut any = false;
        let mut all = true;
        for i in i0..i1 {
            let (lo, hi) = self.row(i);
            let (a, b) = (lo.max(j0), hi.min(j1));
            if a < b {
                any = true;
            }
            if !(lo <= j0 && hi >= j1) {
                all = false;
            }
        }
        match (any, all) {
            (false, _) => TileKind::Empty,
            (true, true) => TileKind::Full,
            (true, false) => TileKind::Partial,
        }
    }
}

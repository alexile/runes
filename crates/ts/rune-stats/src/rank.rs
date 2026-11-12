//! Allocation-free merge walk over two sorted samples, shared by the
//! Mann–Whitney and Kolmogorov–Smirnov tests.

use crate::util::count;

/// What one pass over two sorted samples yields.
#[derive(Debug, Clone, Copy)]
pub struct TwoSampleWalk {
    /// Sum of the (average) ranks of the first sample in the pooled sample.
    pub rank_sum_x: f64,
    /// Tie term `Σ (t³ − t)` over groups of equal values.
    pub tie_term: f64,
    /// `max (i·n − j·m)` over the step points of the two ECDFs, where `i`
    /// and `j` are the counts at or below the current value (at least 0).
    pub max_gap: i128,
    /// `min (i·n − j·m)` over the same points (at most 0).
    pub min_gap: i128,
}

/// Walks the sorted samples `x` (length `m`) and `y` (length `n`) group by
/// group of equal values (by [`f64::total_cmp`]).
///
/// The rank and tie arithmetic deliberately mirrors the straightforward
/// "sort the pooled sample and average tied ranks" algorithm, so results
/// are bit-identical to it.
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
pub fn walk(x: &[f64], y: &[f64]) -> TwoSampleWalk {
    let (m, n) = (x.len(), y.len());
    let (mut i, mut j) = (0usize, 0usize);
    let mut rank_sum_x = 0.0;
    let mut tie_term = 0.0;
    let mut max_gap: i128 = 0;
    let mut min_gap: i128 = 0;
    while i < m || j < n {
        let value = match (x.get(i), y.get(j)) {
            (Some(&a), Some(&b)) => {
                if a.total_cmp(&b).is_le() {
                    a
                } else {
                    b
                }
            }
            (Some(&a), None) => a,
            (None, Some(&b)) => b,
            (None, None) => break,
        };
        let start = i + j;
        let in_x = x[i..]
            .iter()
            .take_while(|v| v.total_cmp(&value).is_eq())
            .count();
        let in_y = y[j..]
            .iter()
            .take_while(|v| v.total_cmp(&value).is_eq())
            .count();
        let end = start + in_x + in_y;
        let average = count(start + end + 1) / 2.0;
        rank_sum_x = count(in_x).mul_add(average, rank_sum_x);
        let tied = count(in_x + in_y);
        tie_term += tied.mul_add(tied * tied, -tied);
        i += in_x;
        j += in_y;
        let gap = (i as i128) * (n as i128) - (j as i128) * (m as i128);
        max_gap = max_gap.max(gap);
        min_gap = min_gap.min(gap);
    }
    TwoSampleWalk {
        rank_sum_x,
        tie_term,
        max_gap,
        min_gap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_and_ties() {
        // Pooled 1,2,2 | 2,3 → ranks 1,3,3 | 3,5; ties: one group of 3.
        let walk = walk(&[1.0, 2.0, 2.0], &[2.0, 3.0]);
        assert_eq!(walk.rank_sum_x, 7.0);
        assert_eq!(walk.tie_term, 24.0);
    }

    #[test]
    fn ecdf_gaps() {
        // x entirely below y: gap climbs to m·n.
        let walk = walk(&[1.0, 2.0], &[3.0, 4.0, 5.0]);
        assert_eq!(walk.max_gap, 6);
        assert_eq!(walk.min_gap, 0);
    }
}

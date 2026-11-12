//! Fan-in merge of N ordered sources into one interleaved, time-ordered stream.
//!
//! Given several sequences that are each already sorted by some key (typically a
//! timestamp), [`multiplex`] interleaves them into a single globally sorted
//! sequence without ever concatenating-then-sorting: it's a k-way merge over a
//! binary heap, `O(n log k)` for `n` total items across `k` sources.
//!
//! # Features
//!
//! - [`multiplex`] — merge `Vec<Vec<T>>` sources into one `Vec<T>`, ordered by a
//!   caller-supplied key function.
//! - Deterministic tie-breaking: when two items from different sources share a key,
//!   the item from the lower-indexed source comes first.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_multiplex::multiplex;
//!
//! let sensor_a = vec![1, 4, 7];
//! let sensor_b = vec![2, 5, 8];
//! let sensor_c = vec![3, 6, 9];
//!
//! let merged = multiplex(vec![sensor_a, sensor_b, sensor_c], |v| *v);
//! assert_eq!(merged, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-multiplex source_a.txt source_b.txt source_c.txt
//! ```

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Merges `sources` — each already sorted ascending by `key` — into one sequence
/// sorted ascending by `key`.
///
/// Items are drawn from a min-heap keyed on `(key(item), source_index)`, so ties
/// between sources are broken by source index: the item from the lower-indexed
/// source is emitted first. Each source is consumed in its original internal
/// order; nothing within a single source is ever reordered.
///
/// # Panics
///
/// Does not panic; malformed (unsorted) input sources simply produce output that
/// is not fully sorted, since correctness depends on each source already being
/// sorted by `key`.
///
/// # Example
///
/// ```rust
/// use rune_multiplex::multiplex;
///
/// let merged = multiplex(vec![vec![10, 20], vec![15]], |v| *v);
/// assert_eq!(merged, vec![10, 15, 20]);
/// ```
pub fn multiplex<T, F>(sources: Vec<Vec<T>>, mut key: F) -> Vec<T>
where
    F: FnMut(&T) -> i64,
{
    let mut iters: Vec<std::iter::Peekable<std::vec::IntoIter<T>>> = sources
        .into_iter()
        .map(|source| source.into_iter().peekable())
        .collect();

    let mut heap: BinaryHeap<Reverse<(i64, usize)>> = BinaryHeap::new();
    for (source_index, iter) in iters.iter_mut().enumerate() {
        if let Some(item) = iter.peek() {
            heap.push(Reverse((key(item), source_index)));
        }
    }

    let mut output = Vec::new();
    while let Some(Reverse((_, source_index))) = heap.pop() {
        // A heap entry is only pushed after a successful peek, so this always yields.
        let Some(item) = iters[source_index].next() else {
            continue;
        };
        output.push(item);

        if let Some(next_item) = iters[source_index].peek() {
            heap.push(Reverse((key(next_item), source_index)));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_three_interleaved_sources() {
        let merged = multiplex(vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]], |v| *v);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn merges_sources_of_different_lengths() {
        let merged = multiplex(vec![vec![1, 2, 3, 4, 5], vec![10]], |v| *v);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 10]);
    }

    #[test]
    fn empty_sources_are_skipped() {
        let merged = multiplex(vec![vec![], vec![1, 2], vec![]], |v| *v);
        assert_eq!(merged, vec![1, 2]);
    }

    #[test]
    fn all_empty_sources_yield_empty_output() {
        let merged: Vec<i64> = multiplex(vec![vec![], vec![]], |v| *v);
        assert_eq!(merged, [] as [i64; 0]);
    }

    #[test]
    fn no_sources_yields_empty_output() {
        let merged: Vec<i64> = multiplex(Vec::new(), |v| *v);
        assert_eq!(merged, [] as [i64; 0]);
    }

    #[test]
    fn single_source_passes_through_unchanged() {
        let merged = multiplex(vec![vec![1, 2, 3]], |v| *v);
        assert_eq!(merged, vec![1, 2, 3]);
    }

    #[test]
    fn ties_break_by_lower_source_index_first() {
        let source_a = vec![(1, "a"), (3, "a2")];
        let source_b = vec![(1, "b"), (3, "b2")];
        let merged = multiplex(vec![source_a, source_b], |item| item.0);
        assert_eq!(
            merged,
            vec![(1, "a"), (1, "b"), (3, "a2"), (3, "b2")],
            "equal keys must resolve source 0 before source 1"
        );
    }

    #[test]
    fn preserves_within_source_order_while_interleaving() {
        // Naive concatenation would yield [1, 3, 5, 2, 4, 6]; a correct merge
        // interleaves across both sources while keeping each source's internal order.
        let merged = multiplex(vec![vec![1, 3, 5], vec![2, 4, 6]], |v| *v);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6]);
    }
}

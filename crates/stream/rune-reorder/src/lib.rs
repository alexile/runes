//! A windowed buffer that reassembles out-of-sequence, sequence-numbered items
//! into ascending order.
//!
//! Network delivery rarely preserves send order. `Reorder` buffers items keyed
//! by an explicit `u64` sequence number and releases them once the run starting
//! at the next expected sequence number is contiguous. If a gap never fills —
//! a genuinely lost item — the buffer doesn't stall forever: once it holds more
//! than `window` entries, it force-advances past the gap and emits whatever run
//! is now contiguous.
//!
//! # Features
//!
//! - [`Reorder::push`] — feed one `(seq, item)` pair, get back the items now
//!   ready to emit in order.
//! - [`Reorder::flush`] — drain everything still buffered, in order, for
//!   stream-end.
//! - Stale duplicates (`seq` below the next expected sequence) are dropped
//!   silently. Duplicates that are still buffered (not yet emitted) follow
//!   last-write-wins: the newer value replaces the older one at that sequence.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_reorder::Reorder;
//!
//! let mut reorder = Reorder::new(4);
//! assert_eq!(reorder.push(1, "b"), Vec::<&str>::new());
//! assert_eq!(reorder.push(0, "a"), vec!["a", "b"]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! printf '1 b\n0 a\n2 c\n' | rune-reorder --window 8
//! ```

use std::collections::BTreeMap;

/// Reassembles sequence-numbered items into ascending order within a bounded window.
pub struct Reorder<T> {
    window: usize,
    next_expected: u64,
    buffer: BTreeMap<u64, T>,
}

impl<T> Reorder<T> {
    /// Creates a new reorder buffer. `window` is the maximum number of items held
    /// behind an unfilled gap before the gap is forced through.
    ///
    /// # Panics
    ///
    /// Panics if `window` is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_reorder::Reorder;
    ///
    /// let reorder = Reorder::<&str>::new(16);
    /// ```
    #[must_use]
    pub fn new(window: usize) -> Self {
        assert!(window > 0, "window must be greater than zero");
        Self {
            window,
            next_expected: 0,
            buffer: BTreeMap::new(),
        }
    }

    /// Feeds one `(seq, item)` pair into the buffer and returns the items now
    /// ready to emit, in ascending sequence order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_reorder::Reorder;
    ///
    /// let mut reorder = Reorder::new(4);
    /// assert_eq!(reorder.push(0, "a"), vec!["a"]);
    /// assert_eq!(reorder.push(2, "c"), Vec::<&str>::new());
    /// assert_eq!(reorder.push(1, "b"), vec!["b", "c"]);
    /// ```
    pub fn push(&mut self, seq: u64, item: T) -> Vec<T> {
        if seq >= self.next_expected {
            self.buffer.insert(seq, item);
        }

        let mut ready = Vec::new();
        self.drain_contiguous(&mut ready);

        if self.buffer.len() > self.window
            && let Some((&lowest, _)) = self.buffer.first_key_value()
        {
            self.next_expected = lowest;
            self.drain_contiguous(&mut ready);
        }

        ready
    }

    /// Emits the contiguous run starting at `next_expected`.
    ///
    /// `next_expected` saturates at `u64::MAX` instead of overflowing once the
    /// last sequence number has been emitted.
    fn drain_contiguous(&mut self, ready: &mut Vec<T>) {
        while let Some(item) = self.buffer.remove(&self.next_expected) {
            ready.push(item);
            if self.next_expected == u64::MAX {
                break;
            }
            self.next_expected += 1;
        }
    }

    /// Drains everything still buffered, in ascending sequence order, regardless
    /// of unfilled gaps. Call this once the source stream has ended.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_reorder::Reorder;
    ///
    /// let mut reorder = Reorder::new(4);
    /// reorder.push(5, "f");
    /// assert_eq!(reorder.flush(), vec!["f"]);
    /// ```
    pub fn flush(&mut self) -> Vec<T> {
        let mut ready = Vec::new();
        while let Some((seq, item)) = self.buffer.pop_first() {
            ready.push(item);
            self.next_expected = seq.saturating_add(1);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_passthrough() {
        let mut reorder = Reorder::new(4);
        assert_eq!(reorder.push(0, "a"), vec!["a"]);
        assert_eq!(reorder.push(1, "b"), vec!["b"]);
        assert_eq!(reorder.push(2, "c"), vec!["c"]);
    }

    #[test]
    fn single_out_of_order_pair_is_corrected() {
        let mut reorder = Reorder::new(4);
        assert_eq!(reorder.push(1, "b"), Vec::<&str>::new());
        assert_eq!(reorder.push(0, "a"), vec!["a", "b"]);
    }

    #[test]
    fn genuine_gap_forces_emission_once_window_overflows() {
        let mut reorder = Reorder::new(2);
        assert_eq!(reorder.push(1, "a"), Vec::<&str>::new());
        assert_eq!(reorder.push(2, "b"), Vec::<&str>::new());
        // seq 0 is presumed lost; buffer now holds 3 entries, past window=2.
        assert_eq!(reorder.push(3, "c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn flush_drains_remaining_items_in_order() {
        let mut reorder = Reorder::new(8);
        assert_eq!(reorder.push(0, "a"), vec!["a"]);
        reorder.push(3, "d");
        reorder.push(2, "c");
        assert_eq!(reorder.flush(), vec!["c", "d"]);
    }

    #[test]
    fn stale_duplicate_below_next_expected_is_dropped() {
        let mut reorder = Reorder::new(4);
        assert_eq!(reorder.push(0, "first"), vec!["first"]);
        assert_eq!(reorder.push(0, "second"), Vec::<&str>::new());
    }

    #[test]
    fn buffered_duplicate_is_last_write_wins() {
        let mut reorder = Reorder::new(4);
        reorder.push(2, "first");
        reorder.push(2, "second");
        assert_eq!(reorder.flush(), vec!["second"]);
    }

    #[test]
    fn empty_flush_returns_empty() {
        let mut reorder = Reorder::<&str>::new(4);
        assert_eq!(reorder.flush(), Vec::<&str>::new());
    }

    #[test]
    #[should_panic(expected = "window must be greater than zero")]
    fn zero_window_panics() {
        let _ = Reorder::<&str>::new(0);
    }

    // ── Ordering / window boundaries ─────────────────────────────────────────

    #[test]
    fn reverse_arrival_within_window_emits_everything_at_once() {
        let mut reorder = Reorder::new(4);
        for seq in (1..=4).rev() {
            assert_eq!(reorder.push(seq, seq), Vec::<u64>::new());
        }
        assert_eq!(reorder.push(0, 0), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn buffer_of_exactly_window_items_does_not_force() {
        let mut reorder = Reorder::new(3);
        assert_eq!(reorder.push(1, 1), Vec::<i32>::new());
        assert_eq!(reorder.push(2, 2), Vec::<i32>::new());
        // Exactly `window` items held: still waiting for 0.
        assert_eq!(reorder.push(3, 3), Vec::<i32>::new());
        // One more overflows the window and forces the gap.
        assert_eq!(reorder.push(4, 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn forced_advance_stops_at_the_next_gap() {
        let mut reorder = Reorder::new(2);
        reorder.push(1, 1);
        reorder.push(3, 3);
        // Buffer {1, 3, 4} overflows; skip to 1, emit 1, then wait at the 2-gap.
        assert_eq!(reorder.push(4, 4), vec![1]);
        assert_eq!(reorder.push(2, 2), vec![2, 3, 4]);
    }

    #[test]
    fn skipped_sequence_arriving_late_is_dropped_as_stale() {
        let mut reorder = Reorder::new(1);
        reorder.push(1, "b");
        assert_eq!(reorder.push(2, "c"), vec!["b", "c"]);
        // 0 was skipped by the forced advance; it is now below next_expected.
        assert_eq!(reorder.push(0, "a"), Vec::<&str>::new());
        assert_eq!(reorder.flush(), Vec::<&str>::new());
    }

    #[test]
    fn flush_then_continue_resumes_after_highest_flushed() {
        let mut reorder = Reorder::new(8);
        reorder.push(5, 5);
        assert_eq!(reorder.flush(), vec![5]);
        assert!(reorder.push(4, 4).is_empty(), "stale after flush");
        assert_eq!(reorder.push(6, 6), vec![6]);
    }

    #[test]
    fn top_of_sequence_space_does_not_overflow() {
        // Regression: `next_expected += 1` overflowed after emitting u64::MAX.
        let mut reorder = Reorder::new(4);
        assert_eq!(reorder.push(u64::MAX, "z"), Vec::<&str>::new());
        assert_eq!(reorder.push(u64::MAX - 1, "y"), Vec::<&str>::new());
        assert_eq!(reorder.flush(), vec!["y", "z"]);

        let mut reorder = Reorder::new(1);
        reorder.push(u64::MAX - 1, "y");
        assert_eq!(reorder.push(u64::MAX, "z"), vec!["y", "z"]);
        assert_eq!(reorder.flush(), Vec::<&str>::new());
    }
}

//! A bounded, synchronous channel with a configurable backpressure policy.
//!
//! `std::sync::mpsc` channels are either unbounded or block forever once full.
//! Real ingest pipelines usually want a third option: when the buffer is full,
//! either drop the oldest buffered item to make room, reject the new item outright,
//! or block the producer until a consumer catches up. This crate wraps a
//! `VecDeque` behind a `Mutex`/`Condvar` pair and picks one of those three
//! behaviors per channel.
//!
//! # Features
//!
//! - [`channel`] — creates a bounded [`Sender`]/[`Receiver`] pair.
//! - [`BackpressurePolicy`] — `DropOldest`, `DropNewest`, or `Block`.
//! - [`PushOutcome`] — reports exactly what happened to a pushed item.
//! - Multi-producer: [`Sender`] is `Clone`. Closes automatically once every
//!   `Sender` is dropped, at which point [`Receiver::recv`] drains the remaining
//!   buffer and then returns `None`.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_bp_channel::{channel, BackpressurePolicy, PushOutcome};
//!
//! let (tx, rx) = channel::<i32>(2, BackpressurePolicy::DropOldest);
//! assert!(matches!(tx.send(1), PushOutcome::Accepted));
//! assert!(matches!(tx.send(2), PushOutcome::Accepted));
//! assert!(matches!(tx.send(3), PushOutcome::DroppedOldest(1)));
//!
//! assert_eq!(rx.recv(), Some(2));
//! assert_eq!(rx.recv(), Some(3));
//! ```
//!
//! # CLI
//!
//! ```bash
//! printf 'a\nb\nc\n' | rune-bp-channel --capacity 2 --policy drop-oldest
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// What a full channel should do with an item pushed past capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Evict the oldest buffered item to make room for the new one.
    DropOldest,
    /// Reject the new item, leaving the buffer untouched.
    DropNewest,
    /// Block the caller until a consumer frees up space.
    Block,
}

/// The result of a [`Sender::send`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome<T> {
    /// The item was buffered immediately; there was room.
    Accepted,
    /// The buffer was full under [`BackpressurePolicy::DropOldest`]; this is the
    /// item that was evicted to make room for the new one.
    DroppedOldest(T),
    /// The buffer was full under [`BackpressurePolicy::DropNewest`]; this is the
    /// item that was rejected (the one just pushed).
    ///
    /// Also returned under [`BackpressurePolicy::Block`] when the buffer is full
    /// and the [`Receiver`] has been dropped, since no consumer can ever make
    /// room.
    DroppedNewest(T),
    /// The buffer was full under [`BackpressurePolicy::Block`]; the caller waited
    /// until a consumer made room, and the item is now buffered.
    BlockedThenAccepted,
}

struct State<T> {
    items: VecDeque<T>,
    senders: usize,
    receiver_alive: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    capacity: usize,
    policy: BackpressurePolicy,
}

/// The sending half of a bounded channel. Cloneable for multiple producers.
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// The receiving half of a bounded channel.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

/// Creates a bounded channel with the given capacity and backpressure policy.
///
/// # Panics
///
/// Panics if `capacity` is zero.
///
/// # Example
///
/// ```rust
/// use rune_bp_channel::{channel, BackpressurePolicy};
///
/// let (tx, rx) = channel::<&str>(4, BackpressurePolicy::Block);
/// tx.send("hello");
/// assert_eq!(rx.recv(), Some("hello"));
/// ```
#[must_use]
pub fn channel<T>(capacity: usize, policy: BackpressurePolicy) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "capacity must be greater than zero");

    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            items: VecDeque::with_capacity(capacity),
            senders: 1,
            receiver_alive: true,
        }),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
        capacity,
        policy,
    });

    (
        Sender {
            shared: Arc::clone(&shared),
        },
        Receiver { shared },
    )
}

impl<T> Sender<T> {
    /// Pushes an item onto the channel, applying the configured backpressure
    /// policy if the buffer is already at capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_bp_channel::{channel, BackpressurePolicy, PushOutcome};
    ///
    /// let (tx, _rx) = channel::<i32>(1, BackpressurePolicy::DropNewest);
    /// assert!(matches!(tx.send(1), PushOutcome::Accepted));
    /// assert!(matches!(tx.send(2), PushOutcome::DroppedNewest(2)));
    /// ```
    pub fn send(&self, item: T) -> PushOutcome<T> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        if state.items.len() < self.shared.capacity {
            state.items.push_back(item);
            drop(state);
            self.shared.not_empty.notify_one();
            return PushOutcome::Accepted;
        }

        match self.shared.policy {
            BackpressurePolicy::DropOldest => {
                // At capacity (always > 0), so `dropped` is always `Some`.
                let dropped = state.items.pop_front();
                state.items.push_back(item);
                drop(state);
                self.shared.not_empty.notify_one();
                dropped.map_or(PushOutcome::Accepted, PushOutcome::DroppedOldest)
            }
            BackpressurePolicy::DropNewest => PushOutcome::DroppedNewest(item),
            BackpressurePolicy::Block => {
                while state.items.len() >= self.shared.capacity {
                    if !state.receiver_alive {
                        // Nobody can drain the buffer: waiting would deadlock.
                        return PushOutcome::DroppedNewest(item);
                    }
                    state = self
                        .shared
                        .not_full
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                state.items.push_back(item);
                drop(state);
                self.shared.not_empty.notify_one();
                PushOutcome::BlockedThenAccepted
            }
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .senders += 1;
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.senders -= 1;
        if state.senders == 0 {
            self.shared.not_empty.notify_all();
        }
    }
}

impl<T> Receiver<T> {
    /// Blocks until an item is available, or returns `None` once the buffer is
    /// empty and every [`Sender`] has been dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_bp_channel::{channel, BackpressurePolicy};
    ///
    /// let (tx, rx) = channel::<i32>(2, BackpressurePolicy::Block);
    /// drop(tx);
    /// assert_eq!(rx.recv(), None);
    /// ```
    #[must_use]
    pub fn recv(&self) -> Option<T> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(item) = state.items.pop_front() {
                self.shared.not_full.notify_one();
                return Some(item);
            }
            if state.senders == 0 {
                return None;
            }
            state = self
                .shared
                .not_empty
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .receiver_alive = false;
        // Wake any producer blocked on a full buffer so it can give up.
        self.shared.not_full.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn drop_oldest_evicts_front_when_full() {
        let (tx, rx) = channel::<i32>(2, BackpressurePolicy::DropOldest);
        assert!(matches!(tx.send(1), PushOutcome::Accepted));
        assert!(matches!(tx.send(2), PushOutcome::Accepted));
        assert!(matches!(tx.send(3), PushOutcome::DroppedOldest(1)));

        assert_eq!(rx.recv(), Some(2));
        assert_eq!(rx.recv(), Some(3));
    }

    #[test]
    fn drop_newest_rejects_when_full() {
        let (tx, rx) = channel::<i32>(2, BackpressurePolicy::DropNewest);
        assert!(matches!(tx.send(1), PushOutcome::Accepted));
        assert!(matches!(tx.send(2), PushOutcome::Accepted));
        assert!(matches!(tx.send(3), PushOutcome::DroppedNewest(3)));

        assert_eq!(rx.recv(), Some(1));
        assert_eq!(rx.recv(), Some(2));
    }

    #[test]
    fn block_policy_unblocks_after_receive() {
        let (tx, rx) = channel::<i32>(1, BackpressurePolicy::Block);
        assert!(matches!(tx.send(1), PushOutcome::Accepted));

        let tx2 = tx;
        let handle = thread::spawn(move || tx2.send(2));

        thread::sleep(Duration::from_millis(20));
        assert_eq!(rx.recv(), Some(1));

        let outcome = handle.join().unwrap();
        assert!(matches!(outcome, PushOutcome::BlockedThenAccepted));
        assert_eq!(rx.recv(), Some(2));
    }

    #[test]
    fn recv_returns_none_after_all_senders_dropped() {
        let (tx, rx) = channel::<i32>(2, BackpressurePolicy::Block);
        drop(tx);
        assert_eq!(rx.recv(), None);
    }

    #[test]
    fn recv_drains_buffer_before_closing() {
        let (tx, rx) = channel::<i32>(2, BackpressurePolicy::Block);
        tx.send(1);
        tx.send(2);
        drop(tx);

        assert_eq!(rx.recv(), Some(1));
        assert_eq!(rx.recv(), Some(2));
        assert_eq!(rx.recv(), None);
    }

    #[test]
    fn fifo_ordering_preserved() {
        let (tx, rx) = channel::<i32>(4, BackpressurePolicy::DropOldest);
        for i in 0..4 {
            tx.send(i);
        }
        for i in 0..4 {
            assert_eq!(rx.recv(), Some(i));
        }
    }

    #[test]
    #[should_panic(expected = "capacity must be greater than zero")]
    fn zero_capacity_panics() {
        let _ = channel::<i32>(0, BackpressurePolicy::Block);
    }

    // ── Per-policy behaviour ─────────────────────────────────────────────────

    use std::sync::mpsc;

    /// Runs `f` on a thread and fails (instead of hanging) if it does not
    /// finish within a generous deadline.
    fn within_deadline<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = done_tx.send(f());
        });
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("operation deadlocked")
    }

    #[test]
    fn drop_oldest_keeps_latest_capacity_items() {
        let (tx, rx) = channel::<i32>(3, BackpressurePolicy::DropOldest);
        let outcomes: Vec<_> = (0..6).map(|i| tx.send(i)).collect();
        assert_eq!(
            outcomes,
            vec![
                PushOutcome::Accepted,
                PushOutcome::Accepted,
                PushOutcome::Accepted,
                PushOutcome::DroppedOldest(0),
                PushOutcome::DroppedOldest(1),
                PushOutcome::DroppedOldest(2),
            ]
        );
        drop(tx);
        assert_eq!(
            std::iter::from_fn(|| rx.recv()).collect::<Vec<_>>(),
            [3, 4, 5]
        );
    }

    #[test]
    fn drop_newest_keeps_first_capacity_items() {
        let (tx, rx) = channel::<i32>(2, BackpressurePolicy::DropNewest);
        let outcomes: Vec<_> = (0..4).map(|i| tx.send(i)).collect();
        assert_eq!(
            outcomes,
            vec![
                PushOutcome::Accepted,
                PushOutcome::Accepted,
                PushOutcome::DroppedNewest(2),
                PushOutcome::DroppedNewest(3),
            ]
        );
        drop(tx);
        assert_eq!(std::iter::from_fn(|| rx.recv()).collect::<Vec<_>>(), [0, 1]);
    }

    #[test]
    fn freed_slot_is_accepted_again_under_every_policy() {
        for policy in [
            BackpressurePolicy::DropOldest,
            BackpressurePolicy::DropNewest,
            BackpressurePolicy::Block,
        ] {
            let (tx, rx) = channel::<i32>(1, policy);
            assert_eq!(tx.send(1), PushOutcome::Accepted);
            assert_eq!(rx.recv(), Some(1));
            assert_eq!(tx.send(2), PushOutcome::Accepted, "{policy:?}");
            assert_eq!(rx.recv(), Some(2));
        }
    }

    #[test]
    fn block_policy_preserves_fifo_under_concurrency() {
        let (tx, rx) = channel::<u32>(2, BackpressurePolicy::Block);
        let producer = thread::spawn(move || {
            (0..2_000)
                .map(|i| tx.send(i))
                .filter(|o| matches!(o, PushOutcome::BlockedThenAccepted))
                .count()
        });
        let got: Vec<u32> = within_deadline(move || std::iter::from_fn(|| rx.recv()).collect());
        let _blocked = producer.join().unwrap();
        assert_eq!(got, (0..2_000).collect::<Vec<_>>());
    }

    #[test]
    fn block_policy_multi_producer_loses_nothing_and_keeps_per_producer_order() {
        let (tx, rx) = channel::<(u8, u32)>(3, BackpressurePolicy::Block);
        let producers: Vec<_> = (0..4u8)
            .map(|p| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for i in 0..500 {
                        assert!(matches!(
                            tx.send((p, i)),
                            PushOutcome::Accepted | PushOutcome::BlockedThenAccepted
                        ));
                    }
                })
            })
            .collect();
        drop(tx);
        let got: Vec<(u8, u32)> =
            within_deadline(move || std::iter::from_fn(|| rx.recv()).collect());
        for p in producers {
            p.join().unwrap();
        }
        assert_eq!(got.len(), 2_000);
        for p in 0..4u8 {
            let seq: Vec<u32> = got.iter().filter(|e| e.0 == p).map(|e| e.1).collect();
            assert_eq!(seq, (0..500).collect::<Vec<_>>());
        }
    }

    #[test]
    fn block_sender_unblocks_when_receiver_dropped() {
        // Regression: with a full buffer and no receiver, `send` waited forever.
        let (tx, rx) = channel::<i32>(1, BackpressurePolicy::Block);
        assert_eq!(tx.send(1), PushOutcome::Accepted);
        let blocked = thread::spawn(move || tx.send(2));
        thread::sleep(Duration::from_millis(20));
        drop(rx);
        let outcome = within_deadline(move || blocked.join().unwrap());
        assert_eq!(outcome, PushOutcome::DroppedNewest(2));
    }

    #[test]
    fn block_send_to_full_channel_without_receiver_returns_immediately() {
        let (tx, rx) = channel::<i32>(1, BackpressurePolicy::Block);
        drop(rx);
        assert_eq!(tx.send(1), PushOutcome::Accepted);
        let outcome = within_deadline(move || tx.send(2));
        assert_eq!(outcome, PushOutcome::DroppedNewest(2));
    }

    #[test]
    fn non_blocking_policies_never_wait_on_full_buffer() {
        for policy in [
            BackpressurePolicy::DropOldest,
            BackpressurePolicy::DropNewest,
        ] {
            let (tx, _rx) = channel::<i32>(1, policy);
            tx.send(0);
            let outcome = within_deadline(move || tx.send(1));
            assert!(!matches!(
                outcome,
                PushOutcome::Accepted | PushOutcome::BlockedThenAccepted
            ));
        }
    }

    #[test]
    fn recv_waits_for_late_sender() {
        let (tx, rx) = channel::<i32>(1, BackpressurePolicy::Block);
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            tx.send(7)
        });
        assert_eq!(within_deadline(move || rx.recv()), Some(7));
        assert_eq!(producer.join().unwrap(), PushOutcome::Accepted);
    }

    #[test]
    fn channel_stays_open_until_last_clone_dropped() {
        let (tx, rx) = channel::<i32>(4, BackpressurePolicy::Block);
        let tx2 = tx.clone();
        drop(tx);
        tx2.send(1);
        assert_eq!(rx.recv(), Some(1));
        let closer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            drop(tx2);
        });
        assert_eq!(within_deadline(move || rx.recv()), None);
        closer.join().unwrap();
    }
}

//! Exact store: a keyed hash table plus a time-ordered index for eviction.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;
use std::time::Duration;

use crate::hash::HashKey;
use crate::time::{Timestamp, within};

/// The accepted times recorded for one key. Almost always a single entry, so
/// that case avoids a heap allocation.
#[derive(Debug, Clone)]
enum Slot<T> {
    One(T, u64),
    /// Sorted, so the occurrences nearest a time are found in `O(log n)`.
    Many(BTreeSet<(T, u64)>),
}

impl<T: Timestamp> Slot<T> {
    fn times(&self) -> impl Iterator<Item = T> + '_ {
        let (one, many) = match self {
            Self::One(t, _) => (Some(*t), None),
            Self::Many(set) => (None, Some(set)),
        };
        one.into_iter()
            .chain(many.into_iter().flatten().map(|&(t, _)| t))
    }

    /// Whether some occurrence is within `window` of `t`. Only the nearest
    /// occurrence on each side can be.
    fn any_within(&self, t: T, window: Duration) -> bool {
        match self {
            Self::One(t0, _) => within(*t0, t, window),
            Self::Many(set) => {
                let before = set.range(..=(t, u64::MAX)).next_back();
                let after = set.range((t, 0)..).next();
                before
                    .into_iter()
                    .chain(after)
                    .any(|&(t0, _)| within(t0, t, window))
            }
        }
    }

    fn push(&mut self, t: T, seq: u64) {
        match self {
            Self::One(t0, s0) => *self = Self::Many(BTreeSet::from([(*t0, *s0), (t, seq)])),
            Self::Many(set) => {
                set.insert((t, seq));
            }
        }
    }

    /// Removes one occurrence; `true` when the slot is now empty.
    fn remove(&mut self, t: T, seq: u64) -> bool {
        match self {
            Self::One(_, s) => *s == seq,
            Self::Many(set) => {
                set.remove(&(t, seq));
                if set.len() == 1
                    && let Some(&(t, s)) = set.first()
                {
                    *self = Self::One(t, s);
                }
                false
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExactStore<K, T> {
    map: HashMap<K, Slot<T>, HashKey>,
    order: BTreeMap<(T, u64), K>,
    next_seq: u64,
}

impl<K: Eq + Hash + Clone, T: Timestamp> ExactStore<K, T> {
    pub const fn new(hash_key: HashKey) -> Self {
        Self {
            map: HashMap::with_hasher(hash_key),
            order: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Number of distinct keys.
    pub fn keys(&self) -> usize {
        self.map.len()
    }

    /// Number of `(key, time)` entries.
    pub fn entries(&self) -> usize {
        self.order.len()
    }

    pub fn times(&self, key: &K) -> impl Iterator<Item = T> + '_ {
        self.map.get(key).into_iter().flat_map(Slot::times)
    }

    /// Whether `key` has an occurrence within `window` of `t`.
    pub fn any_within(&self, key: &K, t: T, window: Duration) -> bool {
        self.map
            .get(key)
            .is_some_and(|slot| slot.any_within(t, window))
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn insert(&mut self, key: K, t: T) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.order.insert((t, seq), key.clone());
        match self.map.get_mut(&key) {
            Some(slot) => slot.push(t, seq),
            None => {
                self.map.insert(key, Slot::One(t, seq));
            }
        }
    }

    pub fn oldest(&self) -> Option<T> {
        self.order.first_key_value().map(|(&(t, _), _)| t)
    }

    pub fn pop_oldest(&mut self) -> Option<(K, T)> {
        let ((t, seq), key) = self.order.pop_first()?;
        if self
            .map
            .get_mut(&key)
            .is_some_and(|slot| slot.remove(t, seq))
        {
            self.map.remove(&key);
        }
        Some((key, t))
    }

    /// Pops entries from the oldest end while `expired(time)` holds. Returns how
    /// many went.
    pub fn pop_while(&mut self, mut expired: impl FnMut(T) -> bool) -> u64 {
        let mut n = 0;
        while self.oldest().is_some_and(&mut expired) {
            self.pop_oldest();
            n += 1;
        }
        n
    }

    /// Pops oldest entries until fewer than `cap` remain, making room for one more.
    pub fn make_room(&mut self, cap: Option<usize>) -> u64 {
        let Some(cap) = cap else { return 0 };
        let mut n = 0;
        while self.order.len() >= cap && self.pop_oldest().is_some() {
            n += 1;
        }
        n
    }

    /// Entries oldest first, the order [`insert`](Self::insert) must replay
    /// them in to rebuild an identical store.
    pub fn to_vec(&self) -> Vec<(K, T)> {
        self.order
            .iter()
            .map(|(&(t, _), k)| (k.clone(), t))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_first_with_ties_in_insertion_order() {
        let mut s = ExactStore::new(HashKey::new(1, 2));
        s.insert("b", 5_i64);
        s.insert("a", 5);
        s.insert("c", 1);
        s.insert("a", 9);
        assert_eq!((s.keys(), s.entries()), (3, 4));
        assert_eq!(s.pop_oldest(), Some(("c", 1)));
        assert_eq!(s.pop_oldest(), Some(("b", 5)));
        assert_eq!(s.pop_oldest(), Some(("a", 5)));
        assert_eq!(s.times(&"a").collect::<Vec<_>>(), vec![9]);
        assert_eq!(s.pop_oldest(), Some(("a", 9)));
        assert!(!s.contains_key(&"a"));
        assert_eq!(s.pop_oldest(), None);
    }

    #[test]
    fn make_room_respects_cap() {
        let mut s = ExactStore::new(HashKey::new(1, 2));
        for i in 0..5_i64 {
            s.insert(i, i);
        }
        assert_eq!(s.make_room(Some(3)), 3);
        assert_eq!(s.entries(), 2);
        assert_eq!(s.make_room(None), 0);
    }
}

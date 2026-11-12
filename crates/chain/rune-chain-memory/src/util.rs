//! Small internal helpers shared by every memory type.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock `m`, recovering the data if a previous holder panicked.
///
/// Every critical section in this crate is a handful of `Vec`/`VecDeque`
/// operations that leave the state consistent at each step, and no user code
/// (token counters, summarizers) ever runs while a lock is held. Recovering
/// from poisoning is therefore sound and keeps one panicking task from turning
/// the memory into a permanent panic source for every other task.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Truncate `s` to at most `max_chars` characters (on a char boundary).
pub fn truncate_chars(s: &mut String, max_chars: usize) {
    if let Some((idx, _)) = s.char_indices().nth(max_chars) {
        s.truncate(idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        let mut s = String::from("héllo");
        truncate_chars(&mut s, 2);
        assert_eq!(s, "hé");
        let mut s = String::from("abc");
        truncate_chars(&mut s, 10);
        assert_eq!(s, "abc");
        truncate_chars(&mut s, 0);
        assert_eq!(s, "");
    }
}

//! Sans-I/O token-budget buffer shared by the budgeted memory types.

use std::collections::VecDeque;

use rune_chain_core::{Message, Role};

/// A stored message with its cached token count.
pub struct Entry {
    pub msg: Message,
    pub tokens: usize,
}

/// Ordered message buffer with an optional pinned system message and a
/// running token total. Pure data structure: no locking, no user callbacks.
#[derive(Default)]
pub struct Buffer {
    pub pinned: Option<Entry>,
    pub turns: VecDeque<Entry>,
    turn_tokens: usize,
    /// Monotonic count of turns ever removed from the front.
    pub evicted: u64,
}

impl Buffer {
    /// Append `msg`; pins it instead if it is the first system message and
    /// pinning is enabled.
    pub fn push(&mut self, pin_system: bool, msg: Message, tokens: usize) {
        if pin_system && self.pinned.is_none() && msg.role == Role::System {
            self.pinned = Some(Entry { msg, tokens });
        } else {
            self.turn_tokens = self.turn_tokens.saturating_add(tokens);
            self.turns.push_back(Entry { msg, tokens });
        }
    }

    /// Tokens held by the pinned message plus all turns.
    pub fn total_tokens(&self) -> usize {
        self.pinned
            .as_ref()
            .map_or(0, |p| p.tokens)
            .saturating_add(self.turn_tokens)
    }

    /// Number of stored messages, pinned one included.
    pub fn len(&self) -> usize {
        self.turns.len() + usize::from(self.pinned.is_some())
    }

    /// Remove the oldest turn.
    pub fn pop_front(&mut self) -> Option<Entry> {
        let e = self.turns.pop_front()?;
        self.turn_tokens = self.turn_tokens.saturating_sub(e.tokens);
        self.evicted = self.evicted.wrapping_add(1);
        Some(e)
    }

    /// Evict the oldest turns until `total + extra <= budget` and
    /// `len <= max_messages`, then drop tool results orphaned by the eviction.
    /// The pinned message is never evicted by the budget, only by a
    /// `max_messages` of zero.
    pub fn trim(&mut self, budget: usize, extra: usize, max_messages: usize) {
        while !self.turns.is_empty()
            && (self.total_tokens().saturating_add(extra) > budget || self.len() > max_messages)
        {
            self.pop_front();
        }
        if max_messages == 0 {
            self.pinned = None;
        }
        self.drop_orphan_tool_results();
    }

    /// Drop leading [`Role::Tool`] turns: once the AI turn that requested
    /// them is gone, providers reject a tool result with no matching call.
    pub fn drop_orphan_tool_results(&mut self) {
        while self.turns.front().is_some_and(|e| e.msg.role == Role::Tool) {
            self.pop_front();
        }
    }

    /// Number of leading turns that must go so the remainder fits in
    /// `budget` (given `extra` tokens held elsewhere), extended so no tool
    /// result is left at the front without its call. At least 1 when
    /// non-empty.
    pub fn overflow_prefix(&self, budget: usize, extra: usize) -> usize {
        let mut total = self.total_tokens().saturating_add(extra);
        let mut k = 0;
        for e in &self.turns {
            if total <= budget && k > 0 {
                break;
            }
            total = total.saturating_sub(e.tokens);
            k += 1;
        }
        while self.turns.get(k).is_some_and(|e| e.msg.role == Role::Tool) {
            k += 1;
        }
        k
    }

    /// Clone the visible messages, pinned one first.
    pub fn messages(&self) -> Vec<Message> {
        self.pinned
            .iter()
            .chain(self.turns.iter())
            .map(|e| e.msg.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(tokens: &[(Role, usize)]) -> Buffer {
        let mut b = Buffer::default();
        for (role, t) in tokens {
            b.push(true, Message::new(role.clone(), "x"), *t);
        }
        b
    }

    #[test]
    fn trim_keeps_pinned_and_drops_orphans() {
        let mut b = buf(&[
            (Role::System, 5),
            (Role::Ai, 1),
            (Role::Tool, 1),
            (Role::Human, 1),
        ]);
        assert_eq!(b.total_tokens(), 8);
        b.trim(7, 0, usize::MAX);
        // Ai evicted -> Tool orphaned -> dropped too.
        assert_eq!(b.len(), 2);
        assert_eq!(b.total_tokens(), 6);
        assert_eq!(b.evicted, 2);
    }

    #[test]
    fn overflow_prefix_counts_minimum_and_skips_tool_results() {
        let b = buf(&[
            (Role::Human, 3),
            (Role::Ai, 3),
            (Role::Tool, 3),
            (Role::Human, 3),
        ]);
        assert_eq!(b.overflow_prefix(100, 0), 1);
        assert_eq!(b.overflow_prefix(9, 0), 1);
        assert_eq!(b.overflow_prefix(6, 0), 3);
        assert_eq!(b.overflow_prefix(0, 0), 4);
    }
}

//! Bounded window of recent messages with an optional pinned system prompt,
//! shared by the retrieval-based memories.

use std::collections::VecDeque;

use rune_chain_core::{Message, Role};

/// The last `max` messages, each tagged with the exchange it belongs to.
#[derive(Default)]
pub struct Recent {
    pub pinned: Option<Message>,
    pub turns: VecDeque<(u64, Message)>,
}

impl Recent {
    /// Append `msg` (or pin it, if it is the first system message and pinning
    /// is on), then drop the oldest turns beyond `max` and any tool results
    /// left at the front without their call.
    pub fn push(&mut self, pin_system: bool, max: usize, tag: u64, msg: Message) {
        if pin_system && self.pinned.is_none() && msg.role == Role::System {
            self.pinned = Some(msg);
            return;
        }
        self.turns.push_back((tag, msg));
        while self.turns.len() > max {
            self.turns.pop_front();
        }
        while self
            .turns
            .front()
            .is_some_and(|(_, m)| m.role == Role::Tool)
        {
            self.turns.pop_front();
        }
    }

    /// Pinned message, then `context`, then the window.
    pub fn render(&self, context: Option<Message>) -> Vec<Message> {
        let mut out = Vec::with_capacity(self.turns.len() + 2);
        out.extend(self.pinned.iter().cloned());
        out.extend(context);
        out.extend(self.turns.iter().map(|(_, m)| m.clone()));
        out
    }

    /// Number of stored messages, pinned one included.
    pub fn len(&self) -> usize {
        self.turns.len() + usize::from(self.pinned.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_pins_system_and_drops_orphans() {
        let mut r = Recent::default();
        r.push(true, 2, 0, Message::system("s"));
        r.push(true, 2, 1, Message::ai("call"));
        r.push(true, 2, 1, Message::tool_result("1", "res"));
        r.push(true, 2, 2, Message::human("next"));
        // "call" slid out, leaving its tool result orphaned at the front.
        let texts: Vec<_> = r.render(None).iter().map(Message::text).collect();
        assert_eq!(texts, ["s", "next"]);
        assert_eq!(r.len(), 2);
        let ctx = r.render(Some(Message::human("ctx")));
        assert_eq!(ctx[1].text(), "ctx");
    }

    #[test]
    fn zero_window_keeps_only_pinned() {
        let mut r = Recent::default();
        r.push(false, 0, 0, Message::system("s"));
        r.push(false, 0, 0, Message::human("h"));
        assert_eq!(r.len(), 0);
    }
}

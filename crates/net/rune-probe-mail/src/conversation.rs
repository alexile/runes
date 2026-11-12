//! The reply buffer both probes share.

use rune_service_probe::Action;

use crate::{Reply, parse_reply};

/// Buffers server bytes and hands out whole replies.
#[derive(Debug, Default)]
pub struct Conversation {
    buf: Vec<u8>,
    /// Whether any byte arrived.
    pub received: bool,
    /// Why the conversation stopped early, if it did.
    pub problem: Option<String>,
}

impl Conversation {
    /// Feed bytes, then call `handle` for each whole reply until it
    /// returns an action. `Receive` while a reply is incomplete; `Done`
    /// (with [`Conversation::problem`] set) on a malformed reply.
    pub fn feed(&mut self, data: &[u8], mut handle: impl FnMut(Reply) -> Option<Action>) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        loop {
            match parse_reply(&self.buf) {
                Ok(None) => return Action::Receive,
                Ok(Some((reply, used))) => {
                    self.buf.drain(..used);
                    if let Some(action) = handle(reply) {
                        return action;
                    }
                }
                Err(e) => {
                    self.problem = Some(e.to_string());
                    return Action::Done;
                }
            }
        }
    }
}

/// A command line: the verb, an optional argument, CR LF.
pub fn command(verb: &str, arg: Option<&str>) -> Action {
    let line = arg.map_or_else(|| format!("{verb}\r\n"), |a| format!("{verb} {a}\r\n"));
    Action::Send(line.into_bytes())
}

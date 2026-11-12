//! The values a [`Parser`](crate::Parser) produces.

use std::time::Duration;

/// The event type used when a stream does not name one.
pub const DEFAULT_EVENT_TYPE: &str = "message";

/// One dispatched server-sent event.
///
/// Mirrors the `MessageEvent` an `EventSource` fires: `type`, `data` and
/// `lastEventId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Event {
    /// The event type: the last `event` field of the event, or `"message"`.
    pub event: String,
    /// The `data` fields of the event joined with `\n`.
    pub data: String,
    /// The last event ID at dispatch time. The ID persists across events
    /// until an `id` field changes it, and is empty if none was ever set.
    pub id: String,
}

impl Event {
    /// Creates a `"message"` event with `data` and no ID.
    #[must_use]
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: DEFAULT_EVENT_TYPE.to_owned(),
            data: data.into(),
            id: String::new(),
        }
    }

    /// Sets [`Event::event`].
    #[must_use]
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = event.into();
        self
    }

    /// Sets [`Event::id`].
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }
}

/// Something the [`Parser`](crate::Parser) found in the stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Item {
    /// A complete event, terminated by a blank line.
    Event(Event),
    /// A valid `retry` field: the client's new reconnection time.
    Retry(Duration),
    /// A comment line (one starting with `:`), without the colon. Only
    /// reported when [`Options::comments`](crate::Options::comments) is set.
    Comment(String),
}

impl Item {
    /// Returns the event, if this item is one.
    #[must_use]
    pub fn into_event(self) -> Option<Event> {
        match self {
            Self::Event(event) => Some(event),
            _ => None,
        }
    }
}

//! The sans-I/O event-stream parser.

use std::collections::VecDeque;
use std::time::Duration;

use crate::event::DEFAULT_EVENT_TYPE;
use crate::{Error, Event, Item};

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Default for [`Options::max_id_len`].
pub const DEFAULT_MAX_ID_LEN: usize = 1024;

/// Settings for a [`Parser`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Longest line, in bytes and without its line ending, the parser
    /// buffers. A longer line raises [`Error::LineTooLong`]. Default 8 MiB.
    pub max_line_len: usize,
    /// Largest data buffer, in bytes, of one event. A larger event raises
    /// [`Error::EventTooLarge`]. Default 16 MiB.
    pub max_event_len: usize,
    /// Longest `id` value, in bytes, the parser accepts. The last event id
    /// is copied into every event that follows, so a long one would
    /// multiply memory; an `id` field over this limit is ignored, like one
    /// containing NUL. Default [`DEFAULT_MAX_ID_LEN`] (1 KiB).
    pub max_id_len: usize,
    /// Whether comment lines are reported as [`Item::Comment`]. Default
    /// `false`: comments (typically keep-alives) are dropped.
    pub comments: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_line_len: 8 << 20,
            max_event_len: 16 << 20,
            max_id_len: DEFAULT_MAX_ID_LEN,
            comments: false,
        }
    }
}

impl Options {
    /// Sets [`Options::max_id_len`].
    ///
    /// ```
    /// use rune_sse::{Options, Parser};
    ///
    /// let mut parser = Parser::with_options(Options::default().with_max_id_len(4));
    /// parser.push(b"id: 1234\ndata: a\n\nid: 12345\ndata: b\n\n");
    /// assert_eq!(parser.next_event().unwrap()?.id, "1234");
    /// assert_eq!(parser.next_event().unwrap()?.id, "1234");
    /// # Ok::<(), rune_sse::Error>(())
    /// ```
    #[must_use]
    pub const fn with_max_id_len(mut self, max_id_len: usize) -> Self {
        self.max_id_len = max_id_len;
        self
    }

    /// Sets [`Options::max_line_len`].
    #[must_use]
    pub const fn with_max_line_len(mut self, max_line_len: usize) -> Self {
        self.max_line_len = max_line_len;
        self
    }

    /// Sets [`Options::max_event_len`].
    #[must_use]
    pub const fn with_max_event_len(mut self, max_event_len: usize) -> Self {
        self.max_event_len = max_event_len;
        self
    }

    /// Sets [`Options::comments`].
    #[must_use]
    pub const fn with_comments(mut self, comments: bool) -> Self {
        self.comments = comments;
        self
    }
}

/// An incremental `text/event-stream` parser.
///
/// Feed it bytes with [`push`](Self::push) in chunks of any size and pull
/// what it found with [`next_item`](Self::next_item),
/// [`next_event`](Self::next_event) or [`items`](Self::items). Call
/// [`finish`](Self::finish) when the stream ends: an unterminated event is
/// then discarded, as the specification requires, and the parser is ready
/// for the next connection, keeping [`last_event_id`](Self::last_event_id).
///
/// Errors (over-long lines or events) are reported in sequence with the
/// items and are not fatal: the offending event is skipped and parsing
/// resumes after the next blank line.
#[derive(Debug, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent flags of the line scanner state machine"
)]
pub struct Parser {
    options: Options,
    /// Bytes of the current, incomplete line.
    line: Vec<u8>,
    /// The previous chunk ended with CR: a leading LF belongs to it.
    skip_lf: bool,
    /// No line has been processed yet on this stream (BOM not yet checked).
    at_start: bool,
    /// The current line overflowed and is dropped up to its end.
    discard_line: bool,
    /// The current event overflowed and is dropped up to the blank line.
    discard_event: bool,
    event_type: String,
    data: String,
    last_event_id: String,
    ready: VecDeque<Result<Item, Error>>,
}

impl Parser {
    /// Creates a parser with default [`Options`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(Options::default())
    }

    /// Creates a parser with `options`.
    #[must_use]
    pub fn with_options(options: Options) -> Self {
        Self {
            options,
            at_start: true,
            ..Self::default()
        }
    }

    /// The options this parser was created with.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// The last event ID seen so far: what a client sends back in the
    /// `Last-Event-ID` header when it reconnects.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        &self.last_event_id
    }

    /// Sets the last event ID, for example when resuming from a stored ID.
    pub fn set_last_event_id(&mut self, id: impl Into<String>) {
        self.last_event_id = id.into();
    }

    /// Feeds the next chunk of the stream. Chunks may split lines, line
    /// endings and UTF-8 sequences anywhere.
    pub fn push(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.skip_lf {
                self.skip_lf = false;
                if let Some((b'\n', rest)) = input.split_first() {
                    input = rest;
                    continue;
                }
            }
            let Some(end) = input.iter().position(|&b| b == b'\n' || b == b'\r') else {
                self.extend_line(input);
                break;
            };
            let (head, rest) = input.split_at(end);
            // `rest` starts with the CR or LF that `position` found.
            self.skip_lf = rest.first() == Some(&b'\r');
            input = rest.get(1..).unwrap_or_default();
            self.end_line(head);
        }
    }

    /// Marks the end of the stream.
    ///
    /// An incomplete line and an event without its terminating blank line
    /// are discarded. The parser is then reset for a new stream (a
    /// reconnection), keeping the last event ID and any items not yet
    /// pulled.
    pub fn finish(&mut self) {
        self.line.clear();
        self.skip_lf = false;
        self.at_start = true;
        self.discard_line = false;
        self.discard_event = false;
        self.event_type.clear();
        self.data.clear();
    }

    /// Returns the next item found in the stream, or `None` until more input
    /// is pushed.
    pub fn next_item(&mut self) -> Option<Result<Item, Error>> {
        self.ready.pop_front()
    }

    /// Returns the next event, skipping [`Item::Retry`] and
    /// [`Item::Comment`]. Errors are still returned.
    pub fn next_event(&mut self) -> Option<Result<Event, Error>> {
        while let Some(next) = self.ready.pop_front() {
            match next {
                Ok(Item::Event(event)) => return Some(Ok(event)),
                Ok(_) => {}
                Err(err) => return Some(Err(err)),
            }
        }
        None
    }

    /// Drains the items found so far.
    pub fn items(&mut self) -> impl Iterator<Item = Result<Item, Error>> + '_ {
        self.ready.drain(..)
    }

    /// Appends bytes of a line whose end has not arrived yet.
    fn extend_line(&mut self, bytes: &[u8]) {
        if self.discard_line {
            return;
        }
        if self.line.len().saturating_add(bytes.len()) > self.options.max_line_len {
            self.line_overflow();
        } else {
            self.line.extend_from_slice(bytes);
        }
    }

    /// Completes the current line with `tail` and processes it.
    fn end_line(&mut self, tail: &[u8]) {
        if self.discard_line {
            self.discard_line = false;
            return;
        }
        if self.line.is_empty() {
            if tail.len() > self.options.max_line_len {
                self.line_overflow();
                self.discard_line = false;
            } else {
                self.process_line(tail);
            }
            return;
        }
        self.extend_line(tail);
        if self.discard_line {
            self.discard_line = false;
            return;
        }
        let mut line = std::mem::take(&mut self.line);
        self.process_line(&line);
        line.clear();
        self.line = line;
    }

    fn line_overflow(&mut self) {
        self.ready.push_back(Err(Error::LineTooLong {
            limit: self.options.max_line_len,
        }));
        self.line.clear();
        self.discard_line = true;
        self.at_start = false;
        self.drop_event();
    }

    /// Discards the event being built, up to its terminating blank line.
    fn drop_event(&mut self) {
        self.discard_event = true;
        self.data.clear();
        self.event_type.clear();
    }

    fn process_line(&mut self, mut line: &[u8]) {
        if self.at_start {
            self.at_start = false;
            line = line.strip_prefix(BOM).unwrap_or(line);
        }
        if line.is_empty() {
            self.dispatch();
            return;
        }
        if self.discard_event {
            return;
        }
        let line = String::from_utf8_lossy(line);
        if let Some(comment) = line.strip_prefix(':') {
            if self.options.comments {
                self.ready.push_back(Ok(Item::Comment(comment.to_owned())));
            }
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*line, ""),
        };
        self.process_field(field, value);
    }

    fn process_field(&mut self, field: &str, value: &str) {
        match field {
            "event" => value.clone_into(&mut self.event_type),
            "data" => {
                let len = self
                    .data
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(1);
                if len > self.options.max_event_len {
                    self.ready.push_back(Err(Error::EventTooLarge {
                        limit: self.options.max_event_len,
                    }));
                    self.drop_event();
                } else {
                    self.data.push_str(value);
                    self.data.push('\n');
                }
            }
            "id" if value.len() <= self.options.max_id_len && !value.contains('\0') => {
                value.clone_into(&mut self.last_event_id);
            }
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                // A value too large for u64 is ignored, like any invalid one.
                if let Ok(millis) = value.parse::<u64>() {
                    self.ready
                        .push_back(Ok(Item::Retry(Duration::from_millis(millis))));
                }
            }
            _ => {}
        }
    }

    fn dispatch(&mut self) {
        if self.discard_event {
            self.discard_event = false;
            return;
        }
        if self.data.is_empty() {
            self.event_type.clear();
            return;
        }
        self.data.pop();
        let event = if self.event_type.is_empty() {
            DEFAULT_EVENT_TYPE.to_owned()
        } else {
            std::mem::take(&mut self.event_type)
        };
        self.ready.push_back(Ok(Item::Event(Event {
            event,
            data: std::mem::take(&mut self.data),
            id: self.last_event_id.clone(),
        })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(parser: &mut Parser) -> Vec<Event> {
        std::iter::from_fn(|| parser.next_event())
            .map(Result::unwrap)
            .collect()
    }

    fn parse(input: &str) -> Vec<Event> {
        let mut parser = Parser::new();
        parser.push(input.as_bytes());
        events(&mut parser)
    }

    fn ev(event: &str, data: &str, id: &str) -> Event {
        Event::new(data).with_event(event).with_id(id)
    }

    #[test]
    fn a_long_id_is_not_copied_into_every_event() {
        // One 64 KiB id followed by a thousand 6-byte events: every event
        // carries the id, so a long one must not multiply memory.
        let mut input = format!("id: {}\n", "x".repeat(64 << 10)).into_bytes();
        input.extend("data\n\n".repeat(1000).bytes());
        let mut parser = Parser::new();
        parser.push(&input);
        let parsed = events(&mut parser);
        assert_eq!(parsed.len(), 1000);
        let id_bytes: usize = parsed.iter().map(|event| event.id.len()).sum();
        assert!(
            id_bytes <= 1000 * DEFAULT_MAX_ID_LEN,
            "{id_bytes} bytes of ids"
        );
        assert_eq!(parser.last_event_id(), "");
        // Ids up to the limit are kept.
        let mut parser = Parser::new();
        let id = "y".repeat(DEFAULT_MAX_ID_LEN);
        parser.push(format!("id: {id}\ndata\n\n").as_bytes());
        assert_eq!(events(&mut parser)[0].id, id);
    }

    #[test]
    fn simple_message() {
        assert_eq!(parse("data: hello\n\n"), vec![Event::new("hello")]);
    }

    #[test]
    fn multiline_data_joined_with_lf() {
        assert_eq!(
            parse("data: YHOO\ndata: +2\ndata: 10\n\n"),
            vec![Event::new("YHOO\n+2\n10")]
        );
    }

    #[test]
    fn crlf_and_cr_line_endings() {
        let expected = vec![Event::new("a\nb"), Event::new("c")];
        assert_eq!(parse("data: a\r\ndata: b\r\n\r\ndata: c\r\n\r\n"), expected);
        assert_eq!(parse("data: a\rdata: b\r\rdata: c\r\r"), expected);
        assert_eq!(parse("data: a\r\ndata: b\r\rdata: c\n\r\n"), expected);
    }

    #[test]
    fn crlf_split_across_chunks_is_one_line_ending() {
        let mut parser = Parser::new();
        parser.push(b"data: a\r");
        parser.push(b"\ndata: b\r");
        parser.push(b"\n\r");
        parser.push(b"\n");
        assert_eq!(events(&mut parser), vec![Event::new("a\nb")]);
    }

    #[test]
    fn utf8_split_across_chunks() {
        let input = "data: héllo → 世界\n\n".as_bytes();
        let mut parser = Parser::new();
        for byte in input {
            parser.push(std::slice::from_ref(byte));
        }
        assert_eq!(events(&mut parser), vec![Event::new("héllo → 世界")]);
    }

    #[test]
    fn invalid_utf8_becomes_replacement_character() {
        let mut parser = Parser::new();
        parser.push(b"data: a\xFFb\n\n");
        assert_eq!(events(&mut parser), vec![Event::new("a\u{FFFD}b")]);
    }

    #[test]
    fn bom_stripped_once_even_when_split() {
        let mut parser = Parser::new();
        parser.push(b"\xEF");
        parser.push(b"\xBB\xBFdata: x\n\n\xEF\xBB\xBFdata: y\n\n");
        // The second BOM is part of an unknown field name and is ignored.
        assert_eq!(events(&mut parser), vec![Event::new("x")]);
    }

    #[test]
    fn field_without_colon_and_without_space() {
        // "data" alone appends an empty line; "data:x" has no space to strip.
        assert_eq!(parse("data\ndata:x\n\n"), vec![Event::new("\nx")]);
        // Only one leading space is stripped.
        assert_eq!(parse("data:  x\n\n"), vec![Event::new(" x")]);
    }

    #[test]
    fn empty_data_field_dispatches_empty_event() {
        assert_eq!(parse("data\n\n"), vec![Event::new("")]);
        assert_eq!(parse("data:\n\n"), vec![Event::new("")]);
    }

    #[test]
    fn event_without_data_is_not_dispatched() {
        assert_eq!(parse("event: ping\n\ndata: x\n\n"), vec![Event::new("x")]);
        assert_eq!(parse("id: 1\n\n"), vec![]);
    }

    #[test]
    fn event_type_resets_but_id_persists() {
        assert_eq!(
            parse("event: add\nid: 1\ndata: a\n\ndata: b\n\nid\ndata: c\n\n"),
            vec![
                ev("add", "a", "1"),
                ev("message", "b", "1"),
                ev("message", "c", "")
            ]
        );
    }

    #[test]
    fn id_with_nul_is_ignored() {
        assert_eq!(
            parse("id: 1\ndata: a\n\nid: 2\0\ndata: b\n\n"),
            vec![ev("message", "a", "1"), ev("message", "b", "1")]
        );
    }

    #[test]
    fn id_without_data_still_updates_last_event_id() {
        let mut parser = Parser::new();
        parser.push(b"id: 9\n\n");
        assert_eq!(parser.last_event_id(), "9");
        assert!(parser.next_item().is_none());
    }

    #[test]
    fn retry_only_accepts_ascii_digits() {
        let mut parser = Parser::new();
        parser.push(b"retry: 1500\nretry: 1.5\nretry: -1\nretry:\nretry: 99999999999999999999999\nretry: x1\n");
        let items: Vec<_> = parser.items().map(Result::unwrap).collect();
        assert_eq!(items, vec![Item::Retry(Duration::from_millis(1500))]);
    }

    #[test]
    fn comments_dropped_by_default_and_reported_on_request() {
        assert_eq!(parse(": hi\ndata: x\n:\n\n"), vec![Event::new("x")]);
        let mut parser = Parser::with_options(Options::default().with_comments(true));
        parser.push(b": hi\n\n");
        assert_eq!(
            parser.next_item().unwrap().unwrap(),
            Item::Comment(" hi".into())
        );
    }

    #[test]
    fn unknown_fields_ignored() {
        assert_eq!(
            parse("foo: bar\ndata: x\nDATA: y\n\n"),
            vec![Event::new("x")]
        );
    }

    #[test]
    fn unterminated_event_discarded_on_finish() {
        let mut parser = Parser::new();
        parser.push(b"data: a\n\ndata: b\n");
        parser.finish();
        parser.push(b"data: c");
        parser.finish();
        assert_eq!(events(&mut parser), vec![Event::new("a")]);
    }

    #[test]
    fn finish_resets_for_reconnection_but_keeps_id() {
        let mut parser = Parser::new();
        parser.push(b"id: 5\ndata: a\n\nevent: x\ndata: partial\r");
        parser.finish();
        // New connection: a leading LF is a blank line, not the end of a CRLF,
        // and a BOM is stripped again.
        parser.push(b"\xEF\xBB\xBFdata: b\n\n");
        assert_eq!(parser.last_event_id(), "5");
        assert_eq!(
            events(&mut parser),
            vec![ev("message", "a", "5"), ev("message", "b", "5")]
        );
    }

    #[test]
    fn over_long_line_skips_event_and_recovers() {
        let mut parser = Parser::with_options(Options::default().with_max_line_len(8));
        parser.push(b"event: a\ndata: 0123");
        parser.push(b"456789");
        parser.push(b"\ndata: mo\n\ndata: ok\n\n");
        assert!(matches!(
            parser.next_item(),
            Some(Err(Error::LineTooLong { limit: 8 }))
        ));
        assert_eq!(events(&mut parser), vec![Event::new("ok")]);
    }

    #[test]
    fn over_long_line_in_one_chunk() {
        let mut parser = Parser::with_options(Options::default().with_max_line_len(4));
        parser.push(b"data: toolong\n\ndata\n\n");
        assert!(matches!(
            parser.next_item(),
            Some(Err(Error::LineTooLong { .. }))
        ));
        assert_eq!(events(&mut parser), vec![Event::new("")]);
    }

    #[test]
    fn line_exactly_at_limit_is_accepted() {
        let mut parser = Parser::with_options(Options::default().with_max_line_len(7));
        parser.push(b"data: ");
        parser.push(b"x\n\n");
        assert_eq!(events(&mut parser), vec![Event::new("x")]);
    }

    #[test]
    fn over_large_event_skipped() {
        let mut parser = Parser::with_options(Options::default().with_max_event_len(6));
        parser.push(b"data: abc\ndata: def\ndata: ghi\n\ndata: ok\n\n");
        assert!(matches!(
            parser.next_item(),
            Some(Err(Error::EventTooLarge { limit: 6 }))
        ));
        assert_eq!(events(&mut parser), vec![Event::new("ok")]);
    }

    /// The four examples from the WHATWG specification, §9.2.6, fed both
    /// whole and one byte at a time.
    #[test]
    fn whatwg_examples() {
        let cases: &[(&str, Vec<Event>)] = &[
            (
                "data: This is the first message.\n\n\
                 data: This is the second message, it\n\
                 data: has two lines.\n\n\
                 data: This is the third message.\n\n",
                vec![
                    Event::new("This is the first message."),
                    Event::new("This is the second message, it\nhas two lines."),
                    Event::new("This is the third message."),
                ],
            ),
            (
                "event: add\ndata: 73857293\n\n\
                 event: remove\ndata: 2153\n\n\
                 event: add\ndata: 113411\n\n",
                vec![
                    ev("add", "73857293", ""),
                    ev("remove", "2153", ""),
                    ev("add", "113411", ""),
                ],
            ),
            (
                "data: YHOO\ndata: +2\ndata: 10\n\n",
                vec![Event::new("YHOO\n+2\n10")],
            ),
            (
                ": test stream\n\n\
                 data: first event\nid: 1\n\n\
                 data:second event\nid\n\n\
                 data:  third event\n",
                vec![
                    ev("message", "first event", "1"),
                    ev("message", "second event", ""),
                ],
            ),
            (
                "data\n\ndata\ndata\n\ndata:",
                vec![Event::new(""), Event::new("\n")],
            ),
            (
                "data:test\n\ndata: test\n\n",
                vec![Event::new("test"), Event::new("test")],
            ),
        ];
        for (input, expected) in cases {
            let mut whole = Parser::new();
            whole.push(input.as_bytes());
            whole.finish();
            assert_eq!(&events(&mut whole), expected, "whole: {input:?}");

            let mut bytewise = Parser::new();
            for byte in input.as_bytes() {
                bytewise.push(std::slice::from_ref(byte));
            }
            bytewise.finish();
            assert_eq!(&events(&mut bytewise), expected, "bytewise: {input:?}");
        }
    }
}

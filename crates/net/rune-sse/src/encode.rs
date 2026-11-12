//! Serialising events back to the wire format.

use std::fmt::Write as _;
use std::time::Duration;

use crate::event::DEFAULT_EVENT_TYPE;
use crate::{Error, Event};

fn has_line_break(value: &str) -> bool {
    value.contains(['\n', '\r'])
}

/// Encodes `event` as an event-stream block, terminated by a blank line.
///
/// The `event` line is omitted for `"message"` (or an empty type) and the
/// `id` line for an empty ID. The encoder is stateless, so an event whose ID
/// is empty after one with an ID does not reset the receiver's last event
/// ID; send `id\n` yourself for that. Line breaks in `data` (`\r\n`, `\r`
/// or `\n`) become separate `data` lines, so they decode as `\n`.
///
/// # Errors
///
/// [`Error::InvalidField`] if `event.event` or `event.id` contains a line
/// break, or `event.id` contains NUL.
///
/// # Example
///
/// ```
/// use rune_sse::{Event, encode};
///
/// let wire = encode(&Event::new("a\nb").with_event("delta").with_id("7"))?;
/// assert_eq!(wire, "event: delta\nid: 7\ndata: a\ndata: b\n\n");
/// # Ok::<(), rune_sse::Error>(())
/// ```
pub fn encode(event: &Event) -> Result<String, Error> {
    if has_line_break(&event.event) {
        return Err(Error::InvalidField { field: "event" });
    }
    if has_line_break(&event.id) || event.id.contains('\0') {
        return Err(Error::InvalidField { field: "id" });
    }
    let mut out = String::with_capacity(event.data.len() + 16);
    if !event.event.is_empty() && event.event != DEFAULT_EVENT_TYPE {
        let _ = writeln!(out, "event: {}", event.event);
    }
    if !event.id.is_empty() {
        let _ = writeln!(out, "id: {}", event.id);
    }
    let data = event.data.replace("\r\n", "\n").replace('\r', "\n");
    for line in data.split('\n') {
        let _ = writeln!(out, "data: {line}");
    }
    out.push('\n');
    Ok(out)
}

/// Encodes a `retry` field setting the client's reconnection time.
#[must_use]
pub fn encode_retry(retry: Duration) -> String {
    format!("retry: {}\n", retry.as_millis())
}

/// Encodes a comment line, such as a keep-alive.
///
/// # Errors
///
/// [`Error::InvalidField`] if `text` contains a line break.
pub fn encode_comment(text: &str) -> Result<String, Error> {
    if has_line_break(text) {
        return Err(Error::InvalidField { field: "comment" });
    }
    Ok(format!(":{text}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_minimal_message() {
        assert_eq!(encode(&Event::new("x")).unwrap(), "data: x\n\n");
        assert_eq!(encode(&Event::new("")).unwrap(), "data: \n\n");
    }

    #[test]
    fn normalises_data_line_breaks() {
        assert_eq!(
            encode(&Event::new("a\r\nb\rc")).unwrap(),
            "data: a\ndata: b\ndata: c\n\n"
        );
    }

    #[test]
    fn rejects_unrepresentable_fields() {
        assert!(matches!(
            encode(&Event::new("x").with_event("a\nb")),
            Err(Error::InvalidField { field: "event" })
        ));
        assert!(matches!(
            encode(&Event::new("x").with_id("a\0")),
            Err(Error::InvalidField { field: "id" })
        ));
        assert!(encode_comment("a\rb").is_err());
    }

    #[test]
    fn encodes_retry_and_comment() {
        assert_eq!(encode_retry(Duration::from_secs(3)), "retry: 3000\n");
        assert_eq!(encode_comment(" ping").unwrap(), ": ping\n");
    }
}

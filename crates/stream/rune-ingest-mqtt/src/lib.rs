//! A minimal MQTT 3.1.1 subscriber that normalizes incoming messages into a typed
//! event shape.
//!
//! Ships three layers, from most to least testable in isolation:
//!
//! - [`packet`] — a pure byte-level codec for the handful of MQTT packet types a
//!   QoS-0 subscriber needs (`CONNECT`/`CONNACK`/`SUBSCRIBE`/`SUBACK`/`PUBLISH`).
//!   No I/O, fully unit tested.
//! - [`topic_matches`] — MQTT topic filter matching (`+` single-level and `#`
//!   multi-level wildcards), also pure and independently useful for routing.
//! - [`normalize`] and [`subscribe_qos0`] — turn a raw topic + payload into a
//!   [`NormalizedMessage`], and a thin blocking client that opens a TCP connection,
//!   performs the CONNECT/SUBSCRIBE handshake, and streams normalized messages to a
//!   callback.
//!
//! # Features
//!
//! - Zero external dependencies beyond `serde_json` — no MQTT client library, no
//!   async runtime.
//! - `QoS` 0 only, by design: this is an ingest-side normalizer for demo/telemetry
//!   pipelines, not a general-purpose MQTT client.
//! - Payloads are parsed as JSON where possible and fall back to a raw string value
//!   otherwise, so non-JSON devices still normalize into something usable.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_ingest_mqtt::{normalize, topic_matches};
//!
//! let msg = normalize("sensors/42/temperature", br#"{"celsius":21.5}"#, 1_700_000_000_000);
//! assert_eq!(msg.topic, "sensors/42/temperature");
//! assert_eq!(msg.payload["celsius"], 21.5);
//!
//! assert!(topic_matches("sensors/+/temperature", "sensors/42/temperature"));
//! assert!(!topic_matches("sensors/+/temperature", "sensors/42/humidity"));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-ingest-mqtt broker.local:1883 "sensors/#"
//! ```

pub mod packet;

use std::io::{self, Read, Write};
use std::net::TcpStream;

/// A normalized MQTT message: topic, JSON-decoded (or raw-string-fallback) payload,
/// and the time it was received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedMessage {
    /// Topic the message was published to.
    pub topic: String,
    /// Payload parsed as JSON.
    pub payload: serde_json::Value,
    /// Local receive time, in Unix milliseconds.
    pub received_at_ms: i64,
}

/// Normalizes a raw MQTT topic/payload pair into a [`NormalizedMessage`].
///
/// The payload is parsed as JSON when possible; otherwise it is kept as a JSON
/// string built from a lossy UTF-8 decode, so binary or plain-text payloads still
/// normalize into a usable value instead of being dropped.
///
/// # Example
///
/// ```rust
/// use rune_ingest_mqtt::normalize;
///
/// let msg = normalize("device/1/status", b"online", 0);
/// assert_eq!(msg.payload, serde_json::Value::String("online".to_string()));
/// ```
#[must_use]
pub fn normalize(topic: &str, payload: &[u8], received_at_ms: i64) -> NormalizedMessage {
    let value = serde_json::from_slice::<serde_json::Value>(payload).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(payload).into_owned())
    });
    NormalizedMessage {
        topic: topic.to_string(),
        payload: value,
        received_at_ms,
    }
}

/// Checks whether an MQTT topic filter matches a concrete topic.
///
/// Follows the MQTT 3.1.1 wildcard rules: `+` matches exactly one level, `#`
/// (only valid as the final level) matches all remaining levels including zero.
///
/// # Example
///
/// ```rust
/// use rune_ingest_mqtt::topic_matches;
///
/// assert!(topic_matches("a/#", "a/b/c"));
/// assert!(topic_matches("a/+/c", "a/b/c"));
/// assert!(!topic_matches("a/+/c", "a/b/b"));
/// ```
#[must_use]
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    let filter_levels: Vec<&str> = filter.split('/').collect();
    let topic_levels: Vec<&str> = topic.split('/').collect();

    let mut fi = 0;
    let mut ti = 0;
    while fi < filter_levels.len() {
        match filter_levels[fi] {
            "#" => return true,
            "+" => {
                if ti >= topic_levels.len() {
                    return false;
                }
            }
            level => {
                if ti >= topic_levels.len() || topic_levels[ti] != level {
                    return false;
                }
            }
        }
        fi += 1;
        ti += 1;
    }
    ti == topic_levels.len()
}

/// Errors from [`subscribe_qos0`].
#[derive(Debug)]
pub enum SubscribeError {
    /// Reading from or writing to the socket failed.
    Io(io::Error),
    /// The broker sent bytes that violate the MQTT protocol.
    Protocol(&'static str),
    /// The broker rejected the connection.
    ConnectionRefused(packet::ConnAckReason),
}

impl From<io::Error> for SubscribeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Connects to `addr`, performs the CONNECT/CONNACK and SUBSCRIBE/SUBACK handshake
/// for `topic_filter` at `QoS` 0, then blocks reading `PUBLISH` packets and invoking
/// `on_message` with each normalized one.
///
/// Runs until the connection closes or a protocol error occurs. This function opens
/// a real TCP connection and talks to a live broker — it is exercised by
/// integration testing against a running broker, not by this crate's unit tests,
/// which cover the packet codec and normalization logic it's built from.
pub fn subscribe_qos0(
    addr: &str,
    client_id: &str,
    topic_filter: &str,
    mut on_message: impl FnMut(NormalizedMessage),
) -> Result<(), SubscribeError> {
    let mut stream = TcpStream::connect(addr)?;

    stream.write_all(&packet::encode_connect(client_id, 30))?;
    let mut connack = [0u8; 4];
    stream.read_exact(&mut connack)?;
    match packet::decode_connack(&connack)
        .map_err(|_| SubscribeError::Protocol("malformed CONNACK"))?
    {
        packet::ConnAckReason::Accepted => {}
        reason @ packet::ConnAckReason::Refused(_) => {
            return Err(SubscribeError::ConnectionRefused(reason));
        }
    }

    stream.write_all(&packet::encode_subscribe(1, topic_filter))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);

        loop {
            match packet::decode_publish(&buf) {
                Ok((publish, consumed)) => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
                    on_message(normalize(&publish.topic, &publish.payload, now_ms));
                    buf.drain(..consumed);
                }
                Err(packet::DecodeError::Incomplete) => break,
                Err(_) => {
                    // Not a PUBLISH frame we recognize (e.g. a SUBACK or PINGRESP);
                    // skip one byte and keep scanning rather than stalling forever.
                    if buf.is_empty() {
                        break;
                    }
                    buf.remove(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_parses_json_payload() {
        let msg = normalize("t", br#"{"a":1}"#, 100);
        assert_eq!(msg.payload, json!({"a": 1}));
        assert_eq!(msg.received_at_ms, 100);
    }

    #[test]
    fn normalize_falls_back_to_string_for_non_json() {
        let msg = normalize("t", b"not json", 0);
        assert_eq!(
            msg.payload,
            serde_json::Value::String("not json".to_string())
        );
    }

    #[test]
    fn topic_matches_exact() {
        assert!(topic_matches("a/b/c", "a/b/c"));
        assert!(!topic_matches("a/b/c", "a/b/d"));
    }

    #[test]
    fn topic_matches_single_level_wildcard() {
        assert!(topic_matches("a/+/c", "a/b/c"));
        assert!(!topic_matches("a/+/c", "a/b/c/d"));
        assert!(!topic_matches("a/+", "a"));
    }

    #[test]
    fn topic_matches_multi_level_wildcard() {
        assert!(topic_matches("a/#", "a"));
        assert!(topic_matches("a/#", "a/b"));
        assert!(topic_matches("a/#", "a/b/c"));
        assert!(!topic_matches("a/#", "x/b/c"));
    }

    #[test]
    fn topic_matches_root_wildcard() {
        assert!(topic_matches("#", "anything/at/all"));
    }

    #[test]
    fn topic_does_not_match_shorter_topic() {
        assert!(!topic_matches("a/b/c", "a/b"));
    }
}

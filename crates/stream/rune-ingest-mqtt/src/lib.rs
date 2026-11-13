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
/// Topics that start with `$` are not matched by a leading `+` or `#`, and an
/// invalid filter (a `#` that isn't the last level, or a wildcard mixed into a
/// level like `a+`) matches nothing.
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

    // Topics starting with `$` (e.g. `$SYS/...`) are broker-internal and are
    // never matched by a filter that starts with a wildcard.
    if topic.starts_with('$') && matches!(filter_levels.first(), Some(&("+" | "#"))) {
        return false;
    }

    let mut fi = 0;
    let mut ti = 0;
    while fi < filter_levels.len() {
        match filter_levels[fi] {
            "#" => return fi + 1 == filter_levels.len(),
            "+" => {
                if ti >= topic_levels.len() {
                    return false;
                }
            }
            level => {
                // A wildcard character inside a level makes the filter invalid.
                if level.contains(['+', '#'])
                    || ti >= topic_levels.len()
                    || topic_levels[ti] != level
                {
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
/// Sends a `PINGREQ` whenever nothing has arrived for half the 30-second
/// keep-alive, and skips packets other than `PUBLISH` frame by frame. A single
/// packet is buffered whole before it is decoded, so a broker can make this hold
/// up to MQTT's 256 MiB packet-size limit in memory.
///
/// Runs until the connection closes or a protocol error occurs. This function opens
/// a real TCP connection and talks to a live broker — it is exercised by
/// integration testing against a running broker, not by this crate's unit tests,
/// which cover the packet codec and normalization logic it's built from.
pub fn subscribe_qos0(
    addr: &str,
    client_id: &str,
    topic_filter: &str,
    on_message: impl FnMut(NormalizedMessage),
) -> Result<(), SubscribeError> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(
        u64::from(KEEP_ALIVE_SECS) / 2,
    )))?;
    run_session(&mut stream, client_id, topic_filter, on_message)
}

const KEEP_ALIVE_SECS: u16 = 30;
const PINGREQ: [u8; 2] = [0xC0, 0x00];

fn run_session<S: Read + Write>(
    stream: &mut S,
    client_id: &str,
    topic_filter: &str,
    mut on_message: impl FnMut(NormalizedMessage),
) -> Result<(), SubscribeError> {
    stream.write_all(&packet::encode_connect(client_id, KEEP_ALIVE_SECS))?;
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
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                // Nothing arrived for a while: ping so the broker's keep-alive
                // timer doesn't drop an otherwise idle subscriber.
                stream.write_all(&PINGREQ)?;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut start = 0;
        loop {
            let frame_len = match packet::frame_len(&buf[start..]) {
                Ok(len) if len <= buf.len() - start => len,
                Ok(_) | Err(packet::DecodeError::Incomplete) => break,
                Err(_) => return Err(SubscribeError::Protocol("malformed packet length")),
            };
            let frame = &buf[start..start + frame_len];
            // Anything that isn't a well-formed QoS 0 PUBLISH (SUBACK, PINGRESP, ...)
            // is skipped as a whole frame so its body is never read as packets.
            if let Ok((publish, _)) = packet::decode_publish(frame) {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
                on_message(normalize(&publish.topic, &publish.payload, now_ms));
            }
            start += frame_len;
        }
        buf.drain(..start);
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

    #[test]
    fn dollar_topics_are_not_matched_by_leading_wildcards() {
        assert!(!topic_matches("#", "$SYS/broker/uptime"));
        assert!(!topic_matches("+/broker/uptime", "$SYS/broker/uptime"));
        assert!(topic_matches("$SYS/#", "$SYS/broker/uptime"));
        assert!(topic_matches("a/+", "a/$b"));
    }

    #[test]
    fn hash_that_is_not_the_last_level_matches_nothing() {
        assert!(!topic_matches("a/#/b", "a/x"));
        assert!(!topic_matches("a/b#", "a/b"));
        assert!(!topic_matches("a+/b", "a+/b"));
    }

    struct MockStream {
        reads: std::collections::VecDeque<io::Result<Vec<u8>>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(reads: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                reads: reads.into(),
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                None => Ok(0),
                Some(Err(e)) => Err(e),
                Some(Ok(bytes)) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.reads.push_front(Ok(bytes[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const CONNACK_OK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];

    fn publish_frame(first_byte: u8, topic: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(topic.len()).unwrap().to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(payload);
        let mut frame = vec![first_byte, u8::try_from(body.len()).unwrap()];
        frame.extend_from_slice(&body);
        frame
    }

    fn run(reads: Vec<io::Result<Vec<u8>>>) -> (Result<(), SubscribeError>, Vec<String>, Vec<u8>) {
        let mut stream = MockStream::new(reads);
        let mut topics = Vec::new();
        let result = run_session(&mut stream, "c", "#", |m| topics.push(m.topic));
        (result, topics, stream.written)
    }

    #[test]
    fn session_skips_whole_non_publish_frames() {
        // A QoS 1 PUBLISH whose payload happens to contain a valid QoS 0 frame.
        let inner = publish_frame(0x30, "fake", b"x");
        let mut qos1_body = vec![0x00, 0x01, b't', 0x00, 0x07];
        qos1_body.extend_from_slice(&inner);
        let mut qos1 = vec![0x32, u8::try_from(qos1_body.len()).unwrap()];
        qos1.extend_from_slice(&qos1_body);

        let mut wire = vec![0x90, 0x03, 0x00, 0x01, 0x00]; // SUBACK
        wire.extend_from_slice(&qos1);
        wire.extend_from_slice(&publish_frame(0x30, "real", b"{}"));

        let (result, topics, _) = run(vec![Ok(CONNACK_OK.to_vec()), Ok(wire)]);
        assert!(result.is_ok());
        assert_eq!(topics, vec!["real".to_string()]);
    }

    #[test]
    fn session_rejects_an_overlong_remaining_length() {
        let mut wire = vec![0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        wire.extend_from_slice(&[0u8; 64]);
        let (result, topics, _) = run(vec![Ok(CONNACK_OK.to_vec()), Ok(wire)]);
        assert!(matches!(result, Err(SubscribeError::Protocol(_))));
        assert_eq!(topics, Vec::<String>::new());
    }

    #[test]
    fn session_sends_pingreq_when_the_read_times_out() {
        let (result, _, written) = run(vec![
            Ok(CONNACK_OK.to_vec()),
            Err(io::Error::from(io::ErrorKind::TimedOut)),
            Err(io::Error::from(io::ErrorKind::WouldBlock)),
        ]);
        assert!(result.is_ok());
        assert!(written.ends_with(&[0xC0, 0x00, 0xC0, 0x00]));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn session_never_panics_on_arbitrary_broker_bytes(
            chunks in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64), 0..8)
        ) {
            let mut reads = vec![Ok(CONNACK_OK.to_vec())];
            reads.extend(chunks.into_iter().map(Ok));
            let _ = run(reads);
        }

        #[test]
        fn topic_matches_never_panics(filter in ".{0,24}", topic in ".{0,24}") {
            let _ = topic_matches(&filter, &topic);
        }
    }
}

//! MQTT 3.1.1 packet encoding/decoding, scoped to `QoS` 0: `CONNECT`, `CONNACK`,
//! `SUBSCRIBE`, `SUBACK`, and `PUBLISH`. Pure byte-level codec, no I/O.

const PACKET_TYPE_CONNECT: u8 = 1;
const PACKET_TYPE_CONNACK: u8 = 2;
const PACKET_TYPE_PUBLISH: u8 = 3;
const PACKET_TYPE_SUBSCRIBE: u8 = 8;
const PACKET_TYPE_SUBACK: u8 = 9;

/// The reason code returned by a broker in a `CONNACK` packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnAckReason {
    /// The broker accepted the connection.
    Accepted,
    /// The broker refused the connection with this return code.
    Refused(u8),
}

/// Errors that can occur while decoding a byte buffer as an MQTT packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ends before the packet does.
    Incomplete,
    /// A different packet type arrived than the one expected.
    UnexpectedPacketType {
        /// Packet type the decoder expected.
        expected: u8,
        /// Packet type found in the buffer.
        found: u8,
    },
    /// The packet is structurally invalid.
    Malformed(&'static str),
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

fn decode_remaining_length(bytes: &[u8]) -> Result<(usize, usize), DecodeError> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    let mut consumed = 0usize;
    for &byte in bytes.iter().take(4) {
        consumed += 1;
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        multiplier *= 128;
    }
    if consumed == 4 {
        // MQTT caps the remaining length at four bytes; a fifth continuation
        // byte can never become valid, so waiting for more input would stall.
        return Err(DecodeError::Malformed(
            "remaining length longer than four bytes",
        ));
    }
    Err(DecodeError::Incomplete)
}

/// Total length (fixed header included) of the packet at the start of `bytes`,
/// whatever its type. Lets a reader skip packets it does not handle.
pub(crate) fn frame_len(bytes: &[u8]) -> Result<usize, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let (remaining_len, header_len) = decode_remaining_length(&bytes[1..])?;
    Ok(1 + header_len + remaining_len)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn encode_utf8_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn decode_utf8_string(bytes: &[u8]) -> Result<(String, usize), DecodeError> {
    if bytes.len() < 2 {
        return Err(DecodeError::Incomplete);
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + len {
        return Err(DecodeError::Incomplete);
    }
    let s = std::str::from_utf8(&bytes[2..2 + len])
        .map_err(|_| DecodeError::Malformed("invalid utf-8 string"))?
        .to_string();
    Ok((s, 2 + len))
}

/// Encodes a `CONNECT` packet requesting a clean session, no will, no auth.
#[must_use]
pub fn encode_connect(client_id: &str, keep_alive_secs: u16) -> Vec<u8> {
    let mut variable_and_payload = Vec::new();
    variable_and_payload.extend_from_slice(&encode_utf8_string("MQTT"));
    variable_and_payload.push(4); // protocol level: MQTT 3.1.1
    variable_and_payload.push(0x02); // connect flags: clean session
    variable_and_payload.extend_from_slice(&keep_alive_secs.to_be_bytes());
    variable_and_payload.extend_from_slice(&encode_utf8_string(client_id));

    let mut packet = Vec::with_capacity(2 + variable_and_payload.len());
    packet.push(PACKET_TYPE_CONNECT << 4);
    packet.extend_from_slice(&encode_remaining_length(variable_and_payload.len()));
    packet.extend_from_slice(&variable_and_payload);
    packet
}

/// Decodes a `CONNACK` packet, returning the broker's accept/refuse reason.
pub const fn decode_connack(bytes: &[u8]) -> Result<ConnAckReason, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError::Incomplete);
    }
    let found_type = bytes[0] >> 4;
    if found_type != PACKET_TYPE_CONNACK {
        return Err(DecodeError::UnexpectedPacketType {
            expected: PACKET_TYPE_CONNACK,
            found: found_type,
        });
    }
    let return_code = bytes[3];
    Ok(if return_code == 0 {
        ConnAckReason::Accepted
    } else {
        ConnAckReason::Refused(return_code)
    })
}

/// Encodes a `SUBSCRIBE` packet for a single topic filter at `QoS` 0.
#[must_use]
pub fn encode_subscribe(packet_id: u16, topic_filter: &str) -> Vec<u8> {
    let mut variable_and_payload = Vec::new();
    variable_and_payload.extend_from_slice(&packet_id.to_be_bytes());
    variable_and_payload.extend_from_slice(&encode_utf8_string(topic_filter));
    variable_and_payload.push(0); // requested QoS 0

    let mut packet = Vec::with_capacity(2 + variable_and_payload.len());
    packet.push((PACKET_TYPE_SUBSCRIBE << 4) | 0x02); // reserved flags required by the spec
    packet.extend_from_slice(&encode_remaining_length(variable_and_payload.len()));
    packet.extend_from_slice(&variable_and_payload);
    packet
}

/// Decodes a `SUBACK` packet, returning the packet id it acknowledges.
pub const fn decode_suback(bytes: &[u8]) -> Result<u16, DecodeError> {
    if bytes.len() < 5 {
        return Err(DecodeError::Incomplete);
    }
    let found_type = bytes[0] >> 4;
    if found_type != PACKET_TYPE_SUBACK {
        return Err(DecodeError::UnexpectedPacketType {
            expected: PACKET_TYPE_SUBACK,
            found: found_type,
        });
    }
    Ok(u16::from_be_bytes([bytes[2], bytes[3]]))
}

/// A decoded `PUBLISH` packet (`QoS` 0 only — no packet id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// Topic name.
    pub topic: String,
    /// Raw message payload.
    pub payload: Vec<u8>,
}

/// Decodes a QoS-0 `PUBLISH` packet from a full, framed buffer (fixed header included).
///
/// Returns the decoded packet and the number of bytes consumed from `bytes`, so callers
/// reading from a byte stream can advance past exactly one packet.
pub fn decode_publish(bytes: &[u8]) -> Result<(Publish, usize), DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    let found_type = bytes[0] >> 4;
    if found_type != PACKET_TYPE_PUBLISH {
        return Err(DecodeError::UnexpectedPacketType {
            expected: PACKET_TYPE_PUBLISH,
            found: found_type,
        });
    }
    let qos = (bytes[0] >> 1) & 0x03;
    if qos != 0 {
        return Err(DecodeError::Malformed(
            "only QoS 0 PUBLISH packets are supported",
        ));
    }

    let (remaining_len, header_len) = decode_remaining_length(&bytes[1..])?;
    let total_len = 1 + header_len + remaining_len;
    if bytes.len() < total_len {
        return Err(DecodeError::Incomplete);
    }

    let body = &bytes[1 + header_len..total_len];
    let (topic, topic_len) = decode_utf8_string(body)?;
    let payload = body[topic_len..].to_vec();

    Ok((Publish { topic, payload }, total_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_round_trips_small_values() {
        for len in [0usize, 1, 127, 128, 16383, 16384, 2_097_151] {
            let encoded = encode_remaining_length(len);
            let (decoded, consumed) = decode_remaining_length(&encoded).unwrap();
            assert_eq!(decoded, len);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn connect_packet_has_expected_header() {
        let packet = encode_connect("client-1", 30);
        assert_eq!(packet[0], PACKET_TYPE_CONNECT << 4);
        // Protocol name "MQTT" appears right after the fixed header + remaining length byte.
        assert_eq!(&packet[2..8], b"\x00\x04MQTT");
        assert_eq!(packet[8], 4); // protocol level
    }

    #[test]
    fn connack_accepted() {
        let bytes = [0x20, 0x02, 0x00, 0x00];
        assert_eq!(decode_connack(&bytes).unwrap(), ConnAckReason::Accepted);
    }

    #[test]
    fn connack_refused() {
        let bytes = [0x20, 0x02, 0x00, 0x05];
        assert_eq!(decode_connack(&bytes).unwrap(), ConnAckReason::Refused(5));
    }

    #[test]
    fn connack_wrong_packet_type_is_rejected() {
        let bytes = [0x30, 0x02, 0x00, 0x00];
        assert_eq!(
            decode_connack(&bytes).unwrap_err(),
            DecodeError::UnexpectedPacketType {
                expected: PACKET_TYPE_CONNACK,
                found: PACKET_TYPE_PUBLISH,
            }
        );
    }

    #[test]
    fn subscribe_then_suback_packet_id_matches() {
        let packet = encode_subscribe(42, "sensors/+/temperature");
        assert_eq!(packet[0], (PACKET_TYPE_SUBSCRIBE << 4) | 0x02);

        let suback = [0x90, 0x03, 0x00, 42, 0x00];
        assert_eq!(decode_suback(&suback).unwrap(), 42);
    }

    #[test]
    fn publish_round_trips() {
        let topic = "sensors/42/temperature";
        let payload = br#"{"celsius":21.5}"#;

        let mut body = Vec::new();
        body.extend_from_slice(&encode_utf8_string(topic));
        body.extend_from_slice(payload);
        let mut packet = vec![PACKET_TYPE_PUBLISH << 4];
        packet.extend_from_slice(&encode_remaining_length(body.len()));
        packet.extend_from_slice(&body);

        let (publish, consumed) = decode_publish(&packet).unwrap();
        assert_eq!(publish.topic, topic);
        assert_eq!(publish.payload, payload);
        assert_eq!(consumed, packet.len());
    }

    #[test]
    fn publish_with_trailing_bytes_only_consumes_its_own_frame() {
        let mut packet = vec![PACKET_TYPE_PUBLISH << 4];
        let mut body = Vec::new();
        body.extend_from_slice(&encode_utf8_string("t"));
        body.extend_from_slice(b"x");
        packet.extend_from_slice(&encode_remaining_length(body.len()));
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // next packet's bytes

        let (publish, consumed) = decode_publish(&packet).unwrap();
        assert_eq!(publish.topic, "t");
        assert_eq!(publish.payload, b"x");
        assert_eq!(consumed, packet.len() - 3);
    }

    #[test]
    fn publish_rejects_non_zero_qos() {
        let mut packet = vec![(PACKET_TYPE_PUBLISH << 4) | (1 << 1)]; // QoS 1
        let mut body = Vec::new();
        body.extend_from_slice(&encode_utf8_string("t"));
        body.extend_from_slice(b"x");
        packet.extend_from_slice(&encode_remaining_length(body.len()));
        packet.extend_from_slice(&body);

        assert_eq!(
            decode_publish(&packet).unwrap_err(),
            DecodeError::Malformed("only QoS 0 PUBLISH packets are supported")
        );
    }

    #[test]
    fn incomplete_buffer_is_reported() {
        assert_eq!(decode_publish(&[]).unwrap_err(), DecodeError::Incomplete);
        assert_eq!(
            decode_connack(&[0x20, 0x02]).unwrap_err(),
            DecodeError::Incomplete
        );
    }

    #[test]
    fn remaining_length_longer_than_four_bytes_is_malformed() {
        let bytes = [0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00];
        assert_eq!(
            decode_publish(&bytes).unwrap_err(),
            DecodeError::Malformed("remaining length longer than four bytes")
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let _ = decode_connack(&bytes);
            let _ = decode_suback(&bytes);
            if let Ok((_, consumed)) = decode_publish(&bytes) {
                proptest::prop_assert!(consumed <= bytes.len());
            }
            let _ = decode_remaining_length(&bytes);
        }
    }
}

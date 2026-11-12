//! Close codes and close frame payloads (RFC 6455 §5.5.1, §7.4).

use std::fmt;

use crate::error::{Error, Result};

/// A WebSocket close status code (RFC 6455 §7.4).
///
/// Any `u16` can be represented; [`is_valid_on_wire`](Self::is_valid_on_wire)
/// tells whether a peer may actually send it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// 1000: normal closure.
    pub const NORMAL: Self = Self(1000);
    /// 1001: the endpoint is going away (server shutdown, page navigation).
    pub const GOING_AWAY: Self = Self(1001);
    /// 1002: protocol error.
    pub const PROTOCOL_ERROR: Self = Self(1002);
    /// 1003: received a data type the endpoint cannot accept.
    pub const UNSUPPORTED_DATA: Self = Self(1003);
    /// 1005: no status code was present (never sent on the wire).
    pub const NO_STATUS: Self = Self(1005);
    /// 1006: closed without a close frame (never sent on the wire).
    pub const ABNORMAL: Self = Self(1006);
    /// 1007: payload inconsistent with the message type (e.g. bad UTF-8).
    pub const INVALID_PAYLOAD: Self = Self(1007);
    /// 1008: policy violation.
    pub const POLICY_VIOLATION: Self = Self(1008);
    /// 1009: message too big to process.
    pub const TOO_BIG: Self = Self(1009);
    /// 1010: the client expected an extension the server did not negotiate.
    pub const MANDATORY_EXTENSION: Self = Self(1010);
    /// 1011: unexpected server condition.
    pub const INTERNAL_ERROR: Self = Self(1011);
    /// 1012: service restart (IANA registry).
    pub const SERVICE_RESTART: Self = Self(1012);
    /// 1013: try again later (IANA registry).
    pub const TRY_AGAIN_LATER: Self = Self(1013);
    /// 1014: bad gateway (IANA registry).
    pub const BAD_GATEWAY: Self = Self(1014);
    /// 1015: TLS handshake failure (never sent on the wire).
    pub const TLS_HANDSHAKE: Self = Self(1015);

    /// Whether an endpoint may send this code in a close frame: 1000–1003,
    /// 1007–1014 and the application ranges 3000–4999.
    #[must_use]
    pub const fn is_valid_on_wire(self) -> bool {
        matches!(self.0, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }
}

impl From<u16> for CloseCode {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        code.0
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The body of a close frame: a status code and an optional UTF-8 reason.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CloseFrame {
    /// The status code.
    pub code: CloseCode,
    /// The reason; at most 123 bytes so the payload fits a control frame.
    pub reason: String,
}

impl CloseFrame {
    /// A close frame with `code` and `reason`.
    pub fn new(code: impl Into<CloseCode>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
        }
    }

    /// Parses a close frame payload. An empty payload is a valid close with
    /// no status and yields `None`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClosePayload`] for a one-byte payload,
    /// [`Error::InvalidCloseCode`] for a code that may not be sent, and
    /// [`Error::InvalidUtf8`] for a reason that is not UTF-8.
    pub fn parse(payload: &[u8]) -> Result<Option<Self>> {
        match payload {
            [] => Ok(None),
            [_] => Err(Error::InvalidClosePayload),
            [hi, lo, reason @ ..] => {
                let code = CloseCode(u16::from_be_bytes([*hi, *lo]));
                if !code.is_valid_on_wire() {
                    return Err(Error::InvalidCloseCode(code.0));
                }
                let reason = std::str::from_utf8(reason).map_err(|_| Error::InvalidUtf8)?;
                Ok(Some(Self::new(code, reason)))
            }
        }
    }

    /// Serialises the frame into a close payload: the code in network byte
    /// order followed by the reason.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.reason.len());
        out.extend_from_slice(&self.code.0.to_be_bytes());
        out.extend_from_slice(self.reason.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_validity_matches_rfc_ranges() {
        for ok in [
            1000, 1001, 1002, 1003, 1007, 1011, 1014, 3000, 3999, 4000, 4999,
        ] {
            assert!(CloseCode(ok).is_valid_on_wire(), "{ok}");
        }
        for bad in [
            0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535,
        ] {
            assert!(!CloseCode(bad).is_valid_on_wire(), "{bad}");
        }
    }

    #[test]
    fn parse_and_serialise_round_trip() {
        let frame = CloseFrame::new(CloseCode::GOING_AWAY, "bye");
        assert_eq!(frame.to_payload(), b"\x03\xe9bye");
        assert_eq!(CloseFrame::parse(&frame.to_payload()).unwrap(), Some(frame));
        assert_eq!(CloseFrame::parse(&[]).unwrap(), None);
    }

    #[test]
    fn parse_rejects_bad_payloads() {
        assert!(matches!(
            CloseFrame::parse(&[3]),
            Err(Error::InvalidClosePayload)
        ));
        assert!(matches!(
            CloseFrame::parse(&1005u16.to_be_bytes()),
            Err(Error::InvalidCloseCode(1005))
        ));
        assert!(matches!(
            CloseFrame::parse(b"\x03\xe8\xff"),
            Err(Error::InvalidUtf8)
        ));
    }
}

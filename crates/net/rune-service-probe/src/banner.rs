//! Banner helpers and a generic banner-grabbing probe.

use crate::{Action, End, Error, ProbeSession, ServiceInfo, ServiceProbe, Target};

/// Render untrusted bytes as printable ASCII, reading at most `max_bytes`.
///
/// Printable ASCII is kept; `\\`, `\r`, `\n` and `\t` are escaped as such;
/// every other byte becomes `\xNN`. The result is safe to log or show in a
/// terminal, and at most `4 * max_bytes` long.
///
/// ```
/// use rune_service_probe::banner::printable;
///
/// assert_eq!(printable(b"SSH-2.0-OpenSSH_9.6\r\n", 64), r"SSH-2.0-OpenSSH_9.6\r\n");
/// assert_eq!(printable(b"\x1b[31mred", 64), r"\x1b[31mred");
/// assert_eq!(printable(b"abcdef", 3), "abc");
/// ```
#[must_use]
pub fn printable(bytes: &[u8], max_bytes: usize) -> String {
    use std::fmt::Write as _;

    let bytes = bytes.get(..max_bytes.min(bytes.len())).unwrap_or_default();
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str(r"\\"),
            b'\r' => out.push_str(r"\r"),
            b'\n' => out.push_str(r"\n"),
            b'\t' => out.push_str(r"\t"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

/// Split the first line off `buf`: the bytes before the first `\n`, without
/// a trailing `\r`, and the rest after it. `None` until a `\n` arrives.
///
/// ```
/// use rune_service_probe::banner::split_line;
///
/// assert_eq!(split_line(b"220 ready\r\n250 more"), Some((&b"220 ready"[..], &b"250 more"[..])));
/// assert_eq!(split_line(b"partial"), None);
/// ```
#[must_use]
pub fn split_line(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = buf.iter().position(|&b| b == b'\n')?;
    let line = buf.get(..end)?;
    let rest = buf.get(end + 1..)?;
    Some((line.strip_suffix(b"\r").unwrap_or(line), rest))
}

/// Grabs the first line a service sends, optionally after sending an inert
/// payload.
///
/// The probe for "what is listening here?" before a protocol probe is
/// chosen. It reads until the first newline or
/// [`max_bytes`](Self::with_max_bytes), and reports it as
/// [`ServiceInfo::banner`] under the id `banner`. It never interprets the
/// banner.
///
/// Only send payloads that cannot change server state, e.g. `\r\n` or an
/// HTTP `HEAD` request: the probe declares itself read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerProbe {
    payload: Option<Vec<u8>>,
    max_bytes: usize,
}

impl Default for BannerProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl BannerProbe {
    /// Default limit on the banner length, in bytes.
    pub const DEFAULT_MAX_BYTES: usize = 1024;

    /// A probe that waits for the server to speak first.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            payload: None,
            max_bytes: Self::DEFAULT_MAX_BYTES,
        }
    }

    /// Send `payload` first, for services that wait for the client.
    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Read at most `max_bytes` (at least one).
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes.max(1);
        self
    }
}

impl ServiceProbe for BannerProbe {
    fn id(&self) -> &'static str {
        "banner"
    }

    fn session(&self, _target: &Target) -> Box<dyn ProbeSession> {
        Box::new(BannerSession {
            payload: self.payload.clone(),
            max_bytes: self.max_bytes,
            buf: Vec::new(),
        })
    }
}

struct BannerSession {
    payload: Option<Vec<u8>>,
    max_bytes: usize,
    buf: Vec<u8>,
}

impl ProbeSession for BannerSession {
    fn start(&mut self) -> Action {
        self.payload.take().map_or(Action::Receive, Action::Send)
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        let room = self.max_bytes.saturating_sub(self.buf.len());
        self.buf
            .extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
        if self.buf.len() >= self.max_bytes || self.buf.contains(&b'\n') {
            Action::Done
        } else {
            Action::Receive
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
        if self.buf.is_empty() {
            return Err(Error::no_response("banner"));
        }
        let line = split_line(&self.buf).map_or(self.buf.as_slice(), |(line, _)| line);
        Ok(ServiceInfo::new("banner").with_banner(printable(line, self.max_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, simulate};

    fn run(probe: &BannerProbe, replies: &[&[u8]]) -> crate::Simulation {
        simulate(probe, &Target::new("h", 1), replies, &Options::default()).unwrap()
    }

    #[test]
    fn escapes_everything_unprintable() {
        assert_eq!(printable(b"a\\b\t\x00\xff", 16), r"a\\b\t\x00\xff");
        assert_eq!(printable(b"", 16), "");
        assert_eq!(printable(b"abc", 0), "");
    }

    #[test]
    fn split_line_handles_bare_lf_and_empty_lines() {
        assert_eq!(split_line(b"\n"), Some((&b""[..], &b""[..])));
        assert_eq!(split_line(b"a\nb\n"), Some((&b"a"[..], &b"b\n"[..])));
        assert_eq!(split_line(b"\r"), None);
    }

    #[test]
    fn reassembles_a_banner_split_across_reads() {
        let sim = run(&BannerProbe::new(), &[b"SSH-2.0-", b"OpenSSH_9.6\r\nrest"]);
        assert_eq!(sim.sent, Vec::<Vec<u8>>::new());
        assert_eq!(sim.end, End::Done);
        assert_eq!(
            sim.result.unwrap().banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
    }

    #[test]
    fn keeps_a_partial_banner_when_the_peer_closes() {
        let sim = run(&BannerProbe::new(), &[b"no newline"]);
        assert_eq!(sim.end, End::Closed);
        assert_eq!(sim.result.unwrap().banner.as_deref(), Some("no newline"));
    }

    #[test]
    fn stops_at_max_bytes() {
        let probe = BannerProbe::new().with_max_bytes(4);
        let sim = run(&probe, &[b"abcdefgh"]);
        assert_eq!(sim.end, End::Done);
        assert_eq!(sim.result.unwrap().banner.as_deref(), Some("abcd"));
    }

    #[test]
    fn silence_is_no_response() {
        let sim = run(&BannerProbe::new(), &[]);
        assert!(matches!(sim.result, Err(Error::NoResponse { .. })));
    }
}

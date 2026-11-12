//! Wire-level quirks of an HTTP/1.x response head.

use std::collections::BTreeSet;
use std::fmt;

/// At most this many bytes of a captured response are scanned for the head.
pub const MAX_HEAD_LEN: usize = 64 * 1024;

/// A deviation from the most common way of writing a response head.
///
/// Wire-level quirks come from the captured bytes ([`analyze_raw_head`]);
/// the rest also show up in the parsed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Quirk {
    /// Lines end in a bare `\n` instead of `\r\n`.
    BareLf,
    /// Some lines end in `\r\n`, others in `\n`.
    MixedLineEndings,
    /// The status line has no reason phrase and no space after the code
    /// (`HTTP/1.1 200`).
    NoReasonPhrase,
    /// The status line ends in a space with an empty reason (`HTTP/1.1 200 `).
    EmptyReasonPhrase,
    /// The reason phrase differs from the registered one (`200 Ok`, `200 Fine`).
    NonStandardReason,
    /// The version token is not `HTTP/1.0` or `HTTP/1.1` verbatim
    /// (`http/1.1`, `HTTP/1.2`).
    NonStandardVersion,
    /// The status line is separated by more than one space.
    ExtraStatusSpace,
    /// Whitespace between a header name and its colon (`Server : x`).
    SpaceBeforeColon,
    /// No space after a header colon (`Server:x`).
    NoSpaceAfterColon,
    /// More than one space or a tab after a header colon.
    ExtraSpaceAfterColon,
    /// A header value with trailing whitespace.
    TrailingWhitespace,
    /// A header continued on the next line (obsolete line folding).
    ObsFold,
    /// A header line without a colon.
    MalformedLine,
    /// A header with an empty value.
    EmptyValue,
    /// The same header (other than `Set-Cookie`) sent more than once.
    DuplicateHeader,
}

impl Quirk {
    /// The short code used in raw fingerprints.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BareLf => "lf",
            Self::MixedLineEndings => "mle",
            Self::NoReasonPhrase => "nrp",
            Self::EmptyReasonPhrase => "erp",
            Self::NonStandardReason => "nsr",
            Self::NonStandardVersion => "nsv",
            Self::ExtraStatusSpace => "ess",
            Self::SpaceBeforeColon => "sbc",
            Self::NoSpaceAfterColon => "nsc",
            Self::ExtraSpaceAfterColon => "esc",
            Self::TrailingWhitespace => "tws",
            Self::ObsFold => "fold",
            Self::MalformedLine => "mal",
            Self::EmptyValue => "ev",
            Self::DuplicateHeader => "dup",
        }
    }
}

impl fmt::Display for Quirk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// What the captured bytes of a response head reveal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RawHead {
    /// The version token of the status line, verbatim (at most 16 characters).
    pub version_token: String,
    /// The reason phrase, verbatim (at most 64 characters); empty when absent.
    pub reason: String,
    /// Header names in wire order, case preserved.
    pub header_names: Vec<String>,
    /// Wire-level quirks found.
    pub quirks: BTreeSet<Quirk>,
}

/// Scans the head of a captured HTTP/1.x response for wire-level quirks.
///
/// The head is the `raw` bytes up to the first blank line, or the first
/// [`MAX_HEAD_LEN`] bytes. Returns `None` when the bytes do not start with an `HTTP/`
/// status line (ignoring case), e.g. for HTTP/2 captures.
///
/// ```
/// use rune_http_fingerprint::{Quirk, analyze_raw_head};
///
/// let head = analyze_raw_head(b"HTTP/1.1 200\nServer:demo\n\nbody").unwrap();
/// assert_eq!(head.version_token, "HTTP/1.1");
/// assert!(head.quirks.contains(&Quirk::BareLf));
/// assert!(head.quirks.contains(&Quirk::NoReasonPhrase));
/// assert!(head.quirks.contains(&Quirk::NoSpaceAfterColon));
/// ```
#[must_use]
pub fn analyze_raw_head(raw: &[u8]) -> Option<RawHead> {
    let raw = raw.get(..MAX_HEAD_LEN).unwrap_or(raw);
    if !raw
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"HTTP/"))
    {
        return None;
    }
    let mut head = RawHead::default();
    let (mut crlf, mut lf) = (false, false);
    let mut lines = raw.split(|&byte| byte == b'\n').peekable();
    let mut first = true;
    while let Some(line) = lines.next() {
        // A final fragment without `\n` is a truncated capture: still scanned,
        // but its (missing) line ending says nothing.
        let terminated = lines.peek().is_some();
        let stripped = line.strip_suffix(b"\r");
        if stripped.is_some() {
            crlf |= terminated;
        } else {
            lf |= terminated;
        }
        let line = stripped.unwrap_or(line);
        if first {
            first = false;
            status_line(&String::from_utf8_lossy(line), &mut head);
            continue;
        }
        if line.is_empty() {
            break;
        }
        header_line(&String::from_utf8_lossy(line), &mut head);
    }
    match (crlf, lf) {
        (true, true) => head.quirks.insert(Quirk::MixedLineEndings),
        (false, true) => head.quirks.insert(Quirk::BareLf),
        _ => false,
    };
    Some(head)
}

fn status_line(line: &str, head: &mut RawHead) {
    let (version, rest) = line.split_once(' ').unwrap_or((line, ""));
    head.version_token = version.chars().take(16).collect();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        head.quirks.insert(Quirk::NonStandardVersion);
    }
    if rest.starts_with(' ') {
        head.quirks.insert(Quirk::ExtraStatusSpace);
    }
    let rest = rest.trim_start_matches(' ');
    match rest.split_once(' ') {
        None => {
            head.quirks.insert(Quirk::NoReasonPhrase);
        }
        Some((_, "")) => {
            head.quirks.insert(Quirk::EmptyReasonPhrase);
        }
        Some((_, reason)) => {
            if reason.starts_with(' ') {
                head.quirks.insert(Quirk::ExtraStatusSpace);
            }
            head.reason = reason.trim().chars().take(64).collect();
        }
    }
}

fn header_line(line: &str, head: &mut RawHead) {
    if line.starts_with([' ', '\t']) {
        head.quirks.insert(Quirk::ObsFold);
        return;
    }
    let Some((name, value)) = line.split_once(':') else {
        head.quirks.insert(Quirk::MalformedLine);
        return;
    };
    if name.ends_with([' ', '\t']) {
        head.quirks.insert(Quirk::SpaceBeforeColon);
    }
    if value.trim().is_empty() {
        head.quirks.insert(Quirk::EmptyValue);
    } else {
        if !value.starts_with([' ', '\t']) {
            head.quirks.insert(Quirk::NoSpaceAfterColon);
        } else if value.starts_with('\t') || value.starts_with("  ") {
            head.quirks.insert(Quirk::ExtraSpaceAfterColon);
        }
        if value.ends_with([' ', '\t']) {
            head.quirks.insert(Quirk::TrailingWhitespace);
        }
    }
    head.header_names.push(name.trim_end().to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quirks(raw: &str) -> Vec<Quirk> {
        analyze_raw_head(raw.as_bytes())
            .unwrap()
            .quirks
            .into_iter()
            .collect()
    }

    #[test]
    fn clean_head_has_no_quirks() {
        let head =
            analyze_raw_head(b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nDate: x\r\n\r\n<html>")
                .unwrap();
        assert!(head.quirks.is_empty());
        assert_eq!(head.reason, "Not Found");
        assert_eq!(head.header_names, ["Server", "Date"]);
    }

    #[test]
    fn detects_each_quirk() {
        assert_eq!(quirks("HTTP/1.1 200 OK\nA: b\n\n"), [Quirk::BareLf]);
        assert_eq!(
            quirks("HTTP/1.1 200 OK\r\nA: b\n\r\n"),
            [Quirk::MixedLineEndings]
        );
        assert_eq!(quirks("HTTP/1.1 200\r\n\r\n"), [Quirk::NoReasonPhrase]);
        assert_eq!(quirks("HTTP/1.1 200 \r\n\r\n"), [Quirk::EmptyReasonPhrase]);
        assert_eq!(
            quirks("http/1.1  200 OK\r\n\r\n"),
            [Quirk::NonStandardVersion, Quirk::ExtraStatusSpace]
        );
        assert_eq!(
            quirks("HTTP/1.1 200 OK\r\nA : b\r\nC:d\r\nE:  f \r\n\tg\r\nbad\r\nH:\r\n\r\n"),
            [
                Quirk::SpaceBeforeColon,
                Quirk::NoSpaceAfterColon,
                Quirk::ExtraSpaceAfterColon,
                Quirk::TrailingWhitespace,
                Quirk::ObsFold,
                Quirk::MalformedLine,
                Quirk::EmptyValue,
            ]
        );
    }

    #[test]
    fn rejects_non_http_and_tolerates_truncation() {
        assert!(analyze_raw_head(b"").is_none());
        assert!(analyze_raw_head(b"SSH-2.0-x\r\n").is_none());
        let head = analyze_raw_head(b"HTTP/1.1 200 OK\r\nServer: a").unwrap();
        assert_eq!(head.header_names, ["Server"]);
        assert!(head.quirks.is_empty());
        let codes: Vec<_> = [Quirk::BareLf, Quirk::DuplicateHeader]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(codes, ["lf", "dup"]);
    }
}

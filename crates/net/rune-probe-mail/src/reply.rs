//! SMTP and FTP replies: a three-digit code and one or more text lines.

use rune_service_probe::banner::{printable, split_line};

use crate::Error;

/// The most lines [`parse_reply`] accepts in one reply.
pub const MAX_REPLY_LINES: usize = 256;

/// Each line's text is cut to this many bytes before it is escaped.
pub const MAX_LINE_BYTES: usize = 1024;

/// One reply ([RFC 5321 §4.2](https://www.rfc-editor.org/rfc/rfc5321#section-4.2),
/// [RFC 959 §4.2](https://www.rfc-editor.org/rfc/rfc959#section-4)).
///
/// `lines` holds the text after the code and its separator, made printable
/// with [`printable`] (so `\x1b` and the like are escaped).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Reply {
    /// The reply code, `100..=599`.
    pub code: u16,
    /// The text of each line, without the code.
    pub lines: Vec<String>,
}

impl Reply {
    /// A reply with these lines.
    #[must_use]
    pub const fn new(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// The first line's text, or `""`.
    #[must_use]
    pub fn first_line(&self) -> &str {
        self.lines.first().map_or("", String::as_str)
    }

    /// True for `2yz` (positive completion) replies.
    #[must_use]
    pub const fn is_positive(&self) -> bool {
        self.code / 100 == 2
    }

    /// True for `1yz` (positive preliminary) replies.
    #[must_use]
    pub const fn is_preliminary(&self) -> bool {
        self.code / 100 == 1
    }
}

/// Split one complete reply off the front of `buf`.
///
/// Returns the reply and the bytes it used, or `None` while it is
/// incomplete. A multi-line reply starts `ddd-` and ends at the first line
/// that starts `ddd ` (or is just `ddd`) with the same code. Lines in
/// between may repeat the `ddd-` prefix (SMTP always does, FTP may not);
/// it is removed when present.
///
/// ```
/// use rune_probe_mail::parse_reply;
///
/// let buf = b"250-mx.test\r\n250-STARTTLS\r\n250 SIZE 10240000\r\n";
/// let (reply, used) = parse_reply(buf)?.unwrap();
/// assert_eq!(reply.code, 250);
/// assert_eq!(reply.lines, ["mx.test", "STARTTLS", "SIZE 10240000"]);
/// assert_eq!(used, buf.len());
///
/// let ftp = b"211-Features:\r\n MDTM\r\n AUTH TLS\r\n211 End\r\n";
/// assert_eq!(parse_reply(ftp)?.unwrap().0.lines, ["Features:", " MDTM", " AUTH TLS", "End"]);
/// assert_eq!(parse_reply(b"220 partial")?, None);
/// assert!(parse_reply(b"SSH-2.0-OpenSSH_9.6\r\n").is_err());
/// # Ok::<(), rune_probe_mail::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Malformed`] when the first line is not a reply line, and
/// [`Error::TooManyLines`] past [`MAX_REPLY_LINES`].
pub fn parse_reply(buf: &[u8]) -> Result<Option<(Reply, usize)>, Error> {
    let Some((first, mut rest)) = split_line(buf) else {
        // Reject non-replies early instead of buffering them.
        let head = buf.get(..4.min(buf.len())).unwrap_or_default();
        if !head.iter().take(3).all(u8::is_ascii_digit)
            || head.get(3).is_some_and(|&b| b != b' ' && b != b'-')
        {
            return Err(Error::Malformed("reply code"));
        }
        return Ok(None);
    };
    let (code, multi, text) = reply_line(first).ok_or(Error::Malformed("reply code"))?;
    let mut lines = vec![printable(text, MAX_LINE_BYTES)];
    if multi {
        let code_bytes = code.to_string().into_bytes();
        loop {
            let Some((line, next)) = split_line(rest) else {
                return Ok(None);
            };
            rest = next;
            if lines.len() >= MAX_REPLY_LINES {
                return Err(Error::TooManyLines);
            }
            match line.strip_prefix(code_bytes.as_slice()) {
                Some([]) => {
                    lines.push(String::new());
                    break;
                }
                Some(tail) if tail.first() == Some(&b' ') => {
                    lines.push(printable(tail.get(1..).unwrap_or_default(), MAX_LINE_BYTES));
                    break;
                }
                Some(tail) if tail.first() == Some(&b'-') => {
                    lines.push(printable(tail.get(1..).unwrap_or_default(), MAX_LINE_BYTES));
                }
                _ => lines.push(printable(line, MAX_LINE_BYTES)),
            }
        }
    }
    Ok(Some((Reply { code, lines }, buf.len() - rest.len())))
}

/// `(code, continues, text)` for a line that starts with a reply code.
fn reply_line(line: &[u8]) -> Option<(u16, bool, &[u8])> {
    let digits = line.get(..3)?;
    let mut code = 0u16;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        code = code * 10 + u16::from(d - b'0');
    }
    if !(100..600).contains(&code) {
        return None;
    }
    match line.get(3) {
        None => Some((code, false, &[])),
        Some(b' ') => Some((code, false, line.get(4..).unwrap_or_default())),
        Some(b'-') => Some((code, true, line.get(4..).unwrap_or_default())),
        Some(_) => None,
    }
}

/// Find the first `needle` in `text` and read a version right after it:
/// separators (` /_-(:,`), an optional `version` word and `v` are skipped,
/// and the version is the run of ASCII letters, digits and dots that
/// follows, when it starts with a digit.
pub fn detect_product(text: &str, table: &[(&str, &str)]) -> Option<(String, Option<String>)> {
    for &(needle, product) in table {
        let Some(at) = text.find(needle) else {
            continue;
        };
        let after = text.get(at + needle.len()..).unwrap_or_default();
        let after = after.trim_start_matches([' ', '/', '_', '-', '(', ':', ',']);
        let after = after
            .strip_prefix("version")
            .or_else(|| after.strip_prefix("Version"))
            .map_or(after, |rest| rest.trim_start_matches([' ', ':']));
        let after = after
            .strip_prefix('v')
            .filter(|s| s.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(after);
        let version: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
            .collect();
        let version = version
            .starts_with(|c: char| c.is_ascii_digit())
            .then(|| version.trim_end_matches('.').to_owned());
        return Some((product.to_owned(), version));
    }
    None
}

/// Keep a client-supplied command argument to safe characters: no CR, LF
/// or spaces, at most 255 bytes.
pub fn sanitize_arg(arg: &str, allowed: impl Fn(char) -> bool) -> String {
    arg.chars().filter(|&c| allowed(c)).take(255).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies() {
        let (r, used) = parse_reply(b"220\r\nrest").unwrap().unwrap();
        assert_eq!(
            (r.code, r.lines.as_slice(), used),
            (220, &[String::new()][..], 5)
        );
        let (r, _) = parse_reply(b"421-a\n421\n").unwrap().unwrap();
        assert_eq!(r.lines, ["a", ""]);
        assert_eq!(parse_reply(b"250-a\r\n250-b\r\n").unwrap(), None);
        assert_eq!(parse_reply(b"").unwrap(), None);
        assert_eq!(parse_reply(b"22").unwrap(), None);
        for bad in [
            &b"HTTP/1.1 200"[..],
            b"2200 x\r\n",
            b"099 x\r\n",
            b"abc\r\n",
            b"22x",
        ] {
            assert!(parse_reply(bad).is_err(), "{bad:?}");
        }
        let (r, _) = parse_reply(b"220 hi \x1b[2J\r\n").unwrap().unwrap();
        assert_eq!(r.first_line(), r"hi \x1b[2J");

        let mut many = b"250-x\r\n".to_vec();
        for _ in 0..MAX_REPLY_LINES {
            many.extend_from_slice(b"250-y\r\n");
        }
        many.extend_from_slice(b"250 z\r\n");
        assert_eq!(parse_reply(&many), Err(Error::TooManyLines));
    }

    #[test]
    fn products() {
        let table = [
            ("Exim", "Exim"),
            ("Sendmail", "Sendmail"),
            ("FileZilla Server", "FileZilla Server"),
            ("Serv-U FTP Server", "Serv-U"),
            ("Microsoft ESMTP MAIL Service", "Microsoft SMTP Service"),
        ];
        let cases = [
            ("mx ESMTP Exim 4.96 Mon, 1 Jan", Some("4.96")),
            ("mx ESMTP Sendmail 8.15.2/8.15.2; Mon", Some("8.15.2")),
            ("FileZilla Server version 0.9.41 beta", Some("0.9.41")),
            ("Serv-U FTP Server v15.1 ready...", Some("15.1")),
            ("FileZilla Server 1.7.0", Some("1.7.0")),
            ("Exim ready", None),
            (
                "Microsoft ESMTP MAIL Service, Version: 10.0.17763.1697 ready",
                Some("10.0.17763.1697"),
            ),
        ];
        for (text, version) in cases {
            let (_, got) = detect_product(text, &table).unwrap();
            assert_eq!(got.as_deref(), version, "{text}");
        }
        assert_eq!(detect_product("nothing", &table), None);
    }
}

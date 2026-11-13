//! Chunked redaction: a sans-I/O [`StreamRedactor`] and the blocking
//! [`RedactingWriter`].

use std::io::{self, Write};

use crate::redactor::Redactor;

/// Default number of trailing bytes held back between chunks.
pub const DEFAULT_WINDOW: usize = 1024;

/// Default hard limit on buffered bytes before output is forced.
pub const DEFAULT_MAX_BUFFER: usize = 64 * 1024;

/// Redacts text that arrives in chunks, without buffering the whole payload.
///
/// Each [`push`](Self::push) returns the redacted output that is final so
/// far; [`finish`](Self::finish) returns the rest. A value split across two
/// chunks is still caught: the redactor holds back the last
/// [`window`](Self::with_window) bytes and cuts at a line boundary where it
/// can, otherwise never inside a detection or inside a run of
/// non-whitespace, so the held-back text is scanned again with the next
/// chunk.
///
/// Detections longer than the window, and context-dependent credential
/// rules on lines longer than the window, may be missed. If the buffer grows past
/// [`max_buffer`](Self::with_max_buffer) (a single huge token with no
/// whitespace), output is forced at the window boundary; a detection
/// crossing that point is still redacted whole.
///
/// With [`line_boundaries`](Self::with_line_boundaries) on, every complete
/// line is emitted as soon as its newline arrives: the right mode for logs.
/// The one multi-line detection, a PEM private key, is held back until its
/// END line arrives (or the buffer limit forces it out, redacted).
///
/// # Example
///
/// ```rust
/// use rune_redact::Redactor;
///
/// let mut stream = Redactor::default().stream();
/// let mut out = String::new();
/// for chunk in ["mail bob@exam", "ple.com about card 4111 1111 ", "1111 1111 please"] {
///     out += &stream.push(chunk);
/// }
/// out += &stream.finish();
/// assert_eq!(out, "mail [EMAIL] about card [CC] please");
/// ```
#[derive(Debug)]
pub struct StreamRedactor {
    redactor: Redactor,
    buf: String,
    utf8_tail: Vec<u8>,
    window: usize,
    max_buffer: usize,
    line_boundaries: bool,
}

impl StreamRedactor {
    /// A stream redactor using `redactor`'s policy and vault.
    #[must_use]
    pub const fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            buf: String::new(),
            utf8_tail: Vec::new(),
            window: DEFAULT_WINDOW,
            max_buffer: DEFAULT_MAX_BUFFER,
            line_boundaries: false,
        }
    }

    /// Sets how many trailing bytes are held back between chunks: an upper
    /// bound on the length of a value guaranteed to be caught across a chunk
    /// boundary. Default [`DEFAULT_WINDOW`].
    #[must_use]
    pub const fn with_window(mut self, window: usize) -> Self {
        self.window = window;
        self
    }

    /// Sets the buffer size past which output is forced. Raised to at least
    /// twice the window. Default [`DEFAULT_MAX_BUFFER`].
    #[must_use]
    pub const fn with_max_buffer(mut self, max_buffer: usize) -> Self {
        self.max_buffer = max_buffer;
        self
    }

    /// Treats newlines as hard boundaries: complete lines are emitted at
    /// once and no detection spans two lines.
    #[must_use]
    pub const fn with_line_boundaries(mut self, on: bool) -> Self {
        self.line_boundaries = on;
        self
    }

    /// The redactor in use.
    #[must_use]
    pub const fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Bytes received but not yet emitted.
    #[must_use]
    pub const fn pending_len(&self) -> usize {
        self.buf.len() + self.utf8_tail.len()
    }

    /// Feeds a chunk and returns the output that is now final.
    #[must_use]
    pub fn push(&mut self, chunk: &str) -> String {
        self.flush_utf8_tail();
        self.buf.push_str(chunk);
        self.drain(false)
    }

    /// Feeds raw bytes. A UTF-8 sequence split across chunks is reassembled;
    /// invalid bytes become U+FFFD.
    #[must_use]
    pub fn push_bytes(&mut self, chunk: &[u8]) -> String {
        let mut bytes = std::mem::take(&mut self.utf8_tail);
        bytes.extend_from_slice(chunk);
        let mut rest = bytes.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    self.buf.push_str(s);
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    self.buf
                        .push_str(std::str::from_utf8(valid).unwrap_or_default());
                    if let Some(bad) = e.error_len() {
                        self.buf.push(char::REPLACEMENT_CHARACTER);
                        rest = after.get(bad..).unwrap_or_default();
                    } else {
                        // An incomplete sequence at the end: wait for more.
                        self.utf8_tail = after.to_vec();
                        break;
                    }
                }
            }
        }
        self.drain(false)
    }

    /// Ends the stream: returns the redacted remainder and resets the
    /// redactor for reuse.
    #[must_use]
    pub fn finish(&mut self) -> String {
        self.flush_utf8_tail();
        self.drain(true)
    }

    fn flush_utf8_tail(&mut self) {
        if !self.utf8_tail.is_empty() {
            self.utf8_tail.clear();
            self.buf.push(char::REPLACEMENT_CHARACTER);
        }
    }

    fn drain(&mut self, all: bool) -> String {
        let len = self.buf.len();
        // Only private keys match across a newline (handled below), so
        // everything up to the last newline is otherwise final in line mode.
        let line_cut = if self.line_boundaries {
            self.buf.rfind('\n').map_or(0, |i| i + 1)
        } else {
            0
        };
        if !all && len <= self.window && line_cut == 0 {
            return String::new();
        }
        let detections = self.redactor.detect(&self.buf);

        let cut = if all {
            len
        } else {
            let target = floor_char_boundary(&self.buf, len.saturating_sub(self.window));
            let head = self.buf.get(..target).unwrap_or_default();
            // Prefer a line boundary: rules with keyword or context
            // (`password = "…"`) work per line, so whole lines keep them.
            let mut cut = head
                .rfind('\n')
                .map_or_else(|| safe_cut(&self.buf, &detections, target), |i| i + 1)
                .max(line_cut);
            // Never emit part of a detection, and hold back a private key
            // whose END line has not arrived yet: more of it may follow.
            if let Some(d) = detections
                .iter()
                .find(|d| d.start < cut && (cut < d.end || is_open_key(&self.buf, d)))
            {
                cut = d.start;
            }
            if cut == 0 && len > self.max_buffer.max(self.window.saturating_mul(2)) {
                // Forced: never split a detection, extend past it instead.
                cut = detections
                    .iter()
                    .find(|d| d.start < target && target < d.end)
                    .map_or(target, |d| d.end);
            }
            cut
        };
        if cut == 0 {
            return String::new();
        }

        let head = self.buf.get(..cut).unwrap_or_default();
        let done = detections.partition_point(|d| d.end <= cut);
        let mut out = String::with_capacity(cut);
        self.redactor
            .render(head, detections.get(..done).unwrap_or_default(), &mut out);
        self.buf.drain(..cut);
        out
    }
}

/// Moves `cut` back until it is neither inside a detection nor inside a run
/// of non-whitespace.
/// Whether `d` is a private key whose END line is not in `buf` and whose
/// body may still continue in the next chunk (nothing but blank space or a
/// partial line follows it).
fn is_open_key(buf: &str, d: &crate::Detection) -> bool {
    d.category == crate::Category::PrivateKey
        && !d.value(buf).unwrap_or_default().contains("-----END")
        && !buf
            .get(d.end..)
            .unwrap_or_default()
            .trim_start()
            .contains('\n')
}

fn safe_cut(buf: &str, detections: &[crate::Detection], mut cut: usize) -> usize {
    loop {
        let before = cut;
        if let Some(d) = detections.iter().find(|d| d.start < cut && cut < d.end) {
            cut = d.start;
        }
        let ws = |c: char| c.is_whitespace();
        let left = buf.get(..cut).and_then(|s| s.chars().next_back());
        let right = buf.get(cut..).and_then(|s| s.chars().next());
        if let (Some(l), Some(r)) = (left, right)
            && !ws(l)
            && !ws(r)
        {
            cut = buf
                .get(..cut)
                .and_then(|s| s.rfind(ws))
                .map_or(0, |i| i + buf[i..].chars().next().map_or(1, char::len_utf8));
        }
        if cut == before {
            return cut;
        }
    }
}

const fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// A [`Write`] adapter that redacts everything written through it.
///
/// Output is delayed by the [`StreamRedactor`] window: [`flush`](Write::flush)
/// flushes what is final, and [`finish`](Self::finish) (or drop) writes the
/// held-back tail. Call `finish` to see errors from that last write.
///
/// # Example
///
/// ```rust
/// use std::io::Write;
/// use rune_redact::{RedactingWriter, Redactor};
///
/// let mut w = RedactingWriter::new(Vec::new(), Redactor::default());
/// w.write_all(b"token: Bearer abc")?;
/// w.write_all(b"def123\nssn 123-45-6789\n")?;
/// let out = w.finish()?;
/// assert_eq!(String::from_utf8(out).unwrap(), "token: [BEARER]\nssn [SSN]\n");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct RedactingWriter<W: Write> {
    inner: Option<W>,
    stream: StreamRedactor,
    pending: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    /// Wraps `inner`, redacting with `redactor`.
    pub const fn new(inner: W, redactor: Redactor) -> Self {
        Self::with_stream(inner, StreamRedactor::new(redactor))
    }

    /// Wraps `inner` with a configured [`StreamRedactor`].
    pub const fn with_stream(inner: W, stream: StreamRedactor) -> Self {
        Self {
            inner: Some(inner),
            stream,
            pending: Vec::new(),
        }
    }

    /// The wrapped writer.
    pub const fn get_ref(&self) -> Option<&W> {
        self.inner.as_ref()
    }

    /// The wrapped writer, mutably. Writing to it directly bypasses redaction.
    pub const fn get_mut(&mut self) -> Option<&mut W> {
        self.inner.as_mut()
    }

    fn write_pending(&mut self) -> io::Result<()> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(());
        };
        while !self.pending.is_empty() {
            match inner.write(&self.pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.pending.drain(..n.min(self.pending.len()));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes the held-back tail, flushes, and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.finish_in_place()?;
        self.inner
            .take()
            .ok_or_else(|| io::Error::other("writer already finished"))
    }

    fn finish_in_place(&mut self) -> io::Result<()> {
        let tail = self.stream.finish();
        self.pending.extend_from_slice(tail.as_bytes());
        self.write_pending()?;
        self.inner.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.inner.is_none() {
            return Err(io::Error::other("writer already finished"));
        }
        self.write_pending()?;
        let out = self.stream.push_bytes(buf);
        self.pending.extend_from_slice(out.as_bytes());
        // `buf` is consumed now; a failure here surfaces on the next call
        // and the output stays pending, so nothing is written twice.
        let _ = self.write_pending();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_pending()?;
        self.inner.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            // Best effort, like `BufWriter`: errors cannot be reported here.
            let _ = self.finish_in_place();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Category, Policy, Replacement};

    fn chunked(stream: &mut StreamRedactor, text: &str, size: usize) -> String {
        let bytes = text.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(size.max(1)) {
            out += &stream.push_bytes(chunk);
        }
        out + &stream.finish()
    }

    const SAMPLE: &str = "user bob@example.com logged in from 192.168.1.10\n\
        auth=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln ok\n\
        card 4111 1111 1111 1111 ssn 123-45-6789 phone (555) 123-4567\n\
        key sK3xPq9mNbYrVwZuAtJhCf7DgLeW2oI5qR8eMvXn aws AKIAIOSFODNN7EXAMPLE é\n";

    #[test]
    fn every_chunk_size_matches_one_shot() {
        let r = Redactor::default();
        let want = r.redact(SAMPLE);
        for size in 1..=SAMPLE.len() {
            for window in [64, 256] {
                for lines in [false, true] {
                    let mut s = r.stream().with_window(window).with_line_boundaries(lines);
                    assert_eq!(chunked(&mut s, SAMPLE, size), want, "size {size}");
                }
            }
        }
    }

    // Regression: a PEM private key spans several lines, and line mode
    // (or a window cut at a newline) emitted the first lines before the
    // END line arrived, so the key body went out unredacted.
    #[test]
    fn private_key_split_across_chunks_is_redacted_whole() {
        let text = "before\n-----BEGIN PRIVATE KEY-----\n\
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf+/P7VnzoQyH+/F6\n\
            n3sVp0RGmSdIKYeaFxns1vjuXfmhRANCAAQV7oIVVRc7OI2lrPc6WNmi7ZmQywRK\n\
            g8mi6bswL0UwjsNB4JWJNvAlVqinM2nbksSeEKFga2saLK8v92voHvOh\n\
            -----END PRIVATE KEY-----\nafter a@b.io\n";
        let r = Redactor::new(Policy::none().with_category(Category::PrivateKey)).unwrap();
        let want = "before\n[PRIVATE_KEY]\nafter a@b.io\n";
        assert_eq!(r.redact(text), want);
        for size in [1, 7, 30, 64, 100] {
            for window in [32, 64, 1024] {
                for lines in [false, true] {
                    let mut s = r.stream().with_window(window).with_line_boundaries(lines);
                    assert_eq!(
                        chunked(&mut s, text, size),
                        want,
                        "size {size} window {window} lines {lines}"
                    );
                }
            }
        }
    }

    #[test]
    fn output_is_incremental() {
        let mut s = Redactor::default().stream().with_window(16);
        let early = s.push(&"word ".repeat(20));
        assert_ne!(early, "");
        assert!(s.pending_len() <= 16);
    }

    #[test]
    fn line_mode_emits_complete_lines() {
        let mut s = Redactor::default().stream().with_line_boundaries(true);
        assert_eq!(s.push("mail a@b.io\npartial"), "mail [EMAIL]\n");
        assert_eq!(s.finish(), "partial");
    }

    #[test]
    fn forced_output_never_splits_a_detection() {
        let r = Redactor::new(
            Policy::none()
                .with_category(Category::Email)
                .with_replacement(Replacement::Label),
        )
        .unwrap();
        let mut s = r.stream().with_window(4).with_max_buffer(8);
        let text = format!("{}a@b.io{}", "x".repeat(30), "y".repeat(30));
        let out = chunked(&mut s, &text, 3);
        assert!(!out.contains("a@b.io"));
    }

    #[test]
    fn invalid_utf8_becomes_replacement_char() {
        let mut s = Redactor::default().stream();
        let mut out = s.push_bytes(b"ok \xff \xc3");
        out += &s.push_bytes(b"\xa9 \xe2\x82");
        out += &s.finish();
        assert_eq!(out, "ok \u{fffd} é \u{fffd}");
    }

    #[test]
    fn writer_redacts_across_writes_and_flushes_on_drop() {
        let mut sink = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut sink, Redactor::default());
            for b in SAMPLE.as_bytes() {
                w.write_all(&[*b]).unwrap();
            }
            w.flush().unwrap();
        }
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            Redactor::default().redact(SAMPLE)
        );
    }

    struct Flaky {
        out: Vec<u8>,
        fail_next: bool,
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.fail_next) {
                return Err(io::Error::other("boom"));
            }
            let n = buf.len().min(3);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_retries_pending_output_after_an_error() {
        let flaky = Flaky {
            out: Vec::new(),
            fail_next: false,
        };
        let s = Redactor::default().stream().with_window(0);
        let mut w = RedactingWriter::with_stream(flaky, s);
        w.write_all(b"a@b.io ").unwrap();
        if let Some(f) = w.get_mut() {
            f.fail_next = true;
        }
        w.write_all(b"one two ").unwrap();
        w.write_all(b"three").unwrap();
        let f = w.finish().unwrap();
        assert_eq!(String::from_utf8(f.out).unwrap(), "[EMAIL] one two three");
    }
}

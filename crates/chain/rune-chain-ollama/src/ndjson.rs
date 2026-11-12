//! Bounded, panic-free newline-delimited JSON line splitting.
//!
//! [`LineSplitter`] is a sans-I/O core: feed it raw bytes in arbitrary
//! chunks and it returns complete lines. Lines are split on raw bytes, so a
//! multi-byte UTF-8 character split across chunks stays intact. A line longer
//! than the line limit, or a body larger than the total limit, is an error
//! instead of an unbounded allocation.

use futures::{Stream, StreamExt};
use rune_chain_core::LlmError;

/// Size limits for an NDJSON body.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest single line, in bytes (without the `\n`).
    pub max_line: usize,
    /// Most bytes in the whole body.
    pub max_total: usize,
}

/// Splits a byte stream into lines under [`Limits`].
#[derive(Debug)]
pub struct LineSplitter {
    limits: Limits,
    buf: Vec<u8>,
    /// Bytes of `buf` already scanned for `\n`.
    scanned: usize,
    total: usize,
}

impl LineSplitter {
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            buf: Vec::new(),
            scanned: 0,
            total: 0,
        }
    }

    /// Feed a chunk; returns every line it completes (without `\n`; a
    /// trailing `\r` is kept and trimmed by the JSON layer).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, LlmError> {
        self.total = self.total.saturating_add(chunk.len());
        if self.total > self.limits.max_total {
            return Err(LlmError::invalid_response(format!(
                "response stream exceeds the {}-byte limit",
                self.limits.max_total
            )));
        }
        self.buf.extend_from_slice(chunk);
        let mut lines = Vec::new();
        let mut start = 0;
        let mut pos = self.scanned;
        while let Some(off) = self.buf[pos..].iter().position(|&b| b == b'\n') {
            let end = pos + off;
            self.check_line(end - start)?;
            lines.push(self.buf[start..end].to_vec());
            start = end + 1;
            pos = start;
        }
        self.buf.drain(..start);
        self.scanned = self.buf.len();
        self.check_line(self.buf.len())?;
        Ok(lines)
    }

    /// End of input: the final unterminated line, if any.
    pub fn finish(&mut self) -> Option<Vec<u8>> {
        self.scanned = 0;
        (!self.buf.is_empty()).then(|| std::mem::take(&mut self.buf))
    }

    fn check_line(&self, len: usize) -> Result<(), LlmError> {
        if len > self.limits.max_line {
            return Err(LlmError::invalid_response(format!(
                "response stream line exceeds the {}-byte limit",
                self.limits.max_line
            )));
        }
        Ok(())
    }
}

/// Turn a byte stream into a stream of NDJSON lines under `limits`.
///
/// Blank lines are skipped. The stream ends at end of input (after any final
/// unterminated line) or after the first error, which is yielded as an item:
/// transport errors as [`LlmError::request_failed`], limit violations as
/// [`LlmError::invalid_response`].
pub fn lines<S, B, E>(
    body: S,
    limits: Limits,
) -> impl Stream<Item = Result<Vec<u8>, LlmError>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + Unpin,
    B: AsRef<[u8]> + Send,
    E: std::fmt::Display + Send,
{
    let mut body = body;
    async_stream::stream! {
        let mut splitter = LineSplitter::new(limits);
        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    yield Err(LlmError::request_failed(e.to_string()));
                    return;
                }
            };
            match splitter.push(chunk.as_ref()) {
                Ok(lines) => {
                    for line in lines {
                        if !is_blank(&line) {
                            yield Ok(line);
                        }
                    }
                }
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
        if let Some(line) = splitter.finish().filter(|l| !is_blank(l)) {
            yield Ok(line);
        }
    }
}

fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::LlmErrorKind;

    const BIG: Limits = Limits {
        max_line: 1 << 20,
        max_total: 1 << 24,
    };

    fn split_all(body: &[u8], size: usize, limits: Limits) -> Result<Vec<Vec<u8>>, LlmError> {
        let mut s = LineSplitter::new(limits);
        let mut out = Vec::new();
        for c in body.chunks(size.max(1)) {
            out.extend(s.push(c)?);
        }
        out.extend(s.finish());
        Ok(out)
    }

    #[test]
    fn splits_at_any_chunking() {
        let body = b"a\nbb\n\nccc";
        for size in 1..=body.len() {
            let lines = split_all(body, size, BIG).unwrap();
            assert_eq!(lines, [&b"a"[..], b"bb", b"", b"ccc"], "size {size}");
        }
    }

    #[test]
    fn long_line_is_an_error_even_without_newline() {
        let limits = Limits {
            max_line: 4,
            max_total: 1000,
        };
        assert!(split_all(b"1234\n5678\n", 3, limits).is_ok());
        assert!(matches!(
            split_all(b"12345\n", 2, limits),
            Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("line")
        ));
        // Never terminated: caught while buffering, not at the end.
        let mut s = LineSplitter::new(limits);
        assert!(s.push(b"123").is_ok());
        assert!(s.push(b"45").is_err());
    }

    #[test]
    fn total_cap_is_enforced() {
        let limits = Limits {
            max_line: 100,
            max_total: 10,
        };
        assert!(split_all(b"12345\n1234", 3, limits).is_ok());
        assert!(matches!(
            split_all(b"12345\n12345", 3, limits),
            Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("stream")
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A small deterministic fuzz: pseudo-random bytes and chunk sizes.
        let mut x: u32 = 0x1234_5678;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..200 {
            let len = (next() % 300) as usize;
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    if next() % 7 == 0 {
                        b'\n'
                    } else {
                        next().to_le_bytes()[0]
                    }
                })
                .collect();
            let size = (next() % 17) as usize + 1;
            let limits = Limits {
                max_line: (next() % 64) as usize,
                max_total: (next() % 400) as usize,
            };
            let _ = split_all(&body, size, limits);
        }
    }

    #[test]
    fn stream_adapter_skips_blank_lines_and_reports_transport_errors() {
        let chunks = futures::stream::iter([
            Ok(b"a\n \r\nb".to_vec()),
            Ok(b"\n".to_vec()),
            Err(std::io::Error::other("reset")),
        ]);
        let items: Vec<_> = futures::executor::block_on(lines(chunks, BIG).collect());
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_ref().unwrap(), b"a");
        assert_eq!(items[1].as_ref().unwrap(), b"b");
        assert!(
            matches!(&items[2], Err(m) if m.kind() == LlmErrorKind::Network && m.message() == "reset")
        );
    }
}

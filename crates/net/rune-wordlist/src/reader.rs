//! Streaming, tamper-checked list reading.

use std::io::{BufRead, BufReader, Read};

use sha2::{Digest as _, Sha256};

use crate::{Error, ListEntry};

/// How lines are split and filtered. Applies to [`ListReader`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOptions {
    /// Longest accepted line in bytes, excluding the line ending. A longer
    /// line is an error rather than an unbounded allocation. Default 64 KiB.
    pub max_line_len: usize,
    /// Skip lines whose first byte is `#`. Default `false`: in payload lists
    /// a leading `#` is often part of the payload.
    pub skip_comments: bool,
    /// Skip empty lines. Default `true`.
    pub skip_blank: bool,
    /// Strip one trailing `\r` from each line (CRLF files). Default `true`.
    pub trim_cr: bool,
    /// Size of the read buffer in bytes. Default 64 KiB.
    pub buffer_size: usize,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            max_line_len: 64 * 1024,
            skip_comments: false,
            skip_blank: true,
            trim_cr: true,
            buffer_size: 64 * 1024,
        }
    }
}

impl ReadOptions {
    /// Sets [`max_line_len`](Self::max_line_len).
    #[must_use]
    pub const fn with_max_line_len(mut self, max: usize) -> Self {
        self.max_line_len = max;
        self
    }

    /// Sets [`skip_comments`](Self::skip_comments).
    #[must_use]
    pub const fn with_skip_comments(mut self, skip: bool) -> Self {
        self.skip_comments = skip;
        self
    }

    /// Sets [`skip_blank`](Self::skip_blank).
    #[must_use]
    pub const fn with_skip_blank(mut self, skip: bool) -> Self {
        self.skip_blank = skip;
        self
    }

    /// Sets [`trim_cr`](Self::trim_cr).
    #[must_use]
    pub const fn with_trim_cr(mut self, trim: bool) -> Self {
        self.trim_cr = trim;
        self
    }

    /// Sets [`buffer_size`](Self::buffer_size).
    #[must_use]
    pub const fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
}

/// Reads a list one line at a time with bounded memory, hashing every byte.
///
/// The reader holds one read buffer and, through [`read_entry`](Self::read_entry),
/// reuses the caller's line buffer, so memory does not grow with the list.
/// Integrity is checked as the bytes go by: reading past the size pinned in
/// the manifest fails at once, and at the end of the input the SHA-256 and
/// size must match, or the last call returns [`Error::Tampered`]. Lines read
/// before that point came from the (tampered) input; open the pack with
/// [`Verify::Eager`](crate::Verify::Eager) to reject a tampered list before
/// any line is used. After any error the reader yields nothing more.
///
/// Works on any [`Read`], so lists can come from files, archives or memory:
///
/// ```
/// use rune_wordlist::{ListEntry, ListReader, ReadOptions, sha256};
///
/// let data = b"admin\nlogin\n\nbackup\n";
/// let entry = ListEntry::new("dirs", "dirs.txt", sha256(data), data.len() as u64);
/// let words: Vec<String> = ListReader::new(&data[..], &entry, &ReadOptions::default())
///     .lines()
///     .collect::<Result<_, _>>()?;
/// assert_eq!(words, ["admin", "login", "backup"]);
///
/// let tampered = b"admin\nlogin\n\nbackdoor\n";
/// let result: Result<Vec<_>, _> =
///     ListReader::new(&tampered[..], &entry, &ReadOptions::default()).collect();
/// assert!(matches!(result, Err(rune_wordlist::Error::Tampered { .. })));
/// # Ok::<(), rune_wordlist::Error>(())
/// ```
#[derive(Debug)]
pub struct ListReader<R> {
    inner: BufReader<R>,
    list: String,
    expected_sha256: [u8; 32],
    expected_size: u64,
    options: ReadOptions,
    hasher: Sha256,
    bytes: u64,
    line: u64,
    done: bool,
}

impl<R: Read> ListReader<R> {
    /// A reader over `inner` that checks it against `entry`.
    pub fn new(inner: R, entry: &ListEntry, options: &ReadOptions) -> Self {
        Self {
            inner: BufReader::with_capacity(options.buffer_size.max(1), inner),
            list: entry.name.clone(),
            expected_sha256: entry.sha256,
            expected_size: entry.size,
            options: options.clone(),
            hasher: Sha256::new(),
            bytes: 0,
            line: 0,
            done: false,
        }
    }

    /// Reads the next entry into `buf` (cleared first), without the line
    /// ending. Returns `Ok(false)` at the end of a list that verified.
    pub fn read_entry(&mut self, buf: &mut Vec<u8>) -> Result<bool, Error> {
        buf.clear();
        if self.done {
            return Ok(false);
        }
        let result = self.next_entry(buf);
        if !matches!(result, Ok(true)) {
            self.done = true;
        }
        result
    }

    /// Bytes consumed so far.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes
    }

    /// Physical lines consumed so far, including skipped ones.
    #[must_use]
    pub const fn line_number(&self) -> u64 {
        self.line
    }

    /// An iterator over entries as UTF-8 strings. A line that is not valid
    /// UTF-8 ends it with an [`Error::ReadList`] of kind `InvalidData`; use
    /// the byte iterator (the reader itself) for binary payloads.
    pub const fn lines(self) -> Lines<R> {
        Lines(self)
    }

    fn next_entry(&mut self, buf: &mut Vec<u8>) -> Result<bool, Error> {
        loop {
            buf.clear();
            if !self.read_raw_line(buf)? {
                self.finish()?;
                return Ok(false);
            }
            self.line += 1;
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if self.options.trim_cr && buf.last() == Some(&b'\r') {
                buf.pop();
            }
            if buf.len() > self.options.max_line_len {
                return Err(self.too_long());
            }
            if (self.options.skip_blank && buf.is_empty())
                || (self.options.skip_comments && buf.first() == Some(&b'#'))
            {
                continue;
            }
            return Ok(true);
        }
    }

    /// Appends one raw line (with its `\n`, if any) to `buf`, hashing it.
    /// Returns `false` at end of input with nothing read.
    fn read_raw_line(&mut self, buf: &mut Vec<u8>) -> Result<bool, Error> {
        // Room for the content plus "\r\n".
        let cap = self.options.max_line_len.saturating_add(2);
        let mut any = false;
        loop {
            let avail = match self.inner.fill_buf() {
                Ok(avail) => avail,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(Error::ReadList {
                        list: self.list.clone(),
                        source,
                    });
                }
            };
            if avail.is_empty() {
                return Ok(any);
            }
            let (len, found) = avail
                .iter()
                .position(|&b| b == b'\n')
                .map_or((avail.len(), false), |i| (i + 1, true));
            let chunk = &avail[..len];
            self.hasher.update(chunk);
            self.bytes = self.bytes.saturating_add(len as u64);
            if self.bytes > self.expected_size {
                return Err(Error::Tampered {
                    list: self.list.clone(),
                    reason: format!("more than the {} bytes in the manifest", self.expected_size),
                });
            }
            if buf.len() + len > cap {
                self.line += 1;
                return Err(self.too_long());
            }
            buf.extend_from_slice(chunk);
            self.inner.consume(len);
            any = true;
            if found {
                return Ok(true);
            }
        }
    }

    fn finish(&mut self) -> Result<(), Error> {
        if self.bytes != self.expected_size {
            return Err(Error::Tampered {
                list: self.list.clone(),
                reason: format!(
                    "{} bytes, the manifest says {}",
                    self.bytes, self.expected_size
                ),
            });
        }
        let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
        if digest != self.expected_sha256 {
            return Err(Error::Tampered {
                list: self.list.clone(),
                reason: "SHA-256 does not match the manifest".to_owned(),
            });
        }
        Ok(())
    }

    fn too_long(&self) -> Error {
        Error::LineTooLong {
            list: self.list.clone(),
            line: self.line,
            max: self.options.max_line_len,
        }
    }
}

impl<R: Read> Iterator for ListReader<R> {
    type Item = Result<Vec<u8>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        match self.read_entry(&mut buf) {
            Ok(true) => Some(Ok(buf)),
            Ok(false) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<R: Read> std::iter::FusedIterator for ListReader<R> {}

/// Entries as UTF-8 strings; see [`ListReader::lines`].
#[derive(Debug)]
pub struct Lines<R>(ListReader<R>);

impl<R: Read> Iterator for Lines<R> {
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        Some(item.and_then(|bytes| {
            String::from_utf8(bytes).map_err(|e| {
                self.0.done = true;
                Error::ReadList {
                    list: self.0.list.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()),
                }
            })
        }))
    }
}

impl<R: Read> std::iter::FusedIterator for Lines<R> {}

/// SHA-256 of `data`, for building [`ListEntry`] values in memory.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Streams `reader` to its end and returns its SHA-256 and length, with
/// constant memory.
pub fn hash_reader<R: Read>(mut reader: R) -> std::io::Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Streams `reader` and checks it against `entry` without splitting lines.
pub fn verify_reader<R: Read>(reader: R, entry: &ListEntry) -> Result<(), Error> {
    let mut limited = reader.take(entry.size.saturating_add(1));
    let (digest, size) = hash_reader(&mut limited).map_err(|source| Error::ReadList {
        list: entry.name.clone(),
        source,
    })?;
    if size != entry.size {
        return Err(Error::Tampered {
            list: entry.name.clone(),
            reason: if size > entry.size {
                format!("more than the {} bytes in the manifest", entry.size)
            } else {
                format!("{size} bytes, the manifest says {}", entry.size)
            },
        });
    }
    if digest != entry.sha256 {
        return Err(Error::Tampered {
            list: entry.name.clone(),
            reason: "SHA-256 does not match the manifest".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(data: &[u8]) -> ListEntry {
        ListEntry::new("l", "l.txt", sha256(data), data.len() as u64)
    }

    fn read_all(data: &[u8], opts: &ReadOptions) -> Result<Vec<Vec<u8>>, Error> {
        ListReader::new(data, &entry_for(data), opts).collect()
    }

    #[test]
    fn splits_and_filters() {
        let data = b"a\r\n#c\n\nb\nlast";
        let got = read_all(data, &ReadOptions::default()).unwrap();
        assert_eq!(got, [&b"a"[..], b"#c", b"b", b"last"]);
        let got = read_all(data, &ReadOptions::default().with_skip_comments(true)).unwrap();
        assert_eq!(got, [&b"a"[..], b"b", b"last"]);
        let raw = ReadOptions::default()
            .with_skip_blank(false)
            .with_trim_cr(false);
        let got = read_all(data, &raw).unwrap();
        assert_eq!(got, [&b"a\r"[..], b"#c", b"", b"b", b"last"]);
    }

    #[test]
    fn empty_list() {
        assert_eq!(
            read_all(b"", &ReadOptions::default()).unwrap(),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn tiny_buffer_matches_default() {
        let data = b"alpha\nbeta\r\ngamma\n\ndelta";
        let tiny = ReadOptions::default().with_buffer_size(1);
        assert_eq!(
            read_all(data, &tiny).unwrap(),
            read_all(data, &ReadOptions::default()).unwrap()
        );
    }

    #[test]
    fn detects_tampering() {
        let data = b"one\ntwo\n";
        let entry = entry_for(data);
        let opts = ReadOptions::default();
        for bad in [&b"one\ntwx\n"[..], b"one\ntwo\nthree\n", b"one\n", b""] {
            let r: Result<Vec<_>, _> = ListReader::new(bad, &entry, &opts).collect();
            assert!(matches!(r, Err(Error::Tampered { .. })), "{bad:?}");
            assert!(matches!(
                verify_reader(bad, &entry),
                Err(Error::Tampered { .. })
            ));
        }
        verify_reader(&data[..], &entry).unwrap();
    }

    #[test]
    fn overlong_input_fails_before_reading_it_all() {
        // A list that keeps growing is cut off at the pinned size.
        let entry = entry_for(b"x\n");
        let endless = std::io::repeat(b'y');
        let mut r = ListReader::new(endless, &entry, &ReadOptions::default());
        assert!(matches!(r.next(), Some(Err(Error::Tampered { .. }))));
        assert!(r.next().is_none());
        assert!(r.bytes_read() <= 64 * 1024 + 2);
    }

    #[test]
    fn line_too_long() {
        let data = b"ok\n0123456789\n";
        let opts = ReadOptions::default().with_max_line_len(5);
        let mut r = ListReader::new(&data[..], &entry_for(data), &opts);
        assert_eq!(r.next().unwrap().unwrap(), b"ok");
        assert!(matches!(
            r.next(),
            Some(Err(Error::LineTooLong {
                line: 2,
                max: 5,
                ..
            }))
        ));
        assert!(r.next().is_none());
        // Exactly at the limit, with CRLF, is fine.
        let data = b"01234\r\n";
        assert_eq!(read_all(data, &opts).unwrap(), [b"01234"]);
    }

    #[test]
    fn lines_rejects_invalid_utf8() {
        let data = b"ok\n\xff\n";
        let mut lines =
            ListReader::new(&data[..], &entry_for(data), &ReadOptions::default()).lines();
        assert_eq!(lines.next().unwrap().unwrap(), "ok");
        assert!(lines.next().unwrap().is_err());
        assert!(lines.next().is_none());
    }

    #[test]
    fn hash_reader_matches_sha256() {
        let data = vec![0x5a; 200_000];
        assert_eq!(hash_reader(&data[..]).unwrap(), (sha256(&data), 200_000));
    }
}

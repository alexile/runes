//! A blocking adapter over [`std::io::Read`].

use std::io::{ErrorKind, Read};

use crate::{Error, Item, Options, Parser};

const CHUNK: usize = 8 * 1024;

/// Iterates over the [`Item`]s of an event stream read from `R`.
///
/// Reads in chunks and yields items as soon as they are complete, so it
/// works on a live socket or response body. At end of input an unterminated
/// event is discarded. An I/O error is yielded once as [`Error::Io`] and
/// ends the iteration; parser errors do not.
///
/// # Example
///
/// ```
/// use rune_sse::Reader;
///
/// let body: &[u8] = b"data: one\n\ndata: two\n\n";
/// let data: Vec<String> = Reader::new(body)
///     .filter_map(|item| item.ok()?.into_event())
///     .map(|event| event.data)
///     .collect();
/// assert_eq!(data, ["one", "two"]);
/// ```
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    parser: Parser,
    buf: Box<[u8]>,
    done: bool,
}

impl<R: Read> Reader<R> {
    /// Wraps `inner` with a parser using default [`Options`].
    pub fn new(inner: R) -> Self {
        Self::with_parser(inner, Parser::new())
    }

    /// Wraps `inner` with a parser using `options`.
    pub fn with_options(inner: R, options: Options) -> Self {
        Self::with_parser(inner, Parser::with_options(options))
    }

    /// Wraps `inner` with an existing parser, for example one carrying the
    /// last event ID of a previous connection.
    pub fn with_parser(inner: R, parser: Parser) -> Self {
        Self {
            inner,
            parser,
            buf: vec![0; CHUNK].into_boxed_slice(),
            done: false,
        }
    }

    /// The parser, for [`Parser::last_event_id`].
    pub const fn parser(&self) -> &Parser {
        &self.parser
    }

    /// Returns the reader and the parser.
    pub fn into_parts(self) -> (R, Parser) {
        (self.inner, self.parser)
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Item, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.parser.next_item() {
                return Some(item);
            }
            if self.done {
                return None;
            }
            match self.inner.read(&mut self.buf) {
                Ok(0) => {
                    self.parser.finish();
                    self.done = true;
                }
                Ok(n) => self.parser.push(self.buf.get(..n).unwrap_or_default()),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    self.done = true;
                    return Some(Err(Error::Io(err)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;

    /// Returns one byte per read, then an error.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.split_first() {
                Some((&b, rest)) => {
                    buf[0] = b;
                    self.0 = rest;
                    Ok(1)
                }
                None => Err(std::io::Error::other("reset")),
            }
        }
    }

    #[test]
    fn reads_trickled_input_then_reports_error_once() {
        let mut reader = Reader::new(Trickle(b"data: a\r\n\r\ndata: b\n\n"));
        assert_eq!(
            reader.next().unwrap().unwrap(),
            Item::Event(Event::new("a"))
        );
        assert_eq!(
            reader.next().unwrap().unwrap(),
            Item::Event(Event::new("b"))
        );
        assert!(matches!(reader.next(), Some(Err(Error::Io(_)))));
        assert!(reader.next().is_none());
    }

    #[test]
    fn eof_discards_unterminated_event() {
        let body: &[u8] = b"id: 3\ndata: a\n\ndata: b";
        let mut reader = Reader::new(body);
        assert_eq!(
            reader.next().unwrap().unwrap(),
            Item::Event(Event::new("a").with_id("3"))
        );
        assert!(reader.next().is_none());
        assert_eq!(reader.parser().last_event_id(), "3");
    }
}

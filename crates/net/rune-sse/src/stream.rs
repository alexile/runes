//! A `futures::Stream` adapter over a stream of byte chunks.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;

use crate::{Error, Item, Options, Parser};

/// Turns a stream of byte chunks (an HTTP response body, say) into a stream
/// of [`Item`]s. Runtime-agnostic; enabled by the `stream` feature.
///
/// Chunk errors are yielded once as [`Error::Transport`] and end the
/// stream. When the inner stream ends, an unterminated event is discarded.
///
/// # Example
///
/// ```
/// use futures::{StreamExt, executor::block_on, stream};
/// use rune_sse::SseStream;
///
/// let body = stream::iter([
///     Ok::<_, std::io::Error>(&b"data: hel"[..]),
///     Ok(&b"lo\n\n"[..]),
/// ]);
/// let events: Vec<_> = block_on(SseStream::new(body).collect());
/// let event = events[0].as_ref().unwrap().clone().into_event().unwrap();
/// assert_eq!(event.data, "hello");
/// ```
#[derive(Debug)]
pub struct SseStream<S> {
    inner: S,
    parser: Parser,
    done: bool,
}

impl<S> SseStream<S> {
    /// Wraps `inner` with a parser using default [`Options`].
    pub fn new(inner: S) -> Self {
        Self::with_parser(inner, Parser::new())
    }

    /// Wraps `inner` with a parser using `options`.
    pub fn with_options(inner: S, options: Options) -> Self {
        Self::with_parser(inner, Parser::with_options(options))
    }

    /// Wraps `inner` with an existing parser, for example one carrying the
    /// last event ID of a previous connection.
    pub const fn with_parser(inner: S, parser: Parser) -> Self {
        Self {
            inner,
            parser,
            done: false,
        }
    }

    /// The parser, for [`Parser::last_event_id`].
    pub const fn parser(&self) -> &Parser {
        &self.parser
    }

    /// Returns the inner stream and the parser.
    pub fn into_parts(self) -> (S, Parser) {
        (self.inner, self.parser)
    }
}

impl<S, B, E> Stream for SseStream<S>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Item = Result<Item, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        loop {
            if let Some(item) = this.parser.next_item() {
                return Poll::Ready(Some(item));
            }
            if this.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => this.parser.push(chunk.as_ref()),
                Poll::Ready(Some(Err(err))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(Error::Transport(err.into()))));
                }
                Poll::Ready(None) => {
                    this.parser.finish();
                    this.done = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use futures::{StreamExt, stream};

    use super::*;
    use crate::Event;

    #[test]
    fn yields_events_across_chunks_then_transport_error() {
        let chunks = stream::iter([
            Ok(b"data: a\r".to_vec()),
            Ok(b"\n\r\nid: 1\ndata: b\n".to_vec()),
            Ok(b"\n".to_vec()),
            Err(std::io::Error::other("reset")),
            Ok(b"data: never\n\n".to_vec()),
        ]);
        let items: Vec<_> = block_on(SseStream::new(chunks).collect());
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_ref().unwrap(), &Item::Event(Event::new("a")));
        assert_eq!(
            items[1].as_ref().unwrap(),
            &Item::Event(Event::new("b").with_id("1"))
        );
        assert!(matches!(items[2], Err(Error::Transport(_))));
    }

    #[test]
    fn end_of_stream_discards_partial_event() {
        let chunks = stream::iter([Ok::<_, std::io::Error>(b"data: a\n\ndata: b\n".to_vec())]);
        let mut sse = SseStream::new(chunks);
        let items: Vec<_> = block_on((&mut sse).collect());
        assert_eq!(items.len(), 1);
        assert!(block_on(sse.next()).is_none());
    }
}

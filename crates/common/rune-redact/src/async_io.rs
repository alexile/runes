//! [`AsyncRedactingWriter`], the `tokio` counterpart of
//! [`RedactingWriter`](crate::RedactingWriter).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::AsyncWrite;

use crate::redactor::Redactor;
use crate::stream::StreamRedactor;

/// A [`tokio::io::AsyncWrite`] adapter that redacts everything written
/// through it, chunk by chunk, with the same boundary handling as
/// [`StreamRedactor`].
///
/// [`poll_flush`](AsyncWrite::poll_flush) flushes what is final;
/// [`poll_shutdown`](AsyncWrite::poll_shutdown) writes the held-back tail
/// before shutting the inner writer down, so always call `shutdown()`.
///
/// # Example
///
/// ```rust
/// use rune_redact::{AsyncRedactingWriter, Redactor};
/// use tokio::io::AsyncWriteExt;
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let mut w = AsyncRedactingWriter::new(Vec::new(), Redactor::default());
/// w.write_all(b"mail bob@exa").await?;
/// w.write_all(b"mple.com\n").await?;
/// w.shutdown().await?;
/// assert_eq!(w.into_inner(), b"mail [EMAIL]\n");
/// # Ok::<(), std::io::Error>(())
/// # }).unwrap();
/// ```
#[derive(Debug)]
pub struct AsyncRedactingWriter<W> {
    inner: W,
    stream: StreamRedactor,
    pending: Vec<u8>,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> AsyncRedactingWriter<W> {
    /// Wraps `inner`, redacting with `redactor`.
    pub const fn new(inner: W, redactor: Redactor) -> Self {
        Self::with_stream(inner, StreamRedactor::new(redactor))
    }

    /// Wraps `inner` with a configured [`StreamRedactor`].
    pub const fn with_stream(inner: W, stream: StreamRedactor) -> Self {
        Self {
            inner,
            stream,
            pending: Vec::new(),
            finished: false,
        }
    }

    /// The wrapped writer.
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The wrapped writer, mutably. Writing to it directly bypasses redaction.
    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwraps the inner writer. Output not yet written (anything before a
    /// completed `shutdown`) is lost.
    pub fn into_inner(self) -> W {
        self.inner
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.drain(..n.min(self.pending.len()));
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncRedactingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Drain earlier output first, so `pending` stays bounded by one chunk.
        ready!(this.poll_pending(cx))?;
        this.finished = false;
        let out = this.stream.push_bytes(buf);
        this.pending.extend_from_slice(out.as_bytes());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.finished {
            let tail = this.stream.finish();
            this.pending.extend_from_slice(tail.as_bytes());
            this.finished = true;
        }
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

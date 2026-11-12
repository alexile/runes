//! The response body produced by the middleware.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;

use crate::codec::Encoder;

/// Boxed error type of [`CompressionBody`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

enum State {
    /// Pass frames through untouched.
    Identity,
    /// Compress data frames as they arrive.
    Encoding(Encoder),
    /// The compressed stream is finished; only trailers may remain.
    Done(Option<HeaderMap>),
}

pin_project! {
    /// Response body of [`CompressionService`](crate::CompressionService):
    /// either the inner body unchanged or a streaming compression of it.
    ///
    /// Each inner data frame is fed to the encoder and whatever compressed
    /// output is ready is emitted as one frame. Trailers are forwarded after
    /// the compressed stream ends.
    pub struct CompressionBody<B> {
        #[pin]
        inner: B,
        state: State,
    }
}

impl<B> CompressionBody<B> {
    pub(crate) const fn identity(inner: B) -> Self {
        Self {
            inner,
            state: State::Identity,
        }
    }

    pub(crate) const fn encoded(inner: B, encoder: Encoder) -> Self {
        Self {
            inner,
            state: State::Encoding(encoder),
        }
    }

    /// Whether this body is compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        !matches!(self.state, State::Identity)
    }
}

impl<B> fmt::Debug for CompressionBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressionBody")
            .field("compressed", &self.is_compressed())
            .finish_non_exhaustive()
    }
}

fn to_bytes(mut data: impl Buf) -> Bytes {
    data.copy_to_bytes(data.remaining())
}

impl<B> Body for CompressionBody<B>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        loop {
            let encoder = match this.state {
                State::Identity => {
                    let frame = ready!(this.inner.as_mut().poll_frame(cx));
                    return Poll::Ready(
                        frame.map(|res| res.map(|f| f.map_data(to_bytes)).map_err(Into::into)),
                    );
                }
                State::Done(trailers) => {
                    return Poll::Ready(trailers.take().map(|t| Ok(Frame::trailers(t))));
                }
                State::Encoding(encoder) => encoder,
            };

            let trailers = match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(mut data) => {
                        while data.has_remaining() {
                            let chunk = data.chunk();
                            let n = chunk.len();
                            if let Err(e) = encoder.write(chunk) {
                                *this.state = State::Done(None);
                                return Poll::Ready(Some(Err(e.into())));
                            }
                            data.advance(n);
                        }
                        let out = encoder.take();
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                        }
                        continue;
                    }
                    // Unknown frame kinds are dropped; trailers end the data.
                    Err(frame) => match frame.into_trailers() {
                        Ok(trailers) => Some(trailers),
                        Err(_) => continue,
                    },
                },
                Some(Err(e)) => {
                    *this.state = State::Done(None);
                    return Poll::Ready(Some(Err(e.into())));
                }
                None => None,
            };

            // End of data: flush the encoder, then hand out the trailers.
            let State::Encoding(mut encoder) = std::mem::replace(this.state, State::Done(trailers))
            else {
                continue;
            };
            let mut out = encoder.take();
            match encoder.finish() {
                Ok(rest) => out.extend(rest),
                Err(e) => {
                    *this.state = State::Done(None);
                    return Poll::Ready(Some(Err(e.into())));
                }
            }
            if !out.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.state {
            State::Identity => self.inner.is_end_stream(),
            State::Encoding(_) => false,
            State::Done(trailers) => trailers.is_none(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.state {
            State::Identity => self.inner.size_hint(),
            _ => SizeHint::default(),
        }
    }
}

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{LengthLimitError, Limited};
use pin_project_lite::pin_project;
use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

/// Boxed error type yielded by [`LimitedBody`].
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

pin_project! {
    /// Request body wrapper installed by [`BodyLimitService`](crate::BodyLimitService).
    ///
    /// Counts the bytes actually streamed and yields an error as soon as the
    /// running total exceeds the request's byte budget. The budget is the
    /// configured limit, or the declared `Content-Length` when that is
    /// smaller, so a body longer than its own header is caught too.
    ///
    /// The error is an [`http_body_util::LengthLimitError`] (boxed), which
    /// Axum's buffering extractors (`Bytes`, `String`, `Json`, `Form`, …)
    /// already recognise. Handlers that stream the body see it from
    /// [`Body::poll_frame`]. Whatever the handler then returns, the
    /// middleware replaces the response with its own empty rejection.
    pub struct LimitedBody<B> {
        #[pin]
        inner: Limited<B>,
        tripped: Arc<AtomicBool>,
    }
}

impl<B> LimitedBody<B> {
    pub(crate) fn new(inner: B, budget: u64, tripped: Arc<AtomicBool>) -> Self {
        let budget = usize::try_from(budget).unwrap_or(usize::MAX);
        Self {
            inner: Limited::new(inner, budget),
            tripped,
        }
    }
}

impl<B> std::fmt::Debug for LimitedBody<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimitedBody")
            .field("tripped", &self.tripped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body,
    B::Data: Buf,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let polled = this.inner.poll_frame(cx);
        if let Poll::Ready(Some(Err(err))) = &polled
            && err.is::<LengthLimitError>()
        {
            this.tripped.store(true, Ordering::Release);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

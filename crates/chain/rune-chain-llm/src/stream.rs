//! Stream helpers shared by chains that need to act once a stream completes.

use std::future::Future;
use std::pin::Pin;

use futures::{Stream, StreamExt, stream};
use rune_chain_core::{ChainError, StreamData};

/// The boxed stream type returned by [`Chain::stream`](rune_chain_core::Chain::stream).
pub type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

type Completion =
    Box<dyn FnOnce(String) -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send>> + Send>;

struct State {
    inner: ChainStream,
    text: String,
    on_complete: Option<Completion>,
    done: bool,
}

impl State {
    async fn complete(&mut self) -> Result<(), ChainError> {
        match self.on_complete.take() {
            Some(f) => f(std::mem::take(&mut self.text)).await,
            None => Ok(()),
        }
    }
}

/// Wrap `inner` so that `on_complete` runs with the full concatenated text
/// once the stream has been read to the end.
///
/// The hook runs exactly once, when the terminal chunk (`is_finished`)
/// arrives or, for streams without one, when the inner stream ends. It runs
/// *before* the terminal chunk is handed to the caller, so a consumer that
/// stops reading at `is_finished` still sees its effect. If the hook fails,
/// its error is yielded in place of the terminal chunk and the stream ends.
///
/// The hook does not run if the inner stream yields an error, or if the
/// caller drops the stream before the end: a partial answer is never
/// committed.
///
/// # Example
///
/// ```rust
/// use std::sync::{Arc, Mutex};
///
/// use futures::{StreamExt, stream};
/// use rune_chain_core::StreamData;
/// use rune_chain_llm::{ChainStream, with_stream_completion};
///
/// # tokio_test::block_on(async {
/// let chunks: ChainStream = Box::pin(stream::iter([
///     Ok(StreamData::chunk("Hel")),
///     Ok(StreamData::chunk("lo")),
///     Ok(StreamData::done()),
/// ]));
/// let seen = Arc::new(Mutex::new(String::new()));
/// let sink = Arc::clone(&seen);
/// let s = with_stream_completion(chunks, move |text| async move {
///     *sink.lock().unwrap() = text;
///     Ok(())
/// });
/// let n = s.count().await;
/// assert_eq!(n, 3);
/// assert_eq!(*seen.lock().unwrap(), "Hello");
/// # });
/// ```
pub fn with_stream_completion<F, Fut>(inner: ChainStream, on_complete: F) -> ChainStream
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), ChainError>> + Send + 'static,
{
    let on_complete: Completion = Box::new(move |text| Box::pin(on_complete(text)));
    let state = State {
        inner,
        text: String::new(),
        on_complete: Some(on_complete),
        done: false,
    };
    Box::pin(stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        match st.inner.next().await {
            Some(Ok(chunk)) => {
                st.text.push_str(&chunk.content);
                if chunk.is_finished {
                    st.done = true;
                    if let Err(e) = st.complete().await {
                        return Some((Err(e), st));
                    }
                }
                Some((Ok(chunk), st))
            }
            Some(Err(e)) => {
                st.done = true;
                st.on_complete = None;
                Some((Err(e), st))
            }
            None => {
                st.done = true;
                match st.complete().await {
                    Ok(()) => None,
                    Err(e) => Some((Err(e), st)),
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn counted(
        items: Vec<Result<StreamData, ChainError>>,
    ) -> (ChainStream, Arc<AtomicUsize>, Arc<std::sync::Mutex<String>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let text = Arc::new(std::sync::Mutex::new(String::new()));
        let (c, t) = (Arc::clone(&calls), Arc::clone(&text));
        let s = with_stream_completion(Box::pin(stream::iter(items)), move |full| async move {
            c.fetch_add(1, Ordering::SeqCst);
            *t.lock().unwrap() = full;
            Ok(())
        });
        (s, calls, text)
    }

    #[tokio::test]
    async fn runs_once_on_stream_end_without_terminal_chunk() {
        let (s, calls, text) =
            counted(vec![Ok(StreamData::chunk("a")), Ok(StreamData::chunk("b"))]);
        assert_eq!(s.count().await, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*text.lock().unwrap(), "ab");
    }

    #[tokio::test]
    async fn runs_before_the_terminal_chunk_is_yielded() {
        let (mut s, calls, _) = counted(vec![Ok(StreamData::chunk("a")), Ok(StreamData::done())]);
        s.next().await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(s.next().await.unwrap().unwrap().is_finished);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Chunks after the terminal one are not read.
        assert!(s.next().await.is_none());
    }

    #[tokio::test]
    async fn skipped_after_an_error_or_an_early_drop() {
        let (s, calls, _) = counted(vec![
            Ok(StreamData::chunk("a")),
            Err(ChainError::Other("cut".into())),
            Ok(StreamData::done()),
        ]);
        let items: Vec<_> = s.collect().await;
        assert_eq!(items.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let (mut s, calls, _) = counted(vec![Ok(StreamData::chunk("a")), Ok(StreamData::done())]);
        s.next().await;
        drop(s);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hook_error_replaces_the_terminal_chunk() {
        let s = with_stream_completion(
            Box::pin(stream::iter([
                Ok(StreamData::chunk("a")),
                Ok(StreamData::done()),
            ])),
            |_| async { Err(ChainError::MemoryError("full".into())) },
        );
        let items: Vec<_> = s.collect().await;
        assert_eq!(items.len(), 2);
        assert!(matches!(items[1], Err(ChainError::MemoryError(_))));
    }
}

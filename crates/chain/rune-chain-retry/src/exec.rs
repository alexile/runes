//! Shared retry loop used by [`RetryLlm`](crate::RetryLlm) and
//! [`Router`](crate::Router).

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::{Stream, StreamExt, future, stream};
use rune_chain_core::{
    EventStream, FunctionDefinition, GenerateResult, Llm, LlmError, Message, ResponseFormat,
    StreamData, ToolChoice,
};
use tokio::time::Instant;

use crate::event::{Event, Observers};
use crate::policy::{RetryPolicy, Rng};
use crate::{ErrorClass, retry_after};

/// The boxed stream type returned by [`Llm::stream`].
pub type LlmStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// An error classifier; [`classify`](crate::classify) by default.
pub type Classifier = fn(&LlmError) -> ErrorClass;

/// One call to make against an [`Llm`].
#[derive(Clone, Copy)]
pub enum Request<'a> {
    Generate(&'a [Message]),
    Tools(
        &'a [Message],
        &'a [FunctionDefinition],
        &'a Option<ToolChoice>,
    ),
    Structured(&'a [Message], &'a ResponseFormat),
    Stream(&'a [Message]),
    Events(
        &'a [Message],
        Option<&'a [FunctionDefinition]>,
        &'a Option<ToolChoice>,
    ),
}

impl<'a> Request<'a> {
    pub const fn messages(&self) -> &'a [Message] {
        match *self {
            Self::Generate(m)
            | Self::Tools(m, ..)
            | Self::Structured(m, _)
            | Self::Stream(m)
            | Self::Events(m, ..) => m,
        }
    }
}

pub enum Output {
    Result(GenerateResult),
    Stream(LlmStream),
    Events(EventStream),
}

impl Output {
    pub fn into_result(self) -> Result<GenerateResult, LlmError> {
        match self {
            Self::Result(r) => Ok(r),
            Self::Stream(_) | Self::Events(_) => {
                Err(LlmError::other("internal: expected a result"))
            }
        }
    }

    pub fn into_stream(self) -> Result<LlmStream, LlmError> {
        match self {
            Self::Stream(s) => Ok(s),
            Self::Result(_) | Self::Events(_) => {
                Err(LlmError::other("internal: expected a stream"))
            }
        }
    }

    pub fn into_events(self) -> Result<EventStream, LlmError> {
        match self {
            Self::Events(s) => Ok(s),
            Self::Result(_) | Self::Stream(_) => {
                Err(LlmError::other("internal: expected an event stream"))
            }
        }
    }
}

/// Await the first item of `s`. An error there fails the attempt; otherwise
/// the item is put back in front of the rest.
async fn peek<T: Send + 'static>(
    mut s: Pin<Box<dyn Stream<Item = Result<T, LlmError>> + Send>>,
) -> Result<Pin<Box<dyn Stream<Item = Result<T, LlmError>> + Send>>, LlmError> {
    match s.next().await {
        Some(Err(e)) => Err(e),
        Some(Ok(first)) => Ok(Box::pin(stream::once(future::ready(Ok(first))).chain(s))),
        None => Ok(Box::pin(stream::empty())),
    }
}

/// Make one call. Streams are opened and polled for their first item, so a
/// failure before any output counts as a failed attempt; the first chunk is
/// then re-attached in front of the rest.
async fn call_once(llm: &dyn Llm, req: Request<'_>) -> Result<Output, LlmError> {
    match req {
        Request::Generate(m) => llm.generate(m).await.map(Output::Result),
        Request::Tools(m, tools, choice) => llm
            .generate_with_tools(m, tools, choice.clone())
            .await
            .map(Output::Result),
        Request::Structured(m, format) => {
            llm.generate_structured(m, format).await.map(Output::Result)
        }
        Request::Stream(m) => Ok(Output::Stream(peek(llm.stream(m).await?).await?)),
        Request::Events(m, tools, choice) => Ok(Output::Events(
            peek(llm.stream_events(m, tools, choice.clone()).await?).await?,
        )),
    }
}

/// Everything the retry loop needs besides the call itself.
pub struct Ctx<'a> {
    pub name: &'a Arc<str>,
    pub policy: &'a RetryPolicy,
    pub rng: &'a Rng,
    pub observers: &'a Observers,
    pub classifier: Classifier,
}

pub struct Success {
    pub output: Output,
    pub latency: Duration,
}

pub struct Failure {
    pub error: LlmError,
    pub class: ErrorClass,
}

/// Call `llm` until it succeeds, fails permanently, or the policy's budget is
/// spent.
pub async fn run(ctx: &Ctx<'_>, llm: &dyn Llm, req: Request<'_>) -> Result<Success, Failure> {
    let policy = ctx.policy;
    let started = Instant::now();
    let mut attempt: u32 = 1;
    loop {
        ctx.observers.emit(|| Event::AttemptStarted {
            provider: Arc::clone(ctx.name),
            attempt,
        });
        let t0 = Instant::now();
        let result = match policy.attempt_timeout {
            Some(limit) => tokio::time::timeout(limit, call_once(llm, req))
                .await
                .unwrap_or_else(|_| {
                    Err(LlmError::timeout(format!(
                        "attempt timed out after {limit:?}"
                    )))
                }),
            None => call_once(llm, req).await,
        };
        let latency = t0.elapsed();
        let error = match result {
            Ok(output) => {
                ctx.observers.emit(|| Event::AttemptSucceeded {
                    provider: Arc::clone(ctx.name),
                    attempt,
                    latency,
                });
                return Ok(Success { output, latency });
            }
            Err(e) => e,
        };
        let class = (ctx.classifier)(&error);
        ctx.observers.emit(|| Event::AttemptFailed {
            provider: Arc::clone(ctx.name),
            attempt,
            class,
            error: error.clone(),
        });
        let retries_done = attempt - 1;
        if !class.is_retryable() || retries_done >= policy.max_retries {
            return Err(Failure { error, class });
        }
        let mut delay = policy.delay(retries_done, ctx.rng.unit());
        if policy.honor_retry_after
            && let Some(hint) = retry_after(&error)
        {
            delay = delay.max(hint);
        }
        if let Some(budget) = policy.max_elapsed
            && started.elapsed().saturating_add(delay) > budget
        {
            return Err(Failure { error, class });
        }
        attempt += 1;
        ctx.observers.emit(|| Event::RetryScheduled {
            provider: Arc::clone(ctx.name),
            attempt,
            delay,
        });
        tokio::time::sleep(delay).await;
    }
}

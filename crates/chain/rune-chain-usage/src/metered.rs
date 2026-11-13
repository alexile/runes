//! An [`Llm`] wrapper that meters every call.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::Stream;
use rune_chain_core::{
    FunctionDefinition, GenerateResult, Llm, LlmError, Message, Pricing, StreamData, ToolChoice,
};

use crate::estimate::{estimate_messages, estimate_reply, estimate_tools};
use crate::meter::Reservation;
use crate::{Usage, UsageMeter};

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Wraps an [`Llm`] so every call is checked against, and recorded in, a
/// [`UsageMeter`].
///
/// Before a call the wrapper estimates its prompt tokens (plus
/// [`expected_output_tokens`](Self::expected_output_tokens)) and asks the
/// meter whether the budget allows it; a refused call fails with
/// [`LlmError::other`] without reaching the provider. After the call it
/// records the provider-reported usage, or a local estimate when the
/// provider reports none (always the case for streams, which are recorded
/// when they finish or are dropped). A call that makes spending reach a cap
/// still returns its result; the *next* call is refused.
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_core::{Cost, GenerateResult, Llm, LlmError, Message, Pricing, TokenUsage};
/// use rune_chain_usage::{Budget, MeteredLlm, UsageMeter};
///
/// struct Fixed;
/// #[async_trait]
/// impl Llm for Fixed {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         let mut r = GenerateResult::from_text("ok");
///         r.tokens = Some(TokenUsage::new(600, 400).with_total_tokens(1000));
///         Ok(r)
///     }
/// }
///
/// let meter = UsageMeter::new(Budget::default().with_max_tokens(1_500));
/// let llm = MeteredLlm::new(Fixed, meter.clone(), "acme", "fixed", Pricing::per_mtok(1_000_000, 1_000_000));
/// # tokio_test::block_on(async {
/// llm.generate(&[Message::human("hi")]).await.unwrap(); // 1000 tokens
/// llm.generate(&[Message::human("hi")]).await.unwrap(); // 2000: cap reached, result kept
/// assert!(llm.generate(&[Message::human("hi")]).await.is_err()); // refused
/// # });
/// assert_eq!(meter.totals().calls, 2);
/// assert_eq!(meter.totals().cost, Cost::from_micros(2_000));
/// ```
#[derive(Debug, Clone)]
pub struct MeteredLlm<L> {
    inner: L,
    meter: UsageMeter,
    provider: String,
    model: String,
    pricing: Pricing,
    tag: Option<String>,
    expected_output_tokens: u64,
}

impl<L: Llm> MeteredLlm<L> {
    /// Meter `inner`, recording its calls under `provider` / `model` at
    /// `pricing` (for a known model, take it from the provider crate's
    /// `models::lookup(id)`).
    pub fn new(
        inner: L,
        meter: UsageMeter,
        provider: impl Into<String>,
        model: impl Into<String>,
        pricing: Pricing,
    ) -> Self {
        Self {
            inner,
            meter,
            provider: provider.into(),
            model: model.into(),
            pricing,
            tag: None,
            expected_output_tokens: 0,
        }
    }

    /// Record every call under `tag` as well (see
    /// [`UsageMeter::by_tag`]), e.g. the feature, tenant or agent making it.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Output tokens to assume in the pre-flight check (default 0: only the
    /// prompt is projected). Set it to the request's `max_tokens` to refuse
    /// any call that *could* pass the budget.
    #[must_use]
    pub const fn expected_output_tokens(mut self, tokens: u64) -> Self {
        self.expected_output_tokens = tokens;
        self
    }

    /// The meter calls are recorded in.
    #[must_use]
    pub const fn meter(&self) -> &UsageMeter {
        &self.meter
    }

    /// The wrapped LLM.
    #[must_use]
    pub const fn inner(&self) -> &L {
        &self.inner
    }

    /// Unwrap, returning the inner LLM.
    pub fn into_inner(self) -> L {
        self.inner
    }

    fn preflight(&self, input_tokens: u64) -> Result<Reservation, LlmError> {
        let cost = self
            .pricing
            .cost_of(input_tokens, self.expected_output_tokens);
        let tokens = input_tokens.saturating_add(self.expected_output_tokens);
        self.meter.reserve(cost, tokens).map_err(LlmError::from)
    }

    /// Record the call, then release its reservation (dropped on return).
    fn settle(&self, _reservation: Reservation, input_estimate: u64, result: &GenerateResult) {
        let usage = result.tokens.as_ref().map_or_else(
            || {
                Usage::estimated(
                    input_estimate,
                    estimate_reply(&result.generation, &result.tool_calls),
                )
            },
            Usage::from_token_usage,
        );
        // Reaching the cap is reported to the next call by `preflight`; this
        // call's result is already paid for and is returned regardless.
        let _ = self.meter.record_tagged(
            &self.provider,
            &self.model,
            self.tag.as_deref(),
            &self.pricing,
            usage,
        );
    }
}

#[async_trait]
impl<L: Llm> Llm for MeteredLlm<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let input = estimate_messages(messages);
        let reservation = self.preflight(input)?;
        let result = self.inner.generate(messages).await?;
        self.settle(reservation, input, &result);
        Ok(result)
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        let input = estimate_messages(messages).saturating_add(estimate_tools(tools));
        let reservation = self.preflight(input)?;
        let result = self
            .inner
            .generate_with_tools(messages, tools, tool_choice)
            .await?;
        self.settle(reservation, input, &result);
        Ok(result)
    }

    async fn stream(&self, messages: &[Message]) -> Result<BoxStream, LlmError> {
        let input = estimate_messages(messages);
        let reservation = self.preflight(input)?;
        let inner = self.inner.stream(messages).await?;
        Ok(Box::pin(MeteredStream {
            inner,
            pending: Some(Pending {
                meter: self.meter.clone(),
                provider: self.provider.clone(),
                model: self.model.clone(),
                tag: self.tag.clone(),
                pricing: self.pricing,
                input_tokens: input,
                output_chars: 0,
                _reservation: reservation,
            }),
        }))
    }
}

/// Usage of a stream in flight, recorded exactly once.
struct Pending {
    meter: UsageMeter,
    provider: String,
    model: String,
    tag: Option<String>,
    pricing: Pricing,
    input_tokens: u64,
    /// Characters streamed so far. Only the count is kept, so a long stream
    /// costs no memory; it is turned into tokens the way
    /// [`estimate_text`](crate::estimate_text) does.
    output_chars: u64,
    /// Released when the stream settles, after its usage is recorded.
    _reservation: Reservation,
}

impl Pending {
    fn settle(self) {
        let usage = Usage::estimated(self.input_tokens, self.output_chars.div_ceil(4));
        let _ = self.meter.record_tagged(
            &self.provider,
            &self.model,
            self.tag.as_deref(),
            &self.pricing,
            usage,
        );
    }
}

/// Passes chunks through, accumulating their text, and records the stream's
/// estimated usage when it finishes, fails or is dropped.
struct MeteredStream {
    inner: BoxStream,
    pending: Option<Pending>,
}

impl MeteredStream {
    fn settle(&mut self) {
        if let Some(p) = self.pending.take() {
            p.settle();
        }
    }
}

impl Stream for MeteredStream {
    type Item = Result<StreamData, LlmError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = this.inner.as_mut().poll_next(cx);
        match &next {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(p) = this.pending.as_mut() {
                    let chars = chunk.content.chars().count() as u64;
                    p.output_chars = p.output_chars.saturating_add(chars);
                }
                if chunk.is_finished {
                    this.settle();
                }
            }
            Poll::Ready(None) => this.settle(),
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        next
    }
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        self.settle();
    }
}

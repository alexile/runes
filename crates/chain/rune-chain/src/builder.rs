//! [`AgentBuilder`] and [`Agent`]: a model plus preamble, context, tools,
//! RAG and memory, behind `prompt` / `chat` / `stream_prompt` /
//! `stream_events`.

use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use rune_chain_agent::{
    AgentLimits, AgentObserver, AgentStreamEvent, Approver, FunctionCallingAgent, StopReason,
    ToolErrorMode, ToolInvocation,
};
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, LlmError, Memory, Message, PromptArgs,
    StreamAccumulator, StreamData, StreamEvent, TokenUsage, Tool, ToolChoice, ToolError,
};
use serde_json::{Value, json};

use crate::CompletionModel;
use crate::context::{DEFAULT_MAX_CONTEXT_CHARS, DOCUMENTS_NOTICE, render_documents};
use crate::tool::{Typed, TypedTool};

/// A stream of answer chunks, as returned by [`Agent::stream_prompt`].
pub type TextStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

/// A stream of [`AgentStreamItem`]s, as returned by [`Agent::stream_events`].
pub type AgentItemStream = Pin<Box<dyn Stream<Item = Result<AgentStreamItem, ChainError>> + Send>>;

/// One item of [`Agent::stream_events`].
///
/// Text and reasoning arrive as the model writes them, in every turn, so
/// with tools the text before a round of tool calls streams too. The last
/// item is [`Final`](Self::Final).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AgentStreamItem {
    /// A fragment of the model's text.
    Text(String),
    /// A fragment of the model's reasoning.
    Reasoning(String),
    /// The model started a tool call (it is checked and run once the turn
    /// ends).
    ToolCall {
        /// Tool round, from 1.
        turn: usize,
        /// Tool-call id.
        call_id: String,
        /// Requested tool name, sanitised.
        name: String,
    },
    /// A tool call finished: its status and the output the model sees.
    ToolResult {
        /// Tool round, from 1.
        turn: usize,
        /// The call and its result.
        invocation: ToolInvocation,
    },
    /// The run ended. As with [`Agent::prompt_with_details`], hitting a
    /// limit is not an error: check [`AgentResponse::stop_reason`].
    Final(AgentResponse),
}

/// Preamble used when documents are given but no preamble is.
const DEFAULT_PREAMBLE: &str = "You are a helpful assistant.";
/// Tool name of an agent used as a tool, unless set with
/// [`AgentBuilder::name`].
const DEFAULT_NAME: &str = "agent";
const DEFAULT_DESCRIPTION: &str =
    "Ask this agent a question or give it a task in plain language. It answers with text.";

type Configure = Box<dyn FnOnce(FunctionCallingAgent) -> FunctionCallingAgent + Send + Sync>;

/// One `dynamic_context` source: top-`k` documents per prompt.
#[cfg(feature = "retrieval")]
struct DynamicSource {
    top_k: usize,
    retriever: Arc<dyn rune_chain_retrieval::Retriever>,
}

/// Builds an [`Agent`]. Get one from
/// [`CompletionClient::agent`](crate::CompletionClient::agent), or wrap any
/// [`Llm`] with [`AgentBuilder::new`].
///
/// ```rust
/// use rune_chain::prelude::*;
/// use rune_chain::testing::FakeLlm;
///
/// # tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
/// let agent = AgentBuilder::new(FakeLlm::with_replies(["Paris."]))
///     .preamble("Answer in one word.")
///     .context("France's capital is Paris.")
///     .build();
/// assert_eq!(agent.prompt("Capital of France?").await.unwrap(), "Paris.");
/// # });
/// ```
pub struct AgentBuilder<M> {
    model: M,
    name: Option<String>,
    description: Option<String>,
    preamble: Option<String>,
    static_context: Vec<String>,
    tools: Vec<(Arc<dyn Tool>, bool)>,
    configure: Vec<Configure>,
    limits: AgentLimits,
    tool_choice: Option<ToolChoice>,
    #[cfg(feature = "retrieval")]
    dynamic: Vec<DynamicSource>,
    max_context_chars: usize,
    memory: Option<Arc<dyn Memory>>,
}

impl<M> fmt::Debug for AgentBuilder<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentBuilder")
            .field("name", &self.name)
            .field("tools", &self.tools.len())
            .field("static_context", &self.static_context.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<M: Llm + 'static> AgentBuilder<M> {
    /// Start an agent on `model`, with the default [`AgentLimits`].
    pub fn new(model: M) -> Self {
        Self {
            model,
            name: None,
            description: None,
            preamble: None,
            static_context: Vec::new(),
            tools: Vec::new(),
            configure: Vec::new(),
            limits: AgentLimits::default(),
            tool_choice: None,
            #[cfg(feature = "retrieval")]
            dynamic: Vec::new(),
            max_context_chars: DEFAULT_MAX_CONTEXT_CHARS,
            memory: None,
        }
    }

    /// The system prompt: who the agent is and how it should answer.
    #[must_use]
    pub fn preamble(mut self, preamble: impl Into<String>) -> Self {
        self.preamble = Some(preamble.into());
        self
    }

    /// Add a document the agent always sees (in the system prompt, fenced
    /// as data). Call it once per document.
    #[must_use]
    pub fn context(mut self, document: impl Into<String>) -> Self {
        self.static_context.push(document.into());
        self
    }

    /// Give the agent a tool. With at least one tool the agent runs the
    /// hardened multi-turn tool loop of `rune-chain-agent`: calls are
    /// validated against the tool schema, run under [`AgentLimits`] and
    /// their output is fenced as untrusted data.
    ///
    /// Any [`Tool`] works, including another [`Agent`].
    #[must_use]
    pub fn tool(mut self, tool: impl Tool + 'static) -> Self {
        self.tools.push((Arc::new(tool), false));
        self
    }

    /// Give the agent several boxed tools, e.g. a ready-made tool set.
    #[must_use]
    pub fn tools(mut self, tools: impl IntoIterator<Item = Box<dyn Tool>>) -> Self {
        self.tools
            .extend(tools.into_iter().map(|t| (Arc::from(t), false)));
        self
    }

    /// Give the agent a [`TypedTool`].
    #[must_use]
    pub fn typed_tool(self, tool: impl TypedTool) -> Self {
        self.tool(Typed::new(tool))
    }

    /// Give the agent a tool that runs only once the
    /// [`approver`](Self::approver) allows each call. Without an approver
    /// every call to it is denied.
    #[must_use]
    pub fn tool_requiring_approval(mut self, tool: impl Tool + 'static) -> Self {
        self.tools.push((Arc::new(tool), true));
        self
    }

    /// Set who approves calls to tools added with
    /// [`tool_requiring_approval`](Self::tool_requiring_approval).
    #[must_use]
    pub fn approver(mut self, approver: impl Approver + 'static) -> Self {
        self.configure.push(Box::new(move |a| a.approver(approver)));
        self
    }

    /// Watch every step, tool call and answer of the tool loop.
    #[must_use]
    pub fn on_event(mut self, observer: impl AgentObserver + 'static) -> Self {
        self.configure.push(Box::new(move |a| a.on_event(observer)));
        self
    }

    /// What a failing tool call does: report the error to the model
    /// (default) or abort the run.
    #[must_use]
    pub fn tool_error_mode(mut self, mode: ToolErrorMode) -> Self {
        self.configure
            .push(Box::new(move |a| a.tool_error_mode(mode)));
        self
    }

    /// How the model may pick tools (default: the provider's, usually
    /// `auto`).
    #[must_use]
    pub fn tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    /// The most tool-call rounds per prompt (default 10). A prompt that
    /// needs more fails instead of looping forever.
    #[must_use]
    pub const fn max_turns(mut self, turns: usize) -> Self {
        self.limits.max_iterations = turns;
        self
    }

    /// Replace every limit of the tool loop: rounds, calls per round,
    /// concurrency, per-tool and total time, output size.
    #[must_use]
    pub const fn limits(mut self, limits: AgentLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Before each prompt, retrieve the `top_k` documents most relevant to
    /// it from `index` and add them to that prompt (fenced as data). Call
    /// it again to add more sources; duplicates across sources are dropped.
    ///
    /// `index` is any retriever: an [`EmbeddingIndex`](crate::EmbeddingIndex)
    /// over a vector store and an embedder, BM25, hybrid, reranking, ….
    #[cfg(feature = "retrieval")]
    #[must_use]
    pub fn dynamic_context(
        mut self,
        top_k: usize,
        index: impl rune_chain_retrieval::Retriever + 'static,
    ) -> Self {
        self.dynamic.push(DynamicSource {
            top_k,
            retriever: Arc::new(index),
        });
        self
    }

    /// Cap the characters of retrieved context added to one prompt
    /// (default 32 000). Documents past the cap are left out.
    #[must_use]
    pub const fn max_context_chars(mut self, chars: usize) -> Self {
        self.max_context_chars = chars;
        self
    }

    /// Remember the conversation: [`Agent::prompt`] sends the stored
    /// history with each prompt and stores the new exchange.
    #[must_use]
    pub fn memory(mut self, memory: impl Memory + 'static) -> Self {
        self.memory = Some(Arc::new(memory));
        self
    }

    /// Name of the agent when it is used as a tool of another agent.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Description of the agent when it is used as a tool of another agent.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Build the agent.
    pub fn build(self) -> Agent {
        #[cfg(feature = "retrieval")]
        let has_dynamic = !self.dynamic.is_empty();
        #[cfg(not(feature = "retrieval"))]
        let has_dynamic = false;

        let static_docs =
            render_documents(self.static_context.iter().map(String::as_str), usize::MAX);
        let has_docs = has_dynamic || static_docs.is_some();
        let mut parts = Vec::with_capacity(3);
        match self.preamble {
            Some(preamble) => parts.push(preamble),
            None if has_docs => parts.push(DEFAULT_PREAMBLE.to_owned()),
            None => {}
        }
        if let Some((docs, _)) = static_docs {
            parts.push(docs);
        }
        if has_docs {
            parts.push(DOCUMENTS_NOTICE.to_owned());
        }
        let system = (!parts.is_empty()).then(|| parts.join("\n\n"));

        let llm: Arc<dyn Llm> = Arc::new(self.model);
        let runner = if self.tools.is_empty() {
            None
        } else {
            let mut agent = FunctionCallingAgent::new(Arc::clone(&llm)).limits(self.limits);
            if let Some(system) = &system {
                agent = agent.system_prompt(system.clone());
            }
            if let Some(choice) = self.tool_choice {
                agent = agent.tool_choice(choice);
            }
            for (tool, approval) in self.tools {
                agent = if approval {
                    agent.tool_requiring_approval(tool)
                } else {
                    agent.tool(tool)
                };
            }
            for f in self.configure {
                agent = f(agent);
            }
            Some(agent)
        };

        Agent {
            inner: Arc::new(Inner {
                llm,
                runner,
                system,
                #[cfg(feature = "retrieval")]
                dynamic: self.dynamic,
                max_context_chars: self.max_context_chars,
                memory: self.memory,
                name: self.name.unwrap_or_else(|| DEFAULT_NAME.to_owned()),
                description: self
                    .description
                    .unwrap_or_else(|| DEFAULT_DESCRIPTION.to_owned()),
            }),
        }
    }
}

impl<M: CompletionModel> AgentBuilder<M> {
    /// Sampling temperature of the model.
    #[must_use]
    pub fn temperature(mut self, temperature: f32) -> Self {
        self.model = self.model.with_temperature(temperature);
        self
    }

    /// Cap on tokens generated per model call.
    #[must_use]
    pub fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.model = self.model.with_max_tokens(max_tokens);
        self
    }
}

/// A retrieved document that was added to a prompt.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ContextDocument {
    /// The document text.
    pub content: String,
    /// The retriever's relevance score.
    pub score: f32,
    /// The document's metadata (source, page, …).
    pub metadata: HashMap<String, String>,
}

/// Everything about one answer: the text plus usage, tool calls and the
/// retrieved documents it was based on.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AgentResponse {
    /// The answer (or the model's last text when the run stopped early).
    pub output: String,
    /// Token usage summed over every model call, when reported.
    pub usage: Option<TokenUsage>,
    /// Every tool call, in order.
    pub tool_calls: Vec<ToolInvocation>,
    /// Tool-call rounds used.
    pub turns: usize,
    /// Why the run ended. Anything but [`StopReason::FinalAnswer`] means a
    /// limit was hit.
    pub stop_reason: StopReason,
    /// Retrieved documents added to the prompt, best first.
    pub documents: Vec<ContextDocument>,
}

impl AgentResponse {
    fn into_final(self) -> Result<Self, ChainError> {
        if self.stop_reason == StopReason::FinalAnswer {
            Ok(self)
        } else {
            Err(ChainError::Other(format!(
                "agent stopped without a final answer: {}",
                self.stop_reason
            )))
        }
    }
}

struct Inner {
    llm: Arc<dyn Llm>,
    runner: Option<FunctionCallingAgent>,
    system: Option<String>,
    #[cfg(feature = "retrieval")]
    dynamic: Vec<DynamicSource>,
    max_context_chars: usize,
    memory: Option<Arc<dyn Memory>>,
    name: String,
    description: String,
}

/// A model with a preamble, documents, tools, RAG and memory. Build one with
/// [`AgentBuilder`].
///
/// Cloning is cheap and clones share memory. An `Agent` is also a
/// [`Chain`] (reads the `"input"` key) and a [`Tool`] (takes
/// `{"prompt": "…"}`), so agents can be steps of a pipeline or tools of
/// other agents.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("name", &self.inner.name)
            .field("tools", &self.inner.runner.is_some())
            .field("memory", &self.inner.memory.is_some())
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Ask one question and get the answer.
    ///
    /// With [`memory`](AgentBuilder::memory) the stored history is sent
    /// along and the exchange is stored afterwards.
    ///
    /// # Errors
    ///
    /// Model, retrieval and memory failures, and a tool loop that hits a
    /// limit before answering.
    pub async fn prompt(&self, text: impl AsRef<str> + Send) -> Result<String, ChainError> {
        Ok(self.prompt_with_details(text).await?.into_final()?.output)
    }

    /// [`prompt`](Self::prompt), returning usage, tool calls and retrieved
    /// documents too. Hitting a limit is not an error here: check
    /// [`AgentResponse::stop_reason`].
    ///
    /// # Errors
    ///
    /// Model, retrieval and memory failures.
    pub async fn prompt_with_details(
        &self,
        text: impl AsRef<str> + Send,
    ) -> Result<AgentResponse, ChainError> {
        let text = text.as_ref();
        let history = self.history().await?;
        let response = self.respond(text, history).await?;
        if response.stop_reason == StopReason::FinalAnswer {
            self.remember(text, &response.output).await?;
        }
        Ok(response)
    }

    /// Answer `text` as the next turn of `history` (earlier human and AI
    /// turns). Memory is neither read nor written.
    ///
    /// # Errors
    ///
    /// As for [`prompt`](Self::prompt).
    pub async fn chat(
        &self,
        text: impl AsRef<str> + Send,
        history: Vec<Message>,
    ) -> Result<String, ChainError> {
        Ok(self
            .chat_with_details(text, history)
            .await?
            .into_final()?
            .output)
    }

    /// [`chat`](Self::chat), returning usage, tool calls and retrieved
    /// documents too.
    ///
    /// # Errors
    ///
    /// As for [`prompt_with_details`](Self::prompt_with_details).
    pub async fn chat_with_details(
        &self,
        text: impl AsRef<str> + Send,
        history: Vec<Message>,
    ) -> Result<AgentResponse, ChainError> {
        self.respond(text.as_ref(), history).await
    }

    /// Stream the answer to `text` as it is generated.
    ///
    /// Tokens arrive as the provider streams them, in every turn: with
    /// tools, the text the model writes before a round of tool calls
    /// streams too, then the tools run (under the same limits, validation
    /// and approval as [`prompt`](Self::prompt)) and the next turn streams.
    /// The last chunk is the terminal one. A run that hits a limit ends
    /// with an error item. With memory, the exchange is stored once the
    /// stream ends cleanly.
    ///
    /// Use [`stream_events`](Self::stream_events) to see tool calls and
    /// results as well.
    ///
    /// # Errors
    ///
    /// Failures before the stream starts; later ones arrive as stream
    /// items.
    pub async fn stream_prompt(
        &self,
        text: impl AsRef<str> + Send,
    ) -> Result<TextStream, ChainError> {
        let history = self.history().await?;
        Ok(text_only(
            self.stream_inner(text.as_ref(), history, true).await?,
        ))
    }

    /// Stream the run for `text` as [`AgentStreamItem`]s: text and
    /// reasoning deltas from every turn, each tool call as the model starts
    /// it, each tool result, and finally the [`AgentResponse`].
    ///
    /// Memory works as in [`stream_prompt`](Self::stream_prompt).
    ///
    /// ```rust
    /// use futures::StreamExt;
    /// use rune_chain::prelude::*;
    /// use rune_chain::testing::{FakeLlm, FakeReply};
    /// use rune_chain::{AgentStreamItem, ToolCall};
    ///
    /// struct Clock;
    ///
    /// #[rune_chain::async_trait]
    /// impl Tool for Clock {
    ///     fn name(&self) -> &str { "clock" }
    ///     fn description(&self) -> &str { "The time." }
    ///     async fn run(&self, _: &str) -> Result<String, ToolError> {
    ///         Ok("noon".into())
    ///     }
    /// }
    ///
    /// # tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
    /// let agent = AgentBuilder::new(FakeLlm::with_replies([
    ///     FakeReply::tool_calls([ToolCall::new("c1", "clock", r#"{"input":"now"}"#)]),
    ///     FakeReply::text("It is noon."),
    /// ]))
    /// .tool(Clock)
    /// .build();
    /// let mut stream = agent.stream_events("Time?").await.unwrap();
    /// while let Some(item) = stream.next().await {
    ///     match item.unwrap() {
    ///         AgentStreamItem::ToolCall { name, .. } => assert_eq!(name, "clock"),
    ///         AgentStreamItem::ToolResult { invocation, .. } => assert_eq!(invocation.output, "noon"),
    ///         AgentStreamItem::Final(response) => assert_eq!(response.output, "It is noon."),
    ///         _ => {}
    ///     }
    /// }
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// As for [`stream_prompt`](Self::stream_prompt).
    pub async fn stream_events(
        &self,
        text: impl AsRef<str> + Send,
    ) -> Result<AgentItemStream, ChainError> {
        let history = self.history().await?;
        self.stream_inner(text.as_ref(), history, true).await
    }

    /// [`stream_events`](Self::stream_events) as the next turn of
    /// `history`. Memory is neither read nor written.
    ///
    /// # Errors
    ///
    /// As for [`stream_prompt`](Self::stream_prompt).
    pub async fn stream_chat_events(
        &self,
        text: impl AsRef<str> + Send,
        history: Vec<Message>,
    ) -> Result<AgentItemStream, ChainError> {
        self.stream_inner(text.as_ref(), history, false).await
    }

    /// [`stream_prompt`](Self::stream_prompt) as the next turn of
    /// `history`. Memory is neither read nor written.
    ///
    /// # Errors
    ///
    /// As for [`stream_prompt`](Self::stream_prompt).
    pub async fn stream_chat(
        &self,
        text: impl AsRef<str> + Send,
        history: Vec<Message>,
    ) -> Result<TextStream, ChainError> {
        Ok(text_only(
            self.stream_inner(text.as_ref(), history, false).await?,
        ))
    }

    /// The system prompt sent with every request, if any (preamble, static
    /// documents and the data notice). With tools, the tool loop adds its
    /// own notice about tool output.
    #[must_use]
    pub fn system_prompt(&self) -> Option<&str> {
        self.inner.system.as_deref()
    }

    /// Whether the agent has tools (and so runs the tool loop).
    #[must_use]
    pub fn has_tools(&self) -> bool {
        self.inner.runner.is_some()
    }

    async fn history(&self) -> Result<Vec<Message>, ChainError> {
        match &self.inner.memory {
            Some(memory) => memory.messages().await,
            None => Ok(Vec::new()),
        }
    }

    async fn remember(&self, text: &str, output: &str) -> Result<(), ChainError> {
        if let Some(memory) = &self.inner.memory {
            remember(memory.as_ref(), text, output).await?;
        }
        Ok(())
    }

    /// The new human turn: retrieved documents, then the question.
    #[cfg_attr(
        not(feature = "retrieval"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "awaits only with retrieval"
        )
    )]
    async fn user_turn(&self, text: &str) -> Result<(String, Vec<ContextDocument>), ChainError> {
        #[cfg(feature = "retrieval")]
        let mut documents = self.retrieve(text).await?;
        #[cfg(not(feature = "retrieval"))]
        let mut documents: Vec<ContextDocument> = Vec::new();
        let rendered = render_documents(
            documents.iter().map(|d| d.content.as_str()),
            self.inner.max_context_chars,
        );
        Ok(match rendered {
            Some((block, used)) => {
                documents.truncate(used);
                (format!("{block}\n\n{text}"), documents)
            }
            None => (text.to_owned(), Vec::new()),
        })
    }

    #[cfg(feature = "retrieval")]
    async fn retrieve(&self, text: &str) -> Result<Vec<ContextDocument>, ChainError> {
        let mut hits = Vec::new();
        for source in &self.inner.dynamic {
            hits.extend(source.retriever.retrieve(text, source.top_k).await?);
        }
        Ok(rune_chain_retrieval::dedupe_by_content(hits)
            .into_iter()
            .filter(|h| !h.document.content.trim().is_empty())
            .map(|h| ContextDocument {
                content: h.document.content,
                score: h.score,
                metadata: h.document.metadata,
            })
            .collect())
    }

    fn messages(&self, mut history: Vec<Message>, user: String) -> Vec<Message> {
        history.push(Message::human(user));
        match &self.inner.system {
            Some(system) => {
                let mut messages = Vec::with_capacity(history.len() + 1);
                messages.push(Message::system(system.clone()));
                messages.extend(history);
                messages
            }
            None => history,
        }
    }

    async fn respond(
        &self,
        text: &str,
        mut history: Vec<Message>,
    ) -> Result<AgentResponse, ChainError> {
        let (user, documents) = self.user_turn(text).await?;
        if let Some(runner) = &self.inner.runner {
            history.push(Message::human(user));
            let run = runner.run_messages(history).await?;
            return Ok(AgentResponse {
                output: run.output,
                usage: run.tokens,
                tool_calls: run.tool_invocations,
                turns: run.iterations,
                stop_reason: run.stop_reason,
                documents,
            });
        }
        let result = self
            .inner
            .llm
            .generate(&self.messages(history, user))
            .await?;
        if result.generation.trim().is_empty() {
            return Err(ChainError::LlmError(LlmError::invalid_response(
                "the model returned an empty reply",
            )));
        }
        Ok(AgentResponse {
            output: result.generation,
            usage: result.tokens,
            tool_calls: Vec::new(),
            turns: 0,
            stop_reason: StopReason::FinalAnswer,
            documents,
        })
    }

    async fn stream_inner(
        &self,
        text: &str,
        mut history: Vec<Message>,
        record: bool,
    ) -> Result<AgentItemStream, ChainError> {
        let (user, documents) = self.user_turn(text).await?;
        let memory = if record {
            self.inner.memory.clone()
        } else {
            None
        };
        let text = text.to_owned();

        if self.inner.runner.is_some() {
            history.push(Message::human(user));
            let inner = Arc::clone(&self.inner);
            return Ok(Box::pin(async_stream::stream! {
                let Some(runner) = inner.runner.as_ref() else {
                    return;
                };
                let mut run = runner.run_stream(history);
                while let Some(item) = run.next().await {
                    let event = match item {
                        Ok(event) => event,
                        Err(err) => {
                            yield Err(err);
                            return;
                        }
                    };
                    let item = match event {
                        AgentStreamEvent::TextDelta(t) => AgentStreamItem::Text(t),
                        AgentStreamEvent::ReasoningDelta(t) => AgentStreamItem::Reasoning(t),
                        AgentStreamEvent::ToolCallStarted {
                            iteration,
                            call_id,
                            name,
                        } => AgentStreamItem::ToolCall {
                            turn: iteration,
                            call_id,
                            name,
                        },
                        AgentStreamEvent::ToolResult {
                            iteration,
                            invocation,
                        } => AgentStreamItem::ToolResult {
                            turn: iteration,
                            invocation,
                        },
                        AgentStreamEvent::Done(run) => {
                            let response = AgentResponse {
                                output: run.output,
                                usage: run.tokens,
                                tool_calls: run.tool_invocations,
                                turns: run.iterations,
                                stop_reason: run.stop_reason,
                                documents,
                            };
                            if response.stop_reason == StopReason::FinalAnswer
                                && let Some(memory) = &memory
                                && let Err(err) =
                                    remember(memory.as_ref(), &text, &response.output).await
                            {
                                yield Err(err);
                                return;
                            }
                            yield Ok(AgentStreamItem::Final(response));
                            return;
                        }
                        _ => continue,
                    };
                    yield Ok(item);
                }
            }));
        }

        let mut events = self
            .inner
            .llm
            .stream_events(&self.messages(history, user), None, None)
            .await?;
        Ok(Box::pin(async_stream::stream! {
            let mut acc = StreamAccumulator::new();
            while let Some(item) = events.next().await {
                let event = match item {
                    Ok(event) => event,
                    Err(err) => {
                        yield Err(ChainError::from(err));
                        return;
                    }
                };
                if let Err(err) = acc.push(&event) {
                    yield Err(ChainError::from(err));
                    return;
                }
                match event {
                    StreamEvent::TextDelta(t) if !t.is_empty() => {
                        yield Ok(AgentStreamItem::Text(t));
                    }
                    StreamEvent::ReasoningDelta { text, .. } if !text.is_empty() => {
                        yield Ok(AgentStreamItem::Reasoning(text));
                    }
                    _ => {}
                }
            }
            let result = acc.finish();
            if let Some(memory) = &memory
                && let Err(err) = remember(memory.as_ref(), &text, &result.generation).await
            {
                yield Err(err);
                return;
            }
            yield Ok(AgentStreamItem::Final(AgentResponse {
                output: result.generation,
                usage: result.tokens,
                tool_calls: Vec::new(),
                turns: 0,
                stop_reason: StopReason::FinalAnswer,
                documents,
            }));
        }))
    }
}

/// The text chunks of an item stream, then the terminal chunk; a run that
/// stopped on a limit ends with an error instead.
fn text_only(mut items: AgentItemStream) -> TextStream {
    Box::pin(async_stream::stream! {
        while let Some(item) = items.next().await {
            match item {
                Ok(AgentStreamItem::Text(t)) => yield Ok(StreamData::chunk(t)),
                Ok(AgentStreamItem::Final(response)) => {
                    yield response.into_final().map(|_| StreamData::done());
                    return;
                }
                Ok(_) => {}
                Err(err) => {
                    yield Err(err);
                    return;
                }
            }
        }
    })
}

async fn remember(memory: &dyn Memory, text: &str, output: &str) -> Result<(), ChainError> {
    memory.add(Message::human(text)).await?;
    memory.add(Message::ai(output)).await
}

#[async_trait]
impl Chain for Agent {
    /// Answers the `"input"` key. A run that hits a limit is an error.
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input_text(&input_variables)?;
        let response = self.prompt_with_details(text).await?.into_final()?;
        Ok(GenerateResult::from_text(response.output).with_tokens(response.usage))
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<TextStream, ChainError> {
        let text = input_text(&input_variables)?;
        self.stream_prompt(text).await
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".to_owned()]
    }
}

fn input_text(input: &PromptArgs) -> Result<&str, ChainError> {
    input
        .get("input")
        .and_then(Value::as_str)
        .ok_or_else(|| ChainError::MissingVariable("input".to_owned()))
}

#[async_trait]
impl Tool for Agent {
    fn name(&self) -> &str {
        &self.inner.name
    }

    fn description(&self) -> &str {
        &self.inner.description
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "The question or task for the agent."
                }
            },
            "required": ["prompt"]
        })
    }

    /// Takes `{"prompt": "…"}`; plain text is used as the prompt as is.
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let prompt = match serde_json::from_str::<Value>(input) {
            Ok(Value::Object(args)) => match args.get("prompt").or_else(|| args.get("input")) {
                Some(Value::String(p)) => p.clone(),
                _ => {
                    return Err(ToolError::InvalidInput(
                        "expected a string argument `prompt`".into(),
                    ));
                }
            },
            _ => input.to_owned(),
        };
        self.prompt(prompt)
            .await
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))
    }
}

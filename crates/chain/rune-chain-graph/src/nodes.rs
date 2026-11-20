//! Ready-made nodes: a model call, tool execution and any `Chain`.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_agent::ToolExecutor;
use rune_chain_core::{
    Chain, FunctionDefinition, GenerateResult, Llm, LlmErrorKind, Message, PromptArgs, Role, Tool,
    ToolChoice,
};

use crate::error::GraphError;
use crate::node::{Node, NodeContext};
use crate::state::{GraphState, HasMessages};

type InputFn<S> = Arc<dyn Fn(&S) -> Vec<Message> + Send + Sync>;
type OutputFn<S> = Arc<dyn Fn(Message) -> <S as GraphState>::Update + Send + Sync>;

/// Calls a model on the state's messages and adds its reply
/// (`LangGraph`'s "call model" node).
///
/// With tools bound it uses
/// [`Llm::generate_with_tools`](rune_chain_core::Llm::generate_with_tools),
/// so the reply may carry tool calls for a [`ToolNode`]. Without tools and
/// under [`CompiledGraph::stream`](crate::CompiledGraph::stream), it streams
/// tokens as [`Event::Token`](crate::Event::Token) when the model supports
/// streaming.
pub struct LlmNode<S: GraphState> {
    llm: Arc<dyn Llm>,
    tools: Vec<FunctionDefinition>,
    tool_choice: Option<ToolChoice>,
    system_prompt: Option<String>,
    input: InputFn<S>,
    output: OutputFn<S>,
    stream: bool,
}

impl<S: GraphState> fmt::Debug for LlmNode<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmNode")
            .field(
                "tools",
                &self.tools.iter().map(|t| &t.name).collect::<Vec<_>>(),
            )
            .field("system_prompt", &self.system_prompt.is_some())
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl<S: HasMessages> LlmNode<S> {
    /// Read [`HasMessages::messages`] and add the reply with
    /// [`HasMessages::messages_update`].
    pub fn new(llm: Arc<dyn Llm>) -> Self {
        Self::with_io(
            llm,
            |s: &S| s.messages().to_vec(),
            |m| S::messages_update(vec![m]),
        )
    }
}

impl<S: GraphState> LlmNode<S> {
    /// For any state: `input` builds the prompt, `output` turns the reply
    /// into an update.
    pub fn with_io(
        llm: Arc<dyn Llm>,
        input: impl Fn(&S) -> Vec<Message> + Send + Sync + 'static,
        output: impl Fn(Message) -> S::Update + Send + Sync + 'static,
    ) -> Self {
        Self {
            llm,
            tools: Vec::new(),
            tool_choice: None,
            system_prompt: None,
            input: Arc::new(input),
            output: Arc::new(output),
            stream: true,
        }
    }

    /// Offer these tools to the model.
    #[must_use]
    pub fn tools(mut self, tools: Vec<FunctionDefinition>) -> Self {
        self.tools = tools;
        self
    }

    /// Set the tool choice.
    #[must_use]
    pub fn tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    /// Put a system message in front of every call. It is not stored in the
    /// state.
    #[must_use]
    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Stream tokens when the run is streamed (default: on).
    #[must_use]
    pub const fn streaming(mut self, on: bool) -> Self {
        self.stream = on;
        self
    }

    async fn generate(
        &self,
        messages: &[Message],
        ctx: &NodeContext<S>,
    ) -> Result<GenerateResult, GraphError> {
        if !self.tools.is_empty() {
            return Ok(self
                .llm
                .generate_with_tools(messages, &self.tools, self.tool_choice.clone())
                .await?);
        }
        if self.stream && ctx.is_streaming() {
            match self.llm.stream(messages).await {
                Ok(mut chunks) => {
                    let mut text = String::new();
                    while let Some(chunk) = chunks.next().await {
                        let chunk = chunk?;
                        if !chunk.content.is_empty() {
                            text.push_str(&chunk.content);
                            ctx.emit_token(chunk.content).await;
                        }
                        if chunk.is_finished {
                            break;
                        }
                    }
                    return Ok(GenerateResult::from_text(text));
                }
                Err(e) if e.kind() == LlmErrorKind::Unsupported => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(self.llm.generate(messages).await?)
    }
}

#[async_trait]
impl<S: GraphState> Node<S> for LlmNode<S> {
    async fn run(&self, state: Arc<S>, ctx: NodeContext<S>) -> Result<S::Update, GraphError> {
        let history = (self.input)(&state);
        drop(state);
        let messages = match &self.system_prompt {
            Some(system) => {
                let mut all = Vec::with_capacity(history.len() + 1);
                all.push(Message::system(system.as_str()));
                all.extend(history);
                all
            }
            None => history,
        };
        let result = self.generate(&messages, &ctx).await?;
        Ok((self.output)(result.to_message()))
    }
}

/// Runs the tool calls of the last AI message and adds one tool message per
/// call (`LangGraph`'s `ToolNode`).
///
/// Calls go through [`ToolExecutor`], so they get its schema validation,
/// limits (calls per turn, concurrency, timeouts, output size), approval
/// gates, error redaction and output fencing. When the last message is not an
/// AI turn with tool calls, the node changes nothing.
#[derive(Debug, Clone)]
pub struct ToolNode {
    executor: Arc<ToolExecutor>,
}

impl ToolNode {
    /// Use a configured executor.
    #[must_use]
    pub fn new(executor: ToolExecutor) -> Self {
        Self {
            executor: Arc::new(executor),
        }
    }

    /// Default limits over `tools`.
    #[must_use]
    pub fn from_tools(tools: impl IntoIterator<Item = Box<dyn Tool>>) -> Self {
        Self::new(ToolExecutor::new().tools(tools))
    }

    /// The executor, for its function definitions and system prompt.
    #[must_use]
    pub fn executor(&self) -> &ToolExecutor {
        &self.executor
    }
}

#[async_trait]
impl<S: HasMessages> Node<S> for ToolNode {
    async fn run(&self, state: Arc<S>, ctx: NodeContext<S>) -> Result<S::Update, GraphError> {
        let calls = match state.messages().last() {
            Some(m) if m.role == Role::Ai && !m.tool_calls.is_empty() => m.tool_calls.clone(),
            _ => return Ok(S::Update::default()),
        };
        drop(state);
        let runs = self.executor.execute(&calls, ctx.step()).await?;
        Ok(S::messages_update(self.executor.tool_messages(&runs)))
    }
}

/// Runs any [`Chain`] as a node: `input` builds its prompt arguments from
/// the state, `output` turns its result into an update.
pub struct ChainNode<S: GraphState> {
    chain: Arc<dyn Chain>,
    input: Arc<dyn Fn(&S) -> PromptArgs + Send + Sync>,
    output: Arc<dyn Fn(GenerateResult) -> S::Update + Send + Sync>,
}

impl<S: GraphState> fmt::Debug for ChainNode<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainNode").finish_non_exhaustive()
    }
}

impl<S: GraphState> ChainNode<S> {
    /// Wrap `chain`.
    pub fn new(
        chain: Arc<dyn Chain>,
        input: impl Fn(&S) -> PromptArgs + Send + Sync + 'static,
        output: impl Fn(GenerateResult) -> S::Update + Send + Sync + 'static,
    ) -> Self {
        Self {
            chain,
            input: Arc::new(input),
            output: Arc::new(output),
        }
    }
}

#[async_trait]
impl<S: GraphState> Node<S> for ChainNode<S> {
    async fn run(&self, state: Arc<S>, _ctx: NodeContext<S>) -> Result<S::Update, GraphError> {
        let args = (self.input)(&state);
        drop(state);
        let result = self.chain.call(args).await?;
        Ok((self.output)(result))
    }
}

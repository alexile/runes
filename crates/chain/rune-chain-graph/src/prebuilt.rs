//! A ready-made tool-calling agent built from graph parts.

use std::sync::Arc;

use rune_chain_agent::ToolExecutor;
use rune_chain_core::{Llm, Role};

use crate::error::GraphError;
use crate::graph::StateGraph;
use crate::node::{END, START};
use crate::nodes::{LlmNode, ToolNode};
use crate::run::CompiledGraph;
use crate::state::{HasMessages, MessagesState};

const DEFAULT_SYSTEM_PROMPT: &str =
    "You are a helpful assistant. Use the provided tools when they help answer the question.";

/// Route to `"tools"` when the last message is an AI turn with tool calls,
/// else to [`END`] (`LangGraph`'s `tools_condition`).
pub fn tools_condition<S: HasMessages>(state: &S) -> &'static str {
    match state.messages().last() {
        Some(m) if m.role == Role::Ai && !m.tool_calls.is_empty() => "tools",
        _ => END,
    }
}

/// The uncompiled `agent ⇄ tools` graph behind [`create_react_agent`], for
/// adding nodes or compiling with your own options (checkpointer,
/// `interrupt_before(["tools"])` for tool approval, limits).
///
/// `system_prompt` defaults to a short helpful-assistant prompt; the tool
/// executor's untrusted-output notice is appended to it.
pub fn react_agent_graph<S: HasMessages>(
    llm: Arc<dyn Llm>,
    tools: ToolExecutor,
    system_prompt: Option<&str>,
) -> StateGraph<S> {
    let tools = ToolNode::new(tools);
    let system = tools
        .executor()
        .system_prompt(system_prompt.unwrap_or(DEFAULT_SYSTEM_PROMPT));
    let agent = LlmNode::<S>::new(llm)
        .tools(tools.executor().definitions())
        .system_prompt(system);

    let mut graph = StateGraph::new();
    graph
        .add_node_with("agent", agent)
        .add_node_with("tools", tools)
        .add_edge(START, "agent")
        .add_conditional_edges("agent", tools_condition::<S>, ["tools", END])
        .add_edge("tools", "agent");
    graph
}

/// A `ReAct`-style agent: the model is called with the tools bound, any tool
/// calls run through a [`ToolNode`], and the results go back to the model
/// until it answers in text (`LangGraph`'s `create_react_agent`).
///
/// Each model turn plus tool turn is two supersteps, so the default
/// recursion limit of 25 allows 12 tool rounds.
///
/// # Errors
///
/// Never in practice; the graph is fixed. The `Result` mirrors
/// [`StateGraph::compile`].
pub fn create_react_agent(
    llm: Arc<dyn Llm>,
    tools: ToolExecutor,
) -> Result<CompiledGraph<MessagesState>, GraphError> {
    react_agent_graph(llm, tools, None).compile()
}

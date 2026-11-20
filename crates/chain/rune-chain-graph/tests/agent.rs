//! Model, tool and chain nodes, and the prebuilt agent, against `FakeLlm`.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_core::testing::{FakeLlm, FakeReply};
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Message, PromptArgs, Role, Tool, ToolCall, ToolError,
};
use rune_chain_graph::{
    AgentLimits, Approval, ApprovalRequest, ChainNode, Command, CompileOptions, END, Event,
    GraphError, InMemoryCheckpointer, LlmNode, MessagesState, MessagesUpdate, RunConfig, START,
    StateGraph, ToolExecutor, ToolNode, create_react_agent, react_agent_graph, tools_condition,
};

struct Add;

#[async_trait]
impl Tool for Add {
    fn name(&self) -> &'static str {
        "add"
    }
    fn description(&self) -> &'static str {
        "Adds two integers."
    }
    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "a": { "type": "integer" }, "b": { "type": "integer" } },
            "required": ["a", "b"],
            "additionalProperties": false
        })
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let v: serde_json::Value =
            serde_json::from_str(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        Ok((v["a"].as_i64().unwrap_or(0) + v["b"].as_i64().unwrap_or(0)).to_string())
    }
}

fn ask(q: &str) -> MessagesState {
    MessagesState::new(vec![Message::human(q)])
}

#[tokio::test]
async fn react_agent_calls_tools_then_answers() {
    let llm = FakeLlm::with_replies([
        FakeReply::tool_calls([
            ToolCall::new("c1", "add", r#"{"a":2,"b":3}"#),
            ToolCall::new("c2", "add", r#"{"a":"x"}"#),
        ]),
        FakeReply::tool_calls([ToolCall::new("c3", "add", r#"{"a":5,"b":10}"#)]),
        FakeReply::text("The answer is 15."),
    ]);
    let app = create_react_agent(Arc::new(llm.clone()), ToolExecutor::new().tool(Add)).unwrap();
    let out = app
        .invoke(ask("What is 2+3+10?"), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.last_text(), "The answer is 15.");
    assert_eq!(out.steps, 5, "agent, tools, agent, tools, agent");

    let roles: Vec<Role> = out.state.messages.iter().map(|m| m.role.clone()).collect();
    assert_eq!(
        roles,
        [
            Role::Human,
            Role::Ai,
            Role::Tool,
            Role::Tool,
            Role::Ai,
            Role::Tool,
            Role::Ai
        ]
    );
    let tool_text = |i: usize| out.state.messages[i].text();
    assert!(tool_text(2).contains("status=\"ok\"") && tool_text(2).contains("\n5\n"));
    assert!(
        tool_text(3).contains("status=\"error\""),
        "bad arguments go back to the model"
    );
    assert!(tool_text(5).contains("\n15\n"));

    // Every model call saw the tool and a system prompt with the fence
    // notice; the system prompt is not stored in the state.
    let requests = llm.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].tool_names(), ["add"]);
    assert!(requests[0].system().unwrap().contains("<tool_output>"));
    assert!(out.state.messages.iter().all(|m| m.role != Role::System));
}

#[tokio::test]
async fn react_agent_hits_the_recursion_limit() {
    let llm = FakeLlm::from_fn(|_| {
        Ok(
            GenerateResult::default().with_tool_calls(vec![ToolCall::new(
                "c",
                "add",
                r#"{"a":1,"b":1}"#,
            )]),
        )
    });
    let app = create_react_agent(Arc::new(llm), ToolExecutor::new().tool(Add)).unwrap();
    let err = app
        .invoke(ask("loop"), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::RecursionLimit(25)), "{err}");
}

struct Rm;
#[async_trait]
impl Tool for Rm {
    fn name(&self) -> &'static str {
        "rm"
    }
    fn description(&self) -> &'static str {
        "Deletes things."
    }
    async fn run(&self, _: &str) -> Result<String, ToolError> {
        Ok("deleted".into())
    }
}

#[tokio::test]
async fn tool_node_applies_agent_limits_and_approval() {
    let tools = ToolExecutor::new().tool(Add).tool(Add);
    // Duplicate names are rejected by the executor.
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with("tools", ToolNode::new(tools))
        .add_edge(START, "tools");
    let state = MessagesState::new(vec![Message::ai_with_tool_calls(
        "",
        vec![ToolCall::new("c1", "add", r#"{"a":1,"b":2}"#)],
    )]);
    let err = g
        .compile()
        .unwrap()
        .invoke(state.clone(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("registered twice"), "{err}");

    let tools = ToolExecutor::new()
        .tool(Add)
        .tool_requiring_approval(Rm)
        .approver(|req: ApprovalRequest| async move {
            if req.arguments.contains('/') {
                Approval::Deny("not the root".into())
            } else {
                Approval::Allow
            }
        })
        .limits(AgentLimits::default().max_tool_calls_per_turn(2));
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with("tools", ToolNode::new(tools))
        .add_edge(START, "tools");
    let state = MessagesState::new(vec![Message::ai_with_tool_calls(
        "",
        vec![
            ToolCall::new("c1", "rm", r#"{"input":"/"}"#),
            ToolCall::new("c2", "add", r#"{"a":1,"b":2}"#),
            ToolCall::new("c3", "add", r#"{"a":1,"b":2}"#),
        ],
    )]);
    let out = g
        .compile()
        .unwrap()
        .invoke(state, &RunConfig::default())
        .await
        .unwrap();
    let texts: Vec<String> = out.state.messages[1..].iter().map(Message::text).collect();
    assert!(texts[0].contains("status=\"denied\"") && texts[0].contains("not the root"));
    assert!(texts[1].contains("status=\"ok\""));
    assert!(texts[2].contains("status=\"skipped\""));

    // With no pending tool calls the node changes nothing.
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with(
        "tools",
        ToolNode::from_tools([Box::new(Add) as Box<dyn Tool>]),
    )
    .add_edge(START, "tools");
    let out = g
        .compile()
        .unwrap()
        .invoke(ask("hi"), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.messages.len(), 1);
}

#[tokio::test]
async fn tool_approval_through_interrupt_before() {
    let llm = FakeLlm::with_replies([
        FakeReply::tool_calls([ToolCall::new("c1", "add", r#"{"a":20,"b":22}"#)]),
        FakeReply::text("42"),
    ]);
    let graph = react_agent_graph::<MessagesState>(
        Arc::new(llm),
        ToolExecutor::new().tool(Add),
        Some("Be brief."),
    );
    let app = graph
        .compile_with(
            CompileOptions::default()
                .checkpointer(Arc::new(InMemoryCheckpointer::new()))
                .interrupt_before(["tools"]),
        )
        .unwrap();
    let config = RunConfig::thread("approve");
    let out = app.invoke(ask("20+22?"), &config).await.unwrap();
    assert_eq!(out.interrupt.unwrap().node, "tools");
    let pending = &out.state.messages.last().unwrap().tool_calls;
    assert_eq!(pending[0].name, "add");

    let out = app.invoke(Command::default(), &config).await.unwrap();
    assert_eq!(out.state.last_text(), "42");
}

#[tokio::test]
async fn llm_node_streams_tokens() {
    let llm = FakeLlm::with_replies([FakeReply::text("hello world")]).with_chunk_chars(4);
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with("model", LlmNode::new(Arc::new(llm)))
        .add_edge(START, "model");
    let app = g.compile().unwrap();
    let mut tokens = Vec::new();
    let mut done = None;
    let mut stream = app.stream(ask("hi"), &RunConfig::default());
    while let Some(event) = stream.next().await {
        match event.unwrap() {
            Event::Token { node, text, .. } => {
                assert_eq!(node, "model");
                tokens.push(text);
            }
            Event::Done(out) => done = Some(out),
            _ => {}
        }
    }
    assert_eq!(tokens, ["hell", "o wo", "rld"]);
    assert_eq!(done.unwrap().state.last_text(), "hello world");
}

#[tokio::test]
async fn llm_node_reports_model_errors() {
    let llm = FakeLlm::with_replies([FakeReply::rate_limited()]);
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with("model", LlmNode::new(Arc::new(llm)))
        .add_edge(START, "model");
    let err = g
        .compile()
        .unwrap()
        .invoke(ask("hi"), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::NodeFailed { node, source } if node == "model" && matches!(**source, GraphError::Llm(_))),
        "{err}"
    );
}

struct Shout;

#[async_trait]
impl Chain for Shout {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input["text"].as_str().unwrap_or_default().to_uppercase();
        Ok(GenerateResult::from_text(text))
    }
}

#[tokio::test]
async fn chain_node_and_tools_condition() {
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node_with(
        "shout",
        ChainNode::new(
            Arc::new(Shout),
            |s: &MessagesState| rune_chain_core::prompt_args! { "text" => s.last_text() },
            |r| MessagesUpdate::new(vec![Message::ai(r.generation)]),
        ),
    )
    .add_edge(START, "shout")
    .add_edge("shout", END);
    let out = g
        .compile()
        .unwrap()
        .invoke(ask("quiet"), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.last_text(), "QUIET");
    assert_eq!(tools_condition(&out.state), END);
    let calling = MessagesState::new(vec![Message::ai_with_tool_calls(
        "",
        vec![ToolCall::new("c", "add", "{}")],
    )]);
    assert_eq!(tools_condition(&calling), "tools");
}

#[test]
fn react_agent_diagram() {
    let app = create_react_agent(Arc::new(FakeLlm::new()), ToolExecutor::new().tool(Add)).unwrap();
    assert_eq!(
        app.draw_mermaid(),
        "\
flowchart TD
    __start__([\"__start__\"])
    n0[\"agent\"]
    n1[\"tools\"]
    __end__([\"__end__\"])
    __start__ --> n0
    n0 -.-> n1
    n0 -.-> __end__
    n1 --> n0
"
    );
}

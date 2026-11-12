//! End-to-end MCP sessions over in-process `tokio::io::duplex` streams.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::unnecessary_literal_bound,
    reason = "test helpers fail loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rune_mcp::{
    ClientOptions, Content, Decision, Error, MaxSafety, McpClient, McpServer, ServerTrust,
    ToolCall, ToolError, ToolOutput, tool_fn,
};
use rune_tool_schema::{SafetyLevel, ToolCategory, ToolDescriptor, ToolHints, single_input_schema};
use serde_json::{Map, Value, json};

fn args(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn upper_descriptor() -> ToolDescriptor {
    ToolDescriptor::new("upper", "Upper-case the input.")
        .with_title("Upper")
        .with_category(ToolCategory::ENCODING)
        .with_hints(ToolHints::PURE)
        .with_tags(["text"])
        .with_version("1.0.0")
        .with_input_schema(single_input_schema("Text"))
}

fn input(args: &Map<String, Value>) -> Result<String, ToolError> {
    args.get("input")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ToolError::new("missing `input`"))
}

/// A server with a passive `upper`, an intrusive `scan` and a failing `fail`.
fn demo_server(scan_calls: Arc<AtomicUsize>) -> McpServer {
    McpServer::new("demo", "1.2.3")
        .with_instructions("Use upper to shout.")
        .tool(
            upper_descriptor(),
            tool_fn(|args| async move { Ok(ToolOutput::text(input(&args)?.to_uppercase())) }),
        )
        .unwrap()
        .tool(
            ToolDescriptor::new("scan", "Scan a host.")
                .with_safety(SafetyLevel::Intrusive)
                .with_hints(ToolHints::MCP_DEFAULT),
            tool_fn(move |_args| {
                let calls = Arc::clone(&scan_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(ToolOutput::structured(json!({"open": [22, 443]})))
                }
            }),
        )
        .unwrap()
        .tool(
            ToolDescriptor::new("fail", "Always fails.").with_hints(ToolHints::PURE),
            tool_fn(|_args| async move { Err(ToolError::new("boom")) }),
        )
        .unwrap()
}

async fn connect<S>(server: S, options: ClientOptions) -> McpClient
where
    S: ServerHandler,
{
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let running = server.serve(server_io).await.unwrap();
        let _ = running.waiting().await;
    });
    McpClient::connect(client_io, options).await.unwrap()
}

#[tokio::test]
async fn rune_tool_is_served_and_called() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = connect(
        demo_server(Arc::clone(&calls)),
        ClientOptions::default()
            .with_client_info("test-client", "0.0.1")
            .with_trust(ServerTrust::Trusted),
    )
    .await;

    let info = client.server_info().unwrap();
    assert_eq!(info.name.as_deref(), Some("demo"));
    assert_eq!(info.version.as_deref(), Some("1.2.3"));
    assert_eq!(info.instructions.as_deref(), Some("Use upper to shout."));

    let tools = client.list_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["fail", "scan", "upper"]);
    // Trusted: the descriptor survives the trip losslessly.
    let upper = tools.iter().find(|t| t.name == "upper").unwrap();
    assert_eq!(*upper, upper_descriptor());

    let out = client
        .call_tool("upper", args(json!({"input": "hello"})))
        .await
        .unwrap();
    assert_eq!(out, ToolOutput::text("HELLO"));

    let out = client.call_tool("scan", args(json!({}))).await.unwrap();
    assert_eq!(out.structured, Some(json!({"open": [22, 443]})));
    assert!(!out.is_error);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    client.close().await.unwrap();
}

#[tokio::test]
async fn tool_failures_are_results_not_errors() {
    let client = connect(demo_server(Arc::default()), ClientOptions::default()).await;
    let out = client.call_tool("fail", Map::new()).await.unwrap();
    assert!(out.is_error);
    assert_eq!(out.text_content(), "boom");

    // Arguments that do not fit the schema never reach the handler.
    let out = client.call_tool("upper", Map::new()).await.unwrap();
    assert!(out.is_error);
    assert_eq!(
        out.text_content(),
        r#"invalid arguments for tool "upper": /input: missing required property"#
    );
}

#[tokio::test]
async fn untrusted_server_tools_are_intrusive() {
    let client = connect(demo_server(Arc::default()), ClientOptions::default()).await;
    let tools = client.list_tools().await.unwrap();
    assert!(tools.iter().all(|t| t.safety == SafetyLevel::Intrusive));
    // Hints still come through; only the safety claim is overridden.
    let upper = tools.iter().find(|t| t.name == "upper").unwrap();
    assert_eq!(upper.hints, ToolHints::PURE);
}

#[tokio::test]
async fn server_policy_hides_and_denies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = demo_server(Arc::clone(&calls)).with_policy(
        rune_mcp::AllOf::new()
            .with(MaxSafety(SafetyLevel::Active))
            .with(|call: &ToolCall<'_>| {
                if call.arguments.get("input") == Some(&json!("forbidden")) {
                    Decision::deny("forbidden input")
                } else {
                    Decision::Allow
                }
            }),
    );

    // In-process call through the same gate.
    assert!(matches!(
        server.call("scan", Map::new()).await,
        Err(Error::UnknownTool(name)) if name == "scan"
    ));

    let client = connect(server, ClientOptions::default()).await;
    let names: Vec<_> = client
        .list_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, ["fail", "upper"]);

    let out = client
        .call_tool("upper", args(json!({"input": "forbidden"})))
        .await
        .unwrap();
    assert!(out.is_error);
    assert!(out.text_content().contains("forbidden input"), "{out:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn server_rejects_hidden_tool_with_protocol_error() {
    let server = demo_server(Arc::default()).with_policy(MaxSafety(SafetyLevel::Passive));
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let running = server.serve(server_io).await.unwrap();
        let _ = running.waiting().await;
    });
    // A raw rmcp client, which skips rune-mcp's client-side checks.
    let raw = ().serve(client_io).await.unwrap();
    let err = raw
        .call_tool(CallToolRequestParams::new("scan"))
        .await
        .unwrap_err();
    let err = Error::from(err);
    assert!(
        matches!(&err, Error::Protocol { code: -32602, message } if message.contains("scan")),
        "{err:?}"
    );
}

#[tokio::test]
async fn client_policy_blocks_before_sending() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = connect(
        demo_server(Arc::clone(&calls)),
        ClientOptions::default()
            .with_trust(ServerTrust::Trusted)
            .with_policy(|call: &ToolCall<'_>| {
                if call.tool.safety > SafetyLevel::Passive {
                    Decision::deny("not passive")
                } else {
                    Decision::Allow
                }
            }),
    )
    .await;
    let err = client.call_tool("scan", Map::new()).await.unwrap_err();
    assert!(
        matches!(&err, Error::Denied { tool, reason } if tool == "scan" && reason == "not passive"),
        "{err:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A client policy that hides tools filters the listing too.
    let client = connect(
        demo_server(Arc::default()),
        ClientOptions::default().with_policy(rune_mcp::AllowNames::new(["upper"])),
    )
    .await;
    assert_eq!(client.list_tools().await.unwrap().len(), 1);
    assert!(matches!(
        client.call_tool("fail", Map::new()).await,
        Err(Error::UnknownTool(_))
    ));
}

#[tokio::test]
async fn unknown_tool_is_reported_without_a_call() {
    let client = connect(demo_server(Arc::default()), ClientOptions::default()).await;
    // Not listed yet: `call_tool` lists first.
    assert!(matches!(
        client.call_tool("nope", Map::new()).await,
        Err(Error::UnknownTool(name)) if name == "nope"
    ));
}

/// A third-party MCP server written directly against rmcp: no `_meta`, no
/// annotations, one tool without a description and one malformed tool.
#[derive(Clone)]
struct ExternalServer;

fn external_tools() -> Vec<Tool> {
    let schema = |v: Value| Arc::new(v.as_object().unwrap().clone());
    let mut bare = Tool::new_with_raw("time_now", None, schema(json!({"type": "object"})));
    bare.title = Some("Now".into());
    vec![
        Tool::new(
            "add",
            "Add two integers.",
            schema(json!({
                "type": "object",
                "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                "required": ["a", "b"]
            })),
        ),
        bare,
        Tool::new(
            "bad name",
            "Breaks the naming rules.",
            schema(json!({"type": "object"})),
        ),
    ]
}

impl ServerHandler for ExternalServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(external_tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = request.arguments.unwrap_or_default();
        let result = match request.name.as_ref() {
            "add" => {
                let a = args.get("a").and_then(Value::as_i64).unwrap_or(0);
                let b = args.get("b").and_then(Value::as_i64).unwrap_or(0);
                CallToolResult::success(vec![
                    ContentBlock::text((a + b).to_string()),
                    ContentBlock::image("aGk=", "image/png"),
                ])
            }
            "time_now" => CallToolResult::structured(json!({"unix": 0})),
            other => {
                return Err(ErrorData::invalid_params(format!("no tool {other}"), None));
            }
        };
        Ok(result.into())
    }
}

#[tokio::test]
async fn external_server_is_consumed() {
    let client = connect(ExternalServer, ClientOptions::default()).await;
    let info = client.server_info().unwrap();
    assert!(info.instructions.is_none());

    // Lenient by default: the malformed tool is skipped.
    let tools = client.list_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["add", "time_now"]);
    let add = &tools[0];
    assert_eq!(add.description, "Add two integers.");
    assert_eq!(add.hints, ToolHints::MCP_DEFAULT);
    assert_eq!(add.safety, SafetyLevel::Intrusive);
    let now = &tools[1];
    assert_eq!(now.description, "");
    assert_eq!(now.title.as_deref(), Some("Now"));

    let out = client
        .call_tool("add", args(json!({"a": 2, "b": 40})))
        .await
        .unwrap();
    assert_eq!(out.text_content(), "42");
    assert_eq!(out.content.len(), 2);
    match &out.content[1] {
        Content::Other(image) => {
            assert_eq!(image["type"], "image");
            assert_eq!(image["mimeType"], "image/png");
        }
        other => panic!("expected an image block, got {other:?}"),
    }

    let out = client.call_tool("time_now", Map::new()).await.unwrap();
    assert_eq!(out.structured, Some(json!({"unix": 0})));

    // Strict mode refuses the malformed listing.
    let strict = connect(ExternalServer, ClientOptions::default().with_strict(true)).await;
    assert!(matches!(
        strict.list_tools().await,
        Err(Error::Rejected { name, .. }) if name == "bad name"
    ));
    // The lenient client reports what it skipped.
    let rejected = client.rejected();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].name, "bad name");
}

#[tokio::test]
async fn remote_tools_are_proxied_through_a_second_server() {
    // external server <- client A <- proxy server <- client B
    let upstream = Arc::new(connect(ExternalServer, ClientOptions::default()).await);
    let mut proxy =
        McpServer::new("proxy", "0.1.0").with_policy(rune_mcp::DenyNames::new(["time_now"]));
    for remote in upstream.remote_tools().await.unwrap() {
        proxy.add_tool(remote.descriptor().clone(), remote).unwrap();
    }
    let names: Vec<_> = proxy.descriptors().map(|d| d.name.clone()).collect();
    assert_eq!(names, ["add", "time_now"]);

    let client = connect(proxy, ClientOptions::default()).await;
    let listed: Vec<_> = client
        .list_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(listed, ["add"]);
    let out = client
        .call_tool("add", args(json!({"a": 1, "b": 2})))
        .await
        .unwrap();
    assert_eq!(out.text_content(), "3");
    // The image block survives both hops.
    assert!(matches!(&out.content[1], Content::Other(v) if v["type"] == "image"));
    let now = client.tool("time_now").await;
    assert!(matches!(now, Err(Error::UnknownTool(_))));
}

#[tokio::test]
async fn registration_is_validated() {
    let server = McpServer::new("s", "1");
    let err = server
        .clone()
        .tool(
            ToolDescriptor::new("bad name", "d"),
            tool_fn(|_| async { Ok(ToolOutput::default()) }),
        )
        .unwrap_err();
    assert!(matches!(err, Error::Descriptor(_)));

    let server = server
        .tool(
            ToolDescriptor::new("a", "d"),
            tool_fn(|_| async { Ok(ToolOutput::default()) }),
        )
        .unwrap();
    let err = server
        .tool(
            ToolDescriptor::new("a", "again"),
            tool_fn(|_| async { Ok(ToolOutput::default()) }),
        )
        .unwrap_err();
    assert!(matches!(err, Error::Duplicate { kind: "tool", name } if name == "a"));
}

#[tokio::test]
async fn builder_on_a_shared_server_leaves_clones_alone() {
    let base = McpServer::new("s", "1")
        .tool(
            ToolDescriptor::new("a", "d"),
            tool_fn(|_| async { Ok(ToolOutput::text("a")) }),
        )
        .unwrap();
    let extended = base
        .clone()
        .tool(
            ToolDescriptor::new("b", "d"),
            tool_fn(|_| async { Ok(ToolOutput::text("b")) }),
        )
        .unwrap();
    assert_eq!(base.descriptors().count(), 1);
    assert_eq!(extended.descriptors().count(), 2);
    assert_eq!(
        extended.call("a", Map::new()).await.unwrap().text_content(),
        "a"
    );
}

#[cfg(feature = "chain")]
mod chain {
    use super::*;
    use async_trait::async_trait;
    use rune_chain_core::Tool as ChainToolTrait;
    use rune_mcp::ChainTool;

    struct Reverse;

    #[async_trait]
    impl ChainToolTrait for Reverse {
        fn name(&self) -> &str {
            "reverse"
        }
        fn description(&self) -> &str {
            "Reverse the input."
        }
        async fn run(&self, input: &str) -> Result<String, rune_chain_core::ToolError> {
            if input.is_empty() {
                return Err(rune_chain_core::ToolError::InvalidInput("empty".into()));
            }
            Ok(input.chars().rev().collect())
        }
    }

    #[tokio::test]
    async fn chain_tool_served_and_remote_tool_used_as_chain_tool() {
        let (descriptor, handler) = ChainTool::described(Reverse);
        assert_eq!(descriptor.safety, SafetyLevel::Intrusive);
        let server = McpServer::new("chain", "0.1.0")
            .tool(descriptor, handler)
            .unwrap();
        let client = Arc::new(connect(server, ClientOptions::default()).await);
        let remote = client.remote_tools().await.unwrap().remove(0);

        // Through the rune-chain Tool trait, as an agent would call it:
        // results are fenced as untrusted data by default.
        assert_eq!(ChainToolTrait::name(&remote), "reverse");
        assert_eq!(
            remote.run("abc").await.unwrap(),
            "<mcp_result tool=\"reverse\" status=\"ok\">\ncba\n</mcp_result>"
        );
        let err = remote.run("").await.unwrap_err();
        assert!(err.to_string().contains("invalid input: empty"), "{err}");
        assert!(err.to_string().contains("status=\"error\""), "{err}");

        let plain = Arc::new(
            connect(
                McpServer::new("chain", "0.1.0")
                    .tool(ChainTool::described(Reverse).0, ChainTool::new(Reverse))
                    .unwrap(),
                ClientOptions::default().with_fence_results(false),
            )
            .await,
        );
        let remote = plain.remote_tools().await.unwrap().remove(0);
        assert_eq!(remote.run(r#"{"input":"xy"}"#).await.unwrap(), "yx");
    }
}

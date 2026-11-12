//! The Streamable HTTP endpoint, driven in-process: requests go straight to
//! the tower service, with no socket.
#![cfg(feature = "http-server")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail loudly"
)]

use std::io::Cursor;

use http_body_util::{BodyExt, Full};
use rmcp::transport::StreamableHttpServerConfig;
use rune_mcp::{McpServer, ToolOutput, tool_fn};
use rune_tool_schema::{ToolDescriptor, ToolHints, single_input_schema};
use serde_json::{Value, json};
use tower::ServiceExt;

fn server() -> McpServer {
    McpServer::new("http-demo", "0.1.0")
        .tool(
            ToolDescriptor::new("upper", "Upper-case the input.")
                .with_hints(ToolHints::PURE)
                .with_input_schema(single_input_schema("Text")),
            tool_fn(|args| async move {
                let input = args.get("input").and_then(Value::as_str).unwrap_or("");
                Ok(ToolOutput::text(input.to_uppercase()))
            }),
        )
        .unwrap()
}

async fn post(
    service: &rmcp::transport::StreamableHttpService<
        McpServer,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    >,
    body: &Value,
) -> (http::StatusCode, Value) {
    let request = http::Request::post("http://localhost/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .body(Full::new(Cursor::new(serde_json::to_vec(body).unwrap())))
        .unwrap();
    let response = service.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let json = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("status {status}, body {text:?}: {err}"));
    (status, json)
}

#[tokio::test]
async fn tools_are_served_over_streamable_http() {
    let mut config = StreamableHttpServerConfig::default();
    config.legacy_session_mode = false;
    config.json_response = true;
    let service = server().into_http_service(config);

    let (status, listed) = post(
        &service,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK, "{listed}");
    assert_eq!(listed["result"]["tools"][0]["name"], "upper");
    assert_eq!(
        listed["result"]["tools"][0]["annotations"]["readOnlyHint"],
        true
    );

    let (status, called) = post(
        &service,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "upper", "arguments": {"input": "hi"}}
        }),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK, "{called}");
    assert_eq!(called["result"]["content"][0]["text"], "HI");
    assert_eq!(called["result"]["isError"], false);
}

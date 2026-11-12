//! Property tests: descriptor <-> MCP round trips, and the importers never
//! panic on arbitrary input.

use proptest::prelude::*;
use rune_tool_schema::{
    McpTool, SafetyLevel, ToolCategory, ToolDescriptor, ToolHints, validate_name,
};
use serde_json::json;

fn name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.-]{1,128}"
}

fn category() -> impl Strategy<Value = Option<ToolCategory>> {
    proptest::option::of(
        "[a-z][a-z0-9_]{0,63}".prop_filter_map("valid category", |s| ToolCategory::new(s).ok()),
    )
}

fn hints() -> impl Strategy<Value = ToolHints> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(r, d, i, o)| {
        ToolHints::PURE
            .with_read_only(r)
            .with_destructive(d)
            .with_idempotent(i)
            .with_open_world(o)
    })
}

prop_compose! {
    fn descriptor()(
        name in name(),
        title in proptest::option::of(".{0,40}"),
        description in "\\PC*[a-z]\\PC*",
        category in category(),
        tags in proptest::collection::vec(".{0,12}", 0..4),
        safety in prop::sample::select(SafetyLevel::ALL.to_vec()),
        hints in hints(),
        version in proptest::option::of("[0-9.]{1,8}"),
        props in proptest::collection::btree_map("[a-z]{1,8}", Just(json!({"type": "string"})), 0..4),
        output in any::<bool>(),
    ) -> ToolDescriptor {
        let mut tool = ToolDescriptor::new(name, description)
            .with_tags(tags)
            .with_safety(safety)
            .with_hints(hints)
            .with_input_schema(json!({"type": "object", "properties": props}));
        if let Some(title) = title { tool = tool.with_title(title); }
        if let Some(category) = category { tool = tool.with_category(category); }
        if let Some(version) = version { tool = tool.with_version(version); }
        if output { tool = tool.with_output_schema(json!({"type": "object"})); }
        tool
    }
}

proptest! {
    #[test]
    fn mcp_round_trip(tool in descriptor()) {
        let mcp = tool.to_mcp().expect("generated descriptors are valid");
        let text = serde_json::to_string(&mcp).expect("serializes");
        let back: McpTool = serde_json::from_str(&text).expect("deserializes");
        prop_assert_eq!(&back, &mcp);
        prop_assert_eq!(back.to_descriptor().expect("imports"), tool);
    }

    #[test]
    fn descriptor_json_round_trip(tool in descriptor()) {
        let text = serde_json::to_string(&tool).expect("serializes");
        let back: ToolDescriptor = serde_json::from_str(&text).expect("deserializes");
        prop_assert_eq!(back, tool);
    }

    #[test]
    fn import_never_panics(text in "\\PC*") {
        if let Ok(tool) = serde_json::from_str::<McpTool>(&text) {
            let _ = tool.to_descriptor();
        }
        let _ = serde_json::from_str::<ToolDescriptor>(&text);
        let _ = validate_name(&text);
        let _ = ToolCategory::new(text);
    }

    #[test]
    fn imported_tools_re_export(
        name in name(),
        read_only in proptest::option::of(any::<bool>()),
        destructive in proptest::option::of(any::<bool>()),
    ) {
        let mut annotations = serde_json::Map::new();
        if let Some(v) = read_only { annotations.insert("readOnlyHint".into(), v.into()); }
        if let Some(v) = destructive { annotations.insert("destructiveHint".into(), v.into()); }
        let raw = json!({
            "name": name,
            "description": "d",
            "inputSchema": {"type": "object"},
            "annotations": annotations,
        });
        let tool: McpTool = serde_json::from_value(raw).expect("valid MCP tool");
        let descriptor = tool.to_descriptor().expect("imports");
        prop_assert_eq!(descriptor.hints.read_only, read_only.unwrap_or(false));
        prop_assert_eq!(descriptor.hints.destructive, destructive.unwrap_or(true));
        prop_assert!(descriptor.to_mcp().is_ok());
    }
}

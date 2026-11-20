//! Building, routing, supersteps, limits and streaming.

#![allow(clippy::unwrap_used, reason = "test assertions")]
#![allow(missing_docs, reason = "test fixtures")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;
use rune_chain_core::{Message, ToolCall};
use rune_chain_graph::{
    AddMessages, Append, CancelToken, CompileOptions, END, Event, GraphError, GraphState, MergeMap,
    MessagesState, MessagesUpdate, Reducer, Replace, RunConfig, START, SendTo, StateGraph, Sum,
    state,
};
use serde::{Deserialize, Serialize};

state! {
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Flow => FlowUpdate {
        pub input: String = Replace,
        pub path: Vec<String> = Append,
        pub count: i64 = Sum,
        pub item: String = Replace,
        pub items: Vec<String> = Replace,
    }
}

fn visit(name: &'static str) -> FlowUpdate {
    FlowUpdate::default().path(vec![name.to_owned()])
}

#[test]
fn reducers() {
    let mut list = vec![1];
    <Append as Reducer<Vec<i32>>>::reduce(&mut list, vec![2, 3]);
    assert_eq!(list, [1, 2, 3]);

    let mut text = "a".to_owned();
    <Replace as Reducer<String>>::reduce(&mut text, "b".to_owned());
    assert_eq!(text, "b");

    let mut total = 1.5_f64;
    <Sum as Reducer<f64>>::reduce(&mut total, 2.0);
    assert!((total - 3.5).abs() < f64::EPSILON);

    let mut map = BTreeMap::from([("a", 1), ("b", 2)]);
    <MergeMap as Reducer<_>>::reduce(&mut map, BTreeMap::from([("b", 20), ("c", 3)]));
    assert_eq!(map, BTreeMap::from([("a", 1), ("b", 20), ("c", 3)]));

    let mut flow = Flow::default();
    flow.merge(FlowUpdate::default());
    assert_eq!(flow, Flow::default(), "an empty update changes nothing");
    flow.merge(visit("a").count(2));
    flow.merge(visit("b").count(-1).input("x".into()));
    assert_eq!(flow.path, ["a", "b"]);
    assert_eq!(flow.count, 1);
    assert_eq!(flow.input, "x");
}

#[test]
fn add_messages_replaces_by_id() {
    let mut history = vec![
        Message::human("hi").with_id("h1"),
        Message::ai_with_tool_calls("", vec![ToolCall::new("c1", "t", "{}")]),
        Message::tool_result("c1", "old").with_id("r1"),
    ];
    <AddMessages as Reducer<Vec<Message>>>::reduce(
        &mut history,
        vec![
            Message::tool_result("c1", "new").with_id("r1"),
            Message::ai("plain"),
            Message::ai("plain"),
            Message::tool_result("c2", "first").with_id("r2"),
            Message::tool_result("c2", "second").with_id("r2"),
            // Same provider call id, no message id: a new turn, appended.
            Message::ai_with_tool_calls("", vec![ToolCall::new("c1", "t", "{}")]),
        ],
    );
    let texts: Vec<String> = history.iter().map(Message::text).collect();
    assert_eq!(texts, ["hi", "", "new", "plain", "plain", "second", ""]);

    let mut plain = vec![Message::human("a")];
    <AddMessages as Reducer<Vec<Message>>>::reduce(&mut plain, vec![Message::human("a")]);
    assert_eq!(plain.len(), 2);

    // The update type round-trips through JSON, skipping empty fields.
    let json = serde_json::to_string(&MessagesUpdate::default()).unwrap();
    assert_eq!(json, "{}");
}

fn linear() -> StateGraph<Flow> {
    let mut g = StateGraph::new();
    g.add_node("a", |_, _| async { Ok(visit("a")) })
        .add_node("b", |_, _| async { Ok(visit("b")) })
        .add_edge(START, "a")
        .add_edge("a", "b")
        .add_edge("b", END);
    g
}

#[tokio::test]
async fn runs_a_linear_graph() {
    let app = linear().compile().unwrap();
    let out = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.path, ["a", "b"]);
    assert_eq!(out.steps, 2);
    assert!(!out.is_interrupted());
    assert_eq!(out.checkpoint_id, None);
}

#[tokio::test]
async fn conditional_routing() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("classify", |_, _| async { Ok(visit("classify")) })
        .add_node("math", |_, _| async { Ok(visit("math")) })
        .add_node("chat", |_, _| async { Ok(visit("chat")) })
        .add_edge(START, "classify")
        .add_conditional_edges(
            "classify",
            |s: &Flow| {
                if s.input.chars().any(|c| c.is_ascii_digit()) {
                    "math"
                } else {
                    "chat"
                }
            },
            ["math", "chat"],
        )
        .add_edge("math", END)
        .add_edge("chat", END);
    let app = g.compile().unwrap();

    let run = |input: &str| {
        let app = app.clone();
        let state = Flow {
            input: input.into(),
            ..Flow::default()
        };
        async move {
            app.invoke(state, &RunConfig::default())
                .await
                .unwrap()
                .state
                .path
        }
    };
    assert_eq!(run("2 + 2").await, ["classify", "math"]);
    assert_eq!(run("hello").await, ["classify", "chat"]);
}

#[tokio::test]
async fn parallel_superstep_merges_in_task_order() {
    let mut g = StateGraph::<Flow>::new();
    // The first branch is the slowest, so finish order is the reverse of
    // task order.
    for (name, ms) in [("slow", 30_u64), ("mid", 15), ("fast", 0)] {
        g.add_node(name, move |_, _| async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(visit(name))
        });
        g.add_edge("fork", name).add_edge(name, "join");
    }
    g.add_node("fork", |_, _| async { Ok(visit("fork")) })
        .add_node("join", |s: Arc<Flow>, _| async move {
            Ok(FlowUpdate::default().path(vec![format!("join after {}", s.path.len())]))
        })
        .add_edge(START, "fork")
        .add_edge("join", END);
    let app = g.compile().unwrap();
    for _ in 0..5 {
        let out = app
            .invoke(Flow::default(), &RunConfig::default())
            .await
            .unwrap();
        // `join` is reached from three branches but runs once, after all of
        // them.
        assert_eq!(
            out.state.path,
            ["fork", "slow", "mid", "fast", "join after 4"]
        );
        assert_eq!(out.steps, 3);
    }
}

#[tokio::test]
async fn send_maps_over_dynamic_items() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("split", |_, _| async {
        Ok(FlowUpdate::default().items(vec!["x".into(), "yy".into(), "zzz".into()]))
    })
    .add_node("work", |s: Arc<Flow>, _| async move {
        // Later items finish first.
        let ms = 30 - 10 * u64::try_from(s.item.len()).unwrap();
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(FlowUpdate::default()
            .path(vec![s.item.to_uppercase()])
            .count(1))
    })
    .add_edge(START, "split")
    .add_conditional_edges(
        "split",
        |s: &Flow| {
            s.items
                .iter()
                .map(|i| SendTo::new("work", FlowUpdate::default().item(i.clone())))
                .collect::<Vec<_>>()
        },
        ["work"],
    )
    .add_edge("work", END);
    let app = g.compile().unwrap();
    let out = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.path, ["X", "YY", "ZZZ"]);
    assert_eq!(out.state.count, 3);
    assert_eq!(
        out.state.item, "",
        "send updates stay private to their task"
    );
}

#[tokio::test]
async fn goto_from_inside_a_node() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("a", |_, ctx| async move {
        ctx.goto("c");
        Ok(visit("a"))
    })
    .add_node("b", |_, _| async { Ok(visit("b")) })
    .add_node("c", |_, _| async { Ok(visit("c")) })
    .add_edge(START, "a")
    .add_edge("a", "b")
    .add_edge("b", END)
    .add_destinations("a", ["c"]);
    let app = g.compile().unwrap();
    let out = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.path, ["a", "c"], "goto overrides the edges");
}

fn looping() -> StateGraph<Flow> {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("again", |_, _| async { Ok(FlowUpdate::default().count(1)) })
        .add_edge(START, "again")
        .add_edge("again", "again");
    g
}

#[tokio::test]
async fn recursion_limit_defaults_to_25() {
    let app = looping().compile().unwrap();
    let err = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::RecursionLimit(25)), "{err}");

    let err = app
        .invoke(Flow::default(), &RunConfig::default().recursion_limit(3))
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::RecursionLimit(3)));

    // Exactly `limit` steps are allowed.
    let mut g = StateGraph::<Flow>::new();
    g.add_node("again", |_, _| async { Ok(FlowUpdate::default().count(1)) })
        .add_edge(START, "again")
        .add_conditional_edges(
            "again",
            |s: &Flow| if s.count < 4 { "again" } else { END },
            ["again", END],
        );
    let app = g
        .compile_with(CompileOptions::default().recursion_limit(4))
        .unwrap();
    let out = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.count, 4);
}

#[tokio::test]
async fn bad_router_output_is_an_error() {
    let build = |target: &'static str, declared: Vec<&'static str>| {
        let mut g = StateGraph::<Flow>::new();
        g.add_node("a", |_, _| async { Ok(visit("a")) })
            .add_node("b", |_, _| async { Ok(visit("b")) })
            .add_edge(START, "a")
            .add_conditional_edges("a", move |_: &Flow| target, declared)
            .add_edge("b", END);
        g.compile().unwrap()
    };
    let err = build("nope", vec![])
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::UnknownNode(n) if n == "nope"),
        "{err}"
    );

    let err = build("a", vec!["b", END])
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::UndeclaredRoute { .. }), "{err}");

    let err = build(START, vec![])
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::UnknownNode(_)), "{err}");

    let mut g = StateGraph::<Flow>::new();
    g.add_node("a", |_, _| async { Ok(visit("a")) })
        .add_edge(START, "a")
        .add_conditional_edges(
            "a",
            |_: &Flow| -> &'static str { panic!("router bug") },
            [END],
        );
    let err = g
        .compile()
        .unwrap()
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("router panicked"), "{err}");
}

#[tokio::test]
async fn fan_out_is_bounded() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("split", |_, _| async { Ok(FlowUpdate::default()) })
        .add_node("work", |_, _| async { Ok(FlowUpdate::default()) })
        .add_edge(START, "split")
        .add_conditional_edges(
            "split",
            |_: &Flow| {
                (0..10)
                    .map(|_| SendTo::new("work", FlowUpdate::default()))
                    .collect::<Vec<_>>()
            },
            ["work"],
        );
    let app = g
        .compile_with(CompileOptions::default().max_fanout(4))
        .unwrap();
    let err = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, GraphError::FanOutLimit { got: 10, limit: 4 }),
        "{err}"
    );
}

#[tokio::test]
async fn concurrency_is_bounded() {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut g = StateGraph::<Flow>::new();
    let (r, p) = (Arc::clone(&running), Arc::clone(&peak));
    g.add_node("split", |_, _| async { Ok(FlowUpdate::default()) })
        .add_node("work", move |_, _| {
            let (r, p) = (Arc::clone(&r), Arc::clone(&p));
            async move {
                let now = r.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                r.fetch_sub(1, Ordering::SeqCst);
                Ok(FlowUpdate::default().count(1))
            }
        })
        .add_edge(START, "split")
        .add_conditional_edges(
            "split",
            |_: &Flow| {
                (0..9)
                    .map(|_| SendTo::new("work", FlowUpdate::default()))
                    .collect::<Vec<_>>()
            },
            ["work"],
        );
    let app = g
        .compile_with(CompileOptions::default().max_concurrency(3))
        .unwrap();
    let out = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap();
    assert_eq!(out.state.count, 9);
    assert!(peak.load(Ordering::SeqCst) <= 3);
}

#[tokio::test]
async fn node_timeout_cancel_and_panic() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("slow", |_, _| async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(FlowUpdate::default())
    })
    .add_edge(START, "slow");
    let app = g
        .compile_with(CompileOptions::default().timeout_for("slow", Duration::from_millis(10)))
        .unwrap();
    let err = app
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::Timeout { node, .. } if node == "slow"),
        "{err}"
    );

    let mut g = StateGraph::<Flow>::new();
    g.add_node("slow", |_, _| async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(FlowUpdate::default())
    })
    .add_edge(START, "slow");
    let app = g.compile().unwrap();
    let token = CancelToken::new();
    let config = RunConfig::default().cancel_token(token.clone());
    let run = tokio::spawn(async move { app.invoke(Flow::default(), &config).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    token.cancel();
    let err = run.await.unwrap().unwrap_err();
    assert!(matches!(err, GraphError::Cancelled), "{err}");

    let mut g = StateGraph::<Flow>::new();
    g.add_node("boom", |_, _| async { panic!("node bug") })
        .add_edge(START, "boom");
    let err = g
        .compile()
        .unwrap()
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, GraphError::NodeFailed { node, .. } if node == "boom"),
        "{err}"
    );
    assert!(err.to_string().contains("panicked"));
}

#[tokio::test]
async fn node_errors_name_the_node() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("fail", |_, _| async { Err(GraphError::other("bad input")) })
        .add_edge(START, "fail");
    let err = g
        .compile()
        .unwrap()
        .invoke(Flow::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "node `fail` failed: bad input");
}

#[test]
fn compile_validates_the_graph() {
    let err = |g: StateGraph<Flow>| g.compile().unwrap_err().to_string();

    let mut g = StateGraph::<Flow>::new();
    g.add_node("a", |_, _| async { Ok(FlowUpdate::default()) });
    assert!(err(g).contains("no entry point"));

    let mut g = linear();
    g.add_edge("b", "ghost");
    assert!(err(g).contains("unknown node `ghost`"));

    let mut g = linear();
    g.add_node("island", |_, _| async { Ok(FlowUpdate::default()) });
    assert!(err(g).contains("`island` is unreachable"));

    let mut g = linear();
    g.add_node("a", |_, _| async { Ok(FlowUpdate::default()) });
    assert!(err(g).contains("added twice"));

    let mut g = linear();
    g.add_node(END, |_, _| async { Ok(FlowUpdate::default()) });
    assert!(err(g).contains("reserved"));

    let mut g = linear();
    g.add_node("", |_, _| async { Ok(FlowUpdate::default()) });
    assert!(err(g).contains("1-128 bytes"));

    let mut g = linear();
    g.add_edge("a", START);
    assert!(err(g).contains("into START"));

    let mut g = linear();
    g.add_conditional_edges("a", |_: &Flow| "b", ["b", "ghost"]);
    assert!(err(g).contains("unknown node `ghost`"));

    let e = linear()
        .compile_with(CompileOptions::default().interrupt_before(["ghost"]))
        .unwrap_err();
    assert!(e.to_string().contains("interrupt on unknown node"));

    let e = linear()
        .compile_with(CompileOptions::default().recursion_limit(0))
        .unwrap_err();
    assert!(e.to_string().contains("at least 1"));

    // A router without declared targets may reach anything.
    let mut g = StateGraph::<Flow>::new();
    g.add_node("a", |_, _| async { Ok(FlowUpdate::default()) })
        .add_node("b", |_, _| async { Ok(FlowUpdate::default()) })
        .add_edge(START, "a")
        .add_conditional_edges("a", |_: &Flow| END, Vec::<String>::new());
    assert!(g.compile().is_ok());
}

#[test]
fn mermaid_output() {
    let mut g = StateGraph::<Flow>::new();
    g.add_node("agent", |_, _| async { Ok(FlowUpdate::default()) })
        .add_node("tools \"x\"", |_, _| async { Ok(FlowUpdate::default()) })
        .add_edge(START, "agent")
        .add_conditional_edges("agent", |_: &Flow| END, ["tools \"x\"", END])
        .add_edge("tools \"x\"", "agent");
    let expected = "\
flowchart TD
    __start__([\"__start__\"])
    n0[\"agent\"]
    n1[\"tools #quot;x#quot;\"]
    __end__([\"__end__\"])
    __start__ --> n0
    n0 -.-> n1
    n0 -.-> __end__
    n1 --> n0
";
    assert_eq!(g.draw_mermaid(), expected);
    assert_eq!(g.compile().unwrap().draw_mermaid(), expected);
}

#[tokio::test]
async fn stream_yields_updates_in_order_then_done() {
    let app = linear().compile().unwrap();
    let events: Vec<_> = app
        .stream(Flow::default(), &RunConfig::default())
        .collect()
        .await;
    let mut seen = Vec::new();
    for e in events {
        match e.unwrap() {
            Event::Update { step, node, update } => {
                seen.push(format!("{step}:{node}:{}", update.path.unwrap().join(",")));
            }
            Event::Done(out) => seen.push(format!("done:{}", out.state.path.join(","))),
            _ => {}
        }
    }
    assert_eq!(seen, ["1:a:a", "2:b:b", "done:a,b"]);
}

#[tokio::test]
async fn stream_ends_with_the_error() {
    let app = looping().compile().unwrap();
    let mut stream = app.stream(Flow::default(), &RunConfig::default().recursion_limit(2));
    let mut updates = 0;
    let mut last = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(Event::Update { .. }) => updates += 1,
            other => last = Some(other),
        }
    }
    assert_eq!(updates, 2);
    assert!(matches!(last, Some(Err(GraphError::RecursionLimit(2)))));
}

#[tokio::test]
async fn messages_state_graph() {
    let mut g = StateGraph::<MessagesState>::new();
    g.add_node("echo", |s: Arc<MessagesState>, _| async move {
        Ok(MessagesUpdate::new(vec![Message::ai(format!(
            "echo: {}",
            s.last_text()
        ))]))
    })
    .add_edge(START, "echo");
    let out = g
        .compile()
        .unwrap()
        .invoke(
            MessagesState::new(vec![Message::human("hi")]),
            &RunConfig::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.state.last_text(), "echo: hi");
    assert_eq!(out.state.messages.len(), 2);
}

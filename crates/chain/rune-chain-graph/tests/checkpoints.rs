//! Checkpoints, resume, time travel, state editing and interrupts.

#![allow(clippy::unwrap_used, reason = "test assertions")]
#![allow(missing_docs, reason = "test fixtures")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rune_chain_graph::{
    Append, Checkpointer, Command, CompileOptions, CompiledGraph, END, GraphError,
    InMemoryCheckpointer, InterruptKind, Replace, RunConfig, START, StateGraph, Sum, state,
};
use serde::{Deserialize, Serialize};

state! {
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Doc => DocUpdate {
        pub draft: String = Replace,
        pub log: Vec<String> = Append,
        pub revisions: u32 = Sum,
    }
}

fn log(entry: impl Into<String>) -> DocUpdate {
    DocUpdate::default().log(vec![entry.into()])
}

/// write -> review -> publish
fn pipeline() -> StateGraph<Doc> {
    let mut g = StateGraph::new();
    g.add_node("write", |_, _| async {
        Ok(log("write").draft("v1".into()).revisions(1))
    })
    .add_node("review", |_, _| async { Ok(log("review")) })
    .add_node("publish", |s: Arc<Doc>, _| async move {
        Ok(log(format!("publish {}", s.draft)))
    })
    .add_edge(START, "write")
    .add_edge("write", "review")
    .add_edge("review", "publish")
    .add_edge("publish", END);
    g
}

fn with_store(
    g: StateGraph<Doc>,
    options: CompileOptions,
) -> (CompiledGraph<Doc>, Arc<InMemoryCheckpointer>) {
    let store = Arc::new(InMemoryCheckpointer::new());
    let app = g.compile_with(options.checkpointer(store.clone())).unwrap();
    (app, store)
}

#[tokio::test]
async fn every_step_is_checkpointed() {
    let (app, store) = with_store(pipeline(), CompileOptions::default());
    let config = RunConfig::thread("t1");
    let out = app.invoke(Doc::default(), &config).await.unwrap();
    assert_eq!(out.state.log, ["write", "review", "publish v1"]);

    // Input checkpoint plus one per step, newest first.
    let history = app.get_state_history(&config, 10).await.unwrap();
    let nexts: Vec<Vec<String>> = history.iter().map(|s| s.next.clone()).collect();
    assert_eq!(
        nexts,
        [
            vec![],
            vec!["publish".to_owned()],
            vec!["review".to_owned()],
            vec!["write".to_owned()]
        ]
    );
    assert_eq!(history[0].checkpoint_id, out.checkpoint_id.clone().unwrap());
    assert_eq!(
        history[0].parent_id.as_deref(),
        Some(history[1].checkpoint_id.as_str())
    );
    assert_eq!(history[0].step, 3);

    let latest = app.get_state(&config).await.unwrap().unwrap();
    assert_eq!(latest.state, out.state);
    assert_eq!(latest.next, Vec::<String>::new());

    // Other threads are separate.
    assert!(
        app.get_state(&RunConfig::thread("t2"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.threads(), ["t1"]);
}

#[tokio::test]
async fn interrupt_before_and_after() {
    let (app, _) = with_store(
        pipeline(),
        CompileOptions::default()
            .interrupt_before(["publish"])
            .interrupt_after(["write"]),
    );
    let config = RunConfig::thread("t");

    let out = app.invoke(Doc::default(), &config).await.unwrap();
    let i = out.interrupt.clone().unwrap();
    assert_eq!((i.node.as_str(), i.kind), ("write", InterruptKind::After));
    assert_eq!(out.state.log, ["write"]);

    let out = app.invoke(Command::default(), &config).await.unwrap();
    let i = out.interrupt.clone().unwrap();
    assert_eq!(
        (i.node.as_str(), i.kind),
        ("publish", InterruptKind::Before)
    );
    assert_eq!(out.state.log, ["write", "review"]);
    assert_eq!(
        app.get_state(&config).await.unwrap().unwrap().next,
        ["publish"]
    );

    // A human edits the draft before it goes out; the pause is kept.
    app.update_state(&config, DocUpdate::default().draft("v2".into()), None)
        .await
        .unwrap();
    let out = app.invoke(Command::default(), &config).await.unwrap();
    assert!(!out.is_interrupted());
    assert_eq!(out.state.log, ["write", "review", "publish v2"]);
}

#[tokio::test]
async fn interrupt_inside_a_node_and_resume() {
    let runs = Arc::new(AtomicUsize::new(0));
    let mut g = StateGraph::<Doc>::new();
    let counter = Arc::clone(&runs);
    g.add_node("approve", move |s: Arc<Doc>, ctx| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            let ok: bool =
                ctx.interrupt(serde_json::json!({ "question": "publish?", "draft": s.draft }))?;
            let note: String = ctx.interrupt("note?")?;
            Ok(log(format!("approved={ok} note={note}")))
        }
    })
    .add_edge(START, "approve")
    .add_edge("approve", END);
    let (app, _) = with_store(g, CompileOptions::default());
    let config = RunConfig::thread("hitl");

    let out = app
        .invoke(
            Doc {
                draft: "hello".into(),
                ..Doc::default()
            },
            &config,
        )
        .await
        .unwrap();
    let i = out.interrupt.unwrap();
    assert_eq!(i.kind, InterruptKind::Node);
    assert_eq!(i.value["draft"], "hello");
    assert!(out.state.log.is_empty(), "nothing is applied while paused");

    let out = app.invoke(Command::resume(true), &config).await.unwrap();
    assert_eq!(out.interrupt.unwrap().value, "note?");

    let out = app
        .invoke(Command::resume("ship it"), &config)
        .await
        .unwrap();
    assert!(!out.is_interrupted());
    assert_eq!(out.state.log, ["approved=true note=ship it"]);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        3,
        "the node reruns on each resume"
    );

    // A finished thread has nothing to resume.
    let err = app.invoke(Command::resume(1), &config).await.unwrap_err();
    assert!(matches!(err, GraphError::InvalidInput(_)), "{err}");

    // A resume value of the wrong type is an error, not a panic.
    let config = RunConfig::thread("hitl-2");
    app.invoke(Doc::default(), &config).await.unwrap();
    let err = app
        .invoke(Command::resume("yes"), &config)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("resume value"), "{err}");
}

#[tokio::test]
async fn interrupts_need_a_checkpointer() {
    let mut g = StateGraph::<Doc>::new();
    g.add_node("ask", |_, ctx| async move {
        let _: bool = ctx.interrupt("?")?;
        Ok(DocUpdate::default())
    })
    .add_edge(START, "ask");
    let app = g.compile().unwrap();
    let err = app
        .invoke(Doc::default(), &RunConfig::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("needs a checkpointer"), "{err}");

    let err = app
        .invoke(Command::default(), &RunConfig::thread("x"))
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::InvalidInput(_)), "{err}");
}

#[tokio::test]
async fn command_goto_and_update() {
    let (app, _) = with_store(
        pipeline(),
        CompileOptions::default().interrupt_before(["review"]),
    );
    let config = RunConfig::thread("g");
    let out = app.invoke(Doc::default(), &config).await.unwrap();
    assert_eq!(out.interrupt.unwrap().node, "review");

    // Skip the review entirely.
    let out = app
        .invoke(
            Command::goto("publish").with_update(log("skipped review")),
            &config,
        )
        .await
        .unwrap();
    assert_eq!(out.state.log, ["write", "skipped review", "publish v1"]);

    let err = app
        .invoke(Command::goto("ghost"), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::UnknownNode(_)));

    // An update on a finished thread starts a new turn from START.
    let out = app
        .invoke(Command::update(log("turn 2")), &config)
        .await
        .unwrap();
    assert_eq!(out.interrupt.unwrap().node, "review");
    assert_eq!(out.state.revisions, 2);
}

#[tokio::test]
async fn time_travel_replays_from_a_past_checkpoint() {
    let (app, store) = with_store(pipeline(), CompileOptions::default());
    let config = RunConfig::thread("tt");
    app.invoke(Doc::default(), &config).await.unwrap();

    let history = app.get_state_history(&config, 10).await.unwrap();
    let before_review = history.iter().find(|s| s.next == ["review"]).unwrap();
    let fork_from = before_review.checkpoint_id.clone();

    // Replay from there with an edited draft.
    let past = config.clone().checkpoint(fork_from.clone());
    let edited = app
        .update_state(&past, DocUpdate::default().draft("v1-edited".into()), None)
        .await
        .unwrap();
    let out = app
        .invoke(
            Command::default(),
            &config.clone().checkpoint(edited.clone()),
        )
        .await
        .unwrap();
    assert_eq!(out.state.log, ["write", "review", "publish v1-edited"]);

    // The fork hangs off the old checkpoint; the original history is intact.
    let fork = store.get("tt", Some(&edited)).await.unwrap().unwrap();
    assert_eq!(fork.parent_id.as_deref(), Some(fork_from.as_str()));
    let all = app.get_state_history(&config, 100).await.unwrap();
    assert_eq!(all.len(), 4 + 1 + 3);
    assert_eq!(
        app.get_state(&config).await.unwrap().unwrap().state,
        out.state
    );

    let err = app
        .invoke(Command::default(), &config.clone().checkpoint("missing"))
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::Checkpoint(_)), "{err}");
}

#[tokio::test]
async fn update_state_as_node_moves_on() {
    let (app, _) = with_store(
        pipeline(),
        CompileOptions::default().interrupt_before(["review"]),
    );
    let config = RunConfig::thread("as-node");
    app.invoke(Doc::default(), &config).await.unwrap();
    // Act as the reviewer: the next task becomes `publish`.
    app.update_state(&config, log("human review"), Some("review"))
        .await
        .unwrap();
    let snap = app.get_state(&config).await.unwrap().unwrap();
    assert_eq!(snap.next, ["publish"]);
    assert!(snap.interrupt.is_none());
    let out = app.invoke(Command::default(), &config).await.unwrap();
    assert_eq!(out.state.log, ["write", "human review", "publish v1"]);

    let err = app
        .update_state(&config, DocUpdate::default(), Some("ghost"))
        .await
        .unwrap_err();
    assert!(matches!(err, GraphError::UnknownNode(_)));
}

#[tokio::test]
async fn checkpoint_size_is_capped() {
    let mut g = StateGraph::<Doc>::new();
    g.add_node("big", |_, _| async {
        Ok(DocUpdate::default().draft("x".repeat(10_000)))
    })
    .add_edge(START, "big");
    let (app, _) = with_store(g, CompileOptions::default().max_checkpoint_bytes(4096));
    let err = app
        .invoke(Doc::default(), &RunConfig::thread("big"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GraphError::CheckpointTooLarge { limit: 4096, .. }),
        "{err}"
    );
}

#[tokio::test]
async fn bad_thread_ids_are_rejected() {
    let (app, _) = with_store(pipeline(), CompileOptions::default());
    for bad in [String::new(), "a\nb".into(), "x".repeat(300)] {
        let err = app
            .invoke(Doc::default(), &RunConfig::thread(bad))
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::InvalidInput(_)), "{err}");
    }
}

#[tokio::test]
async fn in_memory_history_can_be_capped() {
    let store = Arc::new(InMemoryCheckpointer::new().max_per_thread(2));
    let app = pipeline()
        .compile_with(CompileOptions::default().checkpointer(store.clone()))
        .unwrap();
    let config = RunConfig::thread("cap");
    app.invoke(Doc::default(), &config).await.unwrap();
    assert_eq!(store.list("cap", 100).await.unwrap().len(), 2);
    store.delete_thread("cap");
    assert!(store.get("cap", None).await.unwrap().is_none());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_checkpoints_survive_a_reopen() {
    use rune_chain_graph::SqliteCheckpointer;

    let dir = std::env::temp_dir().join(format!("rune-chain-graph-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("checkpoints.db");
    let _ = std::fs::remove_file(&path);
    let config = RunConfig::thread("sql");
    {
        let store = Arc::new(SqliteCheckpointer::open(&path).unwrap());
        let app = pipeline()
            .compile_with(
                CompileOptions::default()
                    .checkpointer(store)
                    .interrupt_before(["publish"]),
            )
            .unwrap();
        let out = app.invoke(Doc::default(), &config).await.unwrap();
        assert_eq!(out.interrupt.unwrap().node, "publish");
    }
    let store = Arc::new(SqliteCheckpointer::open(&path).unwrap());
    let app = pipeline()
        .compile_with(
            CompileOptions::default()
                .checkpointer(store.clone())
                .interrupt_before(["publish"]),
        )
        .unwrap();
    let out = app.invoke(Command::default(), &config).await.unwrap();
    assert_eq!(out.state.log, ["write", "review", "publish v1"]);
    // input, write, review, pause; then input and publish on resume.
    assert_eq!(app.get_state_history(&config, 100).await.unwrap().len(), 6);
    let latest = store.get("sql", None).await.unwrap().unwrap();
    assert_eq!(Some(latest.id), out.checkpoint_id);

    // Oversized rows are refused on read.
    let small = SqliteCheckpointer::open(&path).unwrap().max_row_bytes(16);
    assert!(matches!(
        small.get("sql", None).await,
        Err(GraphError::CheckpointTooLarge { .. })
    ));
    assert!(small.list("sql", 10).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

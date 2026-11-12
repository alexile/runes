//! The `tracing` span: the handler and its log lines run inside a `request`
//! span carrying the request id and trace ids.
//!
//! Kept in its own test binary with a single test: `tracing` caches callsite
//! interest process-wide, so a test without a subscriber running in parallel
//! could disable the span callsite for this one.

#![cfg(feature = "tracing")]
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use axum::{Router, body::Body, routing::get};
use http::{Request, StatusCode};
use rune_axum_requestid::RequestIdLayer;
use tower::ServiceExt;

const SPEC: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

type Fields = Arc<Mutex<HashMap<u64, (String, HashMap<String, String>)>>>;

/// Minimal subscriber that records span names and fields, and the span
/// that is current when an event fires.
#[derive(Default)]
struct Capture {
    spans: Fields,
    next: Mutex<u64>,
    current: Mutex<Vec<u64>>,
    events: Arc<Mutex<Vec<Option<u64>>>>,
}

struct Visitor<'a>(&'a mut HashMap<String, String>);

impl Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut next = self.next.lock().unwrap();
        *next += 1;
        let mut fields = HashMap::new();
        attrs.record(&mut Visitor(&mut fields));
        self.spans
            .lock()
            .unwrap()
            .insert(*next, (attrs.metadata().name().to_owned(), fields));
        Id::from_u64(*next)
    }
    fn record(&self, span: &Id, values: &Record<'_>) {
        if let Some((_, fields)) = self.spans.lock().unwrap().get_mut(&span.into_u64()) {
            values.record(&mut Visitor(fields));
        }
    }
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {
        let current = self.current.lock().unwrap().last().copied();
        self.events.lock().unwrap().push(current);
    }
    fn enter(&self, span: &Id) {
        self.current.lock().unwrap().push(span.into_u64());
    }
    fn exit(&self, _: &Id) {
        self.current.lock().unwrap().pop();
    }
}

#[tokio::test]
async fn handler_runs_inside_request_span() {
    let capture = Capture::default();
    let spans = capture.spans.clone();
    let events = capture.events.clone();
    let _guard = tracing::subscriber::set_default(capture);

    let router = Router::new()
        .route(
            "/log",
            get(|| async {
                tracing::info!("handling");
                "ok"
            }),
        )
        .layer(RequestIdLayer::default());
    let req = Request::builder()
        .uri("/log")
        .header("x-request-id", "span-id-1")
        .header("traceparent", SPEC)
        .body(Body::empty())
        .unwrap();
    let res = router.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let (id, fields) = spans
        .lock()
        .unwrap()
        .iter()
        .find(|(_, (name, _))| name == "request")
        .map(|(id, (_, fields))| (*id, fields.clone()))
        .expect("request span");
    assert_eq!(fields["request_id"], "span-id-1");
    assert_eq!(fields["method"], "GET");
    assert_eq!(fields["path"], "/log");
    assert_eq!(fields["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(fields["parent_span_id"], "00f067aa0ba902b7");
    assert_eq!(fields["span_id"].len(), 16);

    let events = events.lock().unwrap().clone();
    assert_eq!(events, [Some(id)], "log line is inside the span");
}

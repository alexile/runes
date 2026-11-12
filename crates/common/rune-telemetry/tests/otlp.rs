//! OTLP export tests. All offline: an in-memory exporter, or a fake OTLP/gRPC
//! collector bound to 127.0.0.1.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_sdk::trace::InMemorySpanExporter;
use rune_telemetry::{Error, Sampler, Telemetry, TelemetryConfig};
use tokio::sync::mpsc;

fn quiet(config: TelemetryConfig) -> Telemetry {
    Telemetry::new(config).with_writer(std::io::sink)
}

fn exporting() -> TelemetryConfig {
    TelemetryConfig::default()
        .with_filter("trace")
        .with_traces_exporter(rune_telemetry::TracesExporter::Otlp)
}

#[test]
fn spans_reach_a_custom_exporter_with_parent_links_and_fields() {
    let exporter = InMemorySpanExporter::default();
    let (dispatch, guard) = quiet(exporting())
        .with_span_exporter(exporter.clone())
        .build()
        .unwrap();
    assert!(guard.is_exporting());
    tracing::dispatcher::with_default(&dispatch, || {
        let outer = tracing::info_span!("outer", job = "sync");
        let _o = outer.enter();
        tracing::info_span!("inner", rows = 3_i64).in_scope(|| tracing::info!("event"));
    });
    guard.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let outer = spans.iter().find(|s| s.name == "outer").unwrap();
    let inner = spans.iter().find(|s| s.name == "inner").unwrap();
    assert_eq!(inner.parent_span_id, outer.span_context.span_id());
    assert_eq!(inner.span_context.trace_id(), outer.span_context.trace_id());
    assert!(
        outer
            .attributes
            .iter()
            .any(|kv| kv.key.as_str() == "job" && kv.value.as_str() == "sync")
    );
    assert_eq!(inner.events.len(), 1);
    assert_eq!(inner.instrumentation_scope.name(), "rune-telemetry");
    guard.shutdown().unwrap();
}

#[test]
fn filter_also_limits_exported_spans() {
    let exporter = InMemorySpanExporter::default();
    let (dispatch, guard) = quiet(exporting().with_filter("info"))
        .with_span_exporter(exporter.clone())
        .build()
        .unwrap();
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::debug_span!("dropped").in_scope(|| {});
        tracing::info_span!("kept").in_scope(|| {});
        // Spans from the export path itself never feed back into the exporter.
        tracing::info_span!(target: "tonic::transport", "loop").in_scope(|| {});
    });
    guard.force_flush().unwrap();
    let names: Vec<_> = exporter
        .get_finished_spans()
        .unwrap()
        .into_iter()
        .map(|s| s.name.into_owned())
        .collect();
    assert_eq!(names, ["kept"]);
}

#[test]
fn always_off_sampler_exports_nothing() {
    let exporter = InMemorySpanExporter::default();
    let (dispatch, guard) = quiet(exporting().with_sampler(Sampler::AlwaysOff))
        .with_span_exporter(exporter.clone())
        .build()
        .unwrap();
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("unsampled").in_scope(|| {});
    });
    guard.force_flush().unwrap();
    assert_eq!(exporter.get_finished_spans().unwrap().len(), 0);
}

#[test]
fn sdk_disabled_turns_export_off() {
    let env = |k: &str| (k == "OTEL_SDK_DISABLED").then(|| "true".to_owned());
    let config = exporting().with_env(env).unwrap();
    let exporter = InMemorySpanExporter::default();
    let (dispatch, guard) = quiet(config)
        .with_span_exporter(exporter.clone())
        .build()
        .unwrap();
    assert!(!guard.is_exporting());
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("not exported").in_scope(|| {});
    });
    guard.shutdown().unwrap();
    assert_eq!(exporter.get_finished_spans().unwrap().len(), 0);
}

#[test]
fn grpc_exporter_needs_a_tokio_runtime() {
    let config = TelemetryConfig::default().with_otlp_endpoint("http://127.0.0.1:4317");
    assert_eq!(quiet(config).build().unwrap_err(), Error::NoTokioRuntime);
}

#[tokio::test]
async fn http_protocols_are_rejected() {
    let env = |k: &str| match k {
        "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://127.0.0.1:4318".to_owned()),
        "OTEL_EXPORTER_OTLP_PROTOCOL" => Some("http/protobuf".to_owned()),
        _ => None,
    };
    let config = TelemetryConfig::default().with_env(env).unwrap();
    let err = quiet(config).build().unwrap_err();
    assert_eq!(err, Error::UnsupportedProtocol("http/protobuf".to_owned()));
}

#[tokio::test]
async fn invalid_header_names_are_rejected_without_the_value() {
    let config = TelemetryConfig::default()
        .with_otlp_endpoint("http://127.0.0.1:4317")
        .with_otlp_header("bad header", "s3cret");
    let err = quiet(config).build().unwrap_err();
    assert_eq!(
        err,
        Error::InvalidHeader {
            name: "bad header".to_owned()
        }
    );
    assert!(!err.to_string().contains("s3cret"));
}

/// A fake collector that forwards each export request (with its metadata).
struct Collector(mpsc::UnboundedSender<(ExportTraceServiceRequest, Option<String>)>);

#[tonic::async_trait]
impl TraceService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let key = request
            .metadata()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = self.0.send((request.into_inner(), key));
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

#[allow(clippy::unwrap_used, reason = "test helper")]
fn spawn_collector() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<(ExportTraceServiceRequest, Option<String>)>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(Collector(tx)))
            .serve_with_incoming(incoming),
    );
    (addr, rx)
}

fn string_attr(
    attrs: &[opentelemetry_proto::tonic::common::v1::KeyValue],
    key: &str,
) -> Option<String> {
    attrs
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| match &kv.value.as_ref()?.value {
            Some(Value::StringValue(s)) => Some(s.clone()),
            _ => None,
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exports_over_grpc_to_a_local_collector() {
    let (addr, mut rx) = spawn_collector();
    let env = move |k: &str| match k {
        "OTEL_EXPORTER_OTLP_ENDPOINT" => Some(format!("http://{addr}")),
        "OTEL_SERVICE_NAME" => Some("billing".to_owned()),
        "OTEL_RESOURCE_ATTRIBUTES" => Some("deployment.environment=test".to_owned()),
        "OTEL_EXPORTER_OTLP_HEADERS" => Some("x-api-key=k%3D1".to_owned()),
        "OTEL_EXPORTER_OTLP_TIMEOUT" => Some("5000".to_owned()),
        _ => None,
    };
    let config = TelemetryConfig::default().with_env(env).unwrap();
    let (dispatch, guard) = quiet(config).build().unwrap();
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("charge", amount = 42_i64).in_scope(|| {});
    });
    // Flushing blocks this thread while the exporter's I/O runs on another
    // worker, so do it off the async executor.
    tokio::task::spawn_blocking(move || guard.shutdown())
        .await
        .unwrap()
        .unwrap();

    let (request, api_key) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(api_key.as_deref(), Some("k=1"));
    let resource_spans = &request.resource_spans[0];
    let resource = resource_spans.resource.as_ref().unwrap();
    assert_eq!(
        string_attr(&resource.attributes, "service.name").as_deref(),
        Some("billing")
    );
    assert_eq!(
        string_attr(&resource.attributes, "deployment.environment").as_deref(),
        Some("test")
    );
    let span = &resource_spans.scope_spans[0].spans[0];
    assert_eq!(span.name, "charge");
    assert!(span.attributes.iter().any(|kv| kv.key == "amount"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_collector_does_not_hang_shutdown() {
    // Bind and drop a listener to get a local port nobody listens on.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let config = TelemetryConfig::default()
        .with_otlp_endpoint(format!("http://{addr}"))
        .with_otlp_timeout(Duration::from_millis(500));
    let (dispatch, guard) = quiet(config).build().unwrap();
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info_span!("lost").in_scope(|| {});
    });
    let started = Instant::now();
    // The export error is reported or swallowed by the SDK; either way the
    // call returns promptly.
    let _ = tokio::task::spawn_blocking(move || guard.shutdown())
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
}

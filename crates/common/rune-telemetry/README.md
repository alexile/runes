# rune-telemetry

One-call `tracing` setup with optional OTLP/gRPC trace export, configured from
`RUST_LOG`, `RUST_LOG_FORMAT` and the standard `OTEL_*` environment variables.
It is the non-Axum counterpart of `rune-axum-trace`'s `TraceConfig`.

- `tracing-subscriber` stack with an `EnvFilter` and a fmt layer on stderr
  (`full`, `compact`, `pretty`, or `json` with the `json` feature).
- OTLP/gRPC span export through `tracing-opentelemetry`, behind the `otlp`
  feature, so libraries can depend on the configuration types without
  pulling OpenTelemetry.
- Sans-I/O configuration: `TelemetryConfig::with_env` takes any variable
  lookup, so configuration is testable without touching the process
  environment.
- OTLP header values (usually API keys) never appear in `Debug` output or
  error messages.

## Installation

```bash
cargo add rune-telemetry --features otlp
```

## Usage

In an application, inside the Tokio runtime when OTLP export is on:

```rust,no_run
#[tokio::main]
async fn main() -> Result<(), rune_telemetry::Error> {
    let guard = rune_telemetry::init()?;
    tracing::info!("started");
    // ... run the program ...
    guard.shutdown()?;
    Ok(())
}
```

Explicit configuration, and a subscriber used locally instead of globally:

```rust
use rune_telemetry::{LogFormat, Telemetry, TelemetryConfig};

let config = TelemetryConfig::default()
    .with_service_name("worker")
    .with_format(LogFormat::Compact)
    .with_env(|k| std::env::var(k).ok())?;
let (dispatch, guard) = Telemetry::new(config).with_writer(std::io::sink).build()?;
tracing::dispatcher::with_default(&dispatch, || tracing::info!("hello"));
guard.shutdown()?;
# Ok::<(), rune_telemetry::Error>(())
```

## Environment

| Variable                                      | Effect                                                  | Default                  |
| --------------------------------------------- | ------------------------------------------------------- | ------------------------ |
| `RUST_LOG`                                    | `EnvFilter` directives (also limit exported spans)      | `info`                   |
| `RUST_LOG_FORMAT`                             | `full`, `compact`, `pretty`, `json`                     | `full`                   |
| `NO_COLOR`                                    | disables ANSI colours                                   | colours on a terminal    |
| `OTEL_SDK_DISABLED`                           | `true` turns span export off                            |                          |
| `OTEL_TRACES_EXPORTER`                        | `otlp` or `none`                                        | `otlp` once an endpoint is set, else `none` |
| `OTEL_SERVICE_NAME`                           | `service.name`                                          | `unknown_service`        |
| `OTEL_RESOURCE_ATTRIBUTES`                    | `key=value,...` resource attributes                     |                          |
| `OTEL_TRACES_SAMPLER` / `_ARG`                | `always_on`, `always_off`, `traceidratio`, `parentbased_*` | `parentbased_always_on` |
| `OTEL_EXPORTER_OTLP_[TRACES_]ENDPOINT`        | collector endpoint                                      | `http://localhost:4317`  |
| `OTEL_EXPORTER_OTLP_[TRACES_]PROTOCOL`        | `grpc` (HTTP protocols are rejected)                    | `grpc`                   |
| `OTEL_EXPORTER_OTLP_[TRACES_]TIMEOUT`         | export timeout in milliseconds                          | `10000`                  |
| `OTEL_EXPORTER_OTLP_[TRACES_]HEADERS`         | `key=value,...` gRPC metadata                           |                          |

When installed globally with OTLP export, the tracer provider and the W3C
trace-context propagator are also set as OpenTelemetry globals, so
`rune-axum-trace`'s layer and other `opentelemetry::global` users share the
pipeline. Keep the returned guard alive; dropping it flushes and shuts the
exporter down (do that on a multi-threaded runtime or outside one).

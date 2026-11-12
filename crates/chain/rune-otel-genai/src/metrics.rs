//! `GenAI` client metrics: operation duration and token usage.
//!
//! [`TracedLlm`](crate::TracedLlm) reports one [`OperationMetrics`] per
//! call to the [`GenAiMetrics`] sink set with
//! [`GenAiConfig::with_metrics`](crate::GenAiConfig::with_metrics). With the
//! `opentelemetry` feature, [`OtelMetrics`] records them as the two
//! histograms the `GenAI` semantic conventions define:
//!
//! | Instrument | Unit | Attributes |
//! |---|---|---|
//! | `gen_ai.client.operation.duration` | `s` | operation, provider, request model, server, `error.type` on failure |
//! | `gen_ai.client.token.usage` | `{token}` | the same plus `gen_ai.token.type` (`input` / `output`) |

use std::time::Duration;

/// What one model call measured, handed to a [`GenAiMetrics`] sink.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct OperationMetrics<'a> {
    /// `gen_ai.operation.name`.
    pub operation: &'a str,
    /// `gen_ai.provider.name`.
    pub provider: &'a str,
    /// `gen_ai.request.model`.
    pub request_model: &'a str,
    /// `server.address`, if configured.
    pub server_address: Option<&'a str>,
    /// `server.port`, if configured.
    pub server_port: Option<u16>,
    /// Wall-clock time of the call (for a stream, until it ended).
    pub duration: Duration,
    /// Input tokens, when the call succeeded.
    pub input_tokens: Option<u64>,
    /// Output tokens, when the call succeeded.
    pub output_tokens: Option<u64>,
    /// Whether the token counts are local estimates.
    pub usage_estimated: bool,
    /// `error.type`, when the call failed.
    pub error_type: Option<&'a str>,
}

/// Receives per-call measurements. Implement it to feed your own metrics
/// system, or use [`OtelMetrics`] (feature `opentelemetry`).
pub trait GenAiMetrics: Send + Sync {
    /// Record one finished call.
    fn record(&self, metrics: &OperationMetrics<'_>);
}

impl<F: Fn(&OperationMetrics<'_>) + Send + Sync> GenAiMetrics for F {
    fn record(&self, metrics: &OperationMetrics<'_>) {
        self(metrics);
    }
}

/// Bucket boundaries the conventions advise for
/// `gen_ai.client.operation.duration`, in seconds.
pub const DURATION_BUCKETS: [f64; 14] = [
    0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92,
];

/// Bucket boundaries the conventions advise for `gen_ai.client.token.usage`.
pub const TOKEN_BUCKETS: [f64; 14] = [
    1.0,
    4.0,
    16.0,
    64.0,
    256.0,
    1_024.0,
    4_096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    16_777_216.0,
    67_108_864.0,
];

#[cfg(feature = "opentelemetry")]
pub use otel::OtelMetrics;

#[cfg(feature = "opentelemetry")]
mod otel {
    use opentelemetry::KeyValue;
    use opentelemetry::metrics::{Histogram, Meter};

    use super::{DURATION_BUCKETS, GenAiMetrics, OperationMetrics, TOKEN_BUCKETS};
    use crate::attr;

    /// Records [`OperationMetrics`] as the `GenAI` semantic-convention
    /// histograms `gen_ai.client.operation.duration` and
    /// `gen_ai.client.token.usage`.
    ///
    /// Token usage is only recorded when the provider reported it; local
    /// estimates (streams) are left out so the histogram stays exact.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use opentelemetry::metrics::MeterProvider as _;
    /// use rune_otel_genai::{GenAiConfig, OtelMetrics};
    ///
    /// let provider = opentelemetry_sdk::metrics::SdkMeterProvider::default();
    /// let metrics = OtelMetrics::new(&provider.meter("my-app"));
    /// let config = GenAiConfig::new("openai", "gpt-4o").with_metrics(Arc::new(metrics));
    /// ```
    #[derive(Debug, Clone)]
    pub struct OtelMetrics {
        duration: Histogram<f64>,
        tokens: Histogram<u64>,
    }

    impl OtelMetrics {
        /// Creates the two histograms on `meter`.
        #[must_use]
        pub fn new(meter: &Meter) -> Self {
            Self {
                duration: meter
                    .f64_histogram(attr::METRIC_OPERATION_DURATION)
                    .with_unit("s")
                    .with_description("GenAI operation duration.")
                    .with_boundaries(DURATION_BUCKETS.to_vec())
                    .build(),
                tokens: meter
                    .u64_histogram(attr::METRIC_TOKEN_USAGE)
                    .with_unit("{token}")
                    .with_description("Number of input and output tokens used.")
                    .with_boundaries(TOKEN_BUCKETS.to_vec())
                    .build(),
            }
        }
    }

    impl GenAiMetrics for OtelMetrics {
        fn record(&self, m: &OperationMetrics<'_>) {
            let mut attrs = vec![
                KeyValue::new(attr::GEN_AI_OPERATION_NAME, m.operation.to_owned()),
                KeyValue::new(attr::GEN_AI_PROVIDER_NAME, m.provider.to_owned()),
                KeyValue::new(attr::GEN_AI_REQUEST_MODEL, m.request_model.to_owned()),
            ];
            if let Some(a) = m.server_address {
                attrs.push(KeyValue::new(attr::SERVER_ADDRESS, a.to_owned()));
            }
            if let Some(p) = m.server_port {
                attrs.push(KeyValue::new(attr::SERVER_PORT, i64::from(p)));
            }
            let mut timed = attrs.clone();
            if let Some(e) = m.error_type {
                timed.push(KeyValue::new(attr::ERROR_TYPE, e.to_owned()));
            }
            self.duration.record(m.duration.as_secs_f64(), &timed);
            if m.usage_estimated {
                return;
            }
            for (kind, count) in [("input", m.input_tokens), ("output", m.output_tokens)] {
                if let Some(count) = count {
                    let mut a = attrs.clone();
                    a.push(KeyValue::new(attr::GEN_AI_TOKEN_TYPE, kind));
                    self.tokens.record(count, &a);
                }
            }
        }
    }
}

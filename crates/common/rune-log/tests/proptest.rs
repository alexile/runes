//! Properties: JSON output is always one valid JSON object per event, and a
//! plain value without anything to redact survives unchanged.

mod common;

use common::Capture;
use proptest::prelude::*;
use rune_log::{LogConfig, LogFormat, Policy, Redactor};
use serde_json::Value;

fn json_config(redactor: Redactor) -> LogConfig {
    LogConfig::default()
        .with_format(LogFormat::Json)
        .with_timestamps(false)
        .with_redactor(redactor)
}

proptest! {
    #[test]
    fn json_lines_always_parse(msg in any::<String>(), field in any::<String>(), n in any::<i64>()) {
        let capture = Capture::default();
        let config = json_config(Redactor::default());
        tracing::subscriber::with_default(config.subscriber(capture.clone()), || {
            let span = tracing::info_span!("s", tag = %field);
            span.in_scope(|| tracing::info!(value = %field, n, dbg = ?field, "{msg}"));
        });
        let out = capture.text();
        prop_assert_eq!(out.lines().count(), 1);
        let v: Value = serde_json::from_str(out.trim_end_matches('\n'))
            .map_err(|e| TestCaseError::fail(format!("{e}: {out}")))?;
        prop_assert!(v["fields"].is_object());
        prop_assert!(v["spans"][0]["tag"].is_string());
    }

    #[test]
    fn values_round_trip_when_nothing_is_redacted(value in any::<String>(), n in any::<i64>()) {
        let empty = Redactor::new(Policy::none()).unwrap();
        let capture = Capture::default();
        tracing::subscriber::with_default(json_config(empty).subscriber(capture.clone()), || {
            tracing::info!(value = %value, n);
        });
        let v: Value = serde_json::from_str(capture.text().trim_end_matches('\n')).unwrap();
        prop_assert_eq!(v["fields"]["value"].as_str(), Some(value.as_str()));
        prop_assert_eq!(v["fields"]["n"].as_i64(), Some(n));
    }
}

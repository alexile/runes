//! End-to-end: events and spans go through the layer, secrets never reach
//! the writer, and format/level come from env-style values.

mod common;

use common::Capture;
use rune_log::{LogConfig, LogFormat, Policy, RedactionScope, Redactor, Replacement};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;

const SECRETS: &[&str] = &[
    "bob@example.com",
    "10.1.2.3",
    "abcdef0123456789",
    "4111 1111 1111 1111",
    "AKIAIOSFODNN7EXAMPLE",
    "4111111111111111",
];

fn emit() {
    let span = tracing::info_span!("request", user = "bob@example.com", ip = "10.1.2.3");
    let _guard = span.enter();
    tracing::info!(
        auth = "Bearer abcdef0123456789",
        key = ?"AKIAIOSFODNN7EXAMPLE",
        card = 4_111_111_111_111_111_u64,
        attempts = 3_u64,
        ok = true,
        "card 4111 1111 1111 1111 charged"
    );
    tracing::debug!("debug detail");
}

fn run(config: &LogConfig) -> String {
    let capture = Capture::default();
    tracing::subscriber::with_default(config.subscriber(capture.clone()), emit);
    capture.text()
}

fn assert_clean(out: &str) {
    for secret in SECRETS {
        assert!(!out.contains(secret), "{secret:?} leaked into: {out}");
    }
}

#[test]
fn json_fields_are_redacted_and_typed() {
    let out = run(&LogConfig::default()
        .with_format(LogFormat::Json)
        .with_timestamps(false));
    assert_clean(&out);

    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 1, "debug event must be filtered: {out}");
    let v: Value = serde_json::from_str(lines[0]).unwrap();

    assert_eq!(v["level"], "INFO");
    assert_eq!(v["target"], "layer");
    assert!(v.get("timestamp").is_none());
    let fields = &v["fields"];
    assert_eq!(fields["message"], "card [CC] charged");
    assert_eq!(fields["auth"], "[BEARER]");
    assert_eq!(fields["key"], "\"[CREDENTIAL]\"");
    assert_eq!(fields["card"], "[CC]", "numeric card number");
    assert_eq!(fields["attempts"], 3, "plain numbers stay numbers");
    assert_eq!(fields["ok"], true);

    let spans = v["spans"].as_array().unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0]["name"], "request");
    assert_eq!(spans[0]["user"], "[EMAIL]");
    assert_eq!(spans[0]["ip"], "[IP]");
}

#[test]
fn json_has_rfc3339_timestamp_by_default() {
    let out = run(&LogConfig::default().with_format(LogFormat::Json));
    let v: Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let ts = v["timestamp"].as_str().unwrap();
    assert!(ts.contains('T') && ts.ends_with('Z'), "{ts}");
}

#[test]
fn json_span_records_are_appended() {
    let capture = Capture::default();
    let config = LogConfig::default()
        .with_format(LogFormat::Json)
        .with_timestamps(false)
        .with_target(false);
    tracing::subscriber::with_default(config.subscriber(capture.clone()), || {
        let span = tracing::info_span!("job", id = 7_u64, owner = tracing::field::Empty);
        span.record("owner", "alice@example.com");
        span.in_scope(|| tracing::warn!("done"));
    });
    let v: Value = serde_json::from_str(capture.text().trim_end()).unwrap();
    assert!(v.get("target").is_none());
    assert_eq!(v["spans"][0]["id"], 7);
    assert_eq!(v["spans"][0]["owner"], "[EMAIL]");
}

#[test]
fn full_text_redacts_fields_only() {
    let out = run(&LogConfig::default().with_timestamps(false));
    assert_clean(&out);
    assert!(out.starts_with(" INFO request{"), "{out}");
    assert!(out.contains("user=\"[EMAIL]\""), "{out}");
    assert!(out.contains("card [CC] charged"), "{out}");
    assert!(!out.contains("debug detail"));
}

#[test]
fn compact_text_is_redacted() {
    let out = run(&LogConfig::default()
        .with_format(LogFormat::Compact)
        .with_timestamps(false));
    assert_clean(&out);
    assert!(out.contains("[BEARER]"), "{out}");
}

#[test]
fn line_scope_redacts_target_and_span_names_too() {
    let capture = Capture::default();
    let config = LogConfig::default()
        .with_scope(RedactionScope::Line)
        .with_timestamps(false);
    tracing::subscriber::with_default(config.subscriber(capture.clone()), || {
        tracing::info!(target: "ops@example.com", "hello");
    });
    let out = capture.text();
    assert!(!out.contains("ops@example.com"), "{out}");
    assert!(out.contains("[EMAIL]"), "{out}");

    // Fields scope leaves the target alone.
    let capture = Capture::default();
    let fields = LogConfig::default().with_timestamps(false);
    tracing::subscriber::with_default(fields.subscriber(capture.clone()), || {
        tracing::info!(target: "ops@example.com", "hello");
    });
    assert!(capture.text().contains("ops@example.com"));
}

#[test]
fn line_scope_text_is_clean() {
    let out = run(&LogConfig::default()
        .with_scope(RedactionScope::Line)
        .with_timestamps(false));
    assert_clean(&out);
}

#[test]
fn env_drives_format_and_level() {
    let env = |k: &str| match k {
        "RUST_LOG" => Some("debug".to_owned()),
        "LOG_FORMAT" => Some("json".to_owned()),
        _ => None,
    };
    let out = run(&LogConfig::default()
        .with_env(env)
        .unwrap()
        .with_timestamps(false));
    let lines: Vec<Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["level"], "DEBUG");
    assert_eq!(lines[1]["fields"]["message"], "debug detail");
}

#[test]
fn per_target_directives() {
    let capture = Capture::default();
    let config = LogConfig::default()
        .with_filter("warn,app::db=trace")
        .unwrap()
        .with_timestamps(false);
    tracing::subscriber::with_default(config.subscriber(capture.clone()), || {
        tracing::trace!(target: "app::db", "query");
        tracing::info!(target: "app::http", "request");
        tracing::warn!(target: "app::http", "slow");
    });
    let out = capture.text();
    assert!(out.contains("query"));
    assert!(!out.contains("request"));
    assert!(out.contains("slow"));
}

#[test]
fn custom_policy_is_honoured() {
    let redactor =
        Redactor::new(Policy::default().with_replacement(Replacement::Tokenize)).unwrap();
    let capture = Capture::default();
    let config = LogConfig::default()
        .with_format(LogFormat::Json)
        .with_timestamps(false)
        .with_redactor(redactor);
    tracing::subscriber::with_default(config.subscriber(capture.clone()), || {
        tracing::info!(
            a = "x@example.com",
            b = "x@example.com",
            c = "y@example.com"
        );
    });
    let v: Value = serde_json::from_str(capture.text().trim_end()).unwrap();
    assert_eq!(v["fields"]["a"], "[EMAIL_1]");
    assert_eq!(v["fields"]["b"], "[EMAIL_1]");
    assert_eq!(v["fields"]["c"], "[EMAIL_2]");
}

#[test]
fn layer_composes_with_other_layers() {
    let json = Capture::default();
    let text = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(
            LogConfig::default()
                .with_format(LogFormat::Json)
                .with_filter("error")
                .unwrap()
                .layer(json.clone()),
        )
        .with(LogConfig::default().layer(text.clone()));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(email = "bob@example.com", "info");
        tracing::error!("boom");
    });
    assert_eq!(json.text().lines().count(), 1);
    assert_eq!(text.text().lines().count(), 2);
    assert!(text.text().contains("[EMAIL]"));
}

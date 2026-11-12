//! Property tests for the `key=value,...` list parser and the env overlay.

use proptest::prelude::*;
use rune_telemetry::{TelemetryConfig, parse_key_values};

/// Percent-encodes everything outside a conservative unreserved set.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

proptest! {
    #[test]
    fn round_trips(pairs in proptest::collection::vec(("\\PC{1,12}", "\\PC{0,12}"), 0..6)) {
        let encoded = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join(",");
        prop_assert_eq!(parse_key_values(&encoded).unwrap(), pairs);
    }

    #[test]
    fn never_panics(input in "\\PC*") {
        let _ = parse_key_values(&input);
    }

    #[test]
    fn env_overlay_never_panics(name in "[A-Z_]{1,40}", value in "\\PC*") {
        let config = TelemetryConfig::default();
        let _ = config.with_env(|k| (k == name).then(|| value.clone()));
    }
}

//! Property tests: scanning never panics, matches point into the text, and
//! findings never carry a full secret.

use proptest::prelude::*;
use rune_leak::{HistoryScanner, Ruleset, scan_text};
use std::sync::OnceLock;

fn rules() -> &'static Ruleset {
    static RULES: OnceLock<Ruleset> = OnceLock::new();
    RULES.get_or_init(Ruleset::builtin)
}

/// Text built from secret-ish fragments, so rules actually fire.
fn secretish() -> impl Strategy<Value = String> {
    let fragment = prop_oneof![
        Just("AKIAIOSFODNN7EXAMPLE".to_owned()),
        Just("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln".to_owned()),
        Just("data:image/png;base64,".to_owned()),
        Just("password = ".to_owned()),
        Just("-----BEGIN PRIVATE KEY-----".to_owned()),
        "[A-Za-z0-9+/=_-]{0,60}",
        "[ \t\r\n\"':=,;]{0,4}",
        any::<String>(),
    ];
    prop::collection::vec(fragment, 0..12).prop_map(|parts| parts.concat())
}

proptest! {
    #[test]
    fn never_panics_and_offsets_are_consistent(text in secretish()) {
        for m in rules().scan_str(&text) {
            prop_assert_eq!(&text[m.offset..m.offset + m.value.len()], m.value);
            prop_assert!(m.line_number >= 1 && m.column >= 1);
        }
        let _ = scan_text(&text);
    }

    #[test]
    fn findings_never_contain_the_secret(text in secretish()) {
        for m in rules().scan_str(&text) {
            let finding: rune_finding::Finding = m.to_finding("f");
            if m.value.chars().count() > 4 {
                for e in &finding.evidence {
                    prop_assert!(!e.snippet.contains(m.value), "{:?} leaks {:?}", e, m.value);
                }
            }
        }
    }

    #[test]
    fn history_scanner_never_panics(blobs in prop::collection::vec(secretish(), 0..4)) {
        let mut history = HistoryScanner::new(rules(), 50);
        for (i, blob) in blobs.iter().enumerate() {
            history.push_blob(&format!("{i:040}"), "p", blob);
        }
        prop_assert!(history.into_findings().len() <= 50);
    }
}

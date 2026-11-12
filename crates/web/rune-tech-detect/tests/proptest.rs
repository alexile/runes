//! Property tests: rule loading, HTML scanning and detection never panic,
//! and detections stay well-formed.

use std::sync::OnceLock;

use proptest::prelude::*;
use rune_tech_detect::{Detector, Page, Pattern, Ruleset, resolve_version};

fn detector() -> &'static Detector {
    static DETECTOR: OnceLock<Detector> = OnceLock::new();
    DETECTOR.get_or_init(Detector::builtin)
}

proptest! {
    #[test]
    fn detection_never_panics(
        html in ".{0,400}",
        url in ".{0,40}",
        headers in prop::collection::vec(("[A-Za-z-]{1,16}", ".{0,40}"), 0..8),
    ) {
        let mut page = Page::new(url).with_html(html);
        for (name, value) in &headers {
            page = page.with_header(name, value);
        }
        for detection in detector().detect(&page) {
            prop_assert!(detection.confidence <= 100);
            prop_assert!(!detection.evidence.is_empty());
            prop_assert!(detection.version.as_ref().is_none_or(|v| !v.is_empty() && v.chars().count() <= 64));
        }
    }

    #[test]
    fn tag_like_html_never_panics(parts in prop::collection::vec(
        prop_oneof![
            Just("<".to_owned()), Just(">".to_owned()), Just("<script src=".to_owned()),
            Just("<meta name=generator content=".to_owned()), Just("'".to_owned()),
            Just("\"".to_owned()), Just("</script>".to_owned()), Just("<!--".to_owned()),
            Just("-->".to_owned()), "[a-zé ]{0,6}",
        ],
        0..40,
    )) {
        let page = Page::new("u").with_html(parts.concat());
        prop_assert!(page.script_src.len() <= rune_tech_detect::MAX_TAGS);
        let _ = detector().detect(&page);
    }

    #[test]
    fn rule_loading_never_panics(json in ".{0,200}") {
        let _ = Ruleset::from_wappalyzer_json(&json);
        let mut rules = Ruleset::new();
        let _ = rules.extend_categories_from_json(&json);
    }

    #[test]
    fn patterns_and_versions_never_panic(
        text in ".{0,80}",
        groups in prop::collection::vec(proptest::option::of(".{0,8}"), 0..4),
    ) {
        let pattern = Pattern::parse(&text);
        prop_assert!(pattern.confidence <= 100);
        let groups: Vec<Option<&str>> = groups.iter().map(Option::as_deref).collect();
        prop_assert!(resolve_version(&text, &groups).chars().count() <= 64);
    }
}

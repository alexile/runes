//! Properties of route matching and correlation.

use proptest::prelude::*;
use rune_aspm_correlate::{Batch, Options, Route, correlate};
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};

fn finding() -> impl Strategy<Value = (bool, u8, u8, u8)> {
    (any::<bool>(), 0u8..4, 0u8..4, 0u8..3)
}

proptest! {
    #[test]
    fn route_parsing_and_matching_never_panic(pattern in "\\PC{0,24}", url in "\\PC{0,40}", file in "\\PC{0,20}") {
        if let Ok(route) = Route::new(pattern, "a.py") {
            let _ = route.matches_url(&url);
            let _ = route.matches_location(&Location::file(file));
        }
    }

    #[test]
    fn literal_routes_match_their_own_path(segments in prop::collection::vec("[a-z0-9_-]{1,8}", 0..5)) {
        let path = format!("/{}", segments.join("/"));
        let route = Route::new(path.as_str(), "a.py").unwrap();
        let url = format!("https://a.test{path}?x=1");
        prop_assert!(route.matches_url(&url));
        let longer = format!("https://a.test{path}/extra");
        prop_assert!(!route.matches_url(&longer));
    }

    /// Every kept input lands in exactly one issue, and correlation does
    /// not depend on how many times it runs.
    #[test]
    fn correlation_conserves_reports(inputs in prop::collection::vec(finding(), 0..24)) {
        let options = Options::default()
            .with_route(Route::new("/r/0", "src/0.py").unwrap())
            .with_route(Route::new("/r/1", "src/1.py").unwrap());
        let mut batch = Batch::new();
        for (dast, target, cwe, tool) in inputs {
            let location = if dast {
                Location::url(format!("https://a.test/r/{target}"))
            } else {
                Location::file(format!("src/{target}.py")).with_lines(u32::from(cwe), u32::from(cwe))
            };
            let f = Finding::<()>::new(format!("c{cwe}"), "t", Severity::Medium, Confidence::Firm, location)
                .push_taxonomy(TaxonomyRef::cwe(u32::from(cwe) + 1));
            batch.add_findings(&format!("tool{tool}"), [f]);
        }
        let n = batch.len();
        let report = correlate(batch.into_findings(), &options);
        prop_assert_eq!(report.inputs, n);
        prop_assert_eq!(report.issues.iter().map(|i| i.count).sum::<usize>(), n);
        for issue in &report.issues {
            prop_assert!(issue.is_confirmed() != issue.links.is_empty());
        }
        let again = correlate(report.clone().into_findings(), &options);
        prop_assert_eq!(again.issues.len(), report.issues.len());
    }
}

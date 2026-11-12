//! Property tests: apex and subdomain edge cases, normalization, and
//! agreement with the reference matchers this crate replaces.

use proptest::prelude::*;
use rune_host_match::{
    CertName, HostAllowlist, HostPattern, Hostname, PatternKind, cert_name_matches,
};

/// Short labels from a small alphabet, so generated hosts collide often.
fn label() -> impl Strategy<Value = String> {
    "[a-c0-9_-]{1,4}".prop_filter("not all digits", |l| !l.bytes().all(|b| b.is_ascii_digit()))
}

fn labels(min: usize, max: usize) -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(label(), min..=max)
}

fn join(labels: &[String]) -> String {
    labels.join(".")
}

/// `rune-secops-warden`'s `network_proxy::domain_allowed`, verbatim, for
/// one pattern: the egress semantics this crate takes over.
fn warden_domain_allowed(host: &str, pattern: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || host == pattern,
        |suffix| {
            host.ends_with(suffix) && host.len() > suffix.len() && {
                let boundary = host.len() - suffix.len() - 1;
                host.as_bytes()[boundary] == b'.'
            }
        },
    )
}

/// A reference TLS certificate host matcher, kept verbatim.
fn reference_cert_host_matches(server_name: &str, pattern: &str) -> bool {
    let name = server_name.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        return name
            .split_once('.')
            .is_some_and(|(_, tail)| tail == rest && !rest.is_empty());
    }
    name == pattern
}

proptest! {
    #[test]
    fn subdomain_wildcard_matches_every_depth_but_never_the_apex(
        parent in labels(1, 3),
        prefix in labels(1, 3),
    ) {
        let parent = join(&parent);
        let pattern = HostPattern::parse(&format!("*.{parent}")).unwrap();
        let below = format!("{}.{parent}", join(&prefix));
        let glued = format!("{}{parent}", join(&prefix));
        prop_assert!(pattern.matches(&below));
        prop_assert!(!pattern.matches(&parent), "apex must not match");
        prop_assert!(!pattern.matches(&glued), "a suffix without a label boundary must not match");
    }

    #[test]
    fn exact_pattern_matches_only_itself(host in labels(1, 4), prefix in label()) {
        let host = join(&host);
        let pattern = HostPattern::parse(&host).unwrap();
        prop_assert!(pattern.matches(&host));
        let below = format!("{prefix}.{host}");
        prop_assert!(!pattern.matches(&below));
    }

    #[test]
    fn agrees_with_warden_on_valid_input(
        host in labels(1, 4),
        pattern in labels(1, 3),
        wildcard in any::<bool>(),
    ) {
        let host = join(&host);
        let pattern = if wildcard { format!("*.{}", join(&pattern)) } else { join(&pattern) };
        let allow = HostAllowlist::parse_all([&pattern]).unwrap();
        prop_assert_eq!(allow.allows(&host), warden_domain_allowed(&host, &pattern));
    }

    #[test]
    fn agrees_with_reference_cert_matcher_on_valid_input(
        host in labels(1, 4),
        base in labels(2, 3),
        wildcard in any::<bool>(),
    ) {
        let host = join(&host);
        let presented = if wildcard { format!("*.{}", join(&base)) } else { join(&base) };
        prop_assert_eq!(
            cert_name_matches(&presented, &host),
            reference_cert_host_matches(&host, &presented)
        );
    }

    #[test]
    fn cert_wildcard_covers_exactly_one_label(
        base in labels(2, 3),
        first in label(),
        second in label(),
    ) {
        let base = join(&base);
        let name = CertName::parse(&format!("*.{base}")).unwrap();
        let one = format!("{first}.{base}");
        let two = format!("{first}.{second}.{base}");
        prop_assert!(name.matches(&one));
        prop_assert!(!name.matches(&two));
        prop_assert!(!name.matches(&base));
    }

    #[test]
    fn cert_match_implies_allowlist_match(host in labels(1, 4), base in labels(2, 3)) {
        let host = join(&host);
        let text = format!("*.{}", join(&base));
        if cert_name_matches(&text, &host) {
            prop_assert!(HostPattern::parse(&text).unwrap().matches(&host));
        }
    }

    #[test]
    fn label_wildcards_need_equal_label_counts(
        host in labels(1, 5),
        mask in prop::collection::vec(any::<bool>(), 5),
        anchor in label(),
    ) {
        // Turn some labels of `host.anchor` into `*`, keeping the anchor.
        let mut pattern: Vec<String> = host
            .iter()
            .zip(&mask)
            .map(|(label, &star)| if star { "*".to_owned() } else { label.clone() })
            .collect();
        pattern.push(anchor.clone());
        let full = format!("{}.{anchor}", join(&host));
        let pattern = HostPattern::parse(&join(&pattern)).unwrap();
        prop_assert!(pattern.matches(&full));
        // One label deeper only matches the `*.suffix` form.
        let deeper = format!("x.{full}");
        let is_suffix_form = pattern.kind() == PatternKind::Subdomains;
        prop_assert_eq!(pattern.matches(&deeper), is_suffix_form);
    }

    #[test]
    fn matching_ignores_case_and_one_trailing_dot(
        host in labels(1, 4),
        pattern in labels(1, 3),
        wildcard in any::<bool>(),
    ) {
        let host = join(&host);
        let pattern = if wildcard { format!("*.{}", join(&pattern)) } else { join(&pattern) };
        let pattern = HostPattern::parse(&pattern).unwrap();
        let expected = pattern.matches(&host);
        let shouted = format!("{}.", host.to_ascii_uppercase());
        let two_dots = format!("{host}..");
        prop_assert_eq!(pattern.matches(&shouted), expected);
        prop_assert!(!pattern.matches(&two_dots));
    }

    #[test]
    fn canonical_forms_are_fixed_points(text in "[a-zA-Z0-9*._-]{0,40}") {
        if let Ok(host) = Hostname::parse(&text) {
            prop_assert_eq!(Hostname::parse(host.as_str()), Ok(host.clone()));
            prop_assert_eq!(host.as_str(), host.as_str().to_ascii_lowercase());
            prop_assert!(!host.as_str().ends_with('.'));
        }
        if let Ok(pattern) = HostPattern::parse(&text) {
            let shown = format!("{pattern}");
            let reparsed = HostPattern::parse(&shown);
            prop_assert_eq!(reparsed.as_ref(), Ok(&pattern));
        }
        if let Ok(name) = CertName::parse(&text) {
            let reparsed = CertName::parse(name.as_str());
            prop_assert_eq!(reparsed.as_ref(), Ok(&name));
        }
    }

    #[test]
    fn never_panics_on_arbitrary_text(a in "\\PC{0,80}", b in "\\PC{0,80}") {
        let _ = Hostname::parse(&a);
        let _ = HostPattern::parse(&a).map(|p| p.matches(&b));
        let _ = CertName::parse(&a).map(|n| n.matches(&b));
        let _ = cert_name_matches(&a, &b);
    }
}

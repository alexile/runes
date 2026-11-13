//! Property tests for origin matching.

use proptest::prelude::*;
use rune_axum_cors::{Cors, CorsLayer};

proptest! {
    /// An exact allowlist never grants an origin outside it.
    #[test]
    fn exact_allowlist_grants_only_listed(origin in "\\PC{0,40}", host in "[a-z]{1,10}") {
        let listed = format!("https://{host}.example");
        let cors = Cors::new().allow_origin(&listed);
        prop_assert_eq!(cors.is_allowed(&origin), origin == listed);
    }

    /// Any combination of exact https origins and credentials passes the
    /// audit.
    #[test]
    fn exact_https_allowlists_are_accepted(
        hosts in proptest::collection::vec("[a-z]{1,8}(\\.[a-z]{1,8}){1,2}", 1..5),
        credentials: bool,
    ) {
        let cors = Cors::new()
            .allow_origins(hosts.iter().map(|h| format!("https://{h}")))
            .allow_credentials(credentials);
        prop_assert!(CorsLayer::new(cors).is_ok());
    }
}

proptest! {
    /// A one-label wildcard grants exactly `https://<label>.example.com`.
    #[test]
    fn one_label_wildcard_is_exact(origin in "https://[a-z.\\-]{0,12}example\\.com[.:0-9]{0,3}") {
        let cors = Cors::new().allow_origin("https://*.example.com");
        let label = origin
            .strip_prefix("https://")
            .and_then(|o| o.strip_suffix(".example.com"));
        let expected = label.is_some_and(|l| {
            !l.is_empty() && !l.contains('.') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        prop_assert_eq!(cors.is_allowed(&origin), expected);
    }

    /// An any-depth wildcard never grants the apex or anything outside it.
    #[test]
    fn any_depth_wildcard_stays_inside(origin in "\\PC{0,40}") {
        let cors = Cors::new().allow_origin("https://**.example.com");
        if cors.is_allowed(&origin) {
            prop_assert!(origin.starts_with("https://"));
            prop_assert!(origin.ends_with(".example.com"));
            prop_assert!(!origin.contains(".."));
            prop_assert!(origin != "https://example.com");
        }
    }
}

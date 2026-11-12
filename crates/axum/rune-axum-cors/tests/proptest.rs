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

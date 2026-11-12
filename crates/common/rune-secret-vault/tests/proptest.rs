//! Property tests: the vault reference grammar and response parser never
//! panic, and never echo the token or secret in errors.

#![cfg(feature = "vault")]
#![allow(clippy::unwrap_used, reason = "test helpers")]

use proptest::prelude::*;
use rune_secret_vault::{SecretRef, SecretValue, VaultConfig, VaultResponse};

const TOKEN: &str = "hvs.PROPTEST-token";

fn config() -> VaultConfig {
    VaultConfig::new("https://vault.test", SecretValue::new(TOKEN)).unwrap()
}

proptest! {
    #[test]
    fn request_never_panics(location in "\\PC{1,64}") {
        if let Ok(reference) = SecretRef::from_parts("vault", &location)
            && let Ok(request) = config().request(&reference)
        {
            prop_assert!(request.url.starts_with("https://vault.test/v1/"));
            // Every segment is percent-encoded: no raw query or fragment.
            prop_assert!(!request.url.contains(['?', '#', ' ']));
            prop_assert!(!request.url.contains("/../"));
        }
    }

    #[test]
    fn parse_response_never_panics(status in 100u16..600, body in proptest::collection::vec(any::<u8>(), 0..256)) {
        let reference: SecretRef = "vault:kv/app#field".parse().unwrap();
        if let Err(error) = config().parse_response(&reference, &VaultResponse::new(status, body)) {
            let shown = format!("{error} {error:?}");
            prop_assert!(!shown.contains(TOKEN));
        }
    }

    #[test]
    fn string_field_round_trips(secret in "[^\"\\\\\\p{Cc}]{1,64}") {
        let reference: SecretRef = "vault:kv/app#f".parse().unwrap();
        let body = format!(r#"{{"data":{{"data":{{"f":"{secret}"}}}}}}"#);
        let value = config().parse_response(&reference, &VaultResponse::new(200, body)).unwrap();
        prop_assert_eq!(value.expose(), secret.as_str());
    }
}

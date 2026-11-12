//! Property tests: parsing never panics, the string form round-trips, and
//! a `SecretValue` never prints its contents.

use proptest::prelude::*;
use rune_secret_ref::{SecretRef, SecretValue};

fn reference() -> impl Strategy<Value = SecretRef> {
    let word = "[!-~]{1,12}";
    prop_oneof![
        "[A-Za-z_][A-Za-z0-9_]{0,15}".prop_map(SecretRef::Env),
        "[^\\x00]{1,40}".prop_map(|path| SecretRef::File(path.into())),
        (word, proptest::collection::vec(word, 0..4))
            .prop_map(|(program, args)| SecretRef::Command { program, args }),
        ("[^/]{1,12}", ".{1,12}")
            .prop_map(|(service, account)| SecretRef::Keychain { service, account }),
        ".{1,30}".prop_map(SecretRef::Vault),
    ]
}

proptest! {
    #[test]
    fn parse_never_panics(text in any::<String>()) {
        let _ = text.parse::<SecretRef>();
    }

    #[test]
    fn errors_never_echo_input(text in "[a-z]{0,6}:?[A-Za-z0-9+/=-]{16,40}") {
        if let Err(error) = text.parse::<SecretRef>() {
            let tail = text.rsplit(':').next().unwrap_or(&text);
            prop_assert!(!error.to_string().contains(tail));
        }
    }

    #[test]
    fn string_form_round_trips(reference in reference()) {
        prop_assume!(reference.has_string_form());
        let parsed: SecretRef = reference.to_string().parse().unwrap();
        prop_assert_eq!(parsed, reference);
    }

    #[test]
    fn secret_value_is_always_redacted(secret in "[A-Za-z0-9]{6,40}") {
        let value = SecretValue::new(secret.clone());
        let printed = format!("{value} {value:?} {value:#?}");
        prop_assert!(!printed.contains(&secret));
        prop_assert_eq!(value.expose(), secret.as_str());
    }
}

//! Property tests: lookups never panic, and their parts are consistent.

#![cfg(any(feature = "embedded", feature = "runtime"))]

use proptest::prelude::*;

/// Label-shaped strings, mostly valid, with the odd Unicode or `xn--` label.
fn host() -> impl Strategy<Value = String> {
    let label = prop_oneof![
        "[a-z0-9]{1,10}",
        "[a-z0-9_-]{1,12}",
        Just("co".to_owned()),
        Just("uk".to_owned()),
        Just("jp".to_owned()),
        Just("kobe".to_owned()),
        Just("github".to_owned()),
        Just("io".to_owned()),
        Just("公司".to_owned()),
        Just("xn--55qx5d".to_owned()),
        "xn--[a-z0-9]{1,8}",
        "\\PC{1,4}",
    ];
    prop::collection::vec(label, 1..6).prop_map(|labels| labels.join("."))
}

proptest! {
    #[test]
    fn lookup_never_panics_on_arbitrary_text(input in "\\PC{0,80}") {
        #[cfg(feature = "embedded")]
        let _ = rune_psl::lookup(&input);
        #[cfg(feature = "runtime")]
        let _ = rune_psl::List::parse(&input);
    }

    #[cfg(feature = "embedded")]
    #[test]
    fn parts_nest(input in host()) {
        if let Ok(domain) = rune_psl::lookup(&input) {
            let name = domain.as_str();
            let suffix = domain.public_suffix();
            prop_assert!(!suffix.is_empty());
            let dotted = format!(".{suffix}");
            prop_assert!(name == suffix || name.ends_with(&dotted));
            match domain.registrable_domain() {
                None => {
                    prop_assert_eq!(name, suffix);
                    prop_assert!(domain.subdomain().is_none());
                }
                Some(registrable) => {
                    let label = registrable.strip_suffix(suffix).and_then(|l| l.strip_suffix('.'));
                    prop_assert!(label.is_some_and(|l| !l.is_empty() && !l.contains('.')));
                    match domain.subdomain() {
                        None => prop_assert_eq!(name, registrable),
                        Some(sub) => prop_assert_eq!(format!("{sub}.{registrable}"), name),
                    }
                }
            }
            // Looking up the normalized name, or the registrable domain,
            // gives the same split.
            let again = rune_psl::lookup(name).unwrap();
            prop_assert_eq!(&again, &domain);
            if let Some(registrable) = domain.registrable_domain() {
                let parent = rune_psl::lookup(registrable).unwrap();
                prop_assert_eq!(parent.public_suffix(), suffix);
            }
        }
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn parsed_lists_display_and_reparse(rules in prop::collection::vec(host(), 0..20)) {
        let text = rules.join("\n");
        if let Ok(list) = rune_psl::List::parse(&text) {
            let rendered: Vec<String> = list.rules().map(|rule| rule.to_string()).collect();
            let again = rune_psl::List::parse(&rendered.join("\n")).unwrap();
            prop_assert!(again.rules().eq(list.rules()));
        }
    }
}

//! User rules loaded from TOML.

use rune_finding::Severity;
use rune_leak::{Ruleset, SecretRule, rules_from_toml};

#[test]
fn loads_rules_with_defaults() {
    let rules = rules_from_toml(
        r#"
        [[rules]]
        id = "acme_token"
        name = "ACME API token"
        pattern = 'acme_([0-9a-f]{32})'
        keywords = ["acme_"]
        entropy_threshold = 3.0
        severity = "critical"

        [[rules]]
        id = "internal"
        name = "Internal password"
        pattern = 'INTERNAL-[A-Z]{8}'
        cwe = 259
        "#,
    )
    .unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].severity, Severity::Critical);
    assert_eq!(rules[1].severity, Severity::Medium);
    assert_eq!((rules[0].cwe, rules[1].cwe), (798, 259));

    let mut ruleset = Ruleset::builtin().without_entropy();
    ruleset.extend(rules).unwrap();
    let findings = ruleset.findings(
        "a = acme_0123456789abcdef0123456789abcdef\nb = INTERNAL-ABCDEFGH\n",
        "x.cfg",
    );
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[1].taxonomy[0].id, "CWE-259");
}

#[test]
fn rejects_bad_files() {
    assert_eq!(
        rules_from_toml("[[rules]]\nid = 1").unwrap_err().code(),
        "invalid_toml"
    );
    let unknown = "[[rules]]\nid='a'\nname='a'\npattern='a'\nregex='b'";
    assert!(rules_from_toml(unknown).is_err());
    assert_eq!(rules_from_toml("").unwrap(), Vec::<SecretRule>::new());
}

#[test]
fn rules_round_trip_through_toml() {
    #[derive(serde::Serialize)]
    struct File<'a> {
        rules: &'a [SecretRule],
    }
    let rules = rune_leak::default_rules();
    let text = toml::to_string(&File { rules: &rules }).unwrap();
    assert_eq!(rules_from_toml(&text).unwrap(), rules);
}

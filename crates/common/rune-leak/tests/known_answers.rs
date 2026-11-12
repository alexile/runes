//! Known-answer tests for the ruleset engine: real-shaped credentials are
//! found with the right rule id, and common high-entropy non-secrets are not.

use rune_finding::{Confidence, Severity};
use rune_leak::{Ruleset, default_rules, scan_text};

fn ids(text: &str) -> Vec<String> {
    Ruleset::builtin()
        .scan_str(text)
        .iter()
        .map(|m| m.rule.id.clone())
        .collect()
}

/// (rule id, line containing the secret, the secret value).
const POSITIVES: &[(&str, &str, &str)] = &[
    (
        "aws_access_key",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AKIAIOSFODNN7EXAMPLE",
    ),
    (
        "aws_access_key",
        "key: ASIAY34FZKBOKMUTVV7A",
        "ASIAY34FZKBOKMUTVV7A",
    ),
    (
        "aws_secret",
        "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "gcp_api_key",
        "maps: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",
        "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",
    ),
    (
        "github_token",
        "GH=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "gitlab_pat",
        "CI_TOKEN glpat-x9Yz8Wv7Ut6Sr5Qp4On3",
        "glpat-x9Yz8Wv7Ut6Sr5Qp4On3",
    ),
    (
        "slack_token",
        "SLACK=xoxb-123456789012-abcdefABCDEF",
        "xoxb-123456789012-abcdefABCDEF",
    ),
    (
        "slack_webhook",
        "url = https://hooks.slack.com/services/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",
        "https://hooks.slack.com/services/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",
    ),
    (
        "stripe_live",
        "Stripe.key = sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    ),
    (
        "npm_token",
        "//registry.npmjs.org/:_authToken=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "private_key_block",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ),
    (
        "private_key_block",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ),
    (
        "jwt",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ),
    (
        "generic_assignment",
        "API_KEY = \"s3cr3tP@sswordValue123\"",
        "s3cr3tP@sswordValue123",
    ),
    (
        "high_entropy_string",
        "blob: Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6",
        "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6",
    ),
];

#[test]
fn known_secrets_are_found_with_their_rule() {
    let rules = Ruleset::builtin();
    for (id, line, value) in POSITIVES {
        let matches = rules.scan_str(line);
        assert!(
            matches
                .iter()
                .any(|m| m.rule.id == *id && m.value == *value),
            "{id}: expected {value:?} in {line:?}, got {:?}",
            matches
                .iter()
                .map(|m| (&m.rule.id, m.value))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_default_rule_has_a_known_answer() {
    let covered: Vec<&str> = POSITIVES.iter().map(|(id, _, _)| *id).collect();
    let missing: Vec<String> = default_rules()
        .into_iter()
        .map(|r| r.id)
        .filter(|id| {
            !covered.contains(&id.as_str())
                && !["github_fine_grained_pat", "sendgrid_api_key", "pypi_token"]
                    .contains(&id.as_str())
        })
        .collect();
    assert!(
        missing.is_empty(),
        "rules without a known answer: {missing:?}"
    );
}

#[test]
fn long_token_formats() {
    let pat = format!("github_pat_{}", "A1b2C3d4E5".repeat(8) + "Zz");
    assert_eq!(ids(&format!("t={pat}")), ["github_fine_grained_pat"]);
    let sg = format!(
        "SG.{}.{}",
        "aB3dE5gH7jK9mN1pQ3sT5v", "wX7zA9cE1gI3kM5oQ7sU9wY1aC3eG5iK7mO9qS1uW3y"
    );
    assert_eq!(ids(&format!("SENDGRID={sg}")), ["sendgrid_api_key"]);
    let pypi = format!(
        "pypi-AgEIcHlwaS5vcmc{}",
        "Qk2xZ8vN4mR7tY1wP5sL9dH3jF6gK0bC".repeat(2)
    );
    assert_eq!(ids(&format!("password: {pypi}")), ["pypi_token"]);
}

#[test]
fn severities_and_confidence() {
    let rules = Ruleset::builtin();
    let m = rules.scan_str("k=AKIAIOSFODNN7EXAMPLE");
    assert_eq!(
        (m[0].rule.severity, m[0].confidence),
        (Severity::High, Confidence::Firm)
    );
    let m = rules.scan_str("Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6");
    assert_eq!(
        (m[0].rule.severity, m[0].confidence),
        (Severity::Low, Confidence::Tentative)
    );
}

/// High-entropy text that is not a credential.
const NEGATIVES: &[&str] = &[
    // UUIDs, in several spellings.
    "request_id = \"550e8400-e29b-41d4-a716-446655440000\"",
    "ID: 6F9619FF-8B86-D011-B42D-00CF4FC964FF",
    "{\"trace\":\"123e4567-e89b-12d3-a456-426614174000\",\"span\":\"9b2d7c1a-3f4e-4a5b-8c6d-7e8f9a0b1c2d\"}",
    // Inline base64 images and fonts.
    "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\">",
    "background: url(data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7);",
    "src: url('data:font/woff2;base64,d09GMgABAAAAAAQUAA0AAAAACCgAAAPAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP0ZGVE0cGh4GYACCcBEICoRQhDYLCAABNgIkAwwEIAWKMAc3G') format('woff2');",
    // Lockfile integrity digests and git object ids.
    "\"integrity\": \"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==\"",
    "commit 7cc828a559c0f09adcadb31f6af6b4f62dfffa2c",
    // URLs pinned to a commit.
    "url = \"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7/enterprise-attack/enterprise-attack-20.1.json\"",
    "{ url = \"https://raw.githubusercontent.com/OWASP/Top10/3a31f35346c3f4e90f350395124382fa53af2afe/2025/docs/en/A05_2025-Injection.md\" }",
    // Ordinary code.
    "let password = read_password_from_env();",
    "fn verify_token(token: &str) -> bool { token.len() > 0 }",
    "See https://example.com/docs/getting-started/installation for details.",
];

#[test]
fn false_positive_fixtures_are_quiet() {
    let rules = Ruleset::builtin();
    for line in NEGATIVES {
        let matches = rules.scan_str(line);
        assert!(
            matches.is_empty(),
            "false positive in {line:?}: {:?}",
            matches
                .iter()
                .map(|m| (&m.rule.id, m.value))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn simple_api_known_answers() {
    assert!(
        scan_text("k = \"AKIAIOSFODNN7EXAMPLE\"")
            .iter()
            .any(|l| l.category == "aws_key")
    );
    assert!(
        scan_text("-----BEGIN RSA PRIVATE KEY-----")
            .iter()
            .any(|l| l.category == "private_key")
    );
    for line in &NEGATIVES[..6] {
        assert!(
            scan_text(line).is_empty(),
            "simple API false positive in {line:?}"
        );
    }
}

#[test]
fn matches_point_into_the_text() {
    let text = POSITIVES
        .iter()
        .map(|(_, line, _)| *line)
        .collect::<Vec<_>>()
        .join("\r\n");
    for m in Ruleset::builtin().scan_str(&text) {
        assert_eq!(&text[m.offset..m.offset + m.value.len()], m.value);
        let line = text.lines().nth(m.line_number - 1).unwrap();
        assert_eq!(&line[m.column - 1..m.column - 1 + m.value.len()], m.value);
    }
}

#[test]
fn generic_assignment_ignores_code_and_templates() {
    for line in [
        "password = os.getenv(\"DB_PASSWORD_VALUE\")",
        "token: ${{ secrets.GITHUB_TOKEN_VALUE }}",
        "secret = config[\"signing_secret_key\"]",
        "api_key = <your-api-key-goes-here>",
    ] {
        let found = ids(line);
        assert!(
            !found.contains(&"generic_assignment".to_owned()),
            "{line:?}: {found:?}"
        );
    }
    assert_eq!(
        ids("password: 'Tr0ub4dor&3-horse-battery'"),
        ["generic_assignment"]
    );
}

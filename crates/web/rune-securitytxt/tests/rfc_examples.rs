//! Conformance tests built from the examples in RFC 9116 §2.3 and §2.5.

use rune_securitytxt::{FieldKind, Options, SecurityTxt, Timestamp, WeaknessKind, analyze, run};

/// Every field example from RFC 9116 §2.5, in one file.
const RFC_FIELDS: &str = "\
# Our security address
Contact: mailto:security@example.com
Contact: mailto:security%2Buri%2Bencoded@example.com
Contact: tel:+1-201-555-0123
Contact: https://example.com/security-contact.html

# Our OpenPGP key
Encryption: https://example.com/pgp-key.txt
Encryption: dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY
Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f

Acknowledgments: https://example.com/hall-of-fame.html
Canonical: https://www.example.com/.well-known/security.txt
Canonical: https://someserver.example.com/.well-known/security.txt
Policy: https://example.com/disclosure.html
Hiring: https://example.com/jobs.html
Preferred-Languages: en, es, fr
Expires: 2021-12-31T18:37:07z
";

/// The shape of the signed example in RFC 9116 §2.3 (signature elided).
const RFC_SIGNED: &str = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Canonical URI
Canonical: https://example.com/.well-known/security.txt

# Our security address
Contact: mailto:security@example.com

# Our OpenPGP key
Encryption: https://example.com/pgp-key.txt

# Our security policy
Policy: https://example.com/security-policy.html

# Our security acknowledgments page
Acknowledgments: https://example.com/hall-of-fame.html

Expires: 2021-12-31T18:37:07z
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.2

[signature]
-----END PGP SIGNATURE-----
";

fn at(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap_or_else(|e| unreachable!("{e}"))
}

fn kinds(text: &str, options: &Options) -> Vec<WeaknessKind> {
    run(text, options)
        .weaknesses
        .into_iter()
        .map(|w| w.kind)
        .collect()
}

#[test]
fn rfc_field_examples_parse() {
    let doc = SecurityTxt::parse(RFC_FIELDS).unwrap();
    assert_eq!(doc.malformed, []);
    assert_eq!(doc.contacts().len(), 4);
    assert_eq!(doc.contacts()[2], "tel:+1-201-555-0123");
    assert_eq!(doc.encryption().len(), 3);
    assert_eq!(
        doc.acknowledgments(),
        ["https://example.com/hall-of-fame.html"]
    );
    assert_eq!(doc.canonical().len(), 2);
    assert_eq!(doc.policy(), ["https://example.com/disclosure.html"]);
    assert_eq!(doc.hiring(), ["https://example.com/jobs.html"]);
    assert_eq!(doc.preferred_languages(), ["en", "es", "fr"]);
    assert_eq!(doc.expires(), Some(at("2021-12-31T18:37:07Z")));
    assert_eq!(doc.extensions().count(), 0);
}

#[test]
fn rfc_field_examples_are_valid_before_expiry() {
    let options = Options::default()
        .with_now(at("2021-06-01T00:00:00Z"))
        .with_retrieved_from("https://someserver.example.com/.well-known/security.txt");
    let report = run(RFC_FIELDS, &options);
    assert!(report.is_valid(), "{:?}", report.weaknesses);
    assert_eq!(kinds(RFC_FIELDS, &options), [WeaknessKind::Unsigned]);
}

#[test]
fn rfc_examples_are_expired_now() {
    let options = Options::default().with_now(at("2026-11-11T00:00:00Z"));
    for text in [RFC_FIELDS, RFC_SIGNED] {
        let report = run(text, &options);
        assert!(!report.is_valid());
        assert!(
            report
                .weaknesses
                .iter()
                .any(|w| w.kind == WeaknessKind::Expired)
        );
    }
}

#[test]
fn rfc_signed_example() {
    let doc = SecurityTxt::parse(RFC_SIGNED).unwrap();
    let sig = doc.signature.as_ref().unwrap();
    assert_eq!(sig.hash_algorithms, ["SHA256"]);
    assert!(sig.signed_text.starts_with("# Canonical URI\nCanonical: "));
    assert!(sig.signed_text.ends_with("Expires: 2021-12-31T18:37:07z"));
    assert!(sig.armored.contains("Version: GnuPG v2.2"));
    assert_eq!(
        doc.canonical(),
        ["https://example.com/.well-known/security.txt"]
    );
    // Line numbers refer to the whole file.
    let contact = doc.fields_of(FieldKind::Contact).next().unwrap();
    assert_eq!(contact.line, 8);

    let options = Options::default()
        .with_now(at("2021-06-01T00:00:00Z"))
        .with_retrieved_from("https://example.com/.well-known/security.txt");
    assert_eq!(analyze(&doc, &options), []);
    let elsewhere =
        options.with_retrieved_from("https://attacker.example/.well-known/security.txt");
    assert_eq!(
        kinds(RFC_SIGNED, &elsewhere),
        [WeaknessKind::CanonicalMismatch]
    );
}

#[test]
fn crlf_and_bom() {
    let crlf = format!("\u{feff}{}", RFC_FIELDS.replace('\n', "\r\n"));
    assert_eq!(
        SecurityTxt::parse(&crlf).unwrap(),
        SecurityTxt::parse(RFC_FIELDS).unwrap()
    );
}

#[test]
fn rfc_violations_are_flagged() {
    let options = Options::default().with_now(at("2021-06-01T00:00:00Z"));
    let cases: &[(&str, WeaknessKind)] = &[
        (
            "Expires: 2021-12-31T18:37:07z\n",
            WeaknessKind::MissingContact,
        ),
        (
            "Contact: mailto:a@example.com\n",
            WeaknessKind::MissingExpires,
        ),
        (
            "Contact: mailto:a@example.com\nExpires: 2021-12-31T18:37:07z\nExpires: 2021-11-30T00:00:00Z\n",
            WeaknessKind::DuplicateExpires,
        ),
        (
            "Contact: mailto:a@example.com\nExpires: 31 Dec 2021\n",
            WeaknessKind::InvalidExpires,
        ),
        (
            "Contact: http://example.com/report\nExpires: 2021-12-31T18:37:07z\n",
            WeaknessKind::InsecureUri,
        ),
        (
            "Contact: security@example.com\nExpires: 2021-12-31T18:37:07z\n",
            WeaknessKind::InvalidUri,
        ),
        (
            "Contact: mailto:a@example.com\nExpires: 2021-12-31T18:37:07z\nPreferred-Languages: en\nPreferred-Languages: fr\n",
            WeaknessKind::DuplicatePreferredLanguages,
        ),
    ];
    for (text, kind) in cases {
        let report = run(text, &options);
        assert!(!report.is_valid(), "{text:?}");
        assert!(kinds(text, &options).contains(kind), "{text:?}: {kind}");
    }
}

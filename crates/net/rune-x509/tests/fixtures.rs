//! Analysis and chain validation over the certificates in `tests/fixtures`
//! (see `generate.sh` there for what each one is).

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use rune_x509::{
    Certificate, ChainIssue, Curve, ExtendedKeyUsage, HashAlgorithm, HostOptions, Policy,
    PublicKeyInfo, Purpose, SignatureAlgorithm, SignatureError, SubjectAltName, TrustStore,
    VerifyOptions, Weakness, parse_pem, verify_chain,
};

/// 2026-06-01T00:00:00Z: inside every fixture's validity except `expired`.
const T: i64 = 1_780_272_000;

fn load(name: &str) -> Certificate {
    let path = format!("{}/tests/fixtures/{name}.pem", env!("CARGO_MANIFEST_DIR"));
    Certificate::from_pem(&std::fs::read(path).unwrap()).unwrap()
}

fn store() -> TrustStore {
    TrustStore::new().with(load("root"))
}

fn options(host: &str) -> VerifyOptions {
    VerifyOptions::default().with_time(T).with_hostname(host)
}

#[test]
fn summary_of_leaf() {
    let leaf = load("leaf");
    let s = leaf.summary();
    assert_eq!(s.version, 3);
    assert_eq!(s.subject, "CN=example.com");
    assert_eq!(s.issuer, "O=Rune Test, CN=Rune Test Intermediate");
    assert_eq!(s.subject_common_names, ["example.com"]);
    assert_eq!(s.not_before, 1_767_225_600);
    assert_eq!(s.not_after, 1_798_761_600);
    assert_eq!(s.validity_days(), 365);
    assert_eq!(
        s.public_key,
        PublicKeyInfo::Ec {
            curve: Curve::P256,
            bits: 256
        }
    );
    assert_eq!(
        s.signature_algorithm,
        SignatureAlgorithm::Ecdsa(HashAlgorithm::Sha256)
    );
    assert_eq!(
        s.subject_alt_names,
        [
            SubjectAltName::Dns("example.com".into()),
            SubjectAltName::Dns("www.example.com".into()),
            SubjectAltName::Ip("192.0.2.1".parse().unwrap()),
        ]
    );
    assert!(!s.is_ca());
    let bc = s.basic_constraints.unwrap();
    assert!(bc.critical && !bc.ca);
    let ku = s.key_usage.unwrap();
    assert!(ku.digital_signature && !ku.key_cert_sign);
    assert_eq!(
        s.extended_key_usage.as_deref(),
        Some(&[ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth][..])
    );
    assert_eq!(s.sct_count, 1);
    assert!(s.subject_key_id.is_some());
    assert_eq!(s.authority_key_id, load("inter").summary().subject_key_id);
    assert!(!s.self_issued && !s.self_signed);
    assert_eq!(s.unhandled_critical_extensions, Vec::<String>::new());
    assert_eq!(s.sha256_fingerprint_hex().len(), 32 * 3 - 1);
    assert_eq!(leaf.weaknesses(&Policy::default()), []);
}

#[test]
fn summary_of_cas() {
    let root = load("root");
    let s = root.summary();
    assert_eq!(s.public_key, PublicKeyInfo::Rsa { bits: 2048 });
    assert_eq!(
        s.signature_algorithm,
        SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha256)
    );
    assert!(s.is_ca() && s.self_issued && s.self_signed);
    assert!(s.key_usage.unwrap().key_cert_sign);
    // CAs are exempt from the leaf validity limit.
    assert_eq!(root.weaknesses(&Policy::default()), []);

    let inter = load("inter").summary().clone();
    assert_eq!(inter.basic_constraints.unwrap().path_len, Some(0));
    assert!(!inter.self_issued);

    let ed = load("ed25519");
    assert_eq!(ed.summary().public_key, PublicKeyInfo::Ed25519);
    assert_eq!(
        ed.summary().signature_algorithm,
        SignatureAlgorithm::Ed25519
    );
    assert!(ed.summary().self_signed);
}

#[test]
fn pem_round_trip() {
    let leaf = load("leaf");
    let again = Certificate::from_pem(leaf.to_pem().as_bytes()).unwrap();
    assert_eq!(again, leaf);
    assert_eq!(Certificate::from_der(leaf.der()).unwrap(), leaf);

    let bundle = format!("junk\n{}text\n{}", leaf.to_pem(), load("inter").to_pem());
    assert_eq!(parse_pem(bundle.as_bytes()).unwrap().len(), 2);
}

#[test]
fn trailing_der_is_rejected() {
    let mut der = load("leaf").der().to_vec();
    der.push(0);
    assert_eq!(
        Certificate::from_der(&der),
        Err(rune_x509::Error::TrailingData { len: 1 })
    );
}

#[test]
fn signature_checks() {
    let (leaf, inter, root) = (load("leaf"), load("inter"), load("root"));
    assert_eq!(leaf.verify_signed_by(&inter), Ok(()));
    assert_eq!(inter.verify_signed_by(&root), Ok(()));
    assert_eq!(leaf.verify_signed_by(&root), Err(SignatureError::Invalid));
    assert!(leaf.may_be_issued_by(&inter));
    assert!(!leaf.may_be_issued_by(&root));
}

#[test]
fn valid_chain() {
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &store(),
        &options("www.example.com"),
    );
    assert!(report.is_trusted(), "{:?}", report.issues);
    assert!(report.anchored);
    assert_eq!(report.issues, []);
    let subjects: Vec<_> = report
        .path
        .iter()
        .map(|c| c.summary().subject.clone())
        .collect();
    assert_eq!(
        subjects,
        [
            "CN=example.com",
            "O=Rune Test, CN=Rune Test Intermediate",
            "O=Rune Test, CN=Rune Test Root"
        ]
    );
    assert_eq!(report.time, T);
}

#[test]
fn out_of_order_and_extra_certificates() {
    // Servers send roots, unrelated certs and wrong orders; none of that
    // should matter.
    let pool = [
        load("untrusted"),
        load("root"),
        load("other-root"),
        load("inter"),
    ];
    let report = verify_chain(&load("leaf"), &pool, &store(), &options("example.com"));
    assert!(report.is_trusted(), "{:?}", report.issues);
    assert_eq!(report.path.len(), 3);
}

#[test]
fn ip_address_host() {
    let leaf = load("leaf");
    assert!(leaf.matches_host("192.0.2.1"));
    assert!(!leaf.matches_host("192.0.2.2"));
    let report = verify_chain(&leaf, &[load("inter")], &store(), &options("192.0.2.1"));
    assert!(report.is_trusted(), "{:?}", report.issues);
}

#[test]
fn expired() {
    let report = verify_chain(
        &load("expired"),
        &[load("inter")],
        &store(),
        &options("expired.example.com"),
    );
    assert!(!report.is_trusted());
    assert!(report.anchored);
    assert_eq!(
        report.issues,
        [ChainIssue::Expired {
            depth: 0,
            not_after: 1_609_459_200
        }]
    );
    // And it is not yet valid before its notBefore.
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &store(),
        &VerifyOptions::default().with_time(1_750_000_000),
    );
    assert!(matches!(
        report.issues[..],
        [ChainIssue::NotYetValid { depth: 0, .. }]
    ));
}

#[test]
fn self_signed() {
    let cert = load("self-signed");
    assert!(cert.summary().self_signed);
    let report = verify_chain(&cert, &[], &store(), &options("self.example.com"));
    assert!(!report.is_trusted());
    assert!(!report.anchored);
    assert_eq!(report.issues, [ChainIssue::SelfSigned]);
    // Pinning it in the store makes it trusted.
    let pinned = TrustStore::new().with(cert.clone());
    assert!(verify_chain(&cert, &[], &pinned, &options("self.example.com")).is_trusted());
}

#[test]
fn wildcard() {
    let cert = load("wildcard");
    let chain = [load("inter")];
    assert!(verify_chain(&cert, &chain, &store(), &options("api.example.com")).is_trusted());
    for host in ["example.com", "a.b.example.com", "api.example.org"] {
        let report = verify_chain(&cert, &chain, &store(), &options(host));
        assert_eq!(
            report.issues,
            [ChainIssue::NameMismatch {
                hostname: host.into()
            }],
            "{host}"
        );
    }
    // Case and trailing dot are ignored; Unicode names go through IDNA.
    assert!(cert.matches_host("API.Example.COM."));
    assert!(!cert.matches_host("bücher.example.org"));
}

#[test]
fn name_mismatch() {
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &store(),
        &options("other.example.org"),
    );
    assert!(report.anchored);
    assert!(!report.is_trusted());
    assert_eq!(
        report.issues,
        [ChainIssue::NameMismatch {
            hostname: "other.example.org".into()
        }]
    );
}

#[test]
fn common_name_fallback_is_opt_in() {
    let cert = load("cn-only");
    assert_eq!(cert.summary().subject_alt_names, Vec::new());
    assert!(!cert.matches_host("cn-only.example.com"));
    let legacy = HostOptions::default().with_common_name_fallback(true);
    assert!(cert.matches_host_with("cn-only.example.com", legacy));
    assert!(!cert.matches_host_with("other.example.com", legacy));
    // A certificate with DNS SANs never consults its CN.
    assert!(!load("leaf").matches_host_with("example.org", legacy));
}

#[test]
fn sha1_signed() {
    let cert = load("sha1");
    assert_eq!(
        cert.summary().signature_algorithm,
        SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha1)
    );
    assert_eq!(
        cert.weaknesses(&Policy::default()),
        [Weakness::WeakSignature(SignatureAlgorithm::RsaPkcs1(
            HashAlgorithm::Sha1
        ))]
    );
    let report = verify_chain(&cert, &[], &store(), &options("sha1.example.com"));
    assert!(report.anchored, "{:?}", report.issues);
    assert!(!report.is_trusted());
    assert_eq!(
        report.issues,
        [ChainIssue::Weak {
            depth: 0,
            weakness: Weakness::WeakSignature(SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha1)),
        }]
    );
}

#[test]
fn incomplete_chain() {
    let report = verify_chain(&load("leaf"), &[], &store(), &options("example.com"));
    assert!(!report.anchored);
    assert_eq!(report.path.len(), 1);
    assert_eq!(
        report.issues,
        [ChainIssue::Incomplete {
            issuer: "O=Rune Test, CN=Rune Test Intermediate".into()
        }]
    );
}

#[test]
fn untrusted_root() {
    let report = verify_chain(
        &load("untrusted"),
        &[load("other-root")],
        &store(),
        &options("untrusted.example.com"),
    );
    assert!(!report.anchored);
    assert_eq!(report.path.len(), 2);
    assert_eq!(report.issues, [ChainIssue::UntrustedRoot { depth: 1 }]);
}

#[test]
fn empty_store() {
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &TrustStore::new(),
        &options("example.com"),
    );
    assert!(!report.is_trusted());
    assert!(matches!(report.issues[0], ChainIssue::Incomplete { .. }));
}

#[test]
fn issuer_that_is_not_a_ca() {
    // notca-leaf is signed by the leaf's key; the leaf is CA:FALSE, and
    // the inter's pathlen:0 forbids the extra intermediate as well.
    let report = verify_chain(
        &load("notca-leaf"),
        &[load("leaf"), load("inter")],
        &store(),
        &options("notca.example.com"),
    );
    assert!(report.anchored, "{:?}", report.issues);
    assert!(!report.is_trusted());
    assert_eq!(
        report.issues,
        [
            ChainIssue::NotCa { depth: 1 },
            ChainIssue::MissingKeyCertSign { depth: 1 },
            ChainIssue::PathLenExceeded { depth: 2 },
        ]
    );
}

#[test]
fn small_rsa_key() {
    let cert = load("weak-rsa");
    assert_eq!(cert.summary().public_key, PublicKeyInfo::Rsa { bits: 1024 });
    assert_eq!(
        cert.weaknesses(&Policy::default()),
        [Weakness::SmallRsaKey {
            bits: 1024,
            min: 2048
        }]
    );
    assert_eq!(
        cert.weaknesses(&Policy::default().with_min_rsa_bits(1024)),
        []
    );
    // ring refuses RSA keys under 2048 bits with SHA-256, so its own
    // signature cannot be checked and it is not considered self-signed.
    assert!(cert.summary().self_issued);
    assert_eq!(cert.verify_signed_by(&cert), Err(SignatureError::Invalid));
}

#[test]
fn long_validity_is_a_warning() {
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &store(),
        &options("example.com")
            .with_policy(Policy::default().with_max_leaf_validity_days(Some(90))),
    );
    assert!(report.is_trusted());
    assert_eq!(report.warnings().count(), 1);
    assert_eq!(
        report.issues,
        [ChainIssue::Weak {
            depth: 0,
            weakness: Weakness::LongValidity { days: 365, max: 90 },
        }]
    );
}

#[test]
fn purposes() {
    let chain = [load("inter")];
    let client = options("example.com").with_purpose(Purpose::ClientAuth);
    assert!(verify_chain(&load("leaf"), &chain, &store(), &client).is_trusted());
    // The self-signed fixture only allows serverAuth.
    let cert = load("self-signed");
    let pinned = TrustStore::new().with(cert.clone());
    let report = verify_chain(
        &cert,
        &[],
        &pinned,
        &VerifyOptions::default()
            .with_time(T)
            .with_purpose(Purpose::ClientAuth),
    );
    assert_eq!(
        report.issues,
        [ChainIssue::WrongPurpose {
            purpose: Purpose::ClientAuth
        }]
    );
}

#[test]
fn max_depth_limits_the_search() {
    let report = verify_chain(
        &load("leaf"),
        &[load("inter")],
        &store(),
        &options("example.com").with_max_depth(2),
    );
    assert!(!report.anchored);
}

#[test]
fn trust_store_dedups() {
    let store: TrustStore = [load("root"), load("root"), load("other-root")]
        .into_iter()
        .collect();
    assert_eq!(store.len(), 2);
    assert!(store.contains(&load("root")));
    assert!(!store.contains(&load("inter")));
}

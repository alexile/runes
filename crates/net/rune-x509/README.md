# rune-x509

> X.509 certificate analysis: typed summaries, weak-crypto flags, chain building and path validation, hostname checks

[![crates.io](https://img.shields.io/crates/v/rune-x509)](https://crates.io/crates/rune-x509)
[![docs.rs](https://img.shields.io/docsrs/rune-x509)](https://docs.rs/rune-x509)
[![license](https://img.shields.io/crates/l/rune-x509)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The analysis layer over [`x509-parser`](https://docs.rs/x509-parser) for TLS
auditors, PKI tooling and mTLS middleware:

- **Summary**: subject and issuer, validity, key type and size, signature
  algorithm, SANs, basic constraints, key usage and extended key usage,
  key identifiers, embedded CT SCTs, self-signed detection, SHA-256
  fingerprint.
- **Weak crypto**: MD5/SHA-1 signatures, RSA under 2048 bits, EC under
  256, DSA, leaf validity over 398 days, unhandled critical extensions
  (thresholds in `Policy`).
- **Chain building and path validation** against a `TrustStore`
  ([RFC 5280 §6](https://www.rfc-editor.org/rfc/rfc5280#section-6)):
  depth-first path building over out-of-order and cross-signed chains,
  signatures (via `ring`), validity, CA constraints, `keyUsage`,
  path-length limits, server/client purpose. Every problem is reported as a
  `ChainIssue`: expired, not yet valid, self-signed, untrusted root,
  incomplete chain, bad signature, name mismatch...
- **Host names** via [`rune-host-match`](../../common/rune-host-match)
  (RFC 9525 wildcards), [`rune-idna`](../rune-idna) (UTS #46 for Unicode
  names) and [`rune-psl`](../../common/rune-psl) (no `*.co.uk`); IP
  addresses match `iPAddress` SANs only.

Sans-I/O: bring your own bytes, and pass the validation time (or let it
read the system clock). Not covered: revocation (CRL/OCSP), name
constraints and certificate policies.

## Installation

```toml
[dependencies]
rune-x509 = "0.1"
```

The `rune-x509` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-x509 --features cli
```

## Usage

### Library

```rust
use rune_x509::{Certificate, ChainIssue, TrustStore, VerifyOptions, parse_pem, verify_chain};

fn check(chain_pem: &[u8], roots_pem: &[u8]) -> Result<(), rune_x509::Error> {
    let chain = parse_pem(chain_pem)?;
    let Some((leaf, intermediates)) = chain.split_first() else {
        return Err(rune_x509::Error::NoCertificate);
    };

    let summary = leaf.summary();
    println!("{} ({}, {})", summary.subject, summary.public_key, summary.signature_algorithm);
    for weakness in leaf.weaknesses(&Default::default()) {
        println!("weak: {weakness}");
    }

    let store = TrustStore::from_pem(roots_pem)?;
    let options = VerifyOptions::default().with_hostname("www.example.com");
    let report = verify_chain(leaf, intermediates, &store, &options);
    if !report.is_trusted() {
        for issue in &report.issues {
            if matches!(issue, ChainIssue::NameMismatch { .. }) {
                println!("wrong host");
            }
            println!("{:?}: {issue}", issue.severity());
        }
    }
    Ok(())
}
```

For mutual TLS, validate client certificates with
`VerifyOptions::default().with_purpose(Purpose::ClientAuth)` and no host
name.

### CLI

```bash
# Summarize every certificate in a PEM bundle (or one DER file)
rune-x509 chain.pem

# Validate leaf + intermediates against a root bundle
rune-x509 chain.pem --roots roots.pem --host www.example.com
# ...
# path: CN=www.example.com <- CN=Example CA <- CN=Example Root
# trusted
```

Exit status: 0 trusted (or summary only), 1 not trusted, 2 unreadable input.

## Tests

`tests/fixtures/` holds certificates made by `tests/fixtures/generate.sh`
(OpenSSL 3.4+): a valid chain, wildcard, expired, self-signed, SHA-1
signed, 1024-bit RSA, untrusted root, non-CA issuer and CN-only cases.

## License

MIT

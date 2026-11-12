# rune-dns-records

> Typed parsers and weakness checks for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, CAA, TLSA and DNSSEC records

[![crates.io](https://img.shields.io/crates/v/rune-dns-records)](https://crates.io/crates/rune-dns-records)
[![docs.rs](https://img.shields.io/docsrs/rune-dns-records)](https://docs.rs/rune-dns-records)
[![license](https://img.shields.io/crates/l/rune-dns-records)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

`rune-dns-records` parses the email and DNS security records a domain
publishes into typed values, and reports common weaknesses as typed issues
that convert to [`rune-finding`](../../secops/rune-finding) findings. It does
no I/O: fetch the records with `rune-dns-wire` or any resolver and hand them
over as strings or RDATA.

| Module    | Record                                                    | Specification |
| --------- | --------------------------------------------------------- | ------------- |
| `spf`     | SPF, with the `include`/`redirect` 10-lookup limit        | RFC 7208 |
| `dkim`    | DKIM key records, RSA key size, Ed25519                   | RFC 6376, RFC 8301, RFC 8463 |
| `dmarc`   | DMARC policy, including `np=`                             | RFC 7489, RFC 9091 |
| `mta_sts` | `_mta-sts` record and the HTTPS policy file               | RFC 8461 |
| `tls_rpt` | `_smtp._tls` reporting record                             | RFC 8460 |
| `bimi`    | BIMI assertion record                                     | draft-brand-indicators-for-message-identification |
| `caa`     | CAA properties, presentation format, issuance decision    | RFC 8659 |
| `tlsa`    | DANE TLSA parameters, matching, owner names               | RFC 6698 |
| `dnssec`  | DS/DNSKEY/RRSIG: key tags, DS digests, algorithms, expiry | RFC 4034, RFC 8624 |

Weaknesses flagged include `+all` and `?all` SPF, SPF over the lookup limit
or with include loops, `p=none` DMARC, partial `pct`, DKIM keys under 2048
bits or SHA-1 only, MTA-STS in testing mode, missing CAA, critical unknown
CAA tags, unusable TLSA parameters, deprecated DNSSEC algorithms, SHA-1 DS
digests, DS records that match no key, and expired or expiring signatures.
Each issue has a stable check id (`dns.<kind>`, e.g.
`dns.spf_permissive_all`), a severity, CWE references and a remediation.

## Installation

```toml
[dependencies]
rune-dns-records = "0.1"
```

## Usage

```rust
use rune_dns_records::{IssueKind, RecordKind, dmarc::Dmarc, issues_for, spf::Spf};

// TXT records at example.com and _dmarc.example.com.
let apex = ["google-site-verification=abc", "v=spf1 include:_spf.example.net +all"];
let dmarc = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"];

let mut issues = issues_for(Spf::find(apex), RecordKind::Spf, Spf::issues);
issues.extend(issues_for(Dmarc::find(dmarc), RecordKind::Dmarc, Dmarc::issues));
let kinds: Vec<_> = issues.iter().map(|i| i.kind).collect();
assert_eq!(kinds, [IssueKind::SpfPermissiveAll, IssueKind::DmarcPolicyNone]);

// Map to rune-finding at example.com:53.
let finding = issues[0].to_finding::<()>("example.com");
assert_eq!(finding.check_id, "dns.spf_permissive_all");
```

Count SPF lookups across includes with a closure that returns the SPF
record at a domain (from your resolver, or a map in tests):

```rust
use rune_dns_records::spf::Spf;

let spf: Spf = "v=spf1 include:_spf.example.net -all".parse().unwrap();
let report = spf.count_lookups("example.com", |domain| {
    (domain == "_spf.example.net").then(|| "v=spf1 a mx -all".to_owned())
});
assert_eq!(report.lookups, 3);
assert!(!report.exceeded());
```

Decide whether a CA may issue under a CAA RRset:

```rust
use rune_dns_records::caa::{CaaRecord, permits};

let rrset: Vec<_> = [r#"0 issue "letsencrypt.org""#, r#"0 issuewild ";""#]
    .iter()
    .map(|r| r.parse::<CaaRecord>().unwrap().to_rdata())
    .collect();
assert!(permits(&rrset, "letsencrypt.org", false));
assert!(!permits(&rrset, "letsencrypt.org", true));
```

## Untrusted input

Every parser returns a value or an `Error`, never panics, and bounds its
work: the SPF lookup walk stops fetching once the limit is exceeded and
detects loops, and MTA-STS policy files over 64 KiB are rejected. The crate
is property-tested and tested against RFC examples and real responses captured from a public
resolver.

## License

MIT

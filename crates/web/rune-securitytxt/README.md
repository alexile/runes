# rune-securitytxt

> Parse and validate security.txt files (RFC 9116): fields, expiry, canonical URIs and OpenPGP cleartext signatures

[![crates.io](https://img.shields.io/crates/v/rune-securitytxt)](https://crates.io/crates/rune-securitytxt)
[![docs.rs](https://img.shields.io/docsrs/rune-securitytxt)](https://docs.rs/rune-securitytxt)
[![license](https://img.shields.io/crates/l/rune-securitytxt)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O parser and validator for
[`security.txt` (RFC 9116)](https://www.rfc-editor.org/rfc/rfc9116), the
file at `/.well-known/security.txt` that tells researchers how to report
vulnerabilities.

- **Parse** the way clients should: case-insensitive field names, `LF` or
  `CRLF`, comments, unknown fields kept as extensions, and malformed lines
  listed (with line numbers) instead of failing the parse. Typed accessors
  for every registered field: `Contact` (in order of preference),
  `Expires`, `Encryption`, `Acknowledgments`, `Canonical`, `Policy`,
  `Hiring`, `Preferred-Languages` and `CSAF`.
- **Signatures**: an OpenPGP cleartext signature
  ([RFC 4880 §7](https://www.rfc-editor.org/rfc/rfc4880#section-7)) is
  unwrapped and dash-unescaped. The canonical signed text and the armored
  signature are exposed for verification with your OpenPGP library of
  choice; the crate does not verify them itself. Text outside the signed
  part is an error, since unsigned fields could have been injected.
- **Validate** against the RFC: `Contact` required; exactly one `Expires`,
  an RFC 3339 date-time, not in the past (given the current time) and
  recommended under a year away; URIs well formed and `https://` for web
  URIs; at most one `Preferred-Languages` with valid tags; the retrieval URL
  listed in `Canonical`; a signature, and `Canonical` in signed files.
  `Report::is_valid` says whether the file follows the RFC; a "signed" file
  only has intact signature framing, so verify the signature before trusting
  its contacts.
- **Report** each problem as a `rune_finding::Finding`
  (`securitytxt.<kind>`, with field and line as evidence).

Nothing is fetched and the clock is never read: pass the file text, the
URL it came from and the current time.

## Installation

```toml
[dependencies]
rune-securitytxt = "0.1"
```

The `rune-securitytxt` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-securitytxt --features cli
```

## Usage

### Library

```rust
use rune_finding::Location;
use rune_securitytxt::{Options, SecurityTxt, Timestamp, run};

let text = "\
Contact: mailto:security@example.com
Expires: 2026-12-31T18:37:07Z
Canonical: https://example.com/.well-known/security.txt
";
let doc = SecurityTxt::parse(text).expect("not signed, so it always parses");
assert_eq!(doc.contacts(), ["mailto:security@example.com"]);

let options = Options::default()
    .with_now(Timestamp::parse("2027-01-01T00:00:00Z").expect("valid date-time"))
    .with_retrieved_from("https://example.com/.well-known/security.txt");
let report = run(text, &options);
assert!(!report.is_valid()); // expired
let findings = report.to_findings::<()>(&Location::url("https://example.com/.well-known/security.txt"));
assert!(findings.iter().any(|f| f.check_id == "securitytxt.expired"));
```

### CLI

```bash
curl -s https://example.com/.well-known/security.txt \
  | rune-securitytxt --url https://example.com/.well-known/security.txt
# contact  mailto:security@example.com
# expires  2026-12-31T18:37:07Z
# signed   no
# informational securitytxt.unsigned               The file has no OpenPGP signature, ...
# valid

rune-securitytxt security.txt --now 2027-01-01T00:00:00Z --require-signature
```

The exit status is 0 for a valid file and 1 otherwise.

## License

MIT

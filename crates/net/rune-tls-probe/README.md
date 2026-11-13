# rune-tls-probe

> Read-only TLS server probe over raw handshakes: SSLv3-TLS 1.3 version and cipher-suite enumeration, weak-suite flags, DHE/ECDHE parameters, a Mozilla-profile policy grader and JARM fingerprinting

[![crates.io](https://img.shields.io/crates/v/rune-tls-probe)](https://crates.io/crates/rune-tls-probe)
[![docs.rs](https://img.shields.io/docsrs/rune-tls-probe)](https://docs.rs/rune-tls-probe)
[![license](https://img.shields.io/crates/l/rune-tls-probe)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A TLS auditor built on rustls cannot speak SSL 3.0, TLS 1.0 or TLS 1.1, nor
offer export, NULL, anonymous or RC4 suites, so it cannot report the
problems that matter most on old servers. This crate builds each
`ClientHello` itself with [`rune-tls-hello`](../rune-tls-hello) and reads
the server's `ServerHello` or alert, like testssl.sh and sslyze do:

- **Versions:** SSL 3.0, TLS 1.0, 1.1, 1.2 and 1.3, each probed on its own.
- **Cipher suites:** per version, the IANA registry (334 pre-1.3 suites,
  5 TLS 1.3 suites) is offered in chunks; each accepted suite is removed
  and the rest offered again until the server refuses. Suites come out in
  the server's preference order.
- **Weak suites:** export, NULL, anonymous, RC4, DES/RC2, 64-bit blocks
  (Sweet32), MD5 MAC, no forward secrecy (`weaknesses`).
- **Downgrade protection:** `TLS_FALLBACK_SCSV` (RFC 7507) on a hello at
  the second-newest supported version.
- **Compression** (CRIME) and **secure renegotiation** (RFC 5746).
- **Key exchange:** the Diffie-Hellman prime size and ECDHE curve from the
  `ServerKeyExchange`, and the TLS 1.3 key-share group.
- **Policy grading** (`policy`): every version, suite and key exchange is
  judged good, ok, warn or fail under Mozilla's modern, intermediate or old
  profile, with a reason and a source, and the server gets a grade `A` to
  `F`.
- **JARM fingerprinting** (`jarm`): the ten JARM probe hellos, answer
  parsing and the 62-character fuzzy hash.

It is **read-only**: one connection per hello, closed after the server's
first answer (or, for the key-exchange check, after the server's
`ServerKeyExchange`). No handshake is completed, no key material or application
data is sent (TLS 1.3 hellos carry an empty `key_share`; the server's
`HelloRetryRequest` is the answer). Whether a server allows
client-initiated renegotiation needs a full handshake and is not tested.
Probe only systems you are authorised to assess; scope checks are the
caller's.

| Check id | Severity | When |
| --- | --- | --- |
| `tls.sslv3` | high | SSL 3.0 accepted (POODLE) |
| `tls.tls1_0`, `tls.tls1_1` | medium | deprecated versions accepted (RFC 8996) |
| `tls.no_modern_version` | medium | neither TLS 1.2 nor TLS 1.3 |
| `tls.cipher.null`, `.anon`, `.export`, `.des` | high | such suites accepted |
| `tls.cipher.rc4`, `.sweet32` | medium | such suites accepted |
| `tls.cipher.no_forward_secrecy` | low | static RSA/DH/ECDH suites accepted |
| `tls.compression` | medium | DEFLATE accepted (CRIME) |
| `tls.insecure_renegotiation` | medium | no RFC 5746 confirmation |
| `tls.no_fallback_scsv` | low | downgraded hello with the SCSV accepted |

The policy grader adds `tls.weak_<category>` and `tls.discouraged_<category>`
findings (see below).

## Installation

```toml
[dependencies]
rune-tls-probe = { version = "0.1", features = ["tokio"] }
```

or `cargo add rune-tls-probe --features tokio`. Without `tokio` you get the
sans-I/O pieces only (`Offer`, `ResponseReader`, `Scanner`, `Report`,
`TlsHelloProbe`).

## Usage

Scan over `rune-service-probe`'s tokio runner, which bounds every
connection with its timeouts and read budget:

```rust,no_run
use rune_service_probe::{Options, Runner, Target};
use rune_tls_probe::{ScanOptions, scan};

# async fn demo() -> Result<(), rune_tls_probe::Error> {
let runner = Runner::new(Options::default());
let target = Target::new("legacy.internal.example", 443);
let report = scan(&runner, &target, &ScanOptions::default()).await?;

for version in report.supported_versions() {
    println!("{version}: {:?}", report.version(version).map(|v| &v.cipher_suites));
}
for finding in report.findings(&target) {
    println!("[{:?}] {} {}", finding.severity, finding.check_id, finding.title);
}
# Ok(()) }
```

Or drive the sans-I/O `Scanner` with your own transport: send each
`Offer::to_records`, read the answer with a `ResponseReader`, and
`record` the outcome:

```rust
use rune_tls_hello::ProtocolVersion;
use rune_tls_probe::{ResponseReader, ScanOptions, Scanner};

let mut scanner = Scanner::new(
    ScanOptions::default().with_versions([ProtocolVersion::TLS_1_0]).with_enumerate_ciphers(false),
);
while let Some(offer) = scanner.next_offer() {
    let _hello = offer.to_records([0x42; 32]).unwrap(); // write this to a fresh connection
    let mut reader = ResponseReader::new();
    let outcome = reader.feed(&[21, 3, 1, 0, 2, 2, 70]).unwrap(); // the server's answer
    scanner.record(&outcome);
}
let report = scanner.finish();
assert!(report.supported_versions().is_empty());
```

`TlsHelloProbe` is a single hello as a `rune-service-probe` `ServiceProbe`,
for probe sets and port sweeps.

## Policy grading

`policy::Policy` grades a scan `Report` under one of three profiles that
mirror [Mozilla's server-side TLS configurations](https://wiki.mozilla.org/Security/Server_Side_TLS),
with verdicts taken from [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325)
(BCP 195) and the RFCs it builds on:

| Item | modern | intermediate | old | Source |
| --- | --- | --- | --- | --- |
| SSL 3.0 | fail | fail | fail | RFC 7568 |
| TLS 1.0, 1.1 | fail | fail | warn | RFC 8996 |
| TLS 1.2 | warn | ok | ok | RFC 9325 §3.1 (modern is TLS 1.3 only) |
| TLS 1.3 | good | good | good | RFC 8446 |
| TLS 1.3 not supported | fail | warn | ok | RFC 9325 §3.1 |
| NULL, anonymous, export suites | fail (critical) | fail | fail | RFC 9325 §4.1 |
| DES, RC2 | fail (high) | fail | fail | RFC 9325 §4.1 |
| RC4 | fail | fail | fail | RFC 7465 |
| IDEA, HMAC-MD5 | fail | fail | fail | RFC 9325 §4.1, RFC 6151 |
| 3DES | fail | fail | warn | RFC 9325 §4.1 (Sweet32, under 128-bit) |
| static RSA/DH/ECDH (no forward secrecy) | fail | fail | warn | RFC 9325 §4.1 |
| CBC with SHA-1 or SHA-2 MAC | fail | warn | ok | RFC 9325 §4.2 |
| CCM_8 (64-bit tag) | warn | warn | warn | RFC 8446 |
| ECDHE + AES-GCM / ChaCha20-Poly1305 | ok | good | good | Mozilla |
| DHE prime < 1024 bits | fail (high) | fail | fail | RFC 9325 §4.3 (Logjam) |
| DHE prime < 2048 bits | fail | fail | warn | RFC 9325 §4.3 |
| no forward-secret suite at all | fail | fail | warn | RFC 9325 §4.1 |
| compression, no secure renegotiation | fail | fail | fail | RFC 9325 §3.3, §3.5 |
| `TLS_FALLBACK_SCSV` not honoured | warn | warn | warn | RFC 7507 |

| Grade | When |
| --- | --- |
| F | a critical failure (NULL, anonymous or export suites), or no TLS at all |
| D | a high-severity failure: SSL 3.0, DES/RC2, a DH prime under 1024 bits |
| C | any other failure: legacy versions, RC4, 3DES, static RSA, small DH, compression... |
| B | only warnings |
| A | nothing the policy objects to |

`allow`, `deny`, `set` and `allow_only` add your own rules on top, matched
against item names (`TLSv1.0`, IANA suite names, `DHE 1024-bit`, `ECDHE
secp256r1`...) with `*` wildcards. The report lists every assessment, the
grade, its main reason and every reason that lowered it, and turns into
`rune-finding` findings:

| Check id | When |
| --- | --- |
| `tls.weak_<category>` | items at fail; severity of the worst |
| `tls.discouraged_<category>` | items at warn; low |

`<category>` is `protocol`, `cipher`, `key_exchange` or `configuration`.
`Report::service_info` also carries `tls.grade`, `tls.grade_reason` and
`tls.policy` under the default (intermediate) policy.

```rust
use rune_service_probe::Target;
use rune_tls_hello::{CipherSuite, ProtocolVersion};
use rune_tls_probe::policy::{Category, Grade, Policy};
use rune_tls_probe::{Report, VersionResult};

let mut scan = Report::default(); // normally from `scan` or a `Scanner`
let mut tls12 = VersionResult::new(ProtocolVersion::TLS_1_2);
tls12.supported = true;
tls12.cipher_suites = vec![CipherSuite(0xc02f), CipherSuite(0xc013)];
scan.versions.push(tls12);

let report = Policy::intermediate().grade(&scan);
assert_eq!(report.grade, Grade::B); // CBC is discouraged
println!("{}: {}", report.grade, report.grade_reason);

let strict = Policy::intermediate().deny(Category::Cipher, "*_CBC_*");
assert_eq!(strict.grade(&scan).grade, Grade::C);
for finding in strict.grade(&scan).findings(&Target::new("app.example", 443)) {
    println!("{} {:?}: {}", finding.check_id, finding.severity, finding.title);
}
```

Suites come out of the scan in chunks, so their order is only the server's
preference within each chunk; the grader does not judge preference order.

## JARM

[JARM](https://github.com/salesforce/jarm) is an active TLS server
fingerprint by Salesforce (BSD 3-Clause licence). `jarm` is an independent
implementation of its published design: the same ten hellos (TLS 1.1 to
1.3, forward, reverse, top-half, bottom-half and middle-out cipher orders,
GREASE, normal and rare ALPN lists, `supported_versions` variants) and the
same fuzzy hash, so fingerprints match those of other JARM tools for the
same server answers.

```rust,no_run
use rune_service_probe::{Options, Runner, Target};
use rune_tls_probe::jarm;

# async fn demo() -> Result<(), rune_tls_probe::Error> {
let runner = Runner::new(Options::default());
let fp = jarm::fingerprint(&runner, &Target::new("app.example", 443)).await?;
println!("{}", fp.hash()); // 62 hex characters, all zeros when nothing answered
println!("{}", fp.raw());  // the unhashed answers
# Ok(()) }
```

The sans-I/O parts work without tokio: `PROBES[i].client_hello(host, seed)`
builds a hello, `jarm::ResponseReader` / `Entry::parse` reads the answer,
`Fingerprint::hash` and `jarm::hash` hash, and `jarm::decode` reads the
selected suite and version per probe back out of any fingerprint:

```rust
use rune_tls_hello::CipherSuite;

let d = rune_tls_probe::jarm::decode("27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d").unwrap();
assert_eq!(d.answers[0].unwrap().cipher_suite, Some(CipherSuite(0xc02b)));
```

JARM hellos carry a random 32-byte X25519 key share, as the design
requires; nothing is derived from it and the connection closes after the
server's first answer.

## Limits

Every connection runs under the `rune-service-probe` runner's connect, I/O
and total timeouts and its read budget. On top of that the scan's response
reader stops after 256 KiB (enough to read past a certificate chain to the
`ServerKeyExchange`) and JARM's after 32 KiB, and a scan sends at most
`ScanOptions::max_attempts` hellos. Malformed or hostile answers become
`Outcome::NotTls` or `Entry::NoAnswer`; nothing in the readers panics
(property-tested over random and mutated server flights).

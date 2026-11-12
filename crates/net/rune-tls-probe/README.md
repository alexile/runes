# rune-tls-probe

> Read-only TLS server probe over raw handshakes: SSLv3-TLS 1.3 version and cipher-suite enumeration, weak-suite flags, fallback SCSV, compression, secure renegotiation

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

It is **read-only**: one connection per hello, closed after the server's
first answer. No handshake is completed, no key material or application
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

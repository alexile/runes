# rune-probe-mail

> Read-only SMTP/SMTPS and FTP/FTPS probes: greeting banner, EHLO and FEAT capabilities, STARTTLS and AUTH TLS support

[![crates.io](https://img.shields.io/crates/v/rune-probe-mail)](https://crates.io/crates/rune-probe-mail)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-mail)](https://docs.rs/rune-probe-mail)
[![license](https://img.shields.io/crates/l/rune-probe-mail)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

SMTP and FTP modules for [`rune-service-probe`](../rune-service-probe). Both
implement its `ServiceProbe` trait and share a sans-I/O reply parser
(`parse_reply`) for the `ddd-` / `ddd ` multi-line reply format.

| Probe                | Dialogue                                    | Default ports |
| -------------------- | ------------------------------------------- | ------------- |
| `SmtpProbe::new()`   | greeting, `EHLO` (or `HELO`), `QUIT`        | 25, 587       |
| `SmtpProbe::smtps()` | the same, over a TLS stream you opened      | 465           |
| `FtpProbe::new()`    | greeting, `FEAT`, `SYST`, `QUIT`            | 21            |
| `FtpProbe::ftps()`   | the same, over a TLS stream you opened      | 990           |

They are read-only: no login (not even anonymous FTP), no `MAIL`/`RCPT`,
no `VRFY`/`EXPN`. `with_starttls_check(true)` / `with_auth_tls_check(true)`
additionally send `STARTTLS` / `AUTH TLS` to confirm the upgrade and hang up
before the TLS handshake.

Reported: product and version from the greeting (Postfix, Exim, Sendmail,
Microsoft SMTP, OpenSMTPD, vsFTPd, ProFTPD, Pure-FTPd, FileZilla Server, …),
the banner, `EHLO` extensions or `FEAT` features as capabilities, TLS support
(`Optional`, `NotOffered`, `Implicit`), and details such as
`smtp.auth_mechanisms`, `smtp.size` and `ftp.system`.

| Check id                 | When                                                        |
| ------------------------ | ----------------------------------------------------------- |
| `smtp.starttls_missing`  | plaintext SMTP, `EHLO` works, no `STARTTLS`                 |
| `smtp.auth_before_tls`   | `AUTH PLAIN`/`LOGIN` advertised before TLS                  |
| `smtp.user_enumeration`  | `VRFY` or `EXPN` advertised                                 |
| `ftp.tls_not_offered`    | plaintext FTP without `AUTH TLS`                            |
| `ftp.backdoored_version` | banner names vsFTPd 2.3.4 or ProFTPD 1.3.3c                 |

For SMTPS and FTPS the ids start `smtps.` / `ftps.`.

## Installation

```toml
[dependencies]
rune-probe-mail = "0.1"
rune-service-probe = { version = "0.1", features = ["tokio"] }
```

## Usage

```rust,no_run
use rune_probe_mail::{FtpProbe, SmtpProbe};
use rune_service_probe::{Options, Runner, Target};

# async fn demo() -> Result<(), rune_service_probe::Error> {
let runner = Runner::new(Options::default());
let smtp = SmtpProbe::new().with_helo_name("scanner.example.org");
let info = runner.probe(&smtp, &Target::new("mx.example.org", 25)).await?;
println!("{:?} {:?} tls={:?}", info.product, info.version, info.tls);

let info = runner.probe(&FtpProbe::new(), &Target::new("files.example.org", 21)).await?;
for finding in &info.findings {
    println!("{} {:?}: {}", finding.check_id, finding.severity, finding.title);
}
# Ok(())
# }
```

Parsing a captured reply:

```rust
use rune_probe_mail::parse_reply;

let (reply, _) = parse_reply(b"250-mx.test\r\n250 STARTTLS\r\n").unwrap().unwrap();
assert_eq!(reply.code, 250);
assert_eq!(reply.lines, ["mx.test", "STARTTLS"]);
```

## License

MIT

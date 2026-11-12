# rune-port-scan

> Rate-limited async TCP connect scanner with port-list parsing, banner grabbing and service and OS hints

[![crates.io](https://img.shields.io/crates/v/rune-port-scan)](https://crates.io/crates/rune-port-scan)
[![docs.rs](https://img.shields.io/docsrs/rune-port-scan)](https://docs.rs/rune-port-scan)
[![license](https://img.shields.io/crates/l/rune-port-scan)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The scanning engine behind an nmap-style connect scanner, without the
tool around it:

- **Port lists**: `PortSet` parses `22,80,443,8000-8100,top-20`, `1024-`,
  `-1023` and `all`, keeps first-seen order without duplicates, and
  formats back to a canonical list.
- **Service hints**: the customary service for a port, and service,
  product and version from server-first banners (SSH, HTTP `Server:`,
  FTP, SMTP, POP3, IMAP, VNC, rsync, Redis, MySQL/MariaDB, Telnet, ...).
- **OS hints**: a coarse OS family (Linux, Windows, BSD, macOS) from
  banner text, with a per-host majority vote.
- **Scanner** (`tokio` feature): full TCP connects (no raw sockets, no
  privileges) with a semaphore-bounded worker pool, an evenly paced
  attempt rate, connect and banner timeouts, nmap-like timing presets and
  a cap on the number of host/port pairs per scan. It only ever reads
  from open ports.

Hint and parsing code is sans-I/O, bounded and safe against hostile
input.

## Authorised use only

Port scanning systems you do not own or have permission to test may be
illegal. The scanner applies no scope policy and resolves no names: it
connects to exactly the addresses you hand it. Resolve and scope-check
targets first, keep the rate polite, and use `Options::max_targets` as a
guard against accidental sweeps.

## Installation

```toml
[dependencies]
rune-port-scan = { version = "0.1", features = ["tokio"] }
```

Features:

| Feature | Enables                                                            |
| ------- | ------------------------------------------------------------------ |
| `tokio` | `Scanner`, the async connect scanner                               |
| `serde` | `Serialize` / `Deserialize` for port sets, hints and scan reports  |

## Usage

Port lists and hints, without the network:

```rust
use rune_port_scan::{PortSet, banner_hint, os_hint, OsHint};

let ports: PortSet = "22,80,8000-8002,top-5".parse()?;
assert_eq!(ports.to_string(), "22,80,8000-8002,23,443,21");

let hint = banner_hint(b"220 (vsFTPd 3.0.5)\r\n").unwrap();
assert_eq!((hint.service.as_str(), hint.version.as_deref()), ("ftp", Some("3.0.5")));
assert_eq!(os_hint(b"SSH-2.0-OpenSSH_9.2p1 Debian-2"), Some(OsHint::Linux));
# Ok::<(), rune_port_scan::Error>(())
```

Scanning (feature `tokio`):

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};
use rune_port_scan::{Options, PortSet, Scanner, Timing};

# async fn demo() -> Result<(), rune_port_scan::Error> {
let scanner = Scanner::new(
    Options::timing(Timing::Polite)
        .with_rate(Some(100))
        .with_banners(true),
);
let hosts = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
let report = scanner.scan(&hosts, &"top-100".parse::<PortSet>()?).await?;
for port in report.open() {
    println!("{} {:?} {:?}", port.addr, port.service, port.banner_text());
}
println!("os: {:?}", report.os_hint(hosts[0]));
# Ok(())
# }
```

## License

MIT

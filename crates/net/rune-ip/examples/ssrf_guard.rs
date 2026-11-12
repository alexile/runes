//! An SSRF guard: before an outbound request, resolve the host and refuse to
//! connect unless every resolved address is globally reachable.
//!
//! The guard sees through IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible,
//! NAT64 (`64:ff9b::/96`) and 6to4 wrappers, so the cloud metadata endpoint
//! cannot be reached as `::ffff:169.254.169.254`.
//!
//! Run with `cargo run -p rune-ip --example ssrf_guard`.

// Examples report on stdout.
#![allow(clippy::print_stdout)]

use std::fmt;
use std::net::IpAddr;

use rune_ip::{Category, Scope};

/// Why a destination was refused.
#[derive(Debug)]
struct Rejected {
    ip: IpAddr,
    category: Category,
    scope: Scope,
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing {} ({} address, {} scope)",
            self.ip, self.category, self.scope
        )
    }
}

/// Allows `ip` only if it is globally reachable unicast.
///
/// In a real client, call this for *every* address the resolver returns and
/// then connect to the checked address itself (not the host name again), so
/// that DNS rebinding cannot swap it between check and use.
fn check_destination(ip: IpAddr) -> Result<IpAddr, Rejected> {
    if rune_ip::is_global(ip) {
        Ok(ip)
    } else {
        Err(Rejected {
            ip,
            category: rune_ip::category(ip),
            scope: rune_ip::scope(ip),
        })
    }
}

fn main() -> Result<(), std::net::AddrParseError> {
    let candidates = [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.5",
        "169.254.169.254",
        "100.100.100.200",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "::ffff:127.0.0.1",
        "::127.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::",
    ];
    for text in candidates {
        let ip: IpAddr = text.parse()?;
        match check_destination(ip) {
            Ok(ip) => println!("allow  {ip}"),
            Err(rejected) => println!("deny   {rejected}"),
        }
    }
    Ok(())
}

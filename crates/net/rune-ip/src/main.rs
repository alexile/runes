//! `rune-ip` command-line tool: classify IPv4/IPv6 addresses per the IANA
//! special-purpose registries.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::ExitCode;

use clap::Parser;

/// Classify IP addresses: category, scope, global reachability, bogon status
/// and the matching IANA special-purpose block.
#[derive(Parser)]
#[command(name = "rune-ip", version, about)]
struct Cli {
    /// Addresses to classify.
    #[arg(required = true)]
    addrs: Vec<IpAddr>,
    /// Exit with status 1 unless every address is globally reachable.
    #[arg(long)]
    require_global: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut all_global = true;
    for &ip in &cli.addrs {
        let global = rune_ip::is_global(ip);
        all_global &= global;
        let mut line = format!(
            "{ip}\tcategory={} scope={} global={global} bogon={}",
            rune_ip::category(ip),
            rune_ip::scope(ip),
            rune_ip::is_bogon(ip),
        );
        let canonical = rune_ip::canonical(ip);
        if canonical != ip {
            let _ = write!(line, " canonical={canonical}");
        }
        if let IpAddr::V6(v6) = ip
            && let Some(e) = rune_ip::embedded_ipv4(v6)
        {
            let _ = write!(line, " embedded={}({:?})", e.addr, e.kind);
        }
        if let Some(block) = rune_ip::lookup(canonical) {
            let _ = write!(line, " block={block} ({}; {})", block.name(), block.rfc());
        }
        println!("{line}");
    }
    if cli.require_global && !all_global {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

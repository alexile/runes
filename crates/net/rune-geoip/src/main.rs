//! `rune-geoip` command-line tool: look addresses up in a `MaxMind` DB
//! (GeoLite2/GeoIP2, DB-IP) file and print the records as JSON.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_geoip::Reader;

/// Look IP addresses up in a `MaxMind` DB file. Prints one line per address:
/// the address, the matching network and the record as JSON (or `-` when
/// the database has no record).
#[derive(Parser)]
#[command(name = "rune-geoip", version, about)]
struct Cli {
    /// The .mmdb file.
    database: PathBuf,
    /// Addresses to look up.
    ips: Vec<IpAddr>,
    /// Print the database metadata first.
    #[arg(long)]
    metadata: bool,
    /// Print every network in the database instead of looking addresses up.
    #[arg(long)]
    dump: bool,
}

fn run(cli: &Cli) -> Result<(), String> {
    let bytes =
        std::fs::read(&cli.database).map_err(|e| format!("{}: {e}", cli.database.display()))?;
    let reader = Reader::from_source(bytes).map_err(|e| e.to_string())?;
    if cli.metadata {
        let m = reader.metadata();
        println!(
            "type={} ip_version={} record_size={} nodes={} build_epoch={} languages={}",
            m.database_type,
            m.ip_version,
            m.record_size,
            m.node_count,
            m.build_epoch,
            m.languages.join(",")
        );
    }
    if cli.dump {
        for entry in reader.networks() {
            let entry = entry.map_err(|e| e.to_string())?;
            println!("{}\t{}", entry.network, entry.data);
        }
    }
    for ip in &cli.ips {
        match reader.lookup(*ip) {
            Ok(Some(entry)) => println!("{ip}\t{}\t{}", entry.network, entry.data),
            Ok(None) => println!("{ip}\t-\t-"),
            Err(err) => return Err(format!("{ip}: {err}")),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

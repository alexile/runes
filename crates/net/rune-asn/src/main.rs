//! `rune-asn` command-line tool: load BGP/RIR dataset files and look up the
//! origin AS of addresses or the announced prefixes of ASes.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use rune_asn::{
    Asn, AsnDb, Error, parse_asnames, parse_bgpdump, parse_delegated, parse_ip2asn, parse_pfx2as,
    parse_riswhois,
};

/// Look up IP→ASN and ASN→prefixes in BGP/RIR dataset files. Each query is
/// an IP address (prints the matching prefix and origins) or an ASN such as
/// `AS13335` (prints its prefixes). Bad lines in the files are skipped.
#[derive(Parser)]
#[command(name = "rune-asn", version, about)]
struct Cli {
    /// CAIDA `RouteViews` `pfx2as` file (uncompressed).
    #[arg(long)]
    pfx2as: Vec<PathBuf>,
    /// RIPE RIS riswhoisdump file (uncompressed).
    #[arg(long)]
    riswhois: Vec<PathBuf>,
    /// `bgpdump -m` output of an MRT RIB or update file.
    #[arg(long)]
    bgpdump: Vec<PathBuf>,
    /// iptoasn.com ip2asn TSV file (uncompressed).
    #[arg(long)]
    ip2asn: Vec<PathBuf>,
    /// RIR delegated(-extended) statistics file.
    #[arg(long)]
    delegated: Vec<PathBuf>,
    /// AS-name list (`13335 CLOUDFLARENET, US`).
    #[arg(long)]
    asnames: Vec<PathBuf>,
    /// IP addresses or ASNs to look up.
    #[arg(required = true)]
    queries: Vec<String>,
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Count the `Err` items of a parse while passing the `Ok` ones through.
fn ok<T>(items: impl Iterator<Item = Result<T, Error>>, skipped: &mut usize) -> Vec<T> {
    items
        .filter_map(|r| r.inspect_err(|_| *skipped += 1).ok())
        .collect()
}

fn load(cli: &Cli) -> Result<(AsnDb, usize), String> {
    let mut db = AsnDb::new();
    let mut skipped = 0;
    for path in &cli.pfx2as {
        db.extend(ok(parse_pfx2as(&read(path)?), &mut skipped));
    }
    for path in &cli.riswhois {
        db.extend(ok(parse_riswhois(&read(path)?), &mut skipped));
    }
    for path in &cli.bgpdump {
        db.extend(ok(parse_bgpdump(&read(path)?), &mut skipped));
    }
    for path in &cli.ip2asn {
        for rec in ok(parse_ip2asn(&read(path)?), &mut skipped) {
            db.insert_range(&rec);
        }
    }
    for path in &cli.delegated {
        for rec in ok(parse_delegated(&read(path)?), &mut skipped) {
            db.insert_delegation(&rec);
        }
    }
    for path in &cli.asnames {
        for name in ok(parse_asnames(&read(path)?), &mut skipped) {
            db.insert_name(name);
        }
    }
    Ok((db, skipped))
}

fn describe(db: &AsnDb, asn: Asn) -> String {
    let mut out = asn.to_string();
    if let Some(info) = db.info(asn) {
        if let Some(name) = info.name {
            let _ = write!(out, " {name}");
        }
        if let Some(cc) = info.country {
            let _ = write!(out, " [{cc}]");
        }
    }
    out
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (db, skipped) = match load(&cli) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    if skipped > 0 {
        eprintln!("warning: skipped {skipped} unparseable lines");
    }
    let mut status = ExitCode::SUCCESS;
    for query in &cli.queries {
        if let Ok(ip) = query.parse::<IpAddr>() {
            match db.lookup(ip) {
                Some(hit) => {
                    let origins: Vec<_> = hit.origins.iter().map(|&a| describe(&db, a)).collect();
                    println!("{ip}\t{}\t{}", hit.prefix, origins.join(", "));
                }
                None => println!("{ip}\t-\tnot announced"),
            }
        } else if let Ok(asn) = query.parse::<Asn>() {
            println!("{}", describe(&db, asn));
            for prefix in db.prefixes(asn) {
                println!("  {prefix}");
            }
        } else {
            eprintln!("error: {query:?} is neither an IP address nor an ASN");
            status = ExitCode::FAILURE;
        }
    }
    status
}

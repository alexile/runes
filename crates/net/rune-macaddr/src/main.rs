//! `rune-macaddr` command-line tool: normalise and classify MAC addresses,
//! and look up their vendor in IEEE registry files.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_macaddr::{Case, Eui64, MacAddr, Notation, OuiDb, well_known};

/// Output notation.
#[derive(Clone, Copy, ValueEnum)]
enum Style {
    Colon,
    Hyphen,
    Dot,
    Bare,
}

/// Normalise and classify MAC addresses (EUI-48/EUI-64) and look up their
/// vendor.
#[derive(Parser)]
#[command(name = "rune-macaddr", version, about)]
struct Cli {
    /// Addresses in colon, hyphen, dot or bare-hex notation.
    #[arg(required = true)]
    addresses: Vec<String>,
    /// Registry file to load for vendor lookup (IEEE oui.csv/oui.txt,
    /// mam/oui36/iab/cid variants, or Wireshark manuf). Repeatable.
    #[arg(long = "oui", value_name = "FILE")]
    oui: Vec<std::path::PathBuf>,
    /// Output notation.
    #[arg(long, value_enum, default_value_t = Style::Colon)]
    notation: Style,
    /// Print hex digits in upper case.
    #[arg(long)]
    upper: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut db = OuiDb::new();
    for path in &cli.oui {
        let loaded = std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                db.load(&String::from_utf8_lossy(&bytes))
                    .map_err(|e| e.to_string())
            });
        if let Err(err) = loaded {
            eprintln!("error: {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
    }
    let notation = match cli.notation {
        Style::Colon => Notation::Colon,
        Style::Hyphen => Notation::Hyphen,
        Style::Dot => Notation::Dot,
        Style::Bare => Notation::Bare,
    };
    let case = if cli.upper { Case::Upper } else { Case::Lower };
    let mut status = ExitCode::SUCCESS;
    for input in &cli.addresses {
        let (text, flags, vendor, known) = if let Ok(mac) = input.parse::<MacAddr>() {
            (
                mac.format(notation, case),
                [mac.is_multicast(), mac.is_local()],
                db.lookup(&mac),
                well_known(&mac).map(|w| w.name),
            )
        } else if let Ok(eui) = input.parse::<Eui64>() {
            (
                eui.format(notation, case),
                [eui.is_multicast(), eui.is_local()],
                db.lookup_eui64(&eui),
                eui.to_mac().as_ref().and_then(well_known).map(|w| w.name),
            )
        } else {
            eprintln!("error: {input}: not an EUI-48 or EUI-64 address");
            status = ExitCode::FAILURE;
            continue;
        };
        let [multicast, local] = flags;
        let kind = if multicast { "multicast" } else { "unicast" };
        let admin = if local { "local" } else { "universal" };
        let mut line = format!("{text}\t{kind}\t{admin}");
        if let Some(known) = known {
            line.push('\t');
            line.push_str(known);
        }
        if let Some(record) = vendor {
            line.push('\t');
            line.push_str(&record.organization);
        }
        println!("{line}");
    }
    status
}

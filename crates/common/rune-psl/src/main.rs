//! `rune-psl` command-line tool: public suffix and registrable domain of
//! each host name given.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_psl::{List, Section};

/// Print the public suffix and registrable domain (eTLD+1) of host names.
///
/// One line per host, tab-separated: the normalized host, its public
/// suffix, its registrable domain (`-` if it is a public suffix) and the
/// section of the deciding rule (`icann`, `private` or `unlisted`).
#[derive(Parser)]
#[command(name = "rune-psl", version, about, long_about = None)]
struct Cli {
    /// Host names to look up.
    #[arg(required = true)]
    hosts: Vec<String>,
    /// Ignore the private section (`github.io`, `blogspot.com`).
    #[arg(long)]
    icann_only: bool,
    /// Use this `public_suffix_list.dat` instead of the embedded list.
    #[arg(long, value_name = "FILE")]
    list: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let list = match &cli.list {
        None => List::embedded(),
        Some(path) => match std::fs::read_to_string(path).map(|text| List::parse(&text)) {
            Ok(Ok(list)) => list,
            Ok(Err(err)) => {
                eprintln!("error: {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
            Err(err) => {
                eprintln!("error: {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
        },
    };
    let list = list.with_private_rules(!cli.icann_only);
    let mut status = ExitCode::SUCCESS;
    for host in &cli.hosts {
        match list.lookup(host) {
            Ok(domain) => {
                let section = match domain.section() {
                    Some(Section::Icann) => "icann",
                    Some(Section::Private) => "private",
                    _ => "unlisted",
                };
                println!(
                    "{domain}\t{}\t{}\t{section}",
                    domain.public_suffix(),
                    domain.registrable_domain().unwrap_or("-"),
                );
            }
            Err(err) => {
                eprintln!("error: {host}: {err}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

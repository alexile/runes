//! `rune-cve` command-line tool: lists the CVEs in NVD JSON files that
//! affect a product, given as a CPE name.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::Parser;
use rune_cve::{Cpe, CveIndex, NvdFeed};

/// List the CVEs in NVD CVE API 2.0 JSON files (API pages or
/// nvdcve-2.0-*.json feeds) that affect a product.
#[derive(Parser)]
#[command(name = "rune-cve", version, about)]
struct Cli {
    /// The product, as a CPE 2.3 name or CPE 2.2 URI, e.g.
    /// cpe:2.3:a:apache:log4j:2.14.1
    cpe: String,
    /// NVD JSON files to search.
    #[arg(required = true)]
    feeds: Vec<std::path::PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let target: Cpe = cli.cpe.parse()?;
    let mut cves = Vec::new();
    for path in &cli.feeds {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        cves.extend(
            NvdFeed::from_json(&bytes)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .into_cves(),
        );
    }
    let index = CveIndex::new(cves);
    for cve in index.lookup(&target) {
        let score = cve.metrics.preferred().map_or_else(
            || "-".to_owned(),
            |m| format!("{:.1}", m.cvss_data.base_score),
        );
        let kev = if cve.is_known_exploited() { " KEV" } else { "" };
        println!("{}\t{score}{kev}", cve.id);
    }
    Ok(())
}

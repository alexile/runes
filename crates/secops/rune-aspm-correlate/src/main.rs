//! `rune-aspm-correlate` command-line tool: correlate SARIF logs and DAST
//! findings into one risk view.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_aspm_correlate::{Batch, Options, Route};
use rune_finding::Finding;

/// Correlate SAST and DAST findings into one risk view (JSON or SARIF on
/// stdout).
#[derive(Parser)]
#[command(name = "rune-aspm-correlate", version, about)]
struct Cli {
    /// SARIF 2.1.0 log to ingest (repeatable).
    #[arg(long = "sarif", value_name = "FILE")]
    sarif: Vec<PathBuf>,
    /// Native findings: TOOL=FILE, FILE a JSON array of rune-finding
    /// findings (repeatable).
    #[arg(long = "findings", value_name = "TOOL=FILE")]
    findings: Vec<String>,
    /// Routes file: a JSON array of `{"pattern","file","name"?,"host"?,"lines"?}`.
    #[arg(long, value_name = "FILE")]
    routes: Option<PathBuf>,
    /// One route: PATTERN=FILE (repeatable).
    #[arg(long = "route", value_name = "PATTERN=FILE")]
    route: Vec<String>,
    /// Keep results with an accepted suppression.
    #[arg(long)]
    keep_suppressed: bool,
    /// Write SARIF 2.1.0 instead of the report JSON.
    #[arg(long)]
    output_sarif: bool,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    let mut options = Options::default().with_keep_suppressed(cli.keep_suppressed);
    if let Some(path) = &cli.routes {
        let routes: Vec<Route> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        options = options.with_routes(routes);
    }
    for spec in &cli.route {
        let (pattern, file) = spec
            .split_once('=')
            .ok_or_else(|| format!("--route `{spec}`: expected PATTERN=FILE"))?;
        options = options.with_route(Route::new(pattern, file)?);
    }

    let mut batch = Batch::new();
    for path in &cli.sarif {
        batch
            .add_sarif_json(&std::fs::read_to_string(path)?)
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    for spec in &cli.findings {
        let (tool, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--findings `{spec}`: expected TOOL=FILE"))?;
        let findings: Vec<Finding> = serde_json::from_str(&std::fs::read_to_string(path)?)
            .map_err(|err| format!("{path}: {err}"))?;
        batch.add_findings(tool, findings);
    }

    let report = batch.correlate(&options);
    if cli.output_sarif {
        let options = rune_sarif::Options::default().with_tool_name("rune-aspm-correlate");
        Ok(report.to_sarif(&options).to_json_pretty()?)
    } else {
        Ok(serde_json::to_string_pretty(&report)?)
    }
}

//! `rune-leak` command-line tool: scan source trees for hardcoded secrets, API keys, and tokens — combines regex patterns with entropy heuristics.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_leak::{LeakScanner, ScanOptions, Severity, default_rules, rules_from_toml};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

/// Scan source trees for hardcoded secrets, API keys, and credentials.
#[derive(Parser)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
#[command(name = "rune-leak", version, author)]
struct Args {
    /// Files or directories to scan. Use `-` for stdin.
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

    /// Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL).
    #[arg(long, default_value = "HIGH")]
    min_severity: String,

    /// Include Info-severity findings (IPs, emails, UUIDs).
    #[arg(long)]
    include_info: bool,

    /// Minimum entropy threshold for base64 matches.
    #[arg(long, default_value_t = 4.5)]
    min_base64_entropy: f64,

    /// Suppress file paths in output (useful for CI).
    #[arg(long)]
    no_path: bool,

    /// Use the ruleset engine (stable rule ids, redacted output).
    #[arg(long)]
    ruleset: bool,

    /// Add rules from a TOML file (`[[rules]]` tables). Implies `--ruleset`.
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,

    /// Also scan git history (up to `--max-commits`). Implies `--ruleset`.
    #[arg(long)]
    git_history: bool,

    /// Commits walked back from HEAD with `--git-history`.
    #[arg(long, default_value_t = 1000)]
    max_commits: usize,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.ruleset || args.rules.is_some() || args.git_history {
        return run_ruleset(&args);
    }

    let mut scanner = LeakScanner::new().min_base64_entropy(args.min_base64_entropy);
    if args.include_info {
        scanner = scanner.with_info_findings();
    }

    let min_sev = parse_severity(&args.min_severity);

    let mut all_leaks = Vec::new();
    let mut had_error = false;

    for path in &args.paths {
        if path.as_os_str() == "-" {
            let mut buf = String::new();
            if io::stdin().read_to_string(&mut buf).is_ok() {
                all_leaks.extend(scanner.scan_str(&buf));
            }
        } else if path.is_dir() {
            match scanner.scan_dir(path) {
                Ok(leaks) => all_leaks.extend(leaks),
                Err(e) => {
                    eprintln!("error: {}: {e}", path.display());
                    had_error = true;
                }
            }
        } else {
            match scanner.scan_file(path) {
                Ok(leaks) => all_leaks.extend(leaks),
                Err(e) => {
                    eprintln!("error: {}: {e}", path.display());
                    had_error = true;
                }
            }
        }
    }

    let filtered: Vec<_> = all_leaks.iter().filter(|l| l.severity >= min_sev).collect();

    for leak in &filtered {
        let location = if args.no_path {
            format!("line {}", leak.line_number)
        } else if let Some(file) = &leak.file {
            format!("{}:{}", file.display(), leak.line_number)
        } else {
            format!("line {}", leak.line_number)
        };
        println!(
            "[{severity}] {location}  {category}  entropy={entropy:.2}",
            severity = leak.severity,
            category = leak.category,
            entropy = leak.entropy,
        );
        println!("  {}", leak.line.trim());
        println!();
    }

    if !filtered.is_empty() {
        eprintln!("{} leak(s) found", filtered.len());
        return ExitCode::FAILURE;
    }

    if had_error {
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Ruleset mode: rule ids, `rune_finding` severities and redacted secrets.
fn run_ruleset(args: &Args) -> ExitCode {
    let mut rules = default_rules();
    if let Some(file) = &args.rules {
        let loaded = std::fs::read_to_string(file)
            .map_err(|e| e.to_string())
            .and_then(|text| rules_from_toml(&text).map_err(|e| e.to_string()));
        match loaded {
            Ok(extra) => rules.extend(extra),
            Err(e) => {
                eprintln!("error: {}: {e}", file.display());
                return ExitCode::FAILURE;
            }
        }
    }
    let min_sev: rune_finding::Severity = parse_severity(&args.min_severity).into();
    let mut found = 0usize;
    let mut had_error = false;
    for path in &args.paths {
        let options = ScanOptions::new(path)
            .with_rules(rules.clone())
            .with_scan_git_history(args.git_history)
            .with_max_commits(args.max_commits);
        let report = match rune_leak::run(&options) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                had_error = true;
                continue;
            }
        };
        for note in &report.notes {
            eprintln!("note: {note}");
        }
        for finding in report.findings.iter().filter(|f| f.severity >= min_sev) {
            found += 1;
            let location = match &finding.location {
                rune_finding::Location::File {
                    path: file,
                    start_line,
                    ..
                } if !args.no_path => {
                    let shown = if path.is_dir() {
                        path.join(file)
                    } else {
                        path.clone()
                    };
                    format!("{}:{}", shown.display(), start_line.unwrap_or(0))
                }
                rune_finding::Location::File { start_line, .. } => {
                    format!("line {}", start_line.unwrap_or(0))
                }
                other => format!("{other:?}"),
            };
            println!(
                "[{}] {location}  {}  {}",
                finding.severity.as_str().to_uppercase(),
                finding.check_id,
                finding.title
            );
            for evidence in &finding.evidence {
                println!("  {}: {}", evidence.label, evidence.snippet);
            }
            println!();
        }
    }
    if found > 0 {
        eprintln!("{found} secret(s) found");
        return ExitCode::FAILURE;
    }
    if had_error {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "INFO" => Severity::Info,
        "LOW" => Severity::Low,
        "MEDIUM" | "MED" => Severity::Medium,
        "CRITICAL" | "CRIT" => Severity::Critical,
        // "HIGH" and anything unrecognised.
        _ => Severity::High,
    }
}

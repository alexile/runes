//! `rune-payload-encode` command-line tool: print WAF-evasion variants of a
//! payload, one per line as `technique<TAB>payload`.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::Parser;
use rune_payload_encode::{Context, Encoder, Error, Options, Technique};

/// Generate WAF-evasion variants of a payload (for authorized testing).
#[derive(Parser)]
#[command(name = "rune-payload-encode", version, about)]
struct Cli {
    /// The payload to mutate.
    #[arg(required_unless_present = "list")]
    payload: Option<String>,
    /// Injection context: `generic`, `sql`, `xss`, `path`, `os_command` or `html`.
    #[arg(short, long, default_value = "generic")]
    context: Context,
    /// Technique to apply (repeatable); the context defaults when omitted.
    #[arg(short, long = "technique")]
    techniques: Vec<Technique>,
    /// Techniques joined with `+`, applied in sequence to make one variant
    /// (repeatable), e.g. `case_toggle+url_encode`.
    #[arg(short, long = "stack")]
    stack: Vec<String>,
    /// Leave out the unmodified payload.
    #[arg(long)]
    no_original: bool,
    /// Most variants to print.
    #[arg(long, default_value_t = Options::default().max_variants)]
    max_variants: usize,
    /// List the techniques and exit.
    #[arg(long)]
    list: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.list {
        for technique in Technique::ALL {
            println!("{technique}\t{}", technique.description());
        }
        return ExitCode::SUCCESS;
    }
    match generate(&cli) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn generate(cli: &Cli) -> Result<Vec<String>, Error> {
    let mut options = Options::default()
        .with_context(cli.context)
        .with_include_original(!cli.no_original)
        .with_max_variants(cli.max_variants);
    if !cli.techniques.is_empty() {
        options = options.with_techniques(cli.techniques.clone());
    }
    for spec in &cli.stack {
        let stack = spec
            .split('+')
            .map(str::parse)
            .collect::<Result<Vec<Technique>, _>>()?;
        options = options.with_stack(stack);
    }
    let report = Encoder::new()?.run(cli.payload.as_deref().unwrap_or_default(), &options)?;
    Ok(report
        .variants
        .into_iter()
        .map(|v| format!("{}\t{}", v.technique, v.payload))
        .collect())
}

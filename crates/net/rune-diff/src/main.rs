//! `rune-diff` command-line tool: diff two text files, or two HTTP
//! responses / exchanges stored as rune-http-model JSON.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_diff::{Granularity, HttpDiffOptions, HttpDiffer, MaskOptions, Masker, TextDiff};
use rune_http_model::{HttpExchange, HttpResponse};

/// Diff two files: text (unified output) or HTTP messages (structural).
/// Exits 0 when equivalent, 1 when different, 2 on error.
#[derive(Parser)]
#[command(name = "rune-diff", version, about)]
struct Cli {
    /// Old file.
    old: PathBuf,
    /// New file.
    new: PathBuf,
    /// How to read the files.
    #[arg(long, value_enum, default_value_t = Mode::Text)]
    mode: Mode,
    /// Token granularity for text diffs.
    #[arg(long, value_enum, default_value_t = Gran::Line)]
    granularity: Gran,
    /// Lines of context in unified output.
    #[arg(short = 'U', long, default_value_t = 3)]
    context: usize,
    /// Mask volatile content (dates, ids, tokens, nonces) in text mode.
    #[arg(long)]
    mask: bool,
    /// Compare HTTP messages exactly: no masking, no ignored headers.
    #[arg(long)]
    strict: bool,
    /// Extra header to ignore in HTTP modes. Repeatable.
    #[arg(long = "ignore-header", value_name = "NAME")]
    ignore_headers: Vec<String>,
    /// JSON pointer to ignore in bodies (`*` matches any segment). Repeatable.
    #[arg(long = "ignore-pointer", value_name = "POINTER")]
    ignore_pointers: Vec<String>,
    /// Print the HTTP diff as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    /// Plain text files.
    Text,
    /// rune-http-model `HttpResponse` JSON.
    Response,
    /// rune-http-model `HttpExchange` JSON.
    Exchange,
}

#[derive(Clone, Copy, ValueEnum)]
enum Gran {
    Line,
    Word,
    Char,
}

impl From<Gran> for Granularity {
    fn from(g: Gran) -> Self {
        match g {
            Gran::Line => Self::Line,
            Gran::Word => Self::Word,
            Gran::Char => Self::Char,
        }
    }
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?)
}

fn run(cli: &Cli) -> Result<bool, Box<dyn std::error::Error>> {
    let granularity = Granularity::from(cli.granularity);
    if matches!(cli.mode, Mode::Text) {
        let old = std::fs::read_to_string(&cli.old)?;
        let new = std::fs::read_to_string(&cli.new)?;
        let masker = if cli.mask {
            Masker::new(&MaskOptions::default())?
        } else {
            Masker::noop()
        };
        let (old, new) = (masker.mask(&old), masker.mask(&new));
        let diff = TextDiff::new(&old, &new, granularity);
        let (a, b) = (cli.old.display().to_string(), cli.new.display().to_string());
        print!("{}", diff.unified(cli.context).with_header(&a, &b));
        return Ok(diff.is_identical());
    }

    let mut options = if cli.strict {
        HttpDiffOptions::strict()
    } else {
        HttpDiffOptions::default()
    }
    .with_granularity(granularity);
    for h in &cli.ignore_headers {
        options = options.with_ignored_header(h);
    }
    for p in &cli.ignore_pointers {
        options = options.with_ignored_json_pointer(p);
    }
    let differ = HttpDiffer::new(&options)?;
    if matches!(cli.mode, Mode::Response) {
        let old: HttpResponse = read_json(&cli.old)?;
        let new: HttpResponse = read_json(&cli.new)?;
        let diff = differ.diff_responses(&old, &new);
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&diff)?);
        } else {
            print!("{diff}");
        }
        return Ok(diff.is_equivalent());
    }
    let old: HttpExchange = read_json(&cli.old)?;
    let new: HttpExchange = read_json(&cli.new)?;
    let diff = differ.diff_exchanges(&old, &new);
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        print!("{}", diff.request);
        if let Some(p) = &diff.response_presence {
            println!("response: present {} -> {}", p.old, p.new);
        }
        if let Some(r) = &diff.response {
            print!("{r}");
        }
    }
    Ok(diff.request.is_equivalent()
        && diff.response_presence.is_none()
        && diff
            .response
            .as_ref()
            .is_none_or(rune_diff::ResponseDiff::is_equivalent))
}

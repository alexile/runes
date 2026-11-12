//! `rune-entropy` command-line tool: entropy and randomness statistics for
//! files and stdin, with per-block and sliding-window profiles.

use clap::Parser;
use rune_entropy::{
    Analysis, Analyzer, Histogram, Profiler, Region, Window, classify, regions_where,
};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "rune-entropy",
    about = "Entropy and randomness statistics: spot encrypted, packed, or compressed data",
    version
)]
struct Cli {
    /// Files to analyse. Use '-' to read from stdin.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Show every statistic: min-entropy, chi-square, mean, serial
    /// correlation and Monte Carlo pi.
    #[arg(short, long)]
    stats: bool,

    /// Per-block entropy over non-overlapping blocks of this size.
    #[arg(short = 'b', long, value_name = "BYTES", conflicts_with_all = ["window", "regions"])]
    block_size: Option<usize>,

    /// Sliding-window entropy profile with this window size.
    #[arg(short, long, value_name = "BYTES")]
    window: Option<usize>,

    /// Distance between window starts [default: window / 4].
    #[arg(long, value_name = "BYTES")]
    step: Option<usize>,

    /// List high-entropy regions instead of every window (window defaults to 1024).
    #[arg(short, long)]
    regions: bool,

    /// Entropy threshold for --regions, in bits per byte.
    #[arg(short, long, value_name = "BITS", default_value_t = 7.0)]
    threshold: f64,

    /// Drop regions shorter than this [default: window size].
    #[arg(long, value_name = "BYTES")]
    min_len: Option<u64>,

    /// Print results as JSON.
    #[arg(short, long)]
    json: bool,
}

/// Per-source result.
struct Report {
    name: String,
    analysis: Analysis,
    /// Block size and per-block scores.
    blocks: Option<(usize, Vec<f64>)>,
    windows: Option<Vec<Window>>,
    regions: Option<Vec<Region>>,
}

struct Plan {
    block_size: Option<usize>,
    window: Option<(usize, usize)>,
    regions: Option<(f64, u64)>,
}

impl Plan {
    fn from_cli(cli: &Cli) -> Result<Self, String> {
        if cli.block_size == Some(0) {
            return Err("--block-size must be greater than zero".into());
        }
        let window = match (cli.window, cli.regions) {
            (Some(w), _) => Some(w),
            (None, true) => Some(1024),
            (None, false) => None,
        };
        let window = match window {
            Some(0) => return Err("--window must be greater than zero".into()),
            Some(w) => {
                let step = cli.step.unwrap_or_else(|| (w / 4).max(1));
                if step == 0 {
                    return Err("--step must be greater than zero".into());
                }
                Some((w, step))
            }
            None => None,
        };
        let regions = cli.regions.then(|| {
            let min_len = cli
                .min_len
                .unwrap_or_else(|| window.map_or(0, |(w, _)| w as u64));
            (cli.threshold, min_len)
        });
        Ok(Self {
            block_size: cli.block_size,
            window,
            regions,
        })
    }
}

fn run(reader: impl Read, name: String, plan: &Plan) -> io::Result<Report> {
    let mut analyzer = Analyzer::new();
    let mut blocks = plan
        .block_size
        .map(|size| (size, Histogram::new(), Vec::new()));
    let mut profiler = match plan.window {
        Some((window, step)) => Some(Profiler::new(window, step)?),
        None => None,
    };
    let mut windows = Vec::new();

    let mut reader = reader;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let chunk = &buffer[..n];
        analyzer.update(chunk);
        if let Some(profiler) = profiler.as_mut() {
            profiler.push(chunk, |w| windows.push(w));
        }
        if let Some((size, hist, scores)) = blocks.as_mut() {
            let mut rest = chunk;
            while !rest.is_empty() {
                let filled = usize::try_from(hist.total()).unwrap_or(*size);
                let take = (*size - filled).min(rest.len());
                hist.update(&rest[..take]);
                rest = &rest[take..];
                if usize::try_from(hist.total()).unwrap_or(0) == *size {
                    scores.push(hist.shannon());
                    hist.clear();
                }
            }
        }
    }
    if let Some(profiler) = profiler {
        profiler.finish(|w| windows.push(w));
    }
    let blocks = blocks.map(|(size, hist, mut scores)| {
        if !hist.is_empty() {
            scores.push(hist.shannon());
        }
        (size, scores)
    });

    let (windows, regions) = match (plan.window, plan.regions) {
        (Some(_), Some((threshold, min_len))) => (
            None,
            Some(regions_where(&windows, |e| e >= threshold, min_len)),
        ),
        (Some(_), None) => (Some(windows), None),
        _ => (None, None),
    };

    Ok(Report {
        name,
        analysis: analyzer.analysis(),
        blocks,
        windows,
        regions,
    })
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0..=20 first"
)]
fn bar(score: f64) -> String {
    let filled = (score / 8.0 * 20.0).round().clamp(0.0, 20.0) as usize;
    format!("[{}{}]", "#".repeat(filled), ".".repeat(20 - filled))
}

fn fmt_opt(value: Option<f64>, digits: usize) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{v:.digits$}"))
}

fn print_text(
    out: &mut impl Write,
    report: &Report,
    detailed: bool,
    stats: bool,
) -> io::Result<()> {
    let a = &report.analysis;
    let class = classify(a.shannon);
    let assessment = a.assess();
    if !detailed {
        writeln!(
            out,
            "{:.4}  {}  {:>15}  {:>12}  {}",
            a.shannon,
            bar(a.shannon),
            class.as_str(),
            assessment.verdict.as_str(),
            report.name
        )?;
        return Ok(());
    }

    writeln!(out, "file:           {}", report.name)?;
    writeln!(out, "size:           {} bytes", a.len)?;
    writeln!(
        out,
        "entropy:        {:.4} / 8.0  {}  {class}",
        a.shannon,
        bar(a.shannon)
    )?;
    writeln!(out, "verdict:        {assessment}")?;
    if stats {
        writeln!(out, "min-entropy:    {:.4}", a.min_entropy)?;
        writeln!(
            out,
            "chi-square:     {} (p = {}; random data: ~255, p well above 0.001)",
            fmt_opt(a.chi_square, 2),
            fmt_opt(a.chi_square_p_value, 4)
        )?;
        writeln!(
            out,
            "mean:           {} (random: 127.5)",
            fmt_opt(a.mean, 4)
        )?;
        writeln!(
            out,
            "serial corr.:   {} (random: 0.0)",
            fmt_opt(a.serial_correlation, 6)
        )?;
        let pi = a.monte_carlo_pi.map(|pi| {
            let error = (pi - std::f64::consts::PI).abs() / std::f64::consts::PI * 100.0;
            format!("{pi:.6} (error {error:.2}%)")
        });
        writeln!(
            out,
            "monte carlo pi: {}",
            pi.unwrap_or_else(|| "n/a".into())
        )?;
        writeln!(out, "distinct bytes: {}", a.distinct)?;
        writeln!(
            out,
            "printable:      {}",
            fmt_opt(a.printable_ratio.map(|r| r * 100.0), 1) + "%"
        )?;
    }

    let width = a.len.to_string().len();
    if let Some((size, blocks)) = &report.blocks {
        writeln!(out, "blocks:")?;
        for (offset, score) in (0u64..).step_by(*size).zip(blocks) {
            writeln!(
                out,
                "  {offset:>width$}  {score:.4}  {}  {}",
                bar(*score),
                classify(*score)
            )?;
        }
    }
    if let Some(windows) = &report.windows {
        writeln!(out, "windows:")?;
        for w in windows {
            writeln!(
                out,
                "  {:>width$}  {:.4}  {}  {}",
                w.offset,
                w.entropy,
                bar(w.entropy),
                classify(w.entropy)
            )?;
        }
    }
    if let Some(regions) = &report.regions {
        if regions.is_empty() {
            writeln!(out, "regions:        none")?;
        } else {
            writeln!(out, "regions:")?;
            for r in regions {
                writeln!(
                    out,
                    "  {:#010x}..{:#010x}  {:>10} bytes  mean {:.4}  max {:.4}",
                    r.start,
                    r.end,
                    r.len(),
                    r.mean_entropy,
                    r.max_entropy
                )?;
            }
        }
    }
    Ok(())
}

fn to_json(report: &Report) -> Value {
    let a = &report.analysis;
    let assessment = a.assess();
    let mut value = json!({
        "path": report.name,
        "size": a.len,
        "entropy": a.shannon,
        "class": classify(a.shannon).as_str(),
        "verdict": assessment.verdict.as_str(),
        "confidence": assessment.confidence.as_str(),
        "min_entropy": a.min_entropy,
        "chi_square": a.chi_square,
        "chi_square_p_value": a.chi_square_p_value,
        "mean": a.mean,
        "serial_correlation": a.serial_correlation,
        "monte_carlo_pi": a.monte_carlo_pi,
        "distinct_bytes": a.distinct,
        "printable_ratio": a.printable_ratio,
    });
    if let Some((size, blocks)) = &report.blocks {
        value["block_size"] = json!(size);
        value["blocks"] = (0u64..)
            .step_by(*size)
            .zip(blocks)
            .map(|(offset, e)| json!({ "offset": offset, "entropy": e }))
            .collect();
    }
    if let Some(windows) = &report.windows {
        value["windows"] = windows
            .iter()
            .map(|w| json!({ "offset": w.offset, "len": w.len, "entropy": w.entropy }))
            .collect();
    }
    if let Some(regions) = &report.regions {
        value["regions"] = regions
            .iter()
            .map(|r| {
                json!({
                    "start": r.start,
                    "end": r.end,
                    "len": r.len(),
                    "mean_entropy": r.mean_entropy,
                    "max_entropy": r.max_entropy,
                })
            })
            .collect();
    }
    value
}

/// A closed pipe (e.g. `| head`) is a normal way to stop; anything else is an error.
fn write_failure(error: &io::Error) -> ExitCode {
    if error.kind() == io::ErrorKind::BrokenPipe {
        ExitCode::SUCCESS
    } else {
        eprintln!("error: writing output: {error}");
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let plan = match Plan::from_cli(&cli) {
        Ok(plan) => plan,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let detailed =
        cli.files.len() == 1 || cli.stats || plan.block_size.is_some() || plan.window.is_some();

    let mut failed = false;
    let mut json_out = Vec::new();
    let mut out = BufWriter::new(io::stdout().lock());
    for path in &cli.files {
        let result = if path.as_os_str() == "-" {
            run(io::stdin().lock(), "<stdin>".into(), &plan)
        } else {
            let name = path.display().to_string();
            File::open(path).and_then(|file| run(file, name, &plan))
        };
        match result {
            Ok(report) if cli.json => json_out.push(to_json(&report)),
            Ok(report) => {
                if let Err(error) = print_text(&mut out, &report, detailed, cli.stats) {
                    return write_failure(&error);
                }
            }
            Err(error) => {
                failed = true;
                eprintln!("error: {}: {error}", path.display());
                if cli.json {
                    json_out.push(
                        json!({ "path": path.display().to_string(), "error": error.to_string() }),
                    );
                }
            }
        }
    }
    if cli.json {
        match serde_json::to_string_pretty(&Value::Array(json_out)) {
            Ok(text) => {
                if let Err(error) = writeln!(out, "{text}") {
                    return write_failure(&error);
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

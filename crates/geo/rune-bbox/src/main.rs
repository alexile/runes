//! `rune-bbox` command-line tool: bounding-box math: union, intersection, containment, clustering/merge of overlapping boxes.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_bbox::{BBox, contains_point, intersection, merge_overlapping, union};
use std::process::ExitCode;

/// Bounding-box math: union, intersection, containment, merge.
#[derive(Parser)]
#[command(name = "rune-bbox")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Union of two boxes, each as `min_lat,min_lon,max_lat,max_lon`.
    Union { a: String, b: String },
    /// Intersection of two boxes.
    Intersect { a: String, b: String },
    /// Whether a box contains a `lat,lon` point.
    Contains { bbox: String, point: String },
    /// Merge a list of boxes, collapsing overlapping chains.
    Merge { boxes: Vec<String> },
}

fn parse_bbox(s: &str) -> Result<BBox, String> {
    let parts: Vec<f64> = s
        .split(',')
        .map(|p| p.trim().parse::<f64>().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if parts.len() != 4 {
        return Err(format!(
            "expected min_lat,min_lon,max_lat,max_lon, got '{s}'"
        ));
    }
    Ok(BBox {
        min_lat: parts[0],
        min_lon: parts[1],
        max_lat: parts[2],
        max_lon: parts[3],
    })
}

fn parse_point(s: &str) -> Result<(f64, f64), String> {
    let parts: Vec<f64> = s
        .split(',')
        .map(|p| p.trim().parse::<f64>().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if parts.len() != 2 {
        return Err(format!("expected lat,lon, got '{s}'"));
    }
    Ok((parts[0], parts[1]))
}

fn fmt_bbox(b: &BBox) -> String {
    format!("{},{},{},{}", b.min_lat, b.min_lon, b.max_lat, b.max_lon)
}

fn run(command: Command) -> Result<String, String> {
    match command {
        Command::Union { a, b } => Ok(fmt_bbox(&union(&parse_bbox(&a)?, &parse_bbox(&b)?))),
        Command::Intersect { a, b } => intersection(&parse_bbox(&a)?, &parse_bbox(&b)?)
            .map_or_else(|| Ok("none".to_string()), |i| Ok(fmt_bbox(&i))),
        Command::Contains { bbox, point } => {
            let b = parse_bbox(&bbox)?;
            let (lat, lon) = parse_point(&point)?;
            Ok(contains_point(&b, lat, lon).to_string())
        }
        Command::Merge { boxes } => {
            let parsed: Vec<BBox> = boxes
                .iter()
                .map(|s| parse_bbox(s))
                .collect::<Result<_, _>>()?;
            let merged = merge_overlapping(&parsed);
            Ok(merged.iter().map(fmt_bbox).collect::<Vec<_>>().join(" "))
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args.command) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("rune-bbox: {err}");
            ExitCode::FAILURE
        }
    }
}

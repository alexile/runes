//! `rune-rtree` command-line tool: r-tree spatial index for fast nearest-neighbor and range queries over points.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_rtree::{BBox, RTree};

#[derive(Parser)]
#[command(
    name = "rune-rtree",
    about = "Index points from a file and run a range or nearest-neighbor query"
)]
struct Cli {
    /// Input file: one `lat,lon` point per line. Use `-` to read from stdin.
    file: PathBuf,

    /// Range query: `min_x` `min_y` `max_x` `max_y`. Mutually exclusive with `--nearest`.
    #[arg(long, num_args = 4, value_names = ["MIN_X", "MIN_Y", "MAX_X", "MAX_Y"])]
    range: Option<Vec<f64>>,

    /// Nearest-neighbor query point: x y. Mutually exclusive with `--range`.
    #[arg(long, num_args = 2, value_names = ["X", "Y"])]
    nearest: Option<Vec<f64>>,

    /// Number of neighbors to return for `--nearest`.
    #[arg(long, default_value_t = 5)]
    k: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let points = match read_points(&cli.file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut tree = RTree::new();
    for (i, &p) in points.iter().enumerate() {
        tree.insert(p, i);
    }

    match (&cli.range, &cli.nearest) {
        (Some(r), None) => {
            let region = BBox::new(r[0], r[1], r[2], r[3]);
            for (x, y, &id) in tree.range(region) {
                let line = serde_json::json!({ "x": x, "y": y, "id": id });
                println!("{line}");
            }
        }
        (None, Some(q)) => {
            for ((x, y), &id, dist) in tree.nearest((q[0], q[1]), cli.k) {
                let line = serde_json::json!({ "x": x, "y": y, "id": id, "distance": dist });
                println!("{line}");
            }
        }
        (None, None) => {
            eprintln!("error: pass either --range MIN_X MIN_Y MAX_X MAX_Y or --nearest X Y");
            return ExitCode::FAILURE;
        }
        (Some(_), Some(_)) => {
            eprintln!("error: --range and --nearest are mutually exclusive");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

fn read_points(path: &PathBuf) -> io::Result<Vec<(f64, f64)>> {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(io::BufReader::new(io::stdin()))
    } else {
        Box::new(io::BufReader::new(std::fs::File::open(path)?))
    };

    let mut points = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let coords: Vec<&str> = trimmed
            .split(|c: char| c == ',' || c.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
            .collect();
        match coords.as_slice() {
            [x, y] => match (x.parse::<f64>(), y.parse::<f64>()) {
                (Ok(x), Ok(y)) => points.push((x, y)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line {}: could not parse as x,y", line_num + 1),
                    ));
                }
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: expected exactly two numbers", line_num + 1),
                ));
            }
        }
    }
    Ok(points)
}

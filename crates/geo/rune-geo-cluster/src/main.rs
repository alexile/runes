//! `rune-geo-cluster` command-line tool: spatial clustering of point sets (thin geo-domain wrapper over the existing ml clustering crates).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_geo_cluster::{cluster_hdbscan, cluster_kmeans};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Method {
    Kmeans,
    Hdbscan,
}

#[derive(Parser)]
#[command(
    name = "rune-geo-cluster",
    about = "Cluster latitude/longitude points with K-Means or HDBSCAN"
)]
struct Cli {
    /// Input file: one `lat,lon` pair per line. Use `-` to read from stdin.
    file: PathBuf,

    /// Clustering method to use.
    #[arg(long, value_enum, default_value_t = Method::Kmeans)]
    method: Method,

    /// Number of clusters (kmeans only).
    #[arg(long, short = 'k', default_value_t = 2)]
    k: usize,

    /// Minimum cluster size (hdbscan only).
    #[arg(long, default_value_t = 5)]
    min_cluster_size: usize,
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

    if points.is_empty() {
        eprintln!("error: no data points found");
        return ExitCode::FAILURE;
    }

    match cli.method {
        Method::Kmeans => {
            if cli.k == 0 || cli.k > points.len() {
                eprintln!(
                    "error: k must be between 1 and the number of points ({})",
                    points.len()
                );
                return ExitCode::FAILURE;
            }
            let labels = cluster_kmeans(&points, cli.k);
            for ((lat, lon), label) in points.iter().zip(labels) {
                let line = serde_json::json!({ "lat": lat, "lon": lon, "label": label });
                println!("{line}");
            }
        }
        Method::Hdbscan => {
            let labels = cluster_hdbscan(&points, cli.min_cluster_size);
            for ((lat, lon), label) in points.iter().zip(labels) {
                let line = serde_json::json!({ "lat": lat, "lon": lon, "label": label });
                println!("{line}");
            }
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
            [lat, lon] => match (lat.parse::<f64>(), lon.parse::<f64>()) {
                (Ok(lat), Ok(lon)) => points.push((lat, lon)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line {}: could not parse as lat,lon", line_num + 1),
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

//! `rune-robots` command-line tool: check paths against a saved robots.txt,
//! or list the URLs of a saved sitemap.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rune_robots::{Robots, Sitemap};

/// Parse robots.txt and sitemap files. Nothing is fetched.
#[derive(Parser)]
#[command(name = "rune-robots", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check paths (or URLs) against a robots.txt; prints `allow` or
    /// `disallow` per path. Exits 1 if any path is disallowed.
    Check {
        /// The robots.txt file (`-` for stdin).
        file: PathBuf,
        /// Crawler product token.
        #[arg(short = 'a', long, default_value = "*")]
        agent: String,
        /// Paths or URLs to check.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Print the groups, crawl delays and sitemaps of a robots.txt.
    Show {
        /// The robots.txt file (`-` for stdin).
        file: PathBuf,
    },
    /// Print the `<loc>` of every entry of a sitemap (XML, text or gzip).
    Sitemap {
        /// The sitemap file (`-` for stdin).
        file: PathBuf,
    },
}

fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let file = match &cli.command {
        Command::Check { file, .. } | Command::Show { file } | Command::Sitemap { file } => file,
    };
    let body = match read(file) {
        Ok(body) => body,
        Err(err) => {
            eprintln!("error: reading {}: {err}", file.display());
            return ExitCode::FAILURE;
        }
    };
    match cli.command {
        Command::Check { agent, paths, .. } => {
            let robots = Robots::parse_bytes(&body);
            let mut all_allowed = true;
            for path in &paths {
                let verdict = robots.verdict(&agent, path);
                all_allowed &= verdict.allowed;
                let word = if verdict.allowed { "allow" } else { "disallow" };
                match verdict.rule {
                    Some(rule) => {
                        println!("{word}\t{path}\t(line {}: {})", rule.line, rule.pattern);
                    }
                    None => println!("{word}\t{path}"),
                }
            }
            if all_allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Show { .. } => {
            println!("{:#?}", Robots::parse_bytes(&body));
            ExitCode::SUCCESS
        }
        Command::Sitemap { .. } => match Sitemap::parse(&body) {
            Ok(sitemap) => {
                for loc in sitemap.locations() {
                    println!("{loc}");
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}

//! `rune-url` command-line tool: canonical forms, dedup keys, sites and
//! scope checks for URLs given as arguments.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rune_url::{KeyOptions, Options, QueryKey, Scope, Url, canonicalize, dedup_key, site};

/// URL canonicalization, dedup keys, sites and scope checks.
#[derive(Parser)]
#[command(name = "rune-url", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the canonical form of each URL.
    Canon {
        /// Also drop fragments, tracking parameters and trailing dots.
        #[arg(long)]
        crawler: bool,
        /// Sort query parameters by name.
        #[arg(long)]
        sort_query: bool,
        /// URLs to canonicalize.
        #[arg(required = true)]
        urls: Vec<String>,
    },
    /// Print the dedup key of each URL.
    Key {
        /// Treat http and https as one.
        #[arg(long)]
        ignore_scheme: bool,
        /// Ignore a leading `www.`.
        #[arg(long)]
        ignore_www: bool,
        /// Treat `/a/` and `/a` as one.
        #[arg(long)]
        ignore_trailing_slash: bool,
        /// Keep only parameter names from the query.
        #[arg(long)]
        query_names: bool,
        /// URLs to key.
        #[arg(required = true)]
        urls: Vec<String>,
    },
    /// Print the site (scheme and registrable domain) of each URL.
    Site {
        /// URLs to inspect.
        #[arg(required = true)]
        urls: Vec<String>,
    },
    /// Print `in` or `out` for each URL against a scope.
    Scope {
        /// Include rule (repeatable): URL prefix, CIDR, `.domain`, host or pattern.
        #[arg(long = "include", short = 'i', required = true)]
        include: Vec<String>,
        /// Exclude rule (repeatable).
        #[arg(long = "exclude", short = 'x')]
        exclude: Vec<String>,
        /// URLs to check.
        #[arg(required = true)]
        urls: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut failed = false;
    match cli.command {
        Command::Canon {
            crawler,
            sort_query,
            urls,
        } => {
            let base = if crawler {
                Options::crawler()
            } else {
                Options::default()
            };
            let options = base.with_sort_query(sort_query);
            for input in urls {
                report(&input, canonicalize(&input, &options), &mut failed);
            }
        }
        Command::Key {
            ignore_scheme,
            ignore_www,
            ignore_trailing_slash,
            query_names,
            urls,
        } => {
            let mut options = KeyOptions::default()
                .with_ignore_scheme(ignore_scheme)
                .with_ignore_www(ignore_www)
                .with_ignore_trailing_slash(ignore_trailing_slash);
            if query_names {
                options = options.with_query(QueryKey::Names);
            }
            for input in urls {
                report(&input, dedup_key(&input, &options), &mut failed);
            }
        }
        Command::Site { urls } => {
            for input in urls {
                match Url::parse(&input) {
                    Ok(url) => println!("{}", site(&url).unwrap_or_else(|| "-".to_owned())),
                    Err(err) => {
                        eprintln!("error: {input}: {err}");
                        failed = true;
                    }
                }
            }
        }
        Command::Scope {
            include,
            exclude,
            urls,
        } => match Scope::parse(&include, &exclude) {
            Ok(scope) => {
                for input in urls {
                    let verdict = if scope.contains_str(&input) {
                        "in"
                    } else {
                        "out"
                    };
                    println!("{verdict}\t{input}");
                }
            }
            Err(err) => {
                eprintln!("error: {err}");
                failed = true;
            }
        },
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn report<T: std::fmt::Display>(
    input: &str,
    result: Result<T, rune_url::Error>,
    failed: &mut bool,
) {
    match result {
        Ok(value) => println!("{value}"),
        Err(err) => {
            eprintln!("error: {input}: {err}");
            *failed = true;
        }
    }
}

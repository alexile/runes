//! `rune-redact` command-line tool: redact PII and secrets from a file or
//! stdin, streaming the result to stdout.

use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

use rune_redact::{RedactingWriter, Redactor};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let (name, mut input): (&str, Box<dyn Read>) = match args.first().map(String::as_str) {
        None | Some("-") => ("stdin", Box::new(io::stdin().lock())),
        Some(path) => match File::open(path) {
            Ok(f) => (path, Box::new(f)),
            Err(e) => {
                eprintln!("rune-redact: {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let stream = Redactor::default().stream().with_line_boundaries(true);
    let mut out = RedactingWriter::with_stream(io::stdout().lock(), stream);
    if let Err(e) = io::copy(&mut input, &mut out) {
        eprintln!("rune-redact: {name}: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = out.finish() {
        eprintln!("rune-redact: stdout: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

//! Times shingling, signing and clustering 10 000 short documents.
//!
//! ```bash
//! cargo run --release -p rune-simhash --example bench_10k
//! ```
//!
//! Half the documents are soft-404 variants of 20 templates (the path in
//! the body changes); the other half are unique random texts. It reports
//! throughput and how many clusters each method finds (ideal: 20 + 5000).

// An example reports on stdout.
#![allow(clippy::print_stdout)]

use std::time::Instant;

use rune_simhash::{ClusterOptions, Clusterer, MinHasher, ShingleOptions, SimHash, hash_feature};

const DOCS: usize = 10_000;
const TEMPLATES: u64 = 20;

fn word(state: &mut u64) -> String {
    *state = hash_feature(&state.to_le_bytes());
    format!("w{}", *state % 5000)
}

fn corpus() -> Vec<String> {
    let mut state = 1u64;
    let templates: Vec<Vec<String>> = (0..TEMPLATES)
        .map(|_| (0..40).map(|_| word(&mut state)).collect())
        .collect();
    (0..DOCS as u64)
        .map(|i| {
            if i % 2 == 0 {
                let t = &templates[usize::try_from(i / 2 % TEMPLATES).unwrap_or(0)];
                format!(
                    "<html><body><h1>{}</h1><p>{} /path/{i}/file{i}.php {}</p></body></html>",
                    t[0],
                    t[1..20].join(" "),
                    t[20..].join(" ")
                )
            } else {
                (0..50)
                    .map(|_| word(&mut state))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        })
        .collect()
}

fn main() -> Result<(), rune_simhash::Error> {
    let docs = corpus();
    let o = ShingleOptions::default().with_strip_html(true);

    let t = Instant::now();
    let fps = docs
        .iter()
        .map(|d| SimHash::from_text(d, &o))
        .collect::<Result<Vec<_>, _>>()?;
    let sign = t.elapsed();
    for (name, bands) in [("exhaustive", None), ("4 bands", Some(4))] {
        let t = Instant::now();
        let mut c = Clusterer::new(
            ClusterOptions::default()
                .with_threshold(0.8)
                .with_bands(bands),
        )?;
        for fp in &fps {
            c.assign(*fp);
        }
        println!(
            "simhash  sign {sign:>10.2?}  cluster ({name:>10}) {:>10.2?}  clusters {}",
            t.elapsed(),
            c.clusters().len()
        );
    }

    let h = MinHasher::new(128, 0)?;
    let t = Instant::now();
    let signatures = docs
        .iter()
        .map(|d| h.signature_text(d, &o))
        .collect::<Result<Vec<_>, _>>()?;
    let sign = t.elapsed();
    let t = Instant::now();
    let mut c = Clusterer::new(
        ClusterOptions::default()
            .with_threshold(0.7)
            .with_bands(Some(32)),
    )?;
    for s in signatures {
        c.assign(s);
    }
    println!(
        "minhash  sign {sign:>10.2?}  cluster ({:>10}) {:>10.2?}  clusters {}",
        "32 bands",
        t.elapsed(),
        c.clusters().len()
    );
    Ok(())
}

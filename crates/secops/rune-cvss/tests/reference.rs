//! Differential tests against corpora scored by FIRST's reference
//! calculators (see the header of each file in `tests/data/`).
//!
//! The committed corpora are random samples: v3 vectors with their metrics
//! in a random order half of the time, and every corpus with optional
//! metrics at varying densities, including explicit `X` values.
//! `tests/oracle/gen.js` regenerates them, and writes larger corpora (such
//! as every base vector) for `RUNE_CVSS_CORPUS_DIR`: set it to a directory
//! of `.tsv` files in the same formats to check those too.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail the test on a mismatch"
)]

use std::path::Path;

use rune_cvss::{Vector, Vector3, Vector4};

/// Checks one corpus line; returns false for comments.
fn check_line(line: &str) -> bool {
    if line.starts_with('#') || line.is_empty() {
        return false;
    }
    let fields: Vec<&str> = line.split('\t').collect();
    let text = fields[0];
    if text.starts_with("CVSS:4.0/") {
        let vector: Vector4 = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(vector.score().to_string(), fields[1], "score {text}");
        assert_eq!(
            vector.base_score().to_string(),
            fields[2],
            "base score {text}"
        );
        assert_eq!(
            vector.macro_vector().to_string(),
            fields[3],
            "MacroVector {text}"
        );
        check_round_trip(&Vector::V4(vector));
    } else {
        let vector: Vector3 = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(vector.base_score().to_string(), fields[1], "base {text}");
        assert_eq!(
            vector.temporal_score().to_string(),
            fields[2],
            "temporal {text}"
        );
        assert_eq!(
            vector.environmental_score().to_string(),
            fields[3],
            "environmental {text}"
        );
        check_round_trip(&Vector::V3(vector));
    }
    true
}

fn check_round_trip(vector: &Vector) {
    let canonical = vector.to_string();
    let again: Vector = canonical.parse().unwrap();
    assert_eq!(&again, vector, "{canonical}");
    assert_eq!(again.to_string(), canonical);
}

fn check_corpus(text: &str) -> usize {
    text.lines().filter(|line| check_line(line)).count()
}

#[test]
fn v3_0_corpus() {
    assert_eq!(check_corpus(include_str!("data/v3_0.tsv")), 1000);
}

#[test]
fn v3_1_corpus() {
    assert_eq!(check_corpus(include_str!("data/v3_1.tsv")), 2500);
}

#[test]
fn v4_0_corpus() {
    assert_eq!(check_corpus(include_str!("data/v4_0.tsv")), 3000);
}

#[test]
fn external_corpus() {
    let Some(dir) = std::env::var_os("RUNE_CVSS_CORPUS_DIR") else {
        return;
    };
    let mut total = 0;
    for entry in std::fs::read_dir(Path::new(&dir)).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "tsv") {
            let count = check_corpus(&std::fs::read_to_string(&path).unwrap());
            eprintln!("{}: {count} vectors match", path.display());
            total += count;
        }
    }
    assert!(total > 0, "no .tsv corpus in {}", Path::new(&dir).display());
}

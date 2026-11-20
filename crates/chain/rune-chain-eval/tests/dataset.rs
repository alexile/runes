//! Dataset loading, caps, sampling and splits.

#![allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    reason = "test helpers fail loudly"
)]

use rune_chain_eval::{CsvOptions, Dataset, DatasetLimits, EvalError, Example};
use serde_json::json;

fn numbered(n: usize) -> Dataset {
    Dataset::new(
        (0..n)
            .map(|i| Example::from_question(i.to_string(), format!("q{i}")))
            .collect(),
    )
    .unwrap()
}

#[test]
fn jsonl_formats() {
    let text = r#"
{"id": "a", "inputs": {"question": "2+2?"}, "reference": "4", "metadata": {"contexts": ["c1", "c2"]}}

{"inputs": "plain", "expected": {"k": 1}}
{"id": 7, "question": "q", "topic": "x"}
"#;
    let ds = Dataset::from_jsonl_str(text, &DatasetLimits::default()).unwrap();
    assert_eq!(ds.len(), 3);
    let [a, b, c] = ds.examples() else { panic!() };
    assert_eq!(a.question(), Some("2+2?"));
    assert_eq!(a.metadata_strings("contexts"), ["c1", "c2"]);
    assert_eq!(b.id, "2");
    assert_eq!(b.input_str("input"), Some("plain"));
    assert_eq!(b.reference.as_deref(), Some(r#"{"k":1}"#));
    assert_eq!(c.id, "7");
    assert_eq!(c.inputs["topic"], json!("x"));
    // Round trip.
    let again =
        Dataset::from_jsonl_str(&ds.to_jsonl().unwrap(), &DatasetLimits::default()).unwrap();
    assert_eq!(again, ds);
}

#[test]
fn jsonl_errors_name_the_line_not_the_content() {
    let err = Dataset::from_jsonl_str(
        "{\"id\":\"a\"}\n{secret-token oops",
        &DatasetLimits::default(),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("line 2"), "{msg}");
    assert!(!msg.contains("secret"));
    assert!(matches!(
        Dataset::from_jsonl_str("[1]", &DatasetLimits::default()),
        Err(EvalError::Dataset(_))
    ));
    let dup = Dataset::from_jsonl_str("{\"id\":\"a\"}\n{\"id\":\"a\"}", &DatasetLimits::default());
    assert!(dup.unwrap_err().to_string().contains("duplicate"));
}

#[test]
fn jsonl_caps() {
    let limits = DatasetLimits {
        max_record_bytes: 32,
        ..DatasetLimits::default()
    };
    let long = format!("{{\"q\": \"{}\"}}", "x".repeat(100));
    assert!(
        Dataset::from_jsonl_str(&long, &limits)
            .unwrap_err()
            .to_string()
            .contains("longer")
    );
    let limits = DatasetLimits {
        max_examples: 2,
        ..DatasetLimits::default()
    };
    let three = "{\"q\":1}\n{\"q\":2}\n{\"q\":3}\n";
    assert!(Dataset::from_jsonl_str(three, &limits).is_err());
    let limits = DatasetLimits {
        max_bytes: 10,
        ..DatasetLimits::default()
    };
    assert!(Dataset::from_jsonl_str(three, &limits).is_err());
    // A line with no newline at all, far beyond the cap, is rejected
    // without being buffered whole.
    let huge = "y".repeat(10 << 20);
    assert!(Dataset::from_jsonl_str(&huge, &DatasetLimits::default()).is_err());
}

#[test]
fn csv_rfc4180() {
    let csv = "id,question,reference,source\r\n\
               q1,\"Hello, \"\"world\"\"?\",hi,web\r\n\
               q2,\"multi\nline\",,doc\n";
    let opts = CsvOptions {
        metadata_columns: vec!["source".into()],
        ..CsvOptions::default()
    };
    let ds = Dataset::from_csv_str(csv, &opts).unwrap();
    assert_eq!(ds.len(), 2);
    let q1 = ds.get("q1").unwrap();
    assert_eq!(q1.question(), Some("Hello, \"world\"?"));
    assert_eq!(q1.reference.as_deref(), Some("hi"));
    assert_eq!(q1.metadata["source"], json!("web"));
    assert!(!q1.inputs.contains_key("source"));
    assert_eq!(ds.get("q2").unwrap().question(), Some("multi\nline"));
}

#[test]
fn csv_errors_and_defaults() {
    let opts = CsvOptions::default();
    assert!(Dataset::from_csv_str("a,b\n1\n", &opts).is_err());
    assert!(Dataset::from_csv_str("a\n\"open\n", &opts).is_err());
    assert!(Dataset::from_csv_str("a\n\"x\"y\n", &opts).is_err());
    assert!(Dataset::from_csv_str("", &opts).unwrap().is_empty());
    // No id column: numbered from 1; BOM stripped; tab delimiter.
    let ds = Dataset::from_csv_str(
        "\u{feff}question\treference\nq\tr\n",
        &CsvOptions {
            delimiter: b'\t',
            ..CsvOptions::default()
        },
    )
    .unwrap();
    assert_eq!(ds.examples()[0].id, "1");
    assert_eq!(ds.examples()[0].reference.as_deref(), Some("r"));
    let wide = CsvOptions {
        limits: DatasetLimits {
            max_columns: 3,
            ..DatasetLimits::default()
        },
        ..CsvOptions::default()
    };
    assert!(Dataset::from_csv_str("a,b,c,d\n", &wide).is_err());
}

#[test]
fn sampling_is_deterministic() {
    let ds = numbered(100);
    let a = ds.sample(10, 7);
    assert_eq!(a.len(), 10);
    assert_eq!(a, ds.sample(10, 7));
    assert_ne!(a, ds.sample(10, 8));
    // Kept in dataset order, no duplicates.
    let ids: Vec<usize> = a.iter().map(|e| e.id.parse().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(ds.sample(500, 1).len(), 100);
    assert_eq!(ds.shuffled(3), ds.shuffled(3));
    assert_ne!(ds.shuffled(3), ds);
}

#[test]
fn splits_partition_the_dataset() {
    let ds = numbered(10);
    let (train, test) = ds.split(0.25, 9).unwrap();
    assert_eq!((train.len(), test.len()), (7, 3));
    assert_eq!(ds.split(0.25, 9).unwrap().1, test);
    for e in &ds {
        assert_ne!(train.get(&e.id).is_some(), test.get(&e.id).is_some());
    }
    assert!(ds.split(f64::NAN, 1).is_err());
    assert!(ds.split(1.5, 1).is_err());
    assert_eq!(ds.split(0.0, 1).unwrap().1.len(), 0);
    assert_eq!(ds.filter(|e| e.id.len() == 1).len(), 10);
}

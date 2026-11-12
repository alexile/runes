//! File-system edge cases for the text and JSONL loaders, and JSONL round
//! trips. Everything runs in a temporary directory.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};

use proptest::prelude::*;
use rune_chain_loader::Document;
use rune_chain_loader::jsonl::{load_jsonl_file, load_jsonl_str};
use rune_chain_loader::text::{load_dir, load_file};

#[test]
fn missing_paths_are_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.txt");
    let kind = |e: rune_chain_loader::LoadError| io::Error::from(e).kind();
    assert_eq!(kind(load_file(&missing).unwrap_err()), ErrorKind::NotFound);
    assert_eq!(
        kind(load_jsonl_file(&missing).unwrap_err()),
        ErrorKind::NotFound
    );
    assert_eq!(kind(load_dir(&missing).unwrap_err()), ErrorKind::NotFound);
}

#[test]
fn non_utf8_file_is_an_error_but_skipped_by_load_dir() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bad.txt"), [0xff, 0xfe, 0x00]).unwrap();
    fs::write(dir.path().join("good.txt"), "fine").unwrap();
    assert_eq!(
        io::Error::from(load_file(dir.path().join("bad.txt")).unwrap_err()).kind(),
        ErrorKind::InvalidData
    );
    let docs = load_dir(dir.path()).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].content, "fine");
}

#[test]
fn load_dir_takes_only_text_files_at_the_top_level() {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in [
        ("a.txt", "A"),
        ("b.md", "B"),
        ("c.rst", "C"),
        ("d.json", "{}"),
        ("noext", "x"),
        ("E.TXT", "upper-case extension"),
    ] {
        fs::write(dir.path().join(name), body).unwrap();
    }
    fs::create_dir(dir.path().join("sub.txt")).unwrap();
    fs::write(dir.path().join("sub.txt").join("nested.txt"), "deep").unwrap();

    let mut contents: Vec<String> = load_dir(dir.path())
        .unwrap()
        .into_iter()
        .map(|d| d.content)
        .collect();
    contents.sort();
    assert_eq!(contents, ["A", "B", "C"]);
}

#[test]
fn empty_inputs_load_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(load_dir(dir.path()).unwrap(), []);
    assert_eq!(load_jsonl_str(""), []);
    assert_eq!(load_jsonl_str("\n  \n\t\n"), []);
    let empty = dir.path().join("empty.txt");
    fs::write(&empty, "").unwrap();
    let doc = load_file(&empty).unwrap();
    assert_eq!(doc.content, "");
    assert_eq!(doc.metadata["source"], empty.display().to_string());
}

#[test]
fn jsonl_handles_crlf_and_non_object_lines() {
    let input = "{\"content\":\"one\"}\r\n[1,2]\r\n\"str\"\r\n{\"content\":2}\r\n{\"content\":\"two\",\"n\":null}\r\n";
    let docs = load_jsonl_str(input);
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].content, "one");
    assert_eq!(docs[1].content, "two");
    assert_eq!(docs[1].metadata["n"], "null");
}

fn to_jsonl(docs: &[Document]) -> String {
    docs.iter()
        .map(|d| {
            let mut obj = serde_json::Map::new();
            for (k, v) in &d.metadata {
                obj.insert(k.clone(), v.clone().into());
            }
            obj.insert("content".into(), d.content.clone().into());
            serde_json::Value::Object(obj).to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn document() -> impl Strategy<Value = Document> {
    (
        any::<String>(),
        prop::collection::hash_map("[a-z_]{1,8}", any::<String>(), 0..4),
    )
        .prop_map(|(content, metadata): (String, HashMap<String, String>)| {
            let metadata = metadata
                .into_iter()
                .filter(|(k, _)| k != "content")
                .collect();
            Document { content, metadata }
        })
}

/// Drop the metadata the loader adds, leaving what came from the record.
fn record_fields(mut doc: Document) -> Document {
    for key in ["line", "byte_start", "byte_end", "content_sha256"] {
        doc.metadata.remove(key);
    }
    doc
}

proptest! {
    #[test]
    fn jsonl_round_trips(docs in prop::collection::vec(document(), 0..6)) {
        let docs: Vec<Document> = docs
            .into_iter()
            .map(|mut d| {
                for key in ["line", "byte_start", "byte_end", "content_sha256"] {
                    d.metadata.remove(key);
                }
                d
            })
            .collect();
        let loaded: Vec<Document> = load_jsonl_str(&to_jsonl(&docs)).into_iter().map(record_fields).collect();
        prop_assert_eq!(loaded, docs);
    }

    #[test]
    fn jsonl_parser_never_panics(input in any::<String>()) {
        let docs = load_jsonl_str(&input);
        prop_assert!(docs.len() <= input.lines().count());
    }
}

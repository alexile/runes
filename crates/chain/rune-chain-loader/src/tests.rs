use crate::{Document, jsonl, text};

// ── Document ──────────────────────────────────────────────────────────────────

#[test]
fn document_builder_metadata() {
    let doc = Document::new("hello")
        .with_metadata("source", "a.txt")
        .with_metadata("page", "1");
    assert_eq!(doc.content, "hello");
    assert_eq!(doc.metadata["source"], "a.txt");
    assert_eq!(doc.metadata["page"], "1");
}

// ── text loader ───────────────────────────────────────────────────────────────

#[test]
fn load_file_sets_source_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello.txt");
    std::fs::write(&path, "hello world").unwrap();

    let doc = text::load_file(&path).unwrap();
    assert_eq!(doc.content, "hello world");
    assert!(doc.metadata["source"].contains("hello.txt"));
}

#[test]
fn load_dir_finds_text_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "content a").unwrap();
    std::fs::write(dir.path().join("b.md"), "content b").unwrap();
    std::fs::write(dir.path().join("c.bin"), b"\x00\x01\x02").unwrap();

    let docs = text::load_dir(dir.path()).unwrap();
    assert_eq!(docs.len(), 2);
    let contents: Vec<_> = docs.iter().map(|d| d.content.as_str()).collect();
    assert!(contents.contains(&"content a"));
    assert!(contents.contains(&"content b"));
}

// ── jsonl loader ──────────────────────────────────────────────────────────────

#[test]
fn jsonl_str_basic() {
    let input = r#"{"content":"hello","source":"a.txt"}
{"content":"world","source":"b.txt"}"#;

    let docs = jsonl::load_jsonl_str(input);
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].content, "hello");
    assert_eq!(docs[0].metadata["source"], "a.txt");
    assert_eq!(docs[1].content, "world");
}

#[test]
fn jsonl_str_skips_invalid_lines() {
    let input = "not-json\n{\"content\":\"ok\"}\nbad{json}";
    let docs = jsonl::load_jsonl_str(input);
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].content, "ok");
}

#[test]
fn jsonl_str_skips_missing_content_field() {
    let input = r#"{"text":"no content key"}"#;
    let docs = jsonl::load_jsonl_str(input);
    assert_eq!(docs, [] as [Document; 0]);
}

#[test]
fn jsonl_str_numeric_metadata_stringified() {
    let input = r#"{"content":"hello","page":42}"#;
    let docs = jsonl::load_jsonl_str(input);
    assert_eq!(docs[0].metadata["page"], "42");
}

#[test]
fn jsonl_file_sets_source_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.jsonl");
    std::fs::write(&path, r#"{"content":"hello"}"#).unwrap();

    let docs = jsonl::load_jsonl_file(&path).unwrap();
    assert_eq!(docs.len(), 1);
    assert!(docs[0].metadata["source"].contains("data.jsonl"));
}

#[test]
fn jsonl_file_preserves_explicit_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.jsonl");
    std::fs::write(&path, r#"{"content":"hi","source":"custom"}"#).unwrap();

    let docs = jsonl::load_jsonl_file(&path).unwrap();
    assert_eq!(docs[0].metadata["source"], "custom");
}

//! Format behaviour (HTML, JSON, CSV, globs) and no-panic properties for
//! every parser.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use proptest::prelude::*;
use rune_chain_loader::csv::CsvLoader;
use rune_chain_loader::html::{html_title, html_to_text, load_str};
use rune_chain_loader::json::{Fields, JsonLoader, MetadataFields};
use rune_chain_loader::jsonl::JsonlLoader;
use rune_chain_loader::{Glob, Limits, LoadError};

#[test]
fn html_drops_scripts_styles_and_comments() {
    let html = r#"<!DOCTYPE html><html><head><title>Doc &amp; Co</title>
        <style type="text/css">body { color: red }</style>
        <script>var s = "</p>"; alert('<b>');</script></head>
        <body><!-- hidden --><h1 class="x">Heading</h1>
        <p>One <b>bold</b> word.</p><noscript>enable js</noscript>
        <ul><li>a</li><li>b</li></ul>
        <SCRIPT type="module">evil()</SCRIPT>
        <table><tr><td>c1</td><td>c2</td></tr></table>
        <p>5 &lt; 6 &#65;&#x42; &bogus; & done</p></body></html>"#;
    let text = html_to_text(html);
    assert_eq!(
        text,
        "Heading\nOne bold word.\na\nb\nc1 c2\n5 < 6 AB &bogus; & done"
    );
    assert_eq!(html_title(html).as_deref(), Some("Doc & Co"));
    let doc = load_str(html);
    assert_eq!(doc.metadata["title"], "Doc & Co");
    assert_eq!(doc.metadata["content_sha256"], doc.content_sha256());
}

#[test]
fn html_handles_attributes_with_angle_brackets_and_bad_entities() {
    assert_eq!(html_to_text(r#"<a title="x > y">link</a>"#), "link");
    assert_eq!(
        html_to_text("a &#0; b &#xD800; c &#99999999999;"),
        "a \u{fffd} b \u{fffd} c &#99999999999;"
    );
    assert_eq!(html_to_text("1 < 2 <3"), "1 < 2 <3");
    assert_eq!(html_to_text("<script>never closed"), "");
    assert_eq!(html_to_text("<p unterminated"), "");
}

#[test]
fn json_selectors_and_metadata_modes() {
    let input = r#"[{"doc":{"text":"a"},"id":1,"tags":["x"]},{"doc":{"text":"b"},"id":2}]"#;
    let fields = Fields::new().content("/doc/text").unwrap();
    let docs = JsonLoader::new()
        .fields(fields.clone())
        .load_str(input)
        .unwrap();
    assert_eq!(docs[0].content, "a");
    assert_eq!(docs[0].metadata["tags"], r#"["x"]"#);
    assert_eq!(docs[0].metadata["doc"], r#"{"text":"a"}"#);

    let none = JsonLoader::new()
        .fields(fields.clone().metadata(MetadataFields::None))
        .load_str(input)
        .unwrap();
    assert!(!none[0].metadata.contains_key("id"));
    assert_eq!(none[0].metadata["record"], "1");

    let only = JsonLoader::new()
        .fields(fields.metadata_only(&["id"]).unwrap())
        .load_str(input)
        .unwrap();
    assert_eq!(only[1].metadata["id"], "2");
    assert!(!only[1].metadata.contains_key("tags"));
}

#[test]
fn json_missing_fields_are_errors_unless_skipped() {
    let input = r#"[{"content":"a"},{"content":5},{"other":"c"}]"#;
    let err = JsonLoader::new().load_str(input).unwrap_err();
    assert!(matches!(err, LoadError::MissingField { line: 2, .. }));
    let docs = JsonLoader::new()
        .skip_invalid(true)
        .load_str(input)
        .unwrap();
    assert_eq!(docs.len(), 1);
    let err = JsonLoader::new()
        .records("/nope")
        .unwrap()
        .load_str("{}")
        .unwrap_err();
    assert!(matches!(err, LoadError::MissingField { .. }));
    let single = JsonLoader::new().load_str(r#"{"content":"one"}"#).unwrap();
    assert_eq!(single.len(), 1);
}

#[test]
fn jsonl_offsets_cover_crlf_lines() {
    let input = "{\"content\":\"a\"}\r\n\r\n{\"content\":\"b\"}";
    let docs = JsonlLoader::new().load_str(input).unwrap();
    assert_eq!(docs.len(), 2);
    let (s, e): (usize, usize) = (
        docs[1].metadata["byte_start"].parse().unwrap(),
        docs[1].metadata["byte_end"].parse().unwrap(),
    );
    assert_eq!(&input[s..e], "{\"content\":\"b\"}");
    assert_eq!(docs[1].metadata["line"], "3");
    let e0: usize = docs[0].metadata["byte_end"].parse().unwrap();
    assert_eq!(&input[..e0], "{\"content\":\"a\"}");
}

#[test]
fn csv_quoting_crlf_headerless_and_ragged_rows() {
    let input = "name,quote\r\n\"Doe, J\",\"He said \"\"hi\"\"\"\r\n\r\nSmith\r\n";
    let docs = CsvLoader::new().load_str(input).unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].content, "name: Doe, J\nquote: He said \"hi\"");
    assert_eq!(docs[1].content, "name: Smith\nquote: ");
    let (s, e): (usize, usize) = (
        docs[0].metadata["byte_start"].parse().unwrap(),
        docs[0].metadata["byte_end"].parse().unwrap(),
    );
    assert_eq!(&input[s..e], "\"Doe, J\",\"He said \"\"hi\"\"\"");

    let tsv = CsvLoader::new()
        .delimiter(b'\t')
        .has_headers(false)
        .load_str("a\tb\tc\n")
        .unwrap();
    assert_eq!(tsv[0].content, "column_1: a\ncolumn_2: b\ncolumn_3: c");

    let err = CsvLoader::new()
        .content_columns(&["missing"])
        .load_str("a\n1\n")
        .unwrap_err();
    assert!(matches!(err, LoadError::MissingField { line: 1, .. }));
}

#[test]
fn csv_streams_from_a_reader() {
    let input = "text\nrow1\nrow2\nrow3\n";
    let mut iter = CsvLoader::new()
        .limits(Limits::default().with_max_records(2))
        .iter(std::io::BufReader::new(input.as_bytes()));
    assert_eq!(iter.next().unwrap().unwrap().content, "text: row1");
    assert_eq!(iter.next().unwrap().unwrap().content, "text: row2");
    assert!(matches!(
        iter.next(),
        Some(Err(LoadError::TooManyRecords { limit: 2 }))
    ));
    assert!(iter.next().is_none());
}

#[test]
fn glob_semantics() {
    let g = |p: &str| Glob::new(p).unwrap();
    assert!(g("*.md").matches("a/b/c.md"));
    assert!(!g("*.md").matches("a/b/c.mdx"));
    assert!(g("src/*.rs").matches("src/lib.rs"));
    assert!(!g("src/*.rs").matches("src/x/lib.rs"));
    assert!(g("**/*.rs").matches("lib.rs"));
    assert!(g("src/**").matches("src/a/b"));
    assert!(g("file?.[ch]").matches("file1.c"));
    assert!(!g("file?.[!ch]").matches("file1.c"));
    assert!(g("[a-c]x").matches("bx"));
    assert!(g(r"\*").matches("*"));
    for bad in ["", "[abc", "trailing\\"] {
        assert!(matches!(
            Glob::new(bad),
            Err(LoadError::InvalidPattern { .. })
        ));
    }
    // Pathological pattern stays polynomial.
    let evil = format!("{}b", "*a".repeat(200));
    assert!(!g(&evil).matches(&"a".repeat(5000)));
}

proptest! {
    #[test]
    fn html_never_panics_and_never_grows_much(input in any::<String>()) {
        let text = html_to_text(&input);
        prop_assert!(text.len() <= input.len() * 4 + 16);
        let _ = html_title(&input);
    }

    #[test]
    fn html_survives_tag_soup(parts in prop::collection::vec(
        prop::sample::select(vec!["<", ">", "</", "<script>", "</script>", "<!--", "-->", "&", "&#", "&amp;",
            ";", "\"", "'", "<p ", "x", "é", "<title>", "<!", "/>", "&#x"]), 0..64)) {
        let input: String = parts.concat();
        let _ = html_to_text(&input);
    }

    #[test]
    fn csv_never_panics(input in any::<Vec<u8>>(), tab in any::<bool>(), headers in any::<bool>()) {
        let loader = CsvLoader::new()
            .delimiter(if tab { b'\t' } else { b',' })
            .has_headers(headers)
            .limits(Limits::default().with_max_record_bytes(64));
        for doc in loader.iter(&input[..]).flatten() {
            let s: usize = doc.metadata["byte_start"].parse().unwrap();
            let e: usize = doc.metadata["byte_end"].parse().unwrap();
            prop_assert!(s <= e && e <= input.len());
        }
    }

    #[test]
    fn csv_round_trips_quoted_cells(cells in prop::collection::vec("[^\r]{0,12}", 1..5)) {
        let header: Vec<String> = (0..cells.len()).map(|i| format!("c{i}")).collect();
        let row: Vec<String> = cells.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).collect();
        let input = format!("{}\n{}\n", header.join(","), row.join(","));
        let docs = CsvLoader::new()
            .metadata_columns(&header.iter().map(String::as_str).collect::<Vec<_>>())
            .load_str(&input)
            .unwrap();
        prop_assert_eq!(docs.len(), 1);
        for (name, cell) in header.iter().zip(&cells) {
            prop_assert_eq!(&docs[0].metadata[name], cell);
        }
    }

    #[test]
    fn jsonl_never_panics(input in any::<Vec<u8>>()) {
        for item in JsonlLoader::new().strict(true).limits(Limits::default().with_max_record_bytes(32)).iter(&input[..]) {
            let _ = item;
        }
    }

    #[test]
    fn json_never_panics(input in any::<String>(), pointer in "(/[a-z0-9]{0,3}){0,3}") {
        let _ = JsonLoader::new().load_str(&input);
        if let Ok(loader) = JsonLoader::new().records(&format!("/{pointer}")) {
            let _ = loader.skip_invalid(true).load_str(&input);
        }
    }

    #[test]
    fn glob_never_panics(pattern in "[a-z*?/\\[\\]!^\\\\-]{0,24}", path in "[a-z/.]{0,32}") {
        if let Ok(glob) = Glob::new(&pattern) {
            let _ = glob.matches(&path);
        }
    }

    #[test]
    fn literal_globs_match_themselves(name in "[a-z0-9_.-]{1,16}") {
        prop_assert!(Glob::new(&name).unwrap().matches(&name));
        let nested = format!("dir/{name}");
        prop_assert!(Glob::new(&name).unwrap().matches(&nested));
    }
}

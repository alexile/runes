//! Limits, jail and directory-walk hardening. Everything runs in a
//! temporary directory; nothing touches the network.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::fs;

use rune_chain_loader::csv::CsvLoader;
use rune_chain_loader::jsonl::JsonlLoader;
use rune_chain_loader::{DirectoryLoader, Glob, Jail, Limits, LoadError, TextLoader, text};

fn sorted_relative(docs: &[rune_chain_loader::Document]) -> Vec<String> {
    let mut paths: Vec<String> = docs
        .iter()
        .map(|d| d.metadata["relative_path"].clone())
        .collect();
    paths.sort();
    paths
}

#[test]
fn file_size_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    fs::write(&path, "x".repeat(2048)).unwrap();
    let loader = TextLoader::new().limits(Limits::default().with_max_file_bytes(1024));
    assert!(matches!(
        loader.load_file(&path),
        Err(LoadError::TooLarge { limit: 1024, .. })
    ));
    let exact = TextLoader::new().limits(Limits::default().with_max_file_bytes(2048));
    assert_eq!(exact.load_file(&path).unwrap().content.len(), 2048);
}

#[test]
fn reader_size_limit_is_enforced() {
    let loader = TextLoader::new().limits(Limits::default().with_max_file_bytes(3));
    assert!(loader.load_reader(&b"abc"[..], "r").is_ok());
    assert!(matches!(
        loader.load_reader(&b"abcd"[..], "r"),
        Err(LoadError::TooLarge { .. })
    ));
}

#[test]
fn directories_are_not_regular_files() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        text::load_file(dir.path()),
        Err(LoadError::NotRegularFile { .. })
    ));
}

#[test]
fn bom_is_stripped_and_hash_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bom.txt");
    fs::write(&path, "\u{feff}hello").unwrap();
    let doc = text::load_file(&path).unwrap();
    assert_eq!(doc.content, "hello");
    assert_eq!(doc.metadata["content_sha256"], doc.content_sha256());
}

#[test]
fn jail_rejects_dotdot_and_absolute_escapes() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(outer.path().join("secret.txt"), "secret").unwrap();
    fs::write(root.join("ok.txt"), "ok").unwrap();

    let loader = TextLoader::new().jail(Jail::new(&root).unwrap());
    assert_eq!(loader.load_file("ok.txt").unwrap().content, "ok");
    assert!(matches!(
        loader.load_file("../secret.txt"),
        Err(LoadError::OutsideRoot { .. })
    ));
    assert!(matches!(
        loader.load_file(outer.path().join("secret.txt")),
        Err(LoadError::OutsideRoot { .. })
    ));
}

#[cfg(unix)]
#[test]
fn jail_rejects_symlinks_pointing_outside() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(outer.path().join("secret.txt"), "secret").unwrap();
    fs::write(root.join("inside.txt"), "inside").unwrap();
    std::os::unix::fs::symlink(outer.path().join("secret.txt"), root.join("leak.txt")).unwrap();
    std::os::unix::fs::symlink(root.join("inside.txt"), root.join("alias.txt")).unwrap();

    let jail = Jail::new(&root).unwrap();
    let loader = TextLoader::new().jail(jail.clone());
    assert!(matches!(
        loader.load_file("leak.txt"),
        Err(LoadError::OutsideRoot { .. })
    ));
    assert_eq!(loader.load_file("alias.txt").unwrap().content, "inside");
    assert!(matches!(
        JsonlLoader::new().jail(jail.clone()).load_file("leak.txt"),
        Err(LoadError::OutsideRoot { .. })
    ));
    assert!(matches!(
        CsvLoader::new().jail(jail).load_file("leak.txt"),
        Err(LoadError::OutsideRoot { .. })
    ));
}

#[cfg(unix)]
#[test]
fn walk_skips_symlinks_by_default_and_contains_them_when_following() {
    use std::os::unix::fs::symlink;
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::create_dir(outer.path().join("elsewhere")).unwrap();
    fs::write(outer.path().join("elsewhere/secret.txt"), "secret").unwrap();
    fs::write(root.join("sub/a.txt"), "a").unwrap();
    // A file link inside, a link out of the root, and a loop back to the root.
    symlink(root.join("sub/a.txt"), root.join("link.txt")).unwrap();
    symlink(outer.path().join("elsewhere"), root.join("out")).unwrap();
    symlink(&root, root.join("sub/loop")).unwrap();

    let docs = DirectoryLoader::new(&root).load().unwrap();
    assert_eq!(sorted_relative(&docs), ["sub/a.txt"]);

    let docs = DirectoryLoader::new(&root)
        .follow_symlinks(true)
        .load()
        .unwrap();
    // `link.txt` is followed (target inside); `out` is not; `sub/loop` is a
    // directory already visited, so the walk terminates.
    assert_eq!(sorted_relative(&docs), ["link.txt", "sub/a.txt"]);
    assert!(docs.iter().all(|d| d.content != "secret"));
}

#[cfg(unix)]
#[test]
fn fifos_are_skipped_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe.txt");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !status.is_ok_and(|s| s.success()) {
        return; // no mkfifo available; nothing to test
    }
    fs::write(dir.path().join("a.txt"), "a").unwrap();
    let docs = text::load_dir(dir.path()).unwrap();
    assert_eq!(docs.len(), 1);
    assert!(matches!(
        text::load_file(&fifo),
        Err(LoadError::NotRegularFile { .. })
    ));
}

#[test]
fn walk_depth_and_file_limits() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c");
    fs::create_dir_all(&deep).unwrap();
    fs::write(dir.path().join("0.txt"), "0").unwrap();
    fs::write(dir.path().join("a/1.txt"), "1").unwrap();
    fs::write(dir.path().join("a/b/2.txt"), "2").unwrap();
    fs::write(deep.join("3.txt"), "3").unwrap();

    let depth1 = DirectoryLoader::new(dir.path())
        .limits(Limits::default().with_max_depth(1))
        .load()
        .unwrap();
    assert_eq!(sorted_relative(&depth1), ["0.txt", "a/1.txt"]);

    let flat = DirectoryLoader::new(dir.path())
        .recursive(false)
        .load()
        .unwrap();
    assert_eq!(sorted_relative(&flat), ["0.txt"]);

    let err = DirectoryLoader::new(dir.path())
        .limits(Limits::default().with_max_files(3))
        .load()
        .unwrap_err();
    assert!(matches!(err, LoadError::TooManyFiles { limit: 3 }));
}

#[test]
fn walk_globs_hidden_files_and_pruning() {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["docs/api", "node_modules/pkg", ".git"] {
        fs::create_dir_all(dir.path().join(sub)).unwrap();
    }
    for (path, body) in [
        ("docs/guide.md", "guide"),
        ("docs/api/ref.md", "ref"),
        ("docs/api/ref.txt", "ref txt"),
        ("node_modules/pkg/readme.md", "dep"),
        (".git/notes.md", "git"),
        (".env.md", "secret"),
        ("top.md", "top"),
    ] {
        fs::write(dir.path().join(path), body).unwrap();
    }

    let docs = DirectoryLoader::new(dir.path())
        .include([Glob::new("*.md").unwrap()])
        .exclude([Glob::new("node_modules").unwrap()])
        .load()
        .unwrap();
    assert_eq!(
        sorted_relative(&docs),
        ["docs/api/ref.md", "docs/guide.md", "top.md"]
    );

    let docs = DirectoryLoader::new(dir.path())
        .include_patterns(&["docs/**"])
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(
        sorted_relative(&docs),
        ["docs/api/ref.md", "docs/api/ref.txt", "docs/guide.md"]
    );

    let docs = DirectoryLoader::new(dir.path())
        .include_patterns(&["*.md"])
        .unwrap()
        .hidden(true)
        .exclude_patterns(&["node_modules", "docs"])
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(
        sorted_relative(&docs),
        [".env.md", ".git/notes.md", "top.md"]
    );
}

#[test]
fn walk_iter_surfaces_per_file_errors_and_load_skips_them() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("ok.txt"), "ok").unwrap();
    fs::write(dir.path().join("bad.txt"), [0xff, 0xfe]).unwrap();
    fs::write(dir.path().join("big.txt"), "x".repeat(100)).unwrap();
    let loader = DirectoryLoader::new(dir.path()).limits(Limits::default().with_max_file_bytes(10));
    let results: Vec<_> = loader.documents().unwrap().collect();
    assert_eq!(results.len(), 3);
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 2);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(LoadError::is_per_file)
    );
    assert_eq!(loader.load().unwrap().len(), 1);
}

#[test]
fn jsonl_record_limits() {
    let long = format!("{{\"content\":\"{}\"}}", "x".repeat(200));
    let input = format!("{{\"content\":\"a\"}}\n{long}\n{{\"content\":\"b\"}}\n");
    let limits = Limits::default().with_max_record_bytes(64);

    let lenient = JsonlLoader::new().limits(limits).load_str(&input).unwrap();
    assert_eq!(lenient.len(), 2);
    assert_eq!(lenient[1].metadata["line"], "3");

    let strict: Vec<_> = JsonlLoader::new()
        .limits(limits)
        .strict(true)
        .iter(input.as_bytes())
        .collect();
    assert!(matches!(
        strict[1],
        Err(LoadError::RecordTooLarge { line: 2, limit: 64 })
    ));
    assert!(
        strict[2].is_ok(),
        "reader stays in sync after an over-long line"
    );

    let err = JsonlLoader::new()
        .limits(Limits::default().with_max_records(1))
        .load_str(&input)
        .unwrap_err();
    assert!(matches!(err, LoadError::TooManyRecords { limit: 1 }));
}

#[test]
fn csv_unterminated_quote_is_bounded() {
    let input = format!("a,b\n1,\"{}", "y".repeat(10_000));
    let err = CsvLoader::new()
        .limits(Limits::default().with_max_record_bytes(1024))
        .load_str(&input)
        .unwrap_err();
    assert!(matches!(err, LoadError::RecordTooLarge { line: 2, .. }));
    let err = CsvLoader::new().load_str("a\n\"open").unwrap_err();
    assert!(matches!(err, LoadError::Parse { line: 2, .. }));
}

#[test]
fn deeply_nested_json_is_an_error_not_a_stack_overflow() {
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let err = rune_chain_loader::json::JsonLoader::new()
        .load_str(&deep)
        .unwrap_err();
    assert!(matches!(err, LoadError::Parse { .. }));
    let line = format!(
        "{{\"content\":\"x\",\"n\":{}{}}}",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let strict: Vec<_> = JsonlLoader::new()
        .strict(true)
        .iter(line.as_bytes())
        .collect();
    assert!(matches!(strict[0], Err(LoadError::Parse { .. })));
}

#[test]
fn records_cannot_spoof_loader_metadata() {
    let input = r#"{"content":"real","content_sha256":"forged","line":"99"}"#;
    let docs = JsonlLoader::new().load_str(input).unwrap();
    assert_eq!(docs[0].metadata["line"], "1");
    assert_eq!(docs[0].metadata["content_sha256"], docs[0].content_sha256());
}

#[cfg(unix)]
#[test]
fn followed_symlinks_cannot_reach_excluded_or_hidden_entries() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("private/keys")).unwrap();
    fs::write(root.join("private/keys/key.txt"), "private").unwrap();
    fs::write(root.join(".env.txt"), "hidden").unwrap();
    fs::write(root.join("ok.txt"), "ok").unwrap();
    // Aliases with innocent names pointing at an excluded directory, a file
    // under it, and a hidden file.
    symlink(root.join("private"), root.join("public")).unwrap();
    symlink(root.join("private/keys/key.txt"), root.join("key.txt")).unwrap();
    symlink(root.join(".env.txt"), root.join("env.txt")).unwrap();

    let docs = DirectoryLoader::new(root)
        .exclude_patterns(&["private"])
        .unwrap()
        .follow_symlinks(true)
        .load()
        .unwrap();
    assert_eq!(sorted_relative(&docs), ["ok.txt"]);
}

#[test]
fn csv_header_repetition_cannot_amplify_output() {
    // A 64 KiB header repeated into each of 20,000 one-byte rows would
    // produce about 1.3 GB of content from roughly 100 KB of input.
    let header = (0..8_000)
        .map(|i| format!("c{i:05}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut input = header;
    input.push('\n');
    input.push_str(&"x\n".repeat(20_000));

    let mut produced = 0usize;
    let mut rejected = false;
    for doc in CsvLoader::new().iter(input.as_bytes()) {
        match doc {
            Ok(doc) => produced += doc.content.len(),
            Err(err) => {
                assert!(matches!(err, LoadError::OutputTooLarge { .. }), "{err}");
                rejected = true;
                break;
            }
        }
    }
    assert!(
        rejected,
        "produced {produced} bytes without hitting a limit"
    );
    assert!(produced <= Limits::DEFAULT.max_total_bytes);

    // A tight limit is honoured exactly, and legitimate input below it is unchanged.
    let limits = Limits::default().with_max_total_bytes(10);
    let ok = CsvLoader::new()
        .limits(limits)
        .load_str("a,b\n1,2\n")
        .unwrap();
    assert_eq!(ok[0].content, "a: 1\nb: 2");
    let err = CsvLoader::new()
        .limits(limits)
        .load_str("a,b\n1,2\n3,4\n")
        .unwrap_err();
    assert!(
        matches!(err, LoadError::OutputTooLarge { limit: 10 }),
        "{err}"
    );
}

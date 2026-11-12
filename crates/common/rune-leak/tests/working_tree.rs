//! Working-tree scanning with `run`.

use rune_leak::{ScanOptions, run};

#[test]
fn walks_tree_skips_excluded_and_binary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/conf")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    std::fs::write(
        root.join("src/conf/app.py"),
        "API_KEY = \"s3cr3tP@sswordValue123\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("node_modules/pkg/x.js"),
        "k='AKIAIOSFODNN7EXAMPLE'\n",
    )
    .unwrap();
    std::fs::write(root.join("blob.bin"), b"\xff\xfe AKIAIOSFODNN7EXAMPLE").unwrap();
    std::fs::write(
        root.join("id_rsa"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n",
    )
    .unwrap();

    let report = run(&ScanOptions::new(root)).unwrap();
    let mut got: Vec<_> = report
        .findings
        .iter()
        .map(|f| match &f.location {
            rune_finding::Location::File {
                path, start_line, ..
            } => (f.check_id.clone(), path.clone(), *start_line),
            other => panic!("unexpected location {other:?}"),
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            (
                "secret.generic_assignment".to_owned(),
                "src/conf/app.py".to_owned(),
                Some(1)
            ),
            (
                "secret.private_key_block".to_owned(),
                "id_rsa".to_owned(),
                Some(1)
            ),
        ]
    );
    assert_eq!(report.files_scanned, 2);
}

#[test]
fn single_file_budget_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("many.env");
    std::fs::write(
        &file,
        "A=AKIAIOSFODNN7EXAMPLE\nB=AKIAIOSFODNN7EXAMPLF\nC=AKIAIOSFODNN7EXAMPLG\n",
    )
    .unwrap();
    let report = run(&ScanOptions::new(&file).with_max_findings(2)).unwrap();
    assert_eq!(report.findings.len(), 2);
    assert!(
        matches!(&report.findings[0].location, rune_finding::Location::File { path, .. } if path == "many.env")
    );

    assert_eq!(
        run(&ScanOptions::default()).unwrap_err().code(),
        "empty_path"
    );
    assert_eq!(
        run(&ScanOptions::new(dir.path().join("nope")))
            .unwrap_err()
            .code(),
        "io"
    );
}

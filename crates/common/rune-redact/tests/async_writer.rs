//! `AsyncRedactingWriter` redacts across chunk boundaries.

use rune_redact::{AsyncRedactingWriter, Redactor};
use tokio::io::AsyncWriteExt;

const TEXT: &str = "login bob@example.com from 192.168.0.7\n\
    key=AKIAIOSFODNN7EXAMPLE card 4111-1111-1111-1111 tail";

#[tokio::test]
async fn redacts_split_secrets() {
    let redactor = Redactor::default();
    let want = redactor.redact(TEXT);
    for size in [1, 2, 3, 7, 13, 64] {
        let mut w = AsyncRedactingWriter::new(Vec::new(), redactor.clone());
        for chunk in TEXT.as_bytes().chunks(size) {
            w.write_all(chunk).await.unwrap();
        }
        w.flush().await.unwrap();
        w.shutdown().await.unwrap();
        let out = String::from_utf8(w.into_inner()).unwrap();
        assert_eq!(out, want, "chunk size {size}");
        assert!(!out.contains("AKIA") && !out.contains("bob@"));
    }
}

#[tokio::test]
async fn works_over_a_duplex_pipe() {
    use tokio::io::AsyncReadExt;
    let (client, mut server) = tokio::io::duplex(8);
    let writer = tokio::spawn(async move {
        let mut w = AsyncRedactingWriter::new(client, Redactor::default());
        w.write_all(b"ssn 123-45-").await.unwrap();
        w.write_all(b"6789 done\n").await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut out = String::new();
    server.read_to_string(&mut out).await.unwrap();
    writer.await.unwrap();
    assert_eq!(out, "ssn [SSN] done\n");
}

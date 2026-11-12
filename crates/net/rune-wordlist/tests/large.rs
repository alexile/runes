//! Streams a large list and checks that memory stays flat.
//!
//! This file holds a single test so that the peak-RSS measurement is not
//! disturbed by other tests running in parallel threads.

use std::fs::File;
use std::io::{BufWriter, Write};

use rune_wordlist::{Keyring, ListKind, Options, Pack, PackBuilder, SecretKey, Version};

/// Size of the generated list.
const LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Peak resident set size of this process in KiB (Linux only).
fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn streams_large_list_with_flat_memory() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("big.txt");
    let mut out = BufWriter::new(File::create(&path).unwrap());
    let (mut written, mut lines) = (0u64, 0u64);
    while written < LIST_BYTES {
        let line = format!("/path/{lines:010}/entry\n");
        out.write_all(line.as_bytes()).unwrap();
        written += line.len() as u64;
        lines += 1;
    }
    out.flush().unwrap();
    drop(out);

    let key = SecretKey::from_seed(&[3; 32]);
    PackBuilder::new("big", Version::new(1, 0, 0))
        .unwrap()
        .list("big", "big.txt", ListKind::Wordlist)
        .unwrap()
        .write(tmp.path(), &key)
        .unwrap();

    let before = peak_rss_kib();
    let ring = Keyring::new().with_key(key.public_key());
    // Eager: one hashing pass at open, then a second while streaming.
    let pack = Pack::open(tmp.path(), &ring, &Options::default()).unwrap();
    let mut reader = pack.list("big").unwrap();
    let mut buf = Vec::new();
    let mut count = 0u64;
    while reader.read_entry(&mut buf).unwrap() {
        count += 1;
    }
    assert_eq!(count, lines);
    assert_eq!(reader.bytes_read(), written);
    assert!(
        buf.capacity() < 1024,
        "line buffer grew to {}",
        buf.capacity()
    );

    if let (Some(before), Some(after)) = (before, peak_rss_kib()) {
        let growth = after.saturating_sub(before);
        // 64 MiB went through; the reader may add its 64 KiB buffer and some
        // allocator slack, nowhere near the list size.
        assert!(
            growth < 8 * 1024,
            "peak RSS grew by {growth} KiB while streaming 64 MiB"
        );
    }
}

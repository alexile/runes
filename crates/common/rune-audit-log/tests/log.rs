//! Append/verify tests over the memory and file stores.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail the test on error"
)]

use std::fs;
use std::io::Write;

use rune_audit_log::{
    AuditLog, Chain, Digest, Entry, Error, FileStore, HmacSha256, JsonlReader, MemoryStore, Record,
    Store, Tamper, Verifier,
};

fn entry(i: u64) -> Entry {
    Entry::new(format!("user{i}"), "act")
        .with_target(format!("t{i}"))
        .with_field("n", i.to_string())
}

fn filled(n: u64) -> AuditLog<MemoryStore> {
    let mut log = AuditLog::open(MemoryStore::new()).unwrap();
    for i in 0..n {
        log.append_at(entry(i), 1_000 + i).unwrap();
    }
    log
}

type Tampering = fn(&mut Vec<Record>);

fn tampered_kind(result: Result<rune_audit_log::Verified, Error>) -> (u64, Tamper) {
    match result {
        Err(Error::Tampered { seq, kind }) => (seq, kind),
        other => panic!("expected tampering, got {other:?}"),
    }
}

#[test]
fn empty_log_verifies() {
    let log = AuditLog::open(MemoryStore::new()).unwrap();
    let verified = log.verify().unwrap();
    assert_eq!((verified.count, verified.head), (0, Digest::GENESIS));
}

#[test]
fn append_links_records() {
    let log = filled(3);
    let records = log.store().as_slice();
    assert_eq!(records[0].prev, Digest::GENESIS);
    assert_eq!(records[1].prev, records[0].hash);
    assert_eq!(records[2].prev, records[1].hash);
    assert_eq!(log.head(), records[2].hash);
    assert_eq!(log.next_seq(), 3);
    assert_eq!(log.verify().unwrap().count, 3);
}

#[test]
fn every_kind_of_tampering_is_detected() {
    let cases: Vec<(&str, Tampering, u64, Tamper)> = vec![
        (
            "edit actor",
            |r| r[1].entry.actor.push('x'),
            1,
            Tamper::HashMismatch,
        ),
        (
            "edit field",
            |r| {
                r[2].entry.fields.insert("n".into(), "9".into());
            },
            2,
            Tamper::HashMismatch,
        ),
        (
            "drop target",
            |r| r[0].entry.target = None,
            0,
            Tamper::HashMismatch,
        ),
        ("edit ts", |r| r[3].ts += 1, 3, Tamper::HashMismatch),
        (
            "delete middle",
            |r| {
                r.remove(2);
            },
            3,
            Tamper::Sequence { expected: 2 },
        ),
        (
            "swap",
            |r| r.swap(1, 2),
            2,
            Tamper::Sequence { expected: 1 },
        ),
        (
            "relink",
            |r| r[2].prev = Digest([1; 32]),
            2,
            Tamper::BrokenLink,
        ),
    ];
    for (name, tamper, seq, kind) in cases {
        let mut store = filled(5).into_store();
        tamper(store.records_mut());
        let log = AuditLog::open(store).unwrap();
        assert_eq!(tampered_kind(log.verify()), (seq, kind), "{name}");
    }
}

#[test]
fn rehashed_rewrite_is_caught_by_signature_or_checkpoint() {
    let key = HmacSha256::new(b"k");
    let mut log = AuditLog::open(MemoryStore::new())
        .unwrap()
        .with_signer(key.clone());
    for i in 0..3 {
        log.append_at(entry(i), i).unwrap();
    }
    let checkpoint = log.head();
    // An attacker without the key rewrites record 1 and re-chains the rest.
    let mut records = log.into_store().as_slice().to_vec();
    let mut chain = Chain::resume(&records[0]).unwrap();
    let mut forged = vec![records.remove(0)];
    for record in records {
        let mut e = record.entry.clone();
        e.action = "forged".into();
        let mut r = chain.seal(e, record.ts, None).unwrap();
        r.sig = record.sig.clone();
        forged.push(r);
    }
    let mut store = MemoryStore::new();
    for record in &forged {
        store.append(record).unwrap();
    }
    let unsigned = AuditLog::open(store.clone()).unwrap();
    // Without a key the chain itself looks fine; the checkpoint catches it.
    assert!(unsigned.verify().is_ok());
    assert_eq!(
        tampered_kind(unsigned.verify_against(&checkpoint)).1,
        Tamper::HeadMismatch
    );
    // With the key, the stale signature on record 1 gives it away.
    let signed = AuditLog::open(store).unwrap().with_signer(key);
    assert_eq!(tampered_kind(signed.verify()), (1, Tamper::BadSignature));
}

#[test]
fn truncation_needs_a_checkpoint() {
    let log = filled(4);
    let checkpoint = log.head();
    let mut store = log.into_store();
    store.records_mut().pop();
    let log = AuditLog::open(store).unwrap();
    assert_eq!(log.verify().unwrap().count, 3);
    assert_eq!(
        tampered_kind(log.verify_against(&checkpoint)),
        (3, Tamper::HeadMismatch)
    );
}

#[test]
fn missing_signature_is_detected() {
    let log = filled(2);
    let signed = AuditLog::open(log.into_store())
        .unwrap()
        .with_signer(HmacSha256::new(b"k"));
    assert_eq!(
        tampered_kind(signed.verify()),
        (0, Tamper::MissingSignature)
    );
}

#[test]
fn open_rejects_a_forged_head() {
    let mut store = filled(2).into_store();
    store.records_mut()[1].entry.action = "x".into();
    assert!(matches!(
        AuditLog::open(store),
        Err(Error::Tampered {
            seq: 1,
            kind: Tamper::HashMismatch
        })
    ));
}

#[test]
fn verifier_from_checkpoint() {
    let log = filled(4);
    let records = log.store().as_slice();
    let mut verifier = Verifier::starting_at(2, records[1].hash);
    verifier.push(&records[2]).unwrap();
    verifier.push(&records[3]).unwrap();
    assert_eq!(verifier.finish().count, 2);
    assert_eq!(verifier.finish().head, log.head());
}

#[test]
fn file_store_persists_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    {
        let mut log = AuditLog::open(FileStore::open(&path).unwrap().with_sync(true)).unwrap();
        log.append_at(entry(0), 10).unwrap();
        log.append_at(entry(1), 20).unwrap();
    }
    let mut log = AuditLog::open(FileStore::open(&path).unwrap()).unwrap();
    assert_eq!(log.next_seq(), 2);
    log.append_at(entry(2), 30).unwrap();
    assert_eq!(log.verify().unwrap().count, 3);
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 3);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mut exported = Vec::new();
    assert_eq!(log.export_jsonl(&mut exported).unwrap(), 3);
    assert_eq!(exported, fs::read(&path).unwrap());
}

#[test]
fn file_tampering_fails_verification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(FileStore::open(&path).unwrap()).unwrap();
    for i in 0..3 {
        log.append_at(entry(i), i).unwrap();
    }
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replacen("user1", "userX", 1)).unwrap();
    assert_eq!(tampered_kind(log.verify()), (1, Tamper::HashMismatch));

    fs::write(&path, text.replacen("\"seq\":1", "\"seq\":\"one\"", 1)).unwrap();
    assert!(matches!(
        log.verify(),
        Err(Error::Corrupt { line: Some(2), .. })
    ));
}

#[test]
fn file_store_bounds_lines_and_detects_torn_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(FileStore::open(&path).unwrap().with_max_line_len(300)).unwrap();
    log.append_at(entry(0), 0).unwrap();
    let big = Entry::new("a", "b").with_field("blob", "x".repeat(400));
    assert!(matches!(
        log.append_at(big, 1),
        Err(Error::TooLarge { max: 300, .. })
    ));
    // The failed append did not advance the chain.
    log.append_at(entry(1), 1).unwrap();
    assert_eq!(log.verify().unwrap().count, 2);

    // A reader with a smaller bound refuses the lines instead of buffering.
    let store = FileStore::open(&path).unwrap().with_max_line_len(20);
    assert!(matches!(store.last(), Err(Error::TooLarge { .. })));
    assert!(matches!(
        store.records().unwrap().next(),
        Some(Err(Error::TooLarge { .. }))
    ));

    // A half-written last line is reported on reopen.
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"seq\":2")
        .unwrap();
    assert!(matches!(
        FileStore::open(&path).unwrap().last(),
        Err(Error::Corrupt { line: None, .. })
    ));
}

#[test]
fn jsonl_reader_skips_blank_lines_and_accepts_crlf() {
    let log = filled(2);
    let mut out = Vec::new();
    log.export_jsonl(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap().replace('\n', "\r\n\r\n");
    let mut verifier = Verifier::new();
    for record in JsonlReader::new(text.as_bytes()) {
        verifier.push(&record.unwrap()).unwrap();
    }
    assert_eq!(verifier.finish().head, log.head());
}

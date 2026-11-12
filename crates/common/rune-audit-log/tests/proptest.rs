//! Property tests: any single change to a stored log fails verification,
//! and the JSON-lines reader never panics.

use proptest::prelude::*;
use rune_audit_log::{AuditLog, Entry, JsonlReader, MemoryStore};

fn arb_entry() -> impl Strategy<Value = Entry> {
    (
        any::<String>(),
        any::<String>(),
        prop::option::of(any::<String>()),
        prop::collection::btree_map(any::<String>(), any::<String>(), 0..3),
    )
        .prop_map(|(actor, action, target, fields)| {
            let mut entry = Entry::new(actor, action);
            entry.target = target;
            entry.fields = fields;
            entry
        })
}

proptest! {
    #[test]
    fn any_tampering_fails_verification(
        entries in prop::collection::vec((arb_entry(), any::<u64>()), 1..8),
        pick in any::<prop::sample::Index>(),
        how in 0u8..8,
        junk in any::<String>(),
    ) {
        let mut log = AuditLog::open(MemoryStore::new()).unwrap();
        for (entry, ts) in &entries {
            log.append_at(entry.clone(), *ts).unwrap();
        }
        let head = log.head();
        prop_assert!(log.verify_against(&head).is_ok());

        let mut store = log.into_store();
        let records = store.records_mut();
        let i = pick.index(records.len());
        let before = records.clone();
        let r = &mut records[i];
        match how {
            0 => r.entry.actor = format!("{}{junk}!", r.entry.actor),
            1 => r.entry.action = format!("{}{junk}~", r.entry.action),
            2 => r.entry.target = if r.entry.target.is_some() { None } else { Some(junk) },
            3 => { r.entry.fields.insert(format!("{junk}\u{0}"), String::new()); }
            4 => r.ts = r.ts.wrapping_add(1),
            5 => r.seq = r.seq.wrapping_add(1),
            6 => r.hash.0[0] ^= 1,
            _ => { records.remove(i); }
        }
        prop_assume!(*records != before);
        // The tampered store may not even reopen (forged head); either way
        // it must not verify against the saved head.
        if let Ok(log) = AuditLog::open(store) {
            prop_assert!(log.verify_against(&head).is_err());
        }
    }

    #[test]
    fn jsonl_reader_never_panics(text in any::<String>(), max in 0usize..64) {
        for record in JsonlReader::new(text.as_bytes()).with_max_line_len(max).take(100) {
            let _ = record;
        }
    }
}

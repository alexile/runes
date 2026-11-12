//! Property tests: manifest round trips, the reader agrees with a naive
//! line split, any change to a list is detected, and no input panics.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_wordlist::{
    KeyId, ListEntry, ListKind, ListReader, Manifest, ReadOptions, Signature, Version, sha256,
    verify_manifest,
};

fn name() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._-]{0,20}"
}

fn path() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-zA-Z0-9_][a-zA-Z0-9._ -]{0,10}", 1..4).prop_map(|c| c.join("/"))
}

fn manifest() -> impl Strategy<Value = Manifest> {
    (
        name(),
        any::<(u32, u32, u32)>(),
        any::<[u8; 8]>(),
        prop::option::of(".*"),
        prop::collection::vec(
            (
                path(),
                any::<[u8; 32]>(),
                any::<u64>(),
                prop::option::of(any::<u64>()),
                any::<bool>(),
            ),
            0..5,
        ),
    )
        .prop_map(|(name, (a, b, c), id, description, lists)| {
            let mut m = Manifest::new(name, Version::new(a, b, c), KeyId(id)).unwrap();
            m.description = description;
            for (i, (path, hash, size, entries, payload)) in lists.into_iter().enumerate() {
                let mut e = ListEntry::new(format!("list{i}"), path, hash, size);
                if payload {
                    e = e.with_kind(ListKind::Payload);
                }
                if let Some(n) = entries {
                    e = e.with_entries(n);
                }
                m.lists.push(e);
            }
            m
        })
}

/// The entries a straightforward split produces with the default options.
fn naive(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = data
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec())
        .collect();
    if data.ends_with(b"\n") || data.is_empty() {
        out.pop();
    }
    out.retain(|l| !l.is_empty());
    out
}

proptest! {
    #[test]
    fn manifest_round_trip(m in manifest()) {
        let text = m.to_toml().unwrap();
        prop_assert_eq!(Manifest::parse(text.as_bytes()).unwrap(), m);
    }

    #[test]
    fn version_round_trip(a: u32, b: u32, c: u32) {
        let v = Version::new(a, b, c);
        prop_assert_eq!(v.to_string().parse::<Version>().unwrap(), v);
    }

    #[test]
    fn reader_matches_naive_split(
        data in prop::collection::vec(prop::sample::select(b"ab\r\n#\xff".to_vec()), 0..300),
        buffer in 1usize..16,
    ) {
        let entry = ListEntry::new("l", "l", sha256(&data), data.len() as u64);
        let opts = ReadOptions::default().with_buffer_size(buffer);
        let got: Vec<Vec<u8>> = ListReader::new(&data[..], &entry, &opts)
            .collect::<Result<_, _>>()
            .unwrap();
        prop_assert_eq!(got, naive(&data));
    }

    #[test]
    fn any_change_is_detected(
        data in prop::collection::vec(any::<u8>(), 1..300),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let entry = ListEntry::new("l", "l", sha256(&data), data.len() as u64);
        let mut bad = data.clone();
        bad[index.index(data.len())] ^= flip;
        let r: Result<Vec<_>, _> = ListReader::new(&bad[..], &entry, &ReadOptions::default()).collect();
        prop_assert!(r.is_err());
    }

    #[test]
    fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..400), text in ".*") {
        let _ = Manifest::parse(&bytes);
        let _ = Manifest::parse(text.as_bytes());
        let _ = Signature::parse(&text);
        let _ = text.parse::<Version>();
        let _ = verify_manifest(&bytes, &text, &rune_wordlist::Keyring::new());
        let entry = ListEntry::new("l", "l", [0; 32], 64);
        let opts = ReadOptions::default().with_max_line_len(8);
        let _: Vec<_> = ListReader::new(&bytes[..], &entry, &opts).collect();
    }
}

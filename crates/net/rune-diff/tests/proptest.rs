//! Property tests: edit scripts are valid and minimal on small inputs,
//! tokenizers round-trip, masking is idempotent, and nothing panics.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_diff::{
    DiffOp, DiffOptions, EditScript, Granularity, HttpDiffOptions, HttpDiffer, MaskOptions, Masker,
    TextDiff, diff_slices,
};
use rune_http_model::HttpResponse;

/// Applies `script` to `old`, checking that the ops tile both sequences.
fn apply(old: &[u8], new: &[u8], script: &EditScript) -> Vec<u8> {
    let (mut oi, mut ni) = (0, 0);
    let mut out = Vec::new();
    for op in &script.ops {
        assert_eq!((op.old_range().start, op.new_range().start), (oi, ni));
        match *op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => {
                assert_eq!(
                    old[old_index..old_index + len],
                    new[new_index..new_index + len]
                );
                out.extend_from_slice(&old[old_index..old_index + len]);
            }
            DiffOp::Insert {
                new_index, new_len, ..
            } => out.extend_from_slice(&new[new_index..new_index + new_len]),
            _ => {}
        }
        oi = op.old_range().end;
        ni = op.new_range().end;
    }
    assert_eq!((oi, ni), (old.len(), new.len()));
    out
}

fn lcs(a: &[u8], b: &[u8]) -> usize {
    let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in 0..a.len() {
        for j in 0..b.len() {
            dp[i + 1][j + 1] = if a[i] == b[j] {
                dp[i][j] + 1
            } else {
                dp[i][j + 1].max(dp[i + 1][j])
            };
        }
    }
    dp[a.len()][b.len()]
}

fn small_seq() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..4, 0..40)
}

proptest! {
    #[test]
    fn script_is_valid_and_minimal(a in small_seq(), b in small_seq()) {
        let s = diff_slices(&a, &b, &DiffOptions::default());
        prop_assert_eq!(&apply(&a, &b, &s), &b);
        prop_assert!(s.exact);
        prop_assert_eq!(s.matched(), lcs(&a, &b));
    }

    #[test]
    fn capped_script_is_still_valid(a in small_seq(), b in small_seq(), cap in 0usize..4) {
        let s = diff_slices(&a, &b, &DiffOptions::default().with_max_cost(cap));
        prop_assert_eq!(apply(&a, &b, &s), b);
    }

    #[test]
    fn tokenizers_round_trip(text in ".*") {
        for g in [Granularity::Line, Granularity::Word, Granularity::Char] {
            prop_assert_eq!(g.tokenize(&text).concat(), text.clone());
        }
    }

    #[test]
    fn text_diff_reconstructs(a in "[ab\n ]{0,40}", b in "[ab\n ]{0,40}") {
        for g in [Granularity::Line, Granularity::Word, Granularity::Char] {
            let d = TextDiff::new(&a, &b, g);
            let new: String = d.changes().filter(|c| c.tag != rune_diff::ChangeTag::Delete).map(|c| c.value).collect();
            let old: String = d.changes().filter(|c| c.tag != rune_diff::ChangeTag::Insert).map(|c| c.value).collect();
            prop_assert_eq!(&new, &b);
            prop_assert_eq!(&old, &a);
            prop_assert_eq!(d.is_identical(), a == b);
            let _ = d.unified(2).to_string();
        }
    }

    #[test]
    fn masking_is_idempotent(text in ".{0,200}") {
        let m = Masker::new(&MaskOptions::default()).unwrap();
        let once = m.mask(&text).into_owned();
        prop_assert_eq!(m.mask(&once).into_owned(), once);
    }

    #[test]
    fn response_diff_never_panics_and_is_reflexive(a in prop::collection::vec(any::<u8>(), 0..200), b in prop::collection::vec(any::<u8>(), 0..200), json: bool) {
        let ct = if json { "application/json" } else { "text/plain" };
        let ra = HttpResponse::new(200).with_header("Content-Type", ct).with_body(a);
        let rb = HttpResponse::new(201).with_header("content-type", ct).with_body(b);
        let differ = HttpDiffer::new(&HttpDiffOptions::default()).unwrap();
        let d = differ.diff_responses(&ra, &rb);
        prop_assert!((0.0..=1.0).contains(&d.body.similarity()));
        let _ = d.to_string();
        prop_assert!(differ.diff_responses(&ra, &ra).is_equivalent());
    }
}

//! Known-answer tests against the reference implementations.

mod common;

use common::{PAIRS, VECTORS};
use rune_fuzzyhash::{Error, Ssdeep, Tlsh, TlshBuilder};

#[test]
fn tlsh_digests_match_reference() {
    for (i, v) in VECTORS.iter().enumerate() {
        let got = Tlsh::hash(&v.input());
        match v.tlsh {
            Some(want) => assert_eq!(
                got.map(|t| t.to_string()).as_deref(),
                Ok(want),
                "vector {i}: {v:?}"
            ),
            None => assert!(got.is_err(), "vector {i} should be TNULL: {got:?}"),
        }
    }
}

#[test]
fn tlsh_streaming_matches_one_shot() {
    for v in VECTORS.iter().filter(|v| v.tlsh.is_some()) {
        let data = v.input();
        let mut b = TlshBuilder::new();
        for chunk in data.chunks(37) {
            b.update(chunk);
        }
        assert_eq!(b.finish().map(|t| t.to_string()).ok().as_deref(), v.tlsh);
    }
}

#[test]
fn ssdeep_digests_match_reference() {
    for (i, v) in VECTORS.iter().enumerate() {
        let got = Ssdeep::hash(&v.input()).unwrap();
        assert_eq!(got.to_string(), v.ssdeep, "vector {i}: {v:?}");
    }
}

#[test]
fn distances_and_scores_match_reference() {
    for &(i, j, tlsh, score) in PAIRS {
        let (a, b) = (&VECTORS[i], &VECTORS[j]);
        if let Some((diff, diff_xlen)) = tlsh {
            let ta: Tlsh = a.tlsh.unwrap().parse().unwrap();
            let tb: Tlsh = b.tlsh.unwrap().parse().unwrap();
            assert_eq!(ta.distance(&tb), diff, "TLSH diff {i}/{j}");
            assert_eq!(tb.distance(&ta), diff, "TLSH diff {j}/{i}");
            assert_eq!(
                ta.distance_ignoring_len(&tb),
                diff_xlen,
                "TLSH diffxlen {i}/{j}"
            );
        }
        let sa: Ssdeep = a.ssdeep.parse().unwrap();
        let sb: Ssdeep = b.ssdeep.parse().unwrap();
        assert_eq!(sa.compare(&sb), score, "ssdeep {i}/{j}: {sa} vs {sb}");
    }
}

/// TLSH's own published unit test (`Testing/exp/simple_unittest.128.1.EXP`
/// in the TLSH repository): two strings, their digests and distances. The
/// C++ test hashes each string with its terminating NUL (512 and 1024
/// bytes).
#[test]
fn tlsh_published_simple_unittest() {
    let tail = |start: u8, len: usize| -> String {
        (0..len)
            .map(|i| char::from(b'A' + (start + u8::try_from(i % 26).unwrap()) % 26))
            .collect()
    };
    let str1 = format!(
        "This is a test for Lili Diao. This is a string. Hello Hello Hello {}",
        tail(b'O' - b'A', 445)
    );
    let str2 = format!(
        "This is a test for Jon Oliver. This is a string. Hello Hello Hello {}",
        tail(b'P' - b'A', 956)
    );
    let with_nul = |s: &str| [s.as_bytes(), &[0]].concat();
    let h1 = Tlsh::hash(&with_nul(&str1)).unwrap();
    let h2 = Tlsh::hash(&with_nul(&str2)).unwrap();
    assert_eq!(
        h1.to_string(),
        "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448"
    );
    assert_eq!(
        h2.to_string(),
        "T1301124198C869A5A4F0F9380A9AE92F2B9278F42089EA34272885F0FB2D34E6911444C"
    );
    assert_eq!(h1.distance(&h1), 0);
    assert_eq!(h1.distance(&h2), 121);
    assert_eq!(h1.distance_ignoring_len(&h2), 97);
}

#[test]
fn tlsh_rejections_match_reference_tnull() {
    assert!(matches!(Tlsh::hash(&[0u8; 100]), Err(Error::LowVariation)));
    assert!(matches!(Tlsh::hash(b"short"), Err(Error::TooShort { .. })));
}

/// Signatures one block-size step apart, from edited copies of TLSH's
/// `example_data` corpus; scores from ssdeep 2.14.1 `fuzzy_compare`, in
/// both argument orders.
#[test]
fn ssdeep_cross_block_size_scores_match_reference() {
    let cases = [
        (
            "96:koJ37jheOX2F6KflwaZ+8QRcKSqYL49kTh11VD5iomJ0cixwQS0qpybQGE68zE:koJ3RiFZyRre4oPVD52J0cFZ0qsbXpIE",
            "192:koJ3RiFZyR1Ce4oPVD52J0cFZ0qsbXpIE:T4FZ4CYPVeFZfsbZH",
            97,
        ),
        (
            "24:eGZF6hlZ2tkt/HyATR06WjdQduEAa5yFdj29EWPReW6nySF3if9zp1F9YB27Ky02:36hsC/nRHuerAbj29EyDMOp1Ll63HkYI",
            "48:/y6hrIf/qRACsrtn929QDyfMip1MWlnM1PHz:/s3B/tn9oUuT/M4cb",
            0,
        ),
        (
            "24:eGZF6hlZ2tkt/HyATR06WjdQduEAa5yFdj29EWPReW6nySF3if9zp1F9YB27Ky02:36hsC/nRHuerAbj29EyDMOp1Ll63HkYI",
            "48:36hovlC/nRZWECbj29EyDMZp6Vl63HkYI:lvlwCbjoEIu4juq",
            72,
        ),
        (
            "48:RulOqc96nxX0TmhYqYZ+fziwgm1ooskbI+fBjBOMELhnQMM5d8nQ19MUR82zPKxG:QbznRM3+XjpvISMM5d8e9Vq2zcir8CVV",
            "96:QbznRM3+XjpvISMM5d8Rb9Vq2zcir8CVV:QbzRM3wjpvI84b9Vq2girN",
            97,
        ),
    ];
    for (a, b, want) in cases {
        let (a, b): (Ssdeep, Ssdeep) = (a.parse().unwrap(), b.parse().unwrap());
        assert_eq!(a.compare(&b), want, "{a} vs {b}");
        assert_eq!(b.compare(&a), want, "{b} vs {a}");
    }
}

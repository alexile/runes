//! Streaming redaction equals one-shot redaction for every chunking, as long
//! as lines fit in the window.

use proptest::prelude::*;
use rune_redact::Redactor;

const WINDOW: usize = 512;

const PIECES: &[&str] = &[
    "bob@example.com",
    "10.0.0.1",
    "4111 1111 1111 1111",
    "123-45-6789",
    "(555) 123-4567",
    "Bearer abc.def",
    "AKIAIOSFODNN7EXAMPLE",
    "sK3xPq9mNbYrVwZuAtJhCf7DgLeW2oI5qR8eMvXn",
    "hello",
    "world",
    " ",
    " ",
    "é",
    "token=",
    "::1",
    "std::fmt",
];

/// Lines of at most 8 pieces (well under `WINDOW` bytes).
fn text() -> impl Strategy<Value = String> {
    let line = prop::collection::vec(prop::sample::select(PIECES), 0..8).prop_map(|v| v.concat());
    prop::collection::vec(line, 0..8).prop_map(|v| v.join("\n"))
}

fn chunked(r: &Redactor, text: &str, mut points: Vec<usize>, lines: bool) -> String {
    let bytes = text.as_bytes();
    points.sort_unstable();
    let mut s = r.stream().with_window(WINDOW).with_line_boundaries(lines);
    let mut out = String::new();
    let mut last = 0;
    for p in points.into_iter().chain([bytes.len()]) {
        out += &s.push_bytes(&bytes[last..p]);
        last = p;
    }
    out + &s.finish()
}

proptest! {
    #[test]
    fn chunking_does_not_change_the_output(
        text in text(),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..12),
        lines in any::<bool>(),
    ) {
        let r = Redactor::default();
        let points = cuts.iter().map(|i| i.index(text.len() + 1)).collect();
        prop_assert_eq!(chunked(&r, &text, points, lines), r.redact(&text));
    }

    #[test]
    fn never_panics_on_arbitrary_input(text in "\\PC{0,200}", window in 0usize..64) {
        let r = Redactor::default();
        let _ = r.redact(&text);
        let mut s = r.stream().with_window(window).with_max_buffer(16);
        for c in text.as_bytes().chunks(5) {
            let _ = s.push_bytes(c);
        }
        let _ = s.finish();
        prop_assert_eq!(s.pending_len(), 0);
    }
}

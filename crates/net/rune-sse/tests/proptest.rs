//! Property tests: encode/parse round trips and chunking invariance.

use proptest::prelude::*;
use rune_sse::{Event, Item, Options, Parser, encode};

fn parse_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>, options: &Options) -> Vec<String> {
    let mut parser = Parser::with_options(options.clone());
    for chunk in chunks {
        parser.push(chunk);
    }
    parser.finish();
    // Errors and items rendered as text so the two runs can be compared.
    parser
        .items()
        .map(|item| match item {
            Ok(item) => format!("{item:?}"),
            Err(err) => format!("error: {err}"),
        })
        .collect()
}

fn split_at_points<'a>(input: &'a [u8], points: &[usize]) -> Vec<&'a [u8]> {
    let mut cuts: Vec<usize> = points.iter().map(|p| p % (input.len() + 1)).collect();
    cuts.sort_unstable();
    let mut chunks = Vec::new();
    let mut start = 0;
    for cut in cuts {
        chunks.push(&input[start..cut]);
        start = cut;
    }
    chunks.push(&input[start..]);
    chunks
}

/// Bytes biased towards the event-stream grammar.
fn stream_bytes() -> impl Strategy<Value = Vec<u8>> {
    let token = prop_oneof![
        Just(b"data".to_vec()),
        Just(b"event".to_vec()),
        Just(b"id".to_vec()),
        Just(b"retry".to_vec()),
        Just(b":".to_vec()),
        Just(b" ".to_vec()),
        Just(b"\n".to_vec()),
        Just(b"\r".to_vec()),
        Just(b"\r\n".to_vec()),
        Just(b"\xEF\xBB\xBF".to_vec()),
        Just(b"\0".to_vec()),
        Just("é世".as_bytes().to_vec()),
        "[0-9]{1,3}".prop_map(String::into_bytes),
        proptest::collection::vec(any::<u8>(), 0..4),
    ];
    proptest::collection::vec(token, 0..64).prop_map(|t| t.concat())
}

fn event_strategy() -> impl Strategy<Value = Event> {
    (
        "[a-z][a-z0-9.]{0,8}",
        proptest::collection::vec("[^\r\n]{0,12}", 1..4),
        "[^\r\n\0]{1,8}",
    )
        .prop_map(|(event, lines, id)| Event::new(lines.join("\n")).with_event(event).with_id(id))
}

proptest! {
    #[test]
    fn encode_then_parse_round_trips(events in proptest::collection::vec(event_strategy(), 0..6), points in proptest::collection::vec(any::<usize>(), 0..8)) {
        let wire: String = events.iter().map(|e| encode(e).unwrap()).collect();
        let mut parser = Parser::new();
        for chunk in split_at_points(wire.as_bytes(), &points) {
            parser.push(chunk);
        }
        let parsed: Vec<Event> = parser.items().map(|i| i.unwrap().into_event().unwrap()).collect();
        prop_assert_eq!(parsed, events);
    }

    #[test]
    fn chunking_does_not_change_the_result(
        input in stream_bytes(),
        points in proptest::collection::vec(any::<usize>(), 0..16),
        small in any::<bool>(),
    ) {
        let options = if small {
            Options::default().with_max_line_len(12).with_max_event_len(16).with_comments(true)
        } else {
            Options::default().with_comments(true)
        };
        let whole = parse_chunks([input.as_slice()], &options);
        let split = parse_chunks(split_at_points(&input, &points), &options);
        prop_assert_eq!(&whole, &split);
        let bytewise = parse_chunks(input.chunks(1), &options);
        prop_assert_eq!(whole, bytewise);
    }

    #[test]
    fn never_panics_and_events_are_well_formed(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut parser = Parser::new();
        parser.push(&input);
        parser.finish();
        for item in parser.items() {
            if let Ok(Item::Event(event)) = item {
                prop_assert!(!event.event.is_empty());
                prop_assert!(!event.event.contains(['\r', '\n']));
                prop_assert!(!event.id.contains(['\r', '\n', '\0']));
                prop_assert!(!event.data.contains('\r'));
            }
        }
    }
}

/// Field lines, line endings and junk, so the fuzzing reaches every field.
fn piece() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::sample::select(vec![
            &b"data"[..],
            b"data:",
            b"data: x",
            b"event: e",
            b"id: 1",
            b"id",
            b"id:\0",
            b"retry: 10",
            b"retry: 99999999999999999999",
            b": c",
            b"\xEF\xBB\xBF",
            b"\n",
            b"\r",
            b"\r\n",
            b"\xff",
            b"\xe2\x82",
        ])
        .prop_map(<[u8]>::to_vec),
        proptest::collection::vec(any::<u8>(), 0..40),
    ]
}

proptest! {
    #[test]
    fn structured_input_never_panics_and_respects_limits(
        pieces in proptest::collection::vec(piece(), 0..60),
        max_line in 0usize..40,
        max_event in 0usize..60,
        max_id in 0usize..8,
        chunk in 1usize..32,
    ) {
        let options = Options::default()
            .with_max_line_len(max_line)
            .with_max_event_len(max_event)
            .with_max_id_len(max_id)
            .with_comments(true);
        let input = pieces.concat();
        let mut parser = Parser::with_options(options);
        for part in input.chunks(chunk) {
            parser.push(part);
            for item in parser.items() {
                if let Ok(Item::Event(event)) = item {
                    prop_assert!(event.id.len() <= max_id);
                    prop_assert!(event.data.len() < max_event.max(1));
                }
            }
        }
        parser.finish();
        prop_assert!(parser.last_event_id().len() <= max_id);
    }
}

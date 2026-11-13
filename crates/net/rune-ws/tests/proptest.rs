//! Property tests: frame round trips, chunking invariance and no panics.

use proptest::prelude::*;
use rune_ws::{
    Connection, DecoderOptions, Frame, FrameDecoder, Message, OpCode, Options, decode_frame,
    parse_request, parse_response,
};

fn opcode() -> impl Strategy<Value = OpCode> {
    prop_oneof![
        Just(OpCode::Continuation),
        Just(OpCode::Text),
        Just(OpCode::Binary),
        Just(OpCode::Close),
        Just(OpCode::Ping),
        Just(OpCode::Pong),
    ]
}

fn payload() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..300),
        prop::collection::vec(any::<u8>(), 65_530..65_545),
    ]
}

fn frame() -> impl Strategy<Value = Frame> {
    (
        opcode(),
        any::<bool>(),
        0u8..8,
        any::<Option<[u8; 4]>>(),
        payload(),
    )
        .prop_map(|(opcode, fin, rsv, mask, mut payload)| {
            let fin = fin || opcode.is_control();
            if opcode.is_control() {
                payload.truncate(125);
            }
            Frame::new(opcode, payload)
                .with_fin(fin)
                .with_rsv(rsv)
                .with_mask(mask)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn frame_round_trip(frame in frame()) {
        let bytes = frame.to_bytes();
        prop_assert_eq!(bytes.len(), frame.encoded_len());
        let opts = DecoderOptions::default().with_allowed_rsv(0b111);
        let (decoded, used) = decode_frame(&bytes, &opts).unwrap().unwrap();
        prop_assert_eq!(used, bytes.len());
        prop_assert_eq!(decoded, frame);
    }

    #[test]
    fn chunking_does_not_change_frames(frames in prop::collection::vec(frame(), 1..4), chunk in 1usize..2000) {
        let opts = DecoderOptions::default().with_allowed_rsv(0b111);
        let mut bytes = Vec::new();
        for f in &frames {
            f.encode(&mut bytes);
        }
        let mut decoder = FrameDecoder::new(opts);
        let mut out = Vec::new();
        for piece in bytes.chunks(chunk) {
            decoder.push(piece);
            while let Some(f) = decoder.next_frame() {
                out.push(f.unwrap());
            }
        }
        prop_assert_eq!(out, frames);
        prop_assert!(decoder.buffered().is_empty());
    }

    #[test]
    fn messages_survive_any_fragmentation(text in ".{0,300}", size in 1usize..64) {
        let options = Options::default().with_send_fragment_size(Some(size));
        let mut client = Connection::client(options, || [1, 2, 3, 4]);
        let mut server = Connection::server(Options::default());
        client.send(Message::Text(text.clone())).unwrap();
        server.receive(&client.take_outgoing());
        prop_assert_eq!(server.next_message().unwrap().unwrap(), Message::Text(text));
    }

    #[test]
    fn decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_frame(&bytes, &DecoderOptions::default());
        let _ = parse_request(&bytes, 256);
        let _ = parse_response(&bytes, 256);
        let endpoints = [
            Connection::server(Options::default()),
            Connection::client(Options::default(), || [0; 4]),
        ];
        for mut conn in endpoints {
            conn.receive(&bytes);
            while let Some(item) = conn.next_message() {
                if item.is_err() {
                    prop_assert!(conn.is_closed());
                }
            }
        }
    }
}

/// A server, with permessage-deflate when the feature is on.
fn server(max_message: usize) -> Connection {
    let server = Connection::server(Options::default().with_max_message_size(max_message));
    #[cfg(feature = "deflate")]
    let server = server.with_deflate(rune_ws::DeflateParams::default());
    server
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mutated_streams_never_panic(
        texts in prop::collection::vec(".{0,80}", 1..4),
        fragment in 1usize..40,
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
        chunk in 1usize..64,
    ) {
        let client = Connection::client(
            Options::default().with_send_fragment_size(Some(fragment)),
            || [9, 8, 7, 6],
        );
        #[cfg(feature = "deflate")]
        let client = client.with_deflate(rune_ws::DeflateParams::default());
        let mut client = client;
        for text in &texts {
            client.send(Message::Text(text.clone())).unwrap();
            client.send(Message::Ping(b"p".to_vec())).unwrap();
        }
        let mut bytes = client.take_outgoing();
        for (at, byte) in edits {
            let i = at.index(bytes.len());
            bytes[i] ^= byte;
        }
        let mut server = server(256);
        for piece in bytes.chunks(chunk) {
            server.receive(piece);
            while let Some(item) = server.next_message() {
                if item.is_err() {
                    prop_assert!(server.is_closed());
                }
            }
        }
        let _ = server.take_outgoing();
    }
}

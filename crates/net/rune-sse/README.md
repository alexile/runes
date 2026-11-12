# rune-sse

> Incremental sans-I/O Server-Sent Events (text/event-stream) parser

[![crates.io](https://img.shields.io/crates/v/rune-sse)](https://crates.io/crates/rune-sse)
[![docs.rs](https://img.shields.io/docsrs/rune-sse)](https://docs.rs/rune-sse)
[![license](https://img.shields.io/crates/l/rune-sse)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Parses `text/event-stream` exactly as the
[WHATWG HTML standard, §9.2 "Server-sent events"](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation)
describes it, one chunk at a time:

- `event`, multi-line `data`, `id` (persistent last event ID) and `retry`
  fields, and comments;
- CRLF, LF and CR line endings, including a CRLF split across chunks;
- a leading UTF-8 BOM, invalid UTF-8 (U+FFFD) and characters split across
  chunks;
- an event without its terminating blank line is never dispatched.

The core `Parser` does no I/O: push bytes in, pull events out. Thin
adapters cover `std::io::Read` (`Reader`) and `futures::Stream`
(`SseStream`, feature `stream`). `encode` writes events back out, for
servers and proxies. Buffering is bounded (`Options::max_line_len`,
`Options::max_event_len`); an oversized event is reported and skipped, and
parsing continues.

## Installation

```bash
cargo add rune-sse
# with the futures::Stream adapter
cargo add rune-sse --features stream
```

| Feature  | Enables                                                   |
| -------- | --------------------------------------------------------- |
| `stream` | `SseStream`, a `futures::Stream` adapter over byte chunks |
| `serde`  | `Serialize`/`Deserialize` for `Event`                     |

## Usage

### Push bytes, pull events

```rust
use rune_sse::{Item, Parser};

let mut parser = Parser::new();
parser.push(b"event: delta\ndata: {\"text\":");
assert!(parser.next_item().is_none()); // event not complete yet

parser.push(b"\"hi\"}\nid: 7\n\nretry: 3000\n");
let event = parser.next_event().unwrap().unwrap();
assert_eq!((event.event.as_str(), event.data.as_str()), ("delta", "{\"text\":\"hi\"}"));

// At the end of the stream, drop any unterminated event. The parser keeps
// the last event ID for the reconnection's `Last-Event-ID` header.
parser.finish();
assert_eq!(parser.last_event_id(), "7");
```

### From a reader

```rust
use rune_sse::Reader;

let body: &[u8] = b"data: one\n\ndata: two\n\n";
for item in Reader::new(body) {
    if let Some(event) = item.unwrap().into_event() {
        println!("{}", event.data);
    }
}
```

### From a byte stream (feature `stream`)

```rust,ignore
use futures::StreamExt;
use rune_sse::SseStream;

// e.g. reqwest::Response::bytes_stream()
let mut events = SseStream::new(response.bytes_stream());
while let Some(item) = events.next().await {
    // ...
}
```

### Encoding

```rust
use rune_sse::{Event, encode};

let wire = encode(&Event::new("a\nb").with_event("delta").with_id("7")).unwrap();
assert_eq!(wire, "event: delta\nid: 7\ndata: a\ndata: b\n\n");
```

## License

MIT
